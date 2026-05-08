"""
Stream Server Alerts – Web application.

Run from the project folder (where app.py, stream_server_alerts.yaml, templates/ live):
  python app.py
  or: flask --app app run
Then open http://127.0.0.1:5000

Loads .env from project folder so OPENSEARCH_* and other config are set before connecting.
"""

from pathlib import Path

# Load .env so OPENSEARCH_URL etc. are set before any OpenSearch connection
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent / ".env", override=True)
except ImportError:
    pass

import os
import re
from typing import Any

from flask import Flask, Response, jsonify, render_template, request

# Project root = folder containing app.py (so templates/ and stream_server_alerts.yaml are found)
PROJECT_ROOT = Path(__file__).resolve().parent
CONFIG_PATH = PROJECT_ROOT / "stream_server_alerts.yaml"

app = Flask(__name__, template_folder=str(PROJECT_ROOT / "templates"))
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0

# Fail fast if config or templates are missing
if not CONFIG_PATH.exists():
    raise FileNotFoundError(f"Config not found: {CONFIG_PATH}. Run from project folder: {PROJECT_ROOT}")


from alert_engine import run
from agent import AlertAgent


@app.route("/")
def index():
    resp = app.make_response(render_template("index.html"))
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return resp


def _apply_time_minutes(ctx: dict, data: dict) -> None:
    """Set ctx['_time_minutes'] from request data (1–43200, mirrors OpenSearch Discover)."""
    val = data.get("time_minutes")
    if val is None:
        ctx["_time_minutes"] = 15
        return
    try:
        m = int(val)
        ctx["_time_minutes"] = max(1, min(43200, m))  # 1 min to 30 days (Discover range)
    except (TypeError, ValueError):
        ctx["_time_minutes"] = 15


def _client_error_counts_from_context(ctx):
    """Build list of {client, error_count} from opensearch_tenants or impacted_tenants."""
    tenants = ctx.get("opensearch_tenants") or []
    if tenants and isinstance(tenants[0], dict):
        return [{"client": t.get("name") or "", "error_count": t.get("count", 0)} for t in tenants]
    names = ctx.get("impacted_tenants") or []
    if names:
        return [{"client": n if isinstance(n, str) else str(n), "error_count": 0} for n in names]
    return []


@app.route("/api/health")
def api_health():
    """Check that the server and config are OK."""
    return jsonify({"ok": True, "config": str(CONFIG_PATH)})


@app.route("/api/db/status")
def api_db_status():
    """PostgreSQL connectivity and read-only server details (for Database check UI)."""
    from db_client import check_database_status

    return jsonify(check_database_status())


@app.route("/api/symitar/config")
def api_symitar_config():
    """Non-secret SYM_* values from server .env for pre-filling the Symitar screen (password never returned)."""
    import os

    from symitar_api_agent import CONFIGMAP_KEYS

    def g(key: str, default: str = "") -> str:
        return (os.environ.get(key) or default).strip()

    ssl_raw = g("SYM_VERIFY_SSL").lower()
    verify = ssl_raw in ("1", "true", "yes")
    missing = [k for k in CONFIGMAP_KEYS if not g(k)]
    return jsonify({
        "SYM_WSDL_DIRECTORY": g("SYM_WSDL_DIRECTORY"),
        "SYM_VERSION": g("SYM_VERSION"),
        "SYM_CORE_API_DEVICE_TYPE": g("SYM_CORE_API_DEVICE_TYPE"),
        "SYM_CORE_API_DEVICE_NUMBER": g("SYM_CORE_API_DEVICE_NUMBER"),
        "SYM_VERIFY_SSL": "1" if verify else "0",
        "SYM_HTTP_TIMEOUT_SEC": g("SYM_HTTP_TIMEOUT_SEC") or "60",
        "SYM_MESSAGE_ID": g("SYM_MESSAGE_ID") or "123456",
        "has_saved_password": bool(g("SYM_CORE_API_PASSWORD")),
        "configured": len(missing) == 0,
        "missing_keys": missing,
    })


@app.route("/api/symitar/status", methods=["GET", "POST"])
def api_symitar_status():
    """Whether SYM_* is complete — GET uses server .env only; POST merges optional ``config`` from the Symitar UI."""
    from symitar_api_agent import CONFIGMAP_KEYS, SymitarSettings, resolved_symitar_env

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        cfg = data.get("config")
        env_merged = resolved_symitar_env(cfg if isinstance(cfg, dict) else None)
        missing = [k for k in CONFIGMAP_KEYS if not (env_merged.get(k) or "").strip()]
        s = SymitarSettings.from_environ(env_merged)
    else:
        import os

        missing = [k for k in CONFIGMAP_KEYS if not (os.environ.get(k) or "").strip()]
        s = SymitarSettings.from_environ()
    return jsonify({
        "ok": True,
        "configured": s is not None,
        "missing_keys": missing,
        "sym_version": s.version if s else "",
        "wsdl_directory_preview": (
            (s.wsdl_directory[:72] + "…") if s and len(s.wsdl_directory) > 72 else (s.wsdl_directory if s else "")
        ),
    })


@app.route("/api/symitar/run", methods=["POST"])
def api_symitar_run():
    """POST SymXchange SOAP request using SYM_* from server .env merged with optional ``config`` from the UI."""
    from symitar_api_agent import CONFIGMAP_KEYS, SymitarSettings, resolved_symitar_env, run_symitar_request

    data = request.get_json() or {}
    cfg = data.get("config")
    env_merged = resolved_symitar_env(cfg if isinstance(cfg, dict) else None)
    settings = SymitarSettings.from_environ(env_merged)
    if not settings:
        miss = [k for k in CONFIGMAP_KEYS if not (env_merged.get(k) or "").strip()]
        return jsonify({
            "ok": False,
            "error": "Incomplete SYM_* configuration",
            "missing_keys": miss,
            "hint": (
                "Set the listed keys in the Connection (SYM_*) section, in Settings, or in .env. "
                "Blank fields in the form keep values from .env — they no longer erase them."
            ),
        }), 400

    api_endpoint = (data.get("api_endpoint") or "").strip()
    fin_dto = (data.get("fin_dto") or "").strip()
    operation = (data.get("operation") or "").strip()
    request_xml = data.get("request_xml")
    if request_xml is None:
        request_xml = ""
    elif not isinstance(request_xml, str):
        request_xml = str(request_xml)

    if not api_endpoint or not fin_dto or not operation:
        return jsonify({
            "ok": False,
            "error": "api_endpoint, fin_dto, and operation are required",
        }), 400

    try:
        result = run_symitar_request(settings, api_endpoint, fin_dto, operation, request_xml)
        return jsonify(result)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


def _mask(val: str) -> str:
    """Mask a sensitive value, showing only the first 4 and last 4 chars."""
    if not val:
        return "(not set)"
    if len(val) <= 10:
        return val[:2] + "***" + val[-2:]
    return val[:4] + "***" + val[-4:]


def _cap(val: Any, n: int = 240) -> str:
    """Cap a free-text log field at ``n`` chars (suffixing an ellipsis) so the
    analyse prompt doesn't blow past the upstream model's per-request token
    budget. Newlines/tabs collapsed to single spaces."""
    if val is None:
        return ""
    s = str(val).replace("\n", " ").replace("\r", " ").replace("\t", " ")
    s = " ".join(s.split())
    if len(s) > n:
        return s[: max(1, n - 1)] + "…"
    return s


@app.route("/api/settings")
def api_settings():
    """Return configuration details for all agents (sensitive values masked)."""
    import os

    def _env(key, default=""):
        return os.environ.get(key, default).strip()

    def _bool_env(key):
        return _env(key).lower() in ("true", "1", "yes")

    try:
        from ai_summarizer import _openai_base_url as _resolve_openai_base_url
        from ai_summarizer import _openai_model_name as _resolve_openai_model_name

        _llm_openai_base_url = _resolve_openai_base_url()
        _llm_openai_model = _resolve_openai_model_name()
    except Exception:
        _llm_openai_base_url = _env("OPENAI_BASE_URL", "https://api.openai.com/v1")
        _llm_openai_model = _env("OPENAI_MODEL", "gpt-4o-mini")

    return jsonify({
        "stream_server": {
            "title": "Stream Server Alerts",
            "opensearch_url": _env("OPENSEARCH_URL"),
            "opensearch_index": _env("OPENSEARCH_INDEX", "stream-*"),
            "opensearch_user": _env("OPENSEARCH_USER") or "(not set)",
            "opensearch_password": _mask(_env("OPENSEARCH_PASSWORD")),
            "time_field": _env("OPENSEARCH_TIME_FIELD", "@timestamp"),
            "error_code_field": _env("OPENSEARCH_ERROR_CODE_FIELD", "error_code"),
            "error_name_field": _env("OPENSEARCH_ERROR_NAME_FIELD"),
            "error_stack_field": _env("OPENSEARCH_ERROR_STACK_FIELD"),
            "level_field": _env("OPENSEARCH_LEVEL_FIELD"),
            "level_value": _env("OPENSEARCH_LEVEL_VALUE"),
            "k8s_version_prefix": _env("OPENSEARCH_K8S_VERSION_PREFIX"),
            "exclude_error_stack": _env("OPENSEARCH_EXCLUDE_ERROR_STACK"),
            "verify_ssl": _env("OPENSEARCH_VERIFY_SSL", "1") != "0",
            "request_timeout": _env("OPENSEARCH_REQUEST_TIMEOUT", "60"),
            "request_timeout_long": _env("OPENSEARCH_REQUEST_TIMEOUT_LONG", "120"),
            "slack_enabled": _bool_env("SLACK_ENABLED"),
            "slack_channel": _env("SLACK_CHANNEL"),
            "slack_bot_token": _mask(_env("SLACK_BOT_TOKEN")),
            "slack_app_token": _mask(_env("SLACK_APP_TOKEN")),
            "slack_listener_enabled": _bool_env("SLACK_LISTENER_ENABLED"),
            "slack_alert_keywords": _env("SLACK_ALERT_KEYWORDS"),
            "slack_alert_time_minutes": _env("SLACK_ALERT_TIME_MINUTES", "15"),
            "slack_error_threshold": _env("SLACK_ERROR_THRESHOLD", "30"),
        },
        "bot_engine": {
            "title": "Bot Engine Default Logs",
            "opensearch_url": _env("OPENSEARCH_URL"),
            "bot_engine_index": _env("OPENSEARCH_BOT_ENGINE_INDEX"),
            "conversation_index": _env("OPENSEARCH_CONVERSATION_INDEX", "conversation-*"),
            "context_field": _env("OPENSEARCH_BOT_ENGINE_CONTEXT_FIELD"),
            "time_field": _env("OPENSEARCH_TIME_FIELD", "@timestamp"),
            "opensearch_user": _env("OPENSEARCH_USER") or "(not set)",
            "opensearch_password": _mask(_env("OPENSEARCH_PASSWORD")),
        },
        "integration_manager": {
            "title": "Integration Manager Default Logs",
            "opensearch_url": _env("OPENSEARCH_URL"),
            "integration_manager_index": _env("OPENSEARCH_INTEGRATION_MANAGER_INDEX"),
            "time_field": _env("OPENSEARCH_TIME_FIELD", "@timestamp"),
            "opensearch_user": _env("OPENSEARCH_USER") or "(not set)",
            "opensearch_password": _mask(_env("OPENSEARCH_PASSWORD")),
        },
        "stream_server_logs": {
            "title": "Stream Server Default Logs",
            "opensearch_url": _env("OPENSEARCH_URL"),
            "stream_server_index": _env("OPENSEARCH_STREAM_SERVER_INDEX") or _env("OPENSEARCH_INDEX"),
            "context_field": _env("OPENSEARCH_STREAM_SERVER_CONTEXT_FIELD", "rawLog.data.contextId"),
            "apt_field": _env("OPENSEARCH_STREAM_SERVER_APT_FIELD", "rawLog.data.action.event.client.data.name"),
            "connection_field": _env("OPENSEARCH_STREAM_SERVER_CONNECTION_FIELD", "rawLog.data.action.event.connection.id"),
            "time_field": _env("OPENSEARCH_TIME_FIELD", "@timestamp"),
            "opensearch_user": _env("OPENSEARCH_USER") or "(not set)",
            "opensearch_password": _mask(_env("OPENSEARCH_PASSWORD")),
        },
        "nlp_server_logs": {
            "title": "NLP Server Default Logs",
            "opensearch_url": _env("OPENSEARCH_URL"),
            "nlp_server_index": _env("OPENSEARCH_NLP_SERVER_INDEX") or "(not set)",
            "connection_field": _env("OPENSEARCH_NLP_SERVER_CONNECTION_FIELD", "metadata.connection_id"),
            "request_field": _env("OPENSEARCH_NLP_SERVER_REQUEST_FIELD", "metadata.request_id"),
            "time_field": _env("OPENSEARCH_TIME_FIELD", "@timestamp"),
            "opensearch_user": _env("OPENSEARCH_USER") or "(not set)",
            "opensearch_password": _mask(_env("OPENSEARCH_PASSWORD")),
        },
        "twilio": {
            "title": "Twilio Log Analysis",
            "account_sid": _mask(_env("TWILIO_ACCOUNT_SID")),
            "auth_token": _mask(_env("TWILIO_AUTH_TOKEN")),
            "exclude_subaccounts": _env("TWILIO_EXCLUDE_SUBACCOUNTS"),
            "extra_accounts": _mask(_env("TWILIO_EXTRA_ACCOUNTS")),
            "workers": _env("TWILIO_WORKERS", "100"),
        },
        "llm": {
            "title": "AI / LLM",
            "openai_api_key": _mask(_env("OPENAI_API_KEY")),
            "openai_base_url": _llm_openai_base_url,
            "openai_model": _llm_openai_model,
            "openai_max_retries": _env("OPENAI_MAX_RETRIES", "5"),
            "openai_verify_ssl": _env("OPENAI_VERIFY_SSL", "1"),
            "tpm_budget": _env("LLM_TPM_BUDGET"),
        },
        "kubernetes": {
            "title": "Kubernetes (Lens)",
            "pod_filter": _env("KUBE_POD_FILTER"),
            "label_selector": _env("KUBE_LABEL_SELECTOR"),
            "namespace": _env("KUBE_NAMESPACE") or "(default)",
        },
        "database": {
            "title": "PostgreSQL",
            "database_url": _mask(_env("DATABASE_URL")),
            "db_host": _env("DB_HOST"),
            "db_port": _env("DB_PORT", "5432"),
            "db_name": _env("DB_NAME", "postgres"),
            "db_user": _env("DB_USER"),
            "db_password": _mask(_env("DB_PASSWORD")),
            "db_sslmode": _env("DB_SSLMODE", "prefer"),
        },
        "symitar": {
            "title": "Symitar Core / SymXchange",
            "wsdl_directory": _env("SYM_WSDL_DIRECTORY"),
            "version": _env("SYM_VERSION"),
            "device_type": _env("SYM_CORE_API_DEVICE_TYPE"),
            "device_number": _env("SYM_CORE_API_DEVICE_NUMBER"),
            "password": _mask(_env("SYM_CORE_API_PASSWORD")),
            "verify_ssl": _env("SYM_VERIFY_SSL", "0") != "0",
            "timeout_sec": _env("SYM_HTTP_TIMEOUT_SEC", "60"),
            "message_id": _env("SYM_MESSAGE_ID", "123456"),
        },
    })


EDITABLE_ENV_KEYS = {
    "OPENSEARCH_URL", "OPENSEARCH_INDEX", "OPENSEARCH_USER", "OPENSEARCH_PASSWORD",
    "OPENSEARCH_TIME_FIELD", "OPENSEARCH_ERROR_CODE_FIELD", "OPENSEARCH_ERROR_NAME_FIELD",
    "OPENSEARCH_ERROR_STACK_FIELD", "OPENSEARCH_LEVEL_FIELD", "OPENSEARCH_LEVEL_VALUE",
    "OPENSEARCH_K8S_VERSION_PREFIX", "OPENSEARCH_EXCLUDE_ERROR_STACK", "OPENSEARCH_VERIFY_SSL",
    "OPENSEARCH_REQUEST_TIMEOUT", "OPENSEARCH_REQUEST_TIMEOUT_LONG",
    "OPENSEARCH_BOT_ENGINE_INDEX", "OPENSEARCH_CONVERSATION_INDEX",
    "OPENSEARCH_BOT_ENGINE_CONTEXT_FIELD", "OPENSEARCH_INTEGRATION_MANAGER_INDEX",
    "OPENSEARCH_STREAM_SERVER_INDEX", "OPENSEARCH_STREAM_SERVER_CONTEXT_FIELD",
    "OPENSEARCH_STREAM_SERVER_APT_FIELD", "OPENSEARCH_STREAM_SERVER_CONNECTION_FIELD",
    "OPENSEARCH_NLP_SERVER_INDEX", "OPENSEARCH_NLP_SERVER_CONNECTION_FIELD",
    "OPENSEARCH_NLP_SERVER_REQUEST_FIELD",
    "SLACK_ENABLED", "SLACK_CHANNEL", "SLACK_BOT_TOKEN", "SLACK_APP_TOKEN",
    "SLACK_LISTENER_ENABLED", "SLACK_ALERT_KEYWORDS", "SLACK_ALERT_TIME_MINUTES",
    "SLACK_ERROR_THRESHOLD",
    "TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_EXCLUDE_SUBACCOUNTS",
    "TWILIO_EXTRA_ACCOUNTS", "TWILIO_WORKERS",
    "OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_MODEL", "OPENAI_MAX_RETRIES", "OPENAI_VERIFY_SSL",
    "LLM_TPM_BUDGET",
    "KUBE_POD_FILTER", "KUBE_LABEL_SELECTOR", "KUBE_NAMESPACE",
    "DATABASE_URL", "DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD", "DB_SSLMODE",
    "SYM_WSDL_DIRECTORY", "SYM_VERSION", "SYM_CORE_API_DEVICE_TYPE",
    "SYM_CORE_API_DEVICE_NUMBER", "SYM_CORE_API_PASSWORD",
    "SYM_VERIFY_SSL", "SYM_HTTP_TIMEOUT_SEC", "SYM_MESSAGE_ID",
}


def _update_env_file(updates: dict[str, str]):
    """Update .env file in-place, preserving comments and structure."""
    env_path = Path(__file__).resolve().parent / ".env"
    if not env_path.exists():
        env_path.write_text("")

    lines = env_path.read_text(encoding="utf-8").splitlines()
    remaining = dict(updates)
    new_lines = []

    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in remaining:
                new_lines.append(f"{key}={remaining.pop(key)}")
                continue
        new_lines.append(line)

    for key, val in remaining.items():
        new_lines.append(f"{key}={val}")

    env_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")

    import os
    for key, val in updates.items():
        os.environ[key] = val


@app.route("/api/settings", methods=["POST"])
def api_settings_save():
    """Save configuration changes to .env and reload into environment."""
    data = request.get_json() or {}
    updates = {}
    for key, val in data.items():
        if key not in EDITABLE_ENV_KEYS:
            continue
        updates[key] = str(val).strip()

    if not updates:
        return jsonify({"ok": False, "error": "No valid settings to save"}), 400

    try:
        _update_env_file(updates)
        return jsonify({"ok": True, "saved": list(updates.keys())})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/restart", methods=["POST"])
def api_restart():
    """Restart the Flask server by exiting the process (debug auto-reloader will respawn)."""
    import threading

    def _shutdown():
        import time, signal
        time.sleep(0.5)
        os.kill(os.getpid(), signal.SIGTERM)

    threading.Thread(target=_shutdown, daemon=True).start()
    return jsonify({"ok": True, "message": "Server restarting..."})


@app.route("/api/opensearch/status")
def api_opensearch_status():
    """Check OpenSearch connection. Returns ok, connected, error (if any)."""
    import os
    try:
        from opensearch_client import check_opensearch_connection
        url = os.environ.get("OPENSEARCH_URL", "").strip()
        if not url:
            return jsonify({"ok": True, "connected": False, "message": "OpenSearch not configured (set OPENSEARCH_URL in .env)"})
        connected = check_opensearch_connection()
        return jsonify({"ok": True, "connected": connected, "url": url})
    except Exception as e:
        return jsonify({"ok": False, "connected": False, "error": str(e)})


@app.route("/api/k8s/status")
def api_k8s_status():
    """Check Kubernetes (Lens) connection."""
    try:
        from lens_client import check_k8s_connection
        connected = check_k8s_connection()
        return jsonify({"ok": True, "connected": connected})
    except Exception as e:
        return jsonify({"ok": False, "connected": False, "error": str(e)})


@app.route("/api/twilio/error-logs", methods=["POST"])
def api_twilio_error_logs():
    """Fetch Twilio error logs (Monitor Alerts), optionally filtered by tenant and/or error code."""
    from twilio_client import query_alerts

    data = request.get_json() or {}
    tenant = (data.get("tenant") or "").strip()
    error_code = (data.get("error_code") or "").strip()

    time_minutes = 60
    try:
        time_minutes = max(1, min(43200, int(data.get("time_minutes", 60))))
    except (TypeError, ValueError):
        pass

    try:
        result = query_alerts(
            time_minutes=time_minutes,
            tenant_names=[tenant] if tenant else None,
            error_code_filter=error_code or None,
        )
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500

    if result.get("error"):
        return jsonify({"ok": False, "error": result["error"]}), 500

    return jsonify({
        "ok": True,
        "total": result.get("total_alerts", 0),
        "error_codes": result.get("error_codes", {}),
        "by_account": result.get("by_account", {}),
        "alerts": result.get("alerts", []),
        "accounts_checked": result.get("accounts_checked", []),
    })


@app.route("/api/twilio/status")
def api_twilio_status():
    """Check Twilio connection."""
    try:
        from twilio_client import check_twilio_connection
        result = check_twilio_connection()
        return jsonify({"ok": result.get("connected", False), **result})
    except Exception as e:
        return jsonify({"ok": False, "connected": False, "error": str(e)})


def _phone_digits(phone: str) -> str:
    """Normalize a phone string to its core digits (strip non-digits and leading country-code 1)."""
    d = re.sub(r"\D", "", phone)
    if len(d) == 11 and d.startswith("1"):
        d = d[1:]
    return d


@app.route("/api/twilio/logs", methods=["POST"])
def api_twilio_logs():
    """Fetch Twilio call logs filtered by From number and/or tenant."""
    from twilio_client import query_call_logs

    data = request.get_json() or {}
    from_number = (data.get("from_number") or "").strip() or None
    tenant = (data.get("tenant") or "").strip() or None

    if not from_number and not tenant:
        return jsonify({"ok": False, "error": "from_number or tenant is required"}), 400

    time_minutes = 60
    try:
        time_minutes = max(1, min(43200, int(data.get("time_minutes", 60))))
    except (TypeError, ValueError):
        pass

    try:
        result = query_call_logs(
            time_minutes=time_minutes,
            from_number=from_number,
            tenant_names=[tenant] if tenant else None,
        )
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500

    if result.get("error"):
        return jsonify({"ok": False, "error": result["error"]}), 500

    all_calls = result.get("calls", [])
    failed = sum(1 for c in all_calls if c.get("error_code") or c.get("status") in ("failed", "busy"))

    return jsonify({
        "ok": True,
        "total": len(all_calls),
        "failed_calls": failed,
        "calls": all_calls,
        "accounts_checked": result.get("accounts_checked", []),
    })


@app.route("/api/download/twilio-logs", methods=["POST"])
def api_download_twilio_logs():
    """Download Twilio call logs filtered by From number and/or tenant as CSV or JSON."""
    import csv
    import io
    import json as json_mod
    from twilio_client import query_call_logs

    data = request.get_json() or {}
    from_number = (data.get("from_number") or "").strip() or None
    tenant = (data.get("tenant") or "").strip() or None

    if not from_number and not tenant:
        return jsonify({"ok": False, "error": "from_number or tenant is required"}), 400

    time_minutes = 60
    try:
        time_minutes = max(1, min(43200, int(data.get("time_minutes", 60))))
    except (TypeError, ValueError):
        pass

    fmt = (data.get("format") or "csv").strip().lower()

    try:
        result = query_call_logs(
            time_minutes=time_minutes,
            from_number=from_number,
            tenant_names=[tenant] if tenant else None,
        )
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500

    if result.get("error"):
        return jsonify({"ok": False, "error": result["error"]}), 500

    filtered = result.get("calls", [])
    safe_name = re.sub(r"[^\w\-]", "", from_number or tenant or "all")
    base_name = f"twilio_logs_{safe_name}_{len(filtered)}_rows"

    if fmt == "json":
        content = json_mod.dumps(filtered, indent=2, default=str)
        return Response(
            content,
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename={base_name}.json"},
        )

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "call_sid", "start_time", "end_time", "account", "namespace",
        "from", "to", "direction", "status", "duration", "duration_fmt",
        "price", "caller_name", "error_code", "error_message",
    ])
    for c in filtered:
        writer.writerow([
            c.get("sid", ""),
            c.get("start_time", ""),
            c.get("end_time", ""),
            c.get("account", ""),
            c.get("namespace", ""),
            c.get("from_raw", c.get("from", "")),
            c.get("to_raw", c.get("to", "")),
            c.get("direction", ""),
            c.get("status", ""),
            c.get("duration", ""),
            c.get("duration_fmt", ""),
            c.get("price", ""),
            c.get("caller_name", ""),
            c.get("error_code", ""),
            str(c.get("error_message", "")).replace("\n", " ").replace("\r", ""),
        ])

    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={base_name}.csv"},
    )


@app.route("/api/tenants")
def api_tenants():
    """Fetch distinct tenant names from OpenSearch."""
    try:
        from opensearch_client import query_tenant_list
        tenants = query_tenant_list(time_minutes=1440)
        return jsonify({"ok": True, "tenants": tenants})
    except Exception as e:
        return jsonify({"ok": False, "tenants": [], "error": str(e)})


@app.route("/api/tenant/error-logs", methods=["POST"])
def api_tenant_error_logs():
    """Fetch error logs from OpenSearch for a specific tenant."""
    from opensearch_client import query_all_error_logs

    data = request.get_json() or {}
    tenant = (data.get("tenant") or "").strip()
    if not tenant:
        return jsonify({"ok": False, "error": "tenant is required"}), 400

    time_minutes = 60
    try:
        time_minutes = max(1, min(43200, int(data.get("time_minutes", 60))))
    except (TypeError, ValueError):
        pass

    result = query_all_error_logs(error_codes=None, time_minutes=time_minutes, tenant_filter=tenant)
    if result is None:
        return jsonify({"ok": False, "error": "OpenSearch not configured"}), 400
    if result.get("error"):
        return jsonify({"ok": False, "error": result["error"]}), 500

    logs = result.get("logs", [])
    error_codes = {}
    for log in logs:
        code = str(log.get("error_code", "unknown"))
        error_codes[code] = error_codes.get(code, 0) + 1

    return jsonify({
        "ok": True,
        "tenant": tenant,
        "total": len(logs),
        "error_codes": error_codes,
        "logs": logs[:500],
    })


@app.route("/api/run", methods=["POST"])
def api_run():
    data = request.get_json() or {}
    error_codes = data.get("error_codes") or []
    try:
        codes = [int(c) for c in error_codes]
    except (TypeError, ValueError):
        codes = []

    ctx = data.get("context") or {}
    ctx["_error_codes"] = codes  # used by OpenSearch query (OPENSEARCH_ERROR_CODE_FIELD)
    # Map UI-friendly keys to engine context
    simulate = {}
    if ctx.get("calls_ok") is True:
        simulate["calls_ok"] = True
        simulate["calls_fail"] = False
    if ctx.get("calls_fail") is True:
        simulate["calls_fail"] = True
        simulate["calls_ok"] = False
    if "restart_detected" in ctx:
        simulate["restart_detected"] = bool(ctx["restart_detected"])
    if ctx.get("auth_ok") is True:
        simulate["auth_ok"] = True
        simulate["auth_fail"] = False
    if ctx.get("auth_fail") is True:
        simulate["auth_fail"] = True
        simulate["auth_ok"] = False
    if simulate:
        preserved = {k: v for k, v in ctx.items() if k.startswith("_")}
        ctx = {"simulate": simulate, **preserved}
    _apply_time_minutes(ctx, data)

    try:
        result = run(CONFIG_PATH, codes, initial_context=ctx, quiet=True)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    out_context = result.get("context") or {}
    out_context = {k: v for k, v in out_context.items() if not callable(v)}

    # Client-wise (tenant-wise) error counts for UI
    client_error_counts = _client_error_counts_from_context(out_context)

    response_payload = {
        "ok": True,
        "scenario_id": result.get("scenario_id"),
        "conclusion": result.get("conclusion"),
        "next_action": result.get("next_action"),
        "matched_rule": result.get("matched_rule", False),
        "error": result.get("error"),
        "context": out_context,
        "client_error_counts": client_error_counts,
        "total_error_count": out_context.get("error_count") or out_context.get("opensearch_total"),
        "error_codes_used": codes,
    }

    return jsonify(response_payload)


@app.route("/api/slack/status")
def api_slack_status():
    """Check Slack bot connection."""
    try:
        from slack_notifier import check_connection
        result = check_connection()
        return jsonify({"ok": result.get("connected", False), **result})
    except Exception as e:
        return jsonify({"ok": False, "connected": False, "error": str(e)})


@app.route("/api/slack/send", methods=["POST"])
def api_slack_send():
    """Manually send RCA results to Slack (triggered from UI button)."""
    try:
        from slack_notifier import post_rca_to_slack
        data = request.get_json() or {}
        rca = data.get("rca")
        if not rca:
            return jsonify({"ok": False, "error": "No RCA data provided"}), 400
        channel = data.get("channel")
        time_mins = data.get("time_minutes", 15)
        result = post_rca_to_slack(rca, channel=channel, time_minutes=time_mins)
        return jsonify(result)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/api/slack/command", methods=["POST"])
def api_slack_command():
    """Handle Slack slash command /rca."""
    import threading

    try:
        from slack_notifier import verify_signature, post_to_response_url
    except ImportError:
        return jsonify({"text": "Slack notifier not available"}), 500

    timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
    signature = request.headers.get("X-Slack-Signature", "")
    body = request.get_data(as_text=True)

    if not verify_signature(timestamp, body, signature):
        return "", 403

    command_text = request.form.get("text", "").strip()
    response_url = request.form.get("response_url", "")

    parts = command_text.split()
    error_codes = []
    time_minutes = 15
    if parts:
        try:
            error_codes = [int(parts[0])]
        except ValueError:
            if parts[0].lower() == "all":
                error_codes = []
        if len(parts) > 1:
            try:
                time_minutes = max(1, min(43200, int(parts[1])))
            except ValueError:
                pass

    def _run_and_post():
        try:
            ctx = {"_error_codes": error_codes, "_time_minutes": time_minutes}
            result = run(CONFIG_PATH, error_codes, initial_context=ctx, quiet=True)
            out_context = result.get("context") or {}
            rca = out_context.get("rca")
            if rca and response_url:
                post_to_response_url(response_url, rca, time_minutes)
        except Exception:
            if response_url:
                import requests as req
                req.post(response_url, json={"text": "RCA analysis failed. Check server logs."}, timeout=10)

    thread = threading.Thread(target=_run_and_post, daemon=True)
    thread.start()

    codes_str = ", ".join(str(c) for c in error_codes) if error_codes else "all"
    return jsonify({
        "response_type": "ephemeral",
        "text": f"Running RCA analysis (error codes: {codes_str}, time window: {time_minutes}m)... Results will be posted shortly.",
    })


@app.route("/api/bot-engine/status")
def api_bot_engine_status():
    """Check if the bot engine OpenSearch index is configured and reachable."""
    from ai_summarizer import log_analysis_meta_for_status

    try:
        from opensearch_client import check_bot_engine_index
        result = check_bot_engine_index()
        meta = log_analysis_meta_for_status()
        return jsonify({"ok": True, **result, **meta})
    except Exception as e:
        meta = log_analysis_meta_for_status()
        return jsonify({"ok": False, "configured": False, "connected": False, "error": str(e), **meta})


@app.route("/api/bot-engine/logs", methods=["POST"])
def api_bot_engine_logs():
    """Fetch bot engine logs by Connection ID and/or Context ID."""
    from opensearch_client import query_bot_engine_default_logs

    data = request.get_json() or {}
    connection_id = (data.get("connection_id") or "").strip()
    context_id = (data.get("context_id") or "").strip()
    if not connection_id and not context_id:
        return jsonify({"ok": False, "error": "connection_id or context_id is required"}), 400

    time_minutes = 0
    try:
        time_minutes = max(0, int(data.get("time_minutes", 0)))
    except (TypeError, ValueError):
        pass

    max_logs = min(int(data.get("max_logs", 500)), 10000)

    result = query_bot_engine_default_logs(
        connection_id=connection_id or None,
        context_id=context_id or None,
        time_minutes=time_minutes if time_minutes > 0 else None,
        max_logs=max_logs,
    )
    if result is None:
        return jsonify({"ok": False, "error": "Bot engine index not configured (set OPENSEARCH_BOT_ENGINE_INDEX in .env)"}), 400
    if result.get("error"):
        return jsonify({"ok": False, **result}), 500

    ui_logs = [{k: v for k, v in log.items() if k != "_raw"} for log in result.get("logs", [])]
    payload: dict[str, Any] = {
        "ok": True,
        "total": result.get("total", 0),
        "scanned": result.get("scanned", 0),
        "logs": ui_logs,
    }
    if result.get("diagnostics") is not None:
        payload["diagnostics"] = result["diagnostics"]
    return jsonify(payload)


@app.route("/api/download/bot-engine-logs", methods=["POST"])
def api_download_bot_engine_logs():
    """Download bot engine logs by Connection ID and/or Context ID as CSV or JSON."""
    import csv
    import io
    import json as json_mod
    from opensearch_client import query_bot_engine_default_logs

    data = request.get_json() or {}
    connection_id = (data.get("connection_id") or "").strip()
    context_id = (data.get("context_id") or "").strip()
    if not connection_id and not context_id:
        return jsonify({"ok": False, "error": "connection_id or context_id is required"}), 400

    time_minutes = 0
    try:
        time_minutes = max(0, int(data.get("time_minutes", 0)))
    except (TypeError, ValueError):
        pass

    max_logs = min(int(data.get("max_logs", 10000)), 10000)
    fmt = (data.get("format") or "csv").strip().lower()

    result = query_bot_engine_default_logs(
        connection_id=connection_id or None,
        context_id=context_id or None,
        time_minutes=time_minutes if time_minutes > 0 else None,
        max_logs=max_logs,
    )
    if result is None:
        return jsonify({"ok": False, "error": "Bot engine index not configured"}), 400
    if result.get("error"):
        return jsonify({"ok": False, "error": result["error"]}), 500

    logs = result.get("logs", [])
    safe_name = re.sub(r"[^\w\-]", "", connection_id or context_id or "all")
    base_name = f"bot_engine_logs_{safe_name}_{len(logs)}_rows"

    if fmt == "json":
        raw_docs = [log.get("_raw") or log for log in logs]
        content = json_mod.dumps(raw_docs, indent=2, default=str)
        return Response(
            content,
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename={base_name}.json"},
        )

    # "table" / CSV format — flat extracted fields
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "timestamp", "level", "tenant_name", "connection_id", "context_id",
        "api_name", "method_name", "error_code", "message", "error_message", "error_stack",
    ])
    for log in logs:
        writer.writerow([
            log.get("timestamp", ""),
            log.get("level", ""),
            log.get("tenant_name", ""),
            log.get("connection_id", ""),
            log.get("context_id", ""),
            log.get("api_name", ""),
            log.get("method_name", ""),
            log.get("error_code", ""),
            str(log.get("message", "")).replace("\n", " ").replace("\r", ""),
            str(log.get("error_message", "")).replace("\n", " ").replace("\r", ""),
            str(log.get("error_stack", "")).replace("\n", " ").replace("\r", ""),
        ])

    csv_content = buf.getvalue()
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={base_name}.csv"},
    )


@app.route("/api/bot-engine/analyse", methods=["POST"])
def api_bot_engine_analyse():
    """Analyse bot engine logs using the configured OpenAI-compatible Chat Completions API."""
    from ai_summarizer import llm_call_for_log_analysis, _get_provider

    data = request.get_json() or {}
    logs = data.get("logs")
    if not logs or not isinstance(logs, list):
        return jsonify({"ok": False, "error": "logs array is required"}), 400

    if _get_provider() == "none":
        return jsonify({
            "ok": False,
            "error": "Log analysis needs OPENAI_API_KEY or a local OPENAI_BASE_URL (e.g. Ollama) in Settings.",
        }), 400

    log_lines = []
    error_count = 0
    warn_count = 0
    api_set = set()
    connection_set: set[str] = set()
    context_set: set[str] = set()
    for i, log in enumerate(logs[:200], 1):
        parts = [f"[{i}]", log.get("timestamp", "")]
        lvl = log.get("level", "")
        if lvl:
            parts.append(f"level={lvl}")
            if str(lvl) in ("50", "error", "ERROR"):
                error_count += 1
            elif str(lvl) in ("40", "warn", "WARN"):
                warn_count += 1
        if log.get("api_name"):
            parts.append(f"api={_cap(log['api_name'], 80)}")
            api_set.add(log["api_name"])
        if log.get("method_name"):
            parts.append(f"method={_cap(log['method_name'], 80)}")
        if log.get("connection_id"):
            connection_set.add(log["connection_id"])
        if log.get("context_id"):
            context_set.add(log["context_id"])
        if log.get("error_code"):
            parts.append(f"error_code={_cap(log['error_code'], 80)}")
        if log.get("error_message"):
            parts.append(f"error_msg={_cap(log['error_message'], 240)}")
        if log.get("message"):
            parts.append(f"msg={_cap(log['message'], 200)}")
        log_lines.append(" | ".join(parts))

    prompt_data = (
        f"=== SESSION METADATA ===\n"
        f"Connection ID(s): {', '.join(sorted(connection_set)) if connection_set else logs[0].get('connection_id', 'unknown')}\n"
        f"Context ID(s): {', '.join(sorted(context_set)) if context_set else 'unknown'}\n"
        f"Tenant: {logs[0].get('tenant_name', 'unknown')}\n"
        f"Total log entries: {len(logs)}\n"
        f"Error-level entries: {error_count}\n"
        f"Warning-level entries: {warn_count}\n"
        f"Unique APIs called: {', '.join(sorted(api_set)) if api_set else 'none'}\n"
        f"Time range: {logs[0].get('timestamp', '?')} to {logs[-1].get('timestamp', '?')}\n\n"
        "=== LOG ENTRIES ===\n" + "\n".join(log_lines)
    )

    system_prompt = (
        "You are a senior Bot Engine engineer analysing log entries for a single customer "
        "voice/chat session. Produce a thorough, well-structured analysis.\n\n"
        "Your output MUST use these EXACT section headers (with ** bold markers):\n\n"
        "**Session Overview**\n"
        "Summarise: tenant name, connection ID, total log count, time span, and the overall "
        "call flow as a step-by-step sequence (e.g. 1. Session created -> 2. Authentication -> "
        "3. Account lookup -> 4. Balance inquiry -> 5. Transfer -> 6. Session ended). "
        "List every distinct API/method called.\n\n"
        "**Issues Found**\n"
        "For EACH error or warning, create a numbered entry with:\n"
        "- Log entry number, timestamp, and API/method name\n"
        "- Error code and full error message\n"
        "- Severity: CRITICAL / WARNING / INFO\n"
        "- Impact: what this means for the customer\n"
        "If no issues, say: 'No issues detected — session completed successfully.'\n\n"
        "**Timeline Analysis**\n"
        "Walk through the call chronologically. Highlight:\n"
        "- Any unusual delays between API calls (>5 seconds)\n"
        "- Repeated/retried calls\n"
        "- Missing expected steps\n"
        "- Points where the flow deviated from normal\n\n"
        "**Root Cause** (only if errors were found)\n"
        "What caused the issue? Be specific — name the API, error code, and likely underlying reason.\n\n"
        "**Verdict**\n"
        "One clear sentence: SUCCESS or FAILURE, with the reason.\n"
        "Then a confidence level: HIGH / MEDIUM / LOW.\n\n"
        "Rules:\n"
        "- Use the EXACT timestamps, API names, error codes, and messages from the logs.\n"
        "- Be thorough — do not skip any errors or warnings.\n"
        "- If a field is missing or unclear, say so explicitly.\n"
        "- Do NOT use markdown headers (## or #). Use **Bold** labels ONLY.\n"
        "- Do NOT add disclaimers about being an AI.\n"
        "- Use plain language a non-engineer can understand."
    )

    try:
        analysis, prov = llm_call_for_log_analysis(system_prompt, prompt_data, max_tokens=1800)
        return jsonify({"ok": True, "analysis": analysis, "log_analysis_llm": prov})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/api/integration-manager/status")
def api_integration_manager_status():
    """Check if the Integration Manager OpenSearch index is configured and reachable."""
    from ai_summarizer import log_analysis_meta_for_status

    try:
        from opensearch_client import check_integration_manager_index
        result = check_integration_manager_index()
        meta = log_analysis_meta_for_status()
        return jsonify({"ok": True, **result, **meta})
    except Exception as e:
        meta = log_analysis_meta_for_status()
        return jsonify({"ok": False, "configured": False, "connected": False, "error": str(e), **meta})


@app.route("/api/integration-manager/logs", methods=["POST"])
def api_integration_manager_logs():
    """Fetch Integration Manager default logs by connectionId."""
    from opensearch_client import query_integration_manager_default_logs

    data = request.get_json() or {}
    connection_id = (data.get("connection_id") or "").strip()
    if not connection_id:
        return jsonify({"ok": False, "error": "connection_id is required"}), 400

    time_minutes = 0
    try:
        time_minutes = max(0, int(data.get("time_minutes", 0)))
    except (TypeError, ValueError):
        pass

    max_logs = min(int(data.get("max_logs", 500)), 10000)

    result = query_integration_manager_default_logs(
        connection_id=connection_id,
        time_minutes=time_minutes if time_minutes > 0 else None,
        max_logs=max_logs,
    )
    if result is None:
        return jsonify({
            "ok": False,
            "error": "Integration Manager index not configured (set OPENSEARCH_INTEGRATION_MANAGER_INDEX in .env)",
        }), 400
    if result.get("error"):
        return jsonify({"ok": False, **result}), 500

    ui_logs = [{k: v for k, v in log.items() if k != "_raw"} for log in result.get("logs", [])]
    return jsonify({"ok": True, "total": result.get("total", 0), "scanned": result.get("scanned", 0), "logs": ui_logs})


@app.route("/api/download/integration-manager-logs", methods=["POST"])
def api_download_integration_manager_logs():
    """Download Integration Manager logs by connectionId as CSV or JSON."""
    import csv
    import io
    import json as json_mod
    from opensearch_client import query_integration_manager_default_logs

    data = request.get_json() or {}
    connection_id = (data.get("connection_id") or "").strip()
    if not connection_id:
        return jsonify({"ok": False, "error": "connection_id is required"}), 400

    time_minutes = 0
    try:
        time_minutes = max(0, int(data.get("time_minutes", 0)))
    except (TypeError, ValueError):
        pass

    max_logs = min(int(data.get("max_logs", 10000)), 10000)
    fmt = (data.get("format") or "csv").strip().lower()

    result = query_integration_manager_default_logs(
        connection_id=connection_id,
        time_minutes=time_minutes if time_minutes > 0 else None,
        max_logs=max_logs,
    )
    if result is None:
        return jsonify({"ok": False, "error": "Integration Manager index not configured"}), 400
    if result.get("error"):
        return jsonify({"ok": False, "error": result["error"]}), 500

    logs = result.get("logs", [])
    base_name = f"integration_manager_logs_{connection_id}_{len(logs)}_rows"

    if fmt == "json":
        raw_docs = [log.get("_raw") or log for log in logs]
        content = json_mod.dumps(raw_docs, indent=2, default=str)
        return Response(
            content,
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename={base_name}.json"},
        )

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "timestamp", "level", "tenant_name", "connection_id",
        "api_name", "method_name", "error_code", "message", "error_message", "error_stack",
    ])
    for log in logs:
        writer.writerow([
            log.get("timestamp", ""),
            log.get("level", ""),
            log.get("tenant_name", ""),
            log.get("connection_id", ""),
            log.get("api_name", ""),
            log.get("method_name", ""),
            log.get("error_code", ""),
            str(log.get("message", "")).replace("\n", " ").replace("\r", ""),
            str(log.get("error_message", "")).replace("\n", " ").replace("\r", ""),
            str(log.get("error_stack", "")).replace("\n", " ").replace("\r", ""),
        ])

    csv_content = buf.getvalue()
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={base_name}.csv"},
    )


@app.route("/api/integration-manager/analyse", methods=["POST"])
def api_integration_manager_analyse():
    """Analyse Integration Manager logs using the configured OpenAI-compatible Chat Completions API."""
    from ai_summarizer import llm_call_for_log_analysis, _get_provider

    data = request.get_json() or {}
    logs = data.get("logs")
    if not logs or not isinstance(logs, list):
        return jsonify({"ok": False, "error": "logs array is required"}), 400

    if _get_provider() == "none":
        return jsonify({
            "ok": False,
            "error": "Log analysis needs OPENAI_API_KEY or a local OPENAI_BASE_URL (e.g. Ollama) in Settings.",
        }), 400

    log_lines = []
    error_count = 0
    warn_count = 0
    api_set = set()
    for i, log in enumerate(logs[:200], 1):
        parts = [f"[{i}]", log.get("timestamp", "")]
        lvl = log.get("level", "")
        if lvl:
            parts.append(f"level={lvl}")
            if str(lvl) in ("50", "error", "ERROR"):
                error_count += 1
            elif str(lvl) in ("40", "warn", "WARN"):
                warn_count += 1
        if log.get("api_name"):
            parts.append(f"api={_cap(log['api_name'], 80)}")
            api_set.add(log["api_name"])
        if log.get("method_name"):
            parts.append(f"method={_cap(log['method_name'], 80)}")
        if log.get("error_code"):
            parts.append(f"error_code={_cap(log['error_code'], 80)}")
        if log.get("error_message"):
            parts.append(f"error_msg={_cap(log['error_message'], 240)}")
        if log.get("message"):
            parts.append(f"msg={_cap(log['message'], 200)}")
        log_lines.append(" | ".join(parts))

    prompt_data = (
        f"=== SESSION METADATA ===\n"
        f"Connection ID: {logs[0].get('connection_id', 'unknown')}\n"
        f"Tenant: {logs[0].get('tenant_name', 'unknown')}\n"
        f"Total log entries: {len(logs)}\n"
        f"Error-level entries: {error_count}\n"
        f"Warning-level entries: {warn_count}\n"
        f"Unique APIs / endpoints touched: {', '.join(sorted(api_set)) if api_set else 'none'}\n"
        f"Time range: {logs[0].get('timestamp', '?')} to {logs[-1].get('timestamp', '?')}\n\n"
        "=== LOG ENTRIES ===\n" + "\n".join(log_lines)
    )

    system_prompt = (
        "You are a senior Integration Manager engineer analysing log entries for a single customer "
        "voice/chat session. Integration Manager handles auth, core integrations, and mesh calls to "
        "back-end services. Produce a thorough, well-structured analysis.\n\n"
        "Your output MUST use these EXACT section headers (with ** bold markers):\n\n"
        "**Session Overview**\n"
        "Summarise: tenant name, connection ID, total log count, time span, and the overall "
        "flow as a step-by-step sequence (e.g. 1. Session context -> 2. Authentication -> "
        "3. Account / member APIs -> 4. Transfers or external calls -> 5. Session end). "
        "List every distinct API/method or external URL referenced.\n\n"
        "**Issues Found**\n"
        "For EACH error or warning, create a numbered entry with:\n"
        "- Log entry number, timestamp, and API/method or URL\n"
        "- Error code / status and full error message\n"
        "- Severity: CRITICAL / WARNING / INFO\n"
        "- Impact: what this means for the customer\n"
        "If no issues, say: 'No issues detected — session completed successfully.'\n\n"
        "**Timeline Analysis**\n"
        "Walk through the session chronologically. Highlight:\n"
        "- Any unusual delays between calls (>5 seconds)\n"
        "- Repeated/retried calls\n"
        "- Missing expected steps\n"
        "- Points where the flow deviated from normal\n\n"
        "**Root Cause** (only if errors were found)\n"
        "What caused the issue? Be specific — name the API, status code, and likely underlying reason "
        "(e.g. upstream timeout, 4xx from core, mesh error).\n\n"
        "**Verdict**\n"
        "One clear sentence: SUCCESS or FAILURE, with the reason.\n"
        "Then a confidence level: HIGH / MEDIUM / LOW.\n\n"
        "Rules:\n"
        "- Use the EXACT timestamps, API names, error codes, and messages from the logs.\n"
        "- Be thorough — do not skip any errors or warnings.\n"
        "- If a field is missing or unclear, say so explicitly.\n"
        "- Do NOT use markdown headers (## or #). Use **Bold** labels ONLY.\n"
        "- Do NOT add disclaimers about being an AI.\n"
        "- Use plain language a non-engineer can understand."
    )

    try:
        analysis, prov = llm_call_for_log_analysis(system_prompt, prompt_data, max_tokens=1800)
        return jsonify({"ok": True, "analysis": analysis, "log_analysis_llm": prov})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/api/session-rca/analyse", methods=["POST"])
def api_session_rca_analyse():
    """Session RCA agent — runs deterministic detectors over BE+IM+SS logs and
    produces three drafts (structured RCA, client-facing ticket, internal eng ticket).

    When ``question`` is supplied, the LLM answers it grounded in the merged log
    facts. When empty, it produces a generic structured RCA.

    Request body (JSON):
      mode: "fetch" (use OpenSearch via connection_id) or "paste" (use provided JSON).
      connection_id: UUIDv1 connectionId (required for fetch; optional label for paste).
      question: optional free-form user question (e.g. "why did the call drop?").
      bot_engine_logs / integration_manager_logs / stream_server_logs: arrays of raw
                _source docs (paste mode).
      related_calls: optional list of {connection_id, bot_engine_logs,
                integration_manager_logs, stream_server_logs} for paste mode.
      correlate: bool — when fetch mode, auto-find related calls in OpenSearch (default true).
      correlate_window_minutes: int — search ±N minutes around the primary's UUID timestamp (default 10).
      include_stream_server: bool — fetch SS logs (slow + often empty for IVR sessions);
                default false. Auto-enabled when ``question`` mentions transcript/drop/
                transfer/audio/speak/say/hear/silence keywords.
      use_llm: bool — generate prose with the configured LLM (default true). Falls back to
               the deterministic facts block when no provider is configured or the call fails.

    Response: see session_rca.analyse() return shape, plus a ``timings_ms`` block.
    """
    import time
    from concurrent.futures import ThreadPoolExecutor
    import session_rca

    data = request.get_json() or {}
    mode = (data.get("mode") or "fetch").strip().lower()
    use_llm = data.get("use_llm", True) is not False
    correlate = data.get("correlate", True) is not False
    question = (data.get("question") or "").strip()
    try:
        correlate_window_minutes = max(1, min(120, int(data.get("correlate_window_minutes") or 10)))
    except (TypeError, ValueError):
        correlate_window_minutes = 10

    # SS fetch is opt-in — it's the slowest source and empty for most IVR/auth sessions.
    # We auto-enable it when the user's question hints at an SS-relevant concern.
    include_ss = data.get("include_stream_server")
    if include_ss is None:
        ss_keywords = (
            "drop", "dropp", "hangup", "hung up", "hang up", "transfer", "audio",
            "speak", "spoke", "said", "say ", "say,", "say.", "hear", "heard",
            "silence", "silent", "transcript", "intent", "understand", "understood",
            "stt", "twilio", "stream",
        )
        ql = question.lower()
        include_ss = any(kw in ql for kw in ss_keywords)
    include_ss = bool(include_ss)

    primary: dict
    related: list[dict] = []
    timings: dict = {}

    if mode == "paste":
        primary = {
            "connection_id": (data.get("connection_id") or "").strip(),
            "be_logs": data.get("bot_engine_logs") or [],
            "im_logs": data.get("integration_manager_logs") or [],
            "ss_logs": data.get("stream_server_logs") or [],
        }
        for r in data.get("related_calls") or []:
            related.append({
                "connection_id": (r.get("connection_id") or "").strip(),
                "be_logs": r.get("bot_engine_logs") or [],
                "im_logs": r.get("integration_manager_logs") or [],
                "ss_logs": r.get("stream_server_logs") or [],
            })
        if not (primary["be_logs"] or primary["im_logs"] or primary["ss_logs"]):
            return jsonify({"ok": False, "error": "paste mode requires at least one of bot_engine_logs, integration_manager_logs, stream_server_logs"}), 400
    elif mode == "fetch":
        cid = (data.get("connection_id") or "").strip()
        if not cid:
            return jsonify({"ok": False, "error": "connection_id is required for fetch mode"}), 400
        try:
            from opensearch_client import (
                find_related_auth_connections,
                query_bot_engine_default_logs,
                query_integration_manager_default_logs,
                query_stream_server_default_logs,
            )
        except Exception as exc:
            return jsonify({"ok": False, "error": f"OpenSearch client unavailable: {exc}"}), 500

        # 60-min upper bound is plenty for IVR auth flows and async IM callbacks
        # while cutting the BE/IM scan window from the default ±2 h roughly in
        # half — biggest wall-clock win on busy 100M+ doc indexes. Call duration
        # >60 min is exceedingly rare; users can fall back to paste mode if needed.
        FETCH_WINDOW_MINUTES = 60

        def _fetch_one(cid_local: str, want_ss: bool) -> dict:
            """Fetch BE + IM (+optional SS) for a single connection_id in parallel.
            Returns counts and per-source timings under ``_fetch_meta``."""
            def _timed(fn, *args, **kwargs):
                t = time.time()
                try:
                    res = fn(*args, **kwargs) or {}
                except Exception:
                    res = {}
                return res, int((time.time() - t) * 1000)

            tasks: dict = {}
            with ThreadPoolExecutor(max_workers=3) as ex:
                tasks["be"] = ex.submit(
                    _timed, query_bot_engine_default_logs,
                    connection_id=cid_local, max_window_minutes=FETCH_WINDOW_MINUTES,
                )
                tasks["im"] = ex.submit(
                    _timed, query_integration_manager_default_logs,
                    connection_id=cid_local, max_window_minutes=FETCH_WINDOW_MINUTES,
                )
                if want_ss:
                    tasks["ss"] = ex.submit(_timed, query_stream_server_default_logs, connection_id=cid_local)
            out: dict = {"connection_id": cid_local, "be_logs": [], "im_logs": [], "ss_logs": []}
            meta: dict = {}
            for key, fut in tasks.items():
                try:
                    res, took_ms = fut.result()
                except Exception:
                    res, took_ms = {}, 0
                out[f"{key}_logs"] = res.get("logs") or []
                meta[f"{key}_ms"] = took_ms
                meta[f"{key}_count"] = len(out[f"{key}_logs"])
            out["_fetch_meta"] = meta
            return out

        t0 = time.time()
        primary_res = _fetch_one(cid, include_ss)
        primary = primary_res
        timings["primary_fetch_ms"] = int((time.time() - t0) * 1000)
        if isinstance(primary_res.get("_fetch_meta"), dict):
            timings["primary_per_source"] = primary_res.pop("_fetch_meta")

        if not (primary["be_logs"] or primary["im_logs"] or primary["ss_logs"]):
            return jsonify({"ok": False, "error": "no logs found for the supplied connection_id"}), 404

        if correlate:
            t1 = time.time()
            sig = session_rca.extract_signals(
                primary["be_logs"], primary["im_logs"], primary["ss_logs"]
            )
            phone_raw = (sig.get("metadata") or {}).get("user_phone_raw") or ""
            tenant = (sig.get("metadata") or {}).get("tenant") or ""
            rel_cids: list[str] = []
            if phone_raw:
                try:
                    rel_cids = find_related_auth_connections(
                        user_phone=phone_raw,
                        tenant=tenant,
                        around_connection_id=cid,
                        window_minutes=correlate_window_minutes,
                    ) or []
                except Exception:
                    rel_cids = []
            rel_cids = [r for r in rel_cids if r and r != cid][:5]
            timings["correlate_lookup_ms"] = int((time.time() - t1) * 1000)

            if rel_cids:
                t2 = time.time()
                # Fan out one fetch per related cid in parallel; each fetch internally
                # also parallelises its BE/IM/SS sub-queries so total in-flight workers
                # = N * 3, capped at 12 to avoid hammering OpenSearch.
                with ThreadPoolExecutor(max_workers=min(len(rel_cids), 4)) as ex:
                    futs = [ex.submit(_fetch_one, r, include_ss) for r in rel_cids]
                    for fut in futs:
                        try:
                            blk = fut.result()
                        except Exception:
                            continue
                        blk.pop("_fetch_meta", None)
                        if blk["be_logs"] or blk["im_logs"] or blk["ss_logs"]:
                            related.append(blk)
                timings["related_fetch_ms"] = int((time.time() - t2) * 1000)
                timings["related_count"] = len(related)
            else:
                timings["related_count"] = 0
    else:
        return jsonify({"ok": False, "error": "mode must be 'fetch' or 'paste'"}), 400

    try:
        t3 = time.time()
        result = session_rca.analyse(primary, related=related, question=question, use_llm=use_llm)
        timings["analyse_ms"] = int((time.time() - t3) * 1000)
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500

    timings["include_stream_server"] = include_ss
    return jsonify({"ok": True, "timings_ms": timings, **result})


@app.route("/api/stream-server-logs/status")
def api_stream_server_logs_status():
    """Check if the stream-server default-logs index is configured and reachable."""
    from ai_summarizer import log_analysis_meta_for_status

    try:
        from opensearch_client import check_stream_server_default_index
        result = check_stream_server_default_index()
        meta = log_analysis_meta_for_status()
        return jsonify({"ok": True, **result, **meta})
    except Exception as e:
        meta = log_analysis_meta_for_status()
        return jsonify({"ok": False, "configured": False, "connected": False, "error": str(e), **meta})


@app.route("/api/stream-server-logs/logs", methods=["POST"])
def api_stream_server_logs_logs():
    """Fetch stream-server default logs by contextId, APT identifier, and/or connection.id."""
    from opensearch_client import query_stream_server_default_logs

    data = request.get_json() or {}
    context_id = (data.get("context_id") or "").strip()
    apt_name = (data.get("apt_name") or "").strip()
    connection_id = (data.get("connection_id") or "").strip()
    if not context_id and not apt_name and not connection_id:
        return jsonify({
            "ok": False,
            "error": "context_id, apt_name, or connection_id is required",
        }), 400

    time_minutes = 0
    try:
        time_minutes = max(0, int(data.get("time_minutes", 0)))
    except (TypeError, ValueError):
        pass

    max_logs = min(int(data.get("max_logs", 1000)), 10000)
    time_from = (data.get("time_from") or "").strip() or None
    time_to = (data.get("time_to") or "").strip() or None

    result = query_stream_server_default_logs(
        context_id=context_id or None,
        apt_name=apt_name or None,
        connection_id=connection_id or None,
        time_minutes=time_minutes if time_minutes > 0 else None,
        max_logs=max_logs,
        time_from=time_from,
        time_to=time_to,
    )
    if result is None:
        return jsonify({
            "ok": False,
            "error": "Stream-server index not configured (set OPENSEARCH_STREAM_SERVER_INDEX or OPENSEARCH_INDEX in .env)",
        }), 400
    if result.get("error"):
        status_code = 504 if result.get("timeout") else 500
        return jsonify({"ok": False, **result}), status_code

    # Pass each log through as-is, including _raw, so the UI can show the full
    # OpenSearch document when a row is expanded. A 1000-row response averages
    # 2-4 MB which is fine for the local Flask server.
    return jsonify({
        "ok": True,
        "total": result.get("total", 0),
        "scanned": result.get("scanned", 0),
        "logs": result.get("logs", []),
    })


@app.route("/api/download/stream-server-logs", methods=["POST"])
def api_download_stream_server_logs():
    """Download stream-server default logs by contextId, APT identifier, and/or connection.id as CSV or JSON."""
    import csv
    import io
    import json as json_mod
    from opensearch_client import query_stream_server_default_logs

    data = request.get_json() or {}
    context_id = (data.get("context_id") or "").strip()
    apt_name = (data.get("apt_name") or "").strip()
    connection_id = (data.get("connection_id") or "").strip()
    if not context_id and not apt_name and not connection_id:
        return jsonify({
            "ok": False,
            "error": "context_id, apt_name, or connection_id is required",
        }), 400

    time_minutes = 0
    try:
        time_minutes = max(0, int(data.get("time_minutes", 0)))
    except (TypeError, ValueError):
        pass

    max_logs = min(int(data.get("max_logs", 10000)), 10000)
    fmt = (data.get("format") or "csv").strip().lower()
    time_from = (data.get("time_from") or "").strip() or None
    time_to = (data.get("time_to") or "").strip() or None

    result = query_stream_server_default_logs(
        context_id=context_id or None,
        apt_name=apt_name or None,
        connection_id=connection_id or None,
        time_minutes=time_minutes if time_minutes > 0 else None,
        max_logs=max_logs,
        time_from=time_from,
        time_to=time_to,
    )
    if result is None:
        return jsonify({"ok": False, "error": "Stream-server index not configured"}), 400
    if result.get("error"):
        status_code = 504 if result.get("timeout") else 500
        return jsonify({"ok": False, **result}), status_code

    logs = result.get("logs", [])
    safe_name = re.sub(r"[^\w\-]", "", context_id or apt_name or connection_id or "all")
    base_name = f"stream_server_logs_{safe_name}_{len(logs)}_rows"

    if fmt == "json":
        raw_docs = [log.get("_raw") or log for log in logs]
        content = json_mod.dumps(raw_docs, indent=2, default=str)
        return Response(
            content,
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename={base_name}.json"},
        )

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "timestamp", "level", "tenant_name", "module_name",
        "action_type", "action_subtype", "action_text", "speech_text",
        "context_id", "apt_name", "connection_id", "request_id", "error_code",
        "message", "error_message", "error_stack",
    ])
    for log in logs:
        writer.writerow([
            log.get("timestamp", ""),
            log.get("level", ""),
            log.get("tenant_name", ""),
            log.get("module_name", ""),
            log.get("action_type", ""),
            log.get("action_subtype", ""),
            str(log.get("action_text", "")).replace("\n", " ").replace("\r", ""),
            str(log.get("speech_text", "")).replace("\n", " ").replace("\r", ""),
            log.get("context_id", ""),
            log.get("apt_name", ""),
            log.get("connection_id", ""),
            log.get("request_id", ""),
            log.get("error_code", ""),
            str(log.get("message", "")).replace("\n", " ").replace("\r", ""),
            str(log.get("error_message", "")).replace("\n", " ").replace("\r", ""),
            str(log.get("error_stack", "")).replace("\n", " ").replace("\r", ""),
        ])

    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={base_name}.csv"},
    )


@app.route("/api/stream-server-logs/analyse", methods=["POST"])
def api_stream_server_logs_analyse():
    """Analyse stream-server default logs using the configured OpenAI-compatible Chat Completions API."""
    from ai_summarizer import llm_call_for_log_analysis, _get_provider

    data = request.get_json() or {}
    logs = data.get("logs")
    if not logs or not isinstance(logs, list):
        return jsonify({"ok": False, "error": "logs array is required"}), 400

    if _get_provider() == "none":
        return jsonify({
            "ok": False,
            "error": "Log analysis needs OPENAI_API_KEY or a local OPENAI_BASE_URL (e.g. Ollama) in Settings.",
        }), 400

    log_lines = []
    error_count = 0
    warn_count = 0
    module_set = set()
    action_set = set()
    apt_set = set()
    context_set = set()
    connection_set = set()
    speech_lines: list[str] = []
    bot_lines: list[str] = []
    for i, log in enumerate(logs[:300], 1):
        parts = [f"[{i}]", log.get("timestamp", "")]
        lvl = log.get("level", "")
        if lvl != "":
            parts.append(f"level={lvl}")
            try:
                lvl_n = int(lvl)
                if lvl_n >= 50:
                    error_count += 1
                elif lvl_n >= 40:
                    warn_count += 1
            except (TypeError, ValueError):
                if str(lvl).lower() in ("error", "fatal"):
                    error_count += 1
                elif str(lvl).lower() in ("warn", "warning"):
                    warn_count += 1
        if log.get("module_name"):
            parts.append(f"module={_cap(log['module_name'], 80)}")
            module_set.add(log["module_name"])
        if log.get("action_type") or log.get("action_subtype"):
            atype = log.get("action_type") or ""
            asub = log.get("action_subtype") or ""
            label = f"{atype}/{asub}".strip("/")
            if label:
                parts.append(f"action={_cap(label, 80)}")
                action_set.add(label)
        if log.get("apt_name"):
            parts.append(f"apt={_cap(log['apt_name'], 80)}")
            apt_set.add(log["apt_name"])
        if log.get("context_id"):
            context_set.add(log["context_id"])
        if log.get("connection_id"):
            parts.append(f"conn={_cap(log['connection_id'], 80)}")
            connection_set.add(log["connection_id"])
        if log.get("speech_text"):
            parts.append(f"caller={_cap(log['speech_text'], 200)!r}")
            speech_lines.append(str(log["speech_text"]))
        if log.get("action_text"):
            parts.append(f"bot={_cap(log['action_text'], 200)!r}")
            bot_lines.append(str(log["action_text"]))
        if log.get("error_code"):
            parts.append(f"error_code={_cap(log['error_code'], 80)}")
        if log.get("error_message"):
            parts.append(f"error_msg={_cap(log['error_message'], 240)}")
        if log.get("message"):
            parts.append(f"msg={_cap(log['message'], 200)}")
        log_lines.append(" | ".join(parts))

    distinct_sessions = len(context_set) or 1
    multi_session_note = (
        f"\nNOTE: Logs span {distinct_sessions} distinct contextIds (sessions). "
        "Group findings by contextId in your analysis.\n"
        if distinct_sessions > 1 else ""
    )

    prompt_data = (
        f"=== SESSION METADATA ===\n"
        f"Context ID(s): {', '.join(sorted(context_set)) if context_set else logs[0].get('context_id', 'unknown')}\n"
        f"APT identifier(s): {', '.join(sorted(apt_set)) if apt_set else 'unknown'}\n"
        f"Connection ID(s): {', '.join(sorted(connection_set)) if connection_set else 'unknown'}\n"
        f"Tenant: {logs[0].get('tenant_name', 'unknown')}\n"
        f"Total log entries: {len(logs)}\n"
        f"Distinct sessions in this slice: {distinct_sessions}\n"
        f"Error-level entries: {error_count}\n"
        f"Warning-level entries: {warn_count}\n"
        f"Modules involved: {', '.join(sorted(module_set)) if module_set else 'none'}\n"
        f"Distinct bot actions: {', '.join(sorted(action_set)) if action_set else 'none'}\n"
        f"Caller utterance count: {len(speech_lines)}\n"
        f"Bot prompt count: {len(bot_lines)}\n"
        f"Time range: {logs[0].get('timestamp', '?')} to {logs[-1].get('timestamp', '?')}\n"
        f"{multi_session_note}\n"
        "=== LOG ENTRIES ===\n" + "\n".join(log_lines)
    )

    system_prompt = (
        "You are a senior Stream Server engineer analysing log entries for a single voice/chat "
        "session driven by the bot engine. Stream Server orchestrates Twilio SIP, Speechmatics STT, "
        "TTS, and bot-engine action execution. Produce a thorough, well-structured analysis.\n\n"
        "Your output MUST use these EXACT section headers (with ** bold markers):\n\n"
        "**Session Overview**\n"
        "Summarise: tenant, contextId, total log count, time span, and the call flow as a "
        "step-by-step sequence (e.g. 1. Connection initialised -> 2. Bot greeting -> "
        "3. Caller utterance(s) -> 4. Parse / action(s) -> 5. Transfer or hang-up). "
        "List every distinct module (rawLog.moduleName) and every distinct action.type/subtype seen.\n\n"
        "**Issues Found**\n"
        "For EACH error or warning, create a numbered entry with:\n"
        "- Log entry number, timestamp, module name\n"
        "- Error code/name and full error message\n"
        "- Severity: CRITICAL / WARNING / INFO\n"
        "- Impact: what this means for the caller\n"
        "Also flag soft issues like: low-confidence parses, repeated 'I'm sorry' / repeat actions, "
        "STT EndOfTranscript timeouts, caller barge-in, hot-keys/synonym misses, and missing prompts.\n"
        "If no issues, say: 'No issues detected — session completed successfully.'\n\n"
        "**Timeline Analysis**\n"
        "Walk through the call chronologically. Quote actual caller utterances in double-quotes "
        "and the bot's prompt text where useful. Highlight:\n"
        "- Long gaps between bot prompt and caller speech (>5s)\n"
        "- Action queue clears followed by apology prompts\n"
        "- Cases where the parse picked an action that does not match what the caller said\n"
        "- Points where the flow deviated from the expected menu / hot-key set\n\n"
        "**Root Cause** (only if issues were found)\n"
        "What caused the issue? Be specific — name the module, action, and likely underlying reason "
        "(e.g. low-confidence STT classification, missing menu synonym, parser timeout, "
        "TTS / SSML failure, websocket drop).\n\n"
        "**Verdict**\n"
        "One clear sentence: SUCCESS or FAILURE, with the reason.\n"
        "Then a confidence level: HIGH / MEDIUM / LOW.\n\n"
        "Rules:\n"
        "- Use the EXACT timestamps, modules, action types, error codes, and quoted texts from the logs.\n"
        "- Be thorough — do not skip any errors or warnings.\n"
        "- If a field is missing or unclear, say so explicitly.\n"
        "- Do NOT use markdown headers (## or #). Use **Bold** labels ONLY.\n"
        "- Do NOT add disclaimers about being an AI.\n"
        "- Use plain language a non-engineer can understand."
    )

    try:
        analysis, prov = llm_call_for_log_analysis(system_prompt, prompt_data, max_tokens=1800)
        return jsonify({"ok": True, "analysis": analysis, "log_analysis_llm": prov})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


_LINE_SEP = "\n"


def _est_tokens(text: str) -> int:
    """Cheap token estimate (~4 chars/token works for English + log lines)."""
    if not text:
        return 0
    return max(1, len(text) // 4)


def _be_line(i: int, log: dict) -> tuple[str, int]:
    """Return (rendered line, severity score) for prioritisation. Higher score = keep first."""
    parts = [f"[{i}]", log.get("timestamp", "")]
    lvl = log.get("level", "")
    score = 0
    if lvl != "":
        parts.append(f"level={lvl}")
        if str(lvl) in ("50", "error", "ERROR"):
            score += 1000
        elif str(lvl) in ("40", "warn", "WARN"):
            score += 400
    if log.get("api_name"):
        parts.append(f"api={_cap(log['api_name'], 80)}")
    if log.get("method_name"):
        parts.append(f"method={_cap(log['method_name'], 60)}")
    if log.get("error_code"):
        parts.append(f"error_code={_cap(log['error_code'], 60)}")
        score += 1000
    if log.get("error_message"):
        parts.append(f"error_msg={_cap(log['error_message'], 200)}")
        score += 500
    if log.get("message"):
        parts.append(f"msg={_cap(log['message'], 160)}")
    return " | ".join(parts), score


def _ss_line(i: int, log: dict) -> tuple[str, int]:
    parts = [f"[{i}]", log.get("timestamp", "")]
    lvl = log.get("level", "")
    score = 0
    if lvl != "":
        parts.append(f"level={lvl}")
        try:
            lvl_n = int(lvl)
            if lvl_n >= 50:
                score += 1000
            elif lvl_n >= 40:
                score += 400
        except (TypeError, ValueError):
            if str(lvl).lower() in ("error", "fatal"):
                score += 1000
            elif str(lvl).lower() in ("warn", "warning"):
                score += 400
    if log.get("module_name"):
        parts.append(f"module={_cap(log['module_name'], 60)}")
    if log.get("action_type") or log.get("action_subtype"):
        label = f"{log.get('action_type', '')}/{log.get('action_subtype', '')}".strip("/")
        if label:
            parts.append(f"action={_cap(label, 60)}")
    if log.get("speech_text"):
        parts.append(f"caller={_cap(log['speech_text'], 160)!r}")
        score += 100  # keep some caller turns for context
    if log.get("action_text"):
        parts.append(f"bot={_cap(log['action_text'], 160)!r}")
        score += 50
    if log.get("error_code"):
        parts.append(f"error_code={_cap(log['error_code'], 60)}")
        score += 1000
    if log.get("error_message"):
        parts.append(f"error_msg={_cap(log['error_message'], 200)}")
        score += 500
    if log.get("message"):
        parts.append(f"msg={_cap(log['message'], 160)}")
    return " | ".join(parts), score


def _pack_lines_within_token_budget(lines_with_score: list[tuple[str, int]], token_budget: int) -> tuple[list[str], int]:
    """Pick lines to keep — error/warn first by score, then preserve original order. Returns (kept lines in original order, dropped count)."""
    if token_budget <= 0:
        return [], len(lines_with_score)
    indexed = list(enumerate(lines_with_score))  # (orig_idx, (line, score))
    boundary_bonus = {0, 1, 2}
    n = len(indexed)
    if n >= 3:
        boundary_bonus |= {n - 1, n - 2, n - 3}

    def sort_key(item):
        idx, (_line, score) = item
        bonus = 50 if idx in boundary_bonus else 0
        return (-(score + bonus), idx)

    ordered = sorted(indexed, key=sort_key)
    kept_idx: set[int] = set()
    used = 0
    for idx, (line, _score) in ordered:
        ltok = _est_tokens(line) + 1  # +1 for newline
        if used + ltok > token_budget:
            continue
        kept_idx.add(idx)
        used += ltok
    if not kept_idx:
        return [], n
    kept = [lines_with_score[i][0] for i in sorted(kept_idx)]
    dropped = n - len(kept)
    if dropped > 0:
        kept.append(f"... [trimmed {dropped} lower-priority entries to fit token budget; errors/warnings preserved] ...")
    return kept, dropped


def _summarise_be_logs(logs: list, token_budget: int = 0) -> tuple[str, dict]:
    """Compact one-line-per-entry block for the combined RCA. If token_budget>0, keep error/warn lines first up to that budget."""
    lines: list[tuple[str, int]] = []
    err = warn = 0
    apis: set[str] = set()
    for i, log in enumerate(logs[:300], 1):
        line, _score = _be_line(i, log)
        lvl = log.get("level", "")
        if str(lvl) in ("50", "error", "ERROR"):
            err += 1
        elif str(lvl) in ("40", "warn", "WARN"):
            warn += 1
        if log.get("api_name"):
            apis.add(log["api_name"])
        lines.append((line, _score))
    if token_budget > 0:
        kept, _dropped = _pack_lines_within_token_budget(lines, token_budget)
        rendered = _LINE_SEP.join(kept)
    else:
        rendered = _LINE_SEP.join(line for line, _ in lines)
    return rendered, {"errors": err, "warnings": warn, "apis": sorted(apis)}


def _summarise_im_logs(logs: list, token_budget: int = 0) -> tuple[str, dict]:
    """Compact summary of Integration Manager logs (auth/mesh/core API path)."""
    lines: list[tuple[str, int]] = []
    err = warn = 0
    apis: set[str] = set()
    for i, log in enumerate(logs[:300], 1):
        line, _score = _be_line(i, log)
        lvl = log.get("level", "")
        if str(lvl) in ("50", "error", "ERROR"):
            err += 1
        elif str(lvl) in ("40", "warn", "WARN"):
            warn += 1
        if log.get("api_name"):
            apis.add(log["api_name"])
        lines.append((line, _score))
    if token_budget > 0:
        kept, _dropped = _pack_lines_within_token_budget(lines, token_budget)
        rendered = _LINE_SEP.join(kept)
    else:
        rendered = _LINE_SEP.join(line for line, _ in lines)
    return rendered, {"errors": err, "warnings": warn, "apis": sorted(apis)}


def _summarise_ss_logs(logs: list, token_budget: int = 0) -> tuple[str, dict]:
    """Compact summary of Stream Server logs — keeps caller/bot turns for cross-source analysis."""
    lines: list[tuple[str, int]] = []
    err = warn = 0
    modules: set[str] = set()
    actions: set[str] = set()
    for i, log in enumerate(logs[:400], 1):
        line, score = _ss_line(i, log)
        lvl = log.get("level", "")
        try:
            lvl_n = int(lvl) if lvl != "" else 0
            if lvl_n >= 50:
                err += 1
            elif lvl_n >= 40:
                warn += 1
        except (TypeError, ValueError):
            if str(lvl).lower() in ("error", "fatal"):
                err += 1
            elif str(lvl).lower() in ("warn", "warning"):
                warn += 1
        if log.get("module_name"):
            modules.add(log["module_name"])
        if log.get("action_type") or log.get("action_subtype"):
            label = f"{log.get('action_type', '')}/{log.get('action_subtype', '')}".strip("/")
            if label:
                actions.add(label)
        lines.append((line, score))
    if token_budget > 0:
        kept, _dropped = _pack_lines_within_token_budget(lines, token_budget)
        rendered = _LINE_SEP.join(kept)
    else:
        rendered = _LINE_SEP.join(line for line, _ in lines)
    return rendered, {"errors": err, "warnings": warn, "modules": sorted(modules), "actions": sorted(actions)}


def _allocate_combined_log_budget(be_count: int, im_count: int, ss_count: int, system_prompt_tokens: int, max_output_tokens: int) -> dict[str, int]:
    """Split the LLM TPM budget across the 3 sources by log count, leaving headroom for system prompt + output + scaffolding."""
    from ai_summarizer import _llm_tpm_budget
    total_budget = _llm_tpm_budget()
    safety = 350  # provider-side overhead + token-estimate slack
    scaffold = 250  # IDENTIFIERS + SOURCE SUMMARY headers + section markers
    log_budget = total_budget - system_prompt_tokens - max_output_tokens - safety - scaffold
    if log_budget < 600:
        log_budget = 600  # always send something even on tiny tiers; trim helper will catch HTTP 413
    counts = {"be": be_count, "im": im_count, "ss": ss_count}
    nonzero = {k: v for k, v in counts.items() if v > 0}
    if not nonzero:
        return {"be": 0, "im": 0, "ss": 0, "_total": log_budget}
    # Reserve a fair floor for each present source then distribute the rest by ratio.
    floor = min(150, log_budget // (len(nonzero) * 2))  # ~150 tokens floor (≈ 25-40 lines)
    remaining = log_budget - floor * len(nonzero)
    if remaining < 0:
        remaining = 0
        floor = log_budget // len(nonzero)
    total_count = sum(nonzero.values()) or 1
    out = {"be": 0, "im": 0, "ss": 0}
    for k, c in nonzero.items():
        out[k] = floor + int(remaining * c / total_count)
    out["_total"] = log_budget
    return out


# ============================================================================
# Combined cross-source log analyser — DETERMINISTIC (no LLM, no token limits).
# Walks Bot Engine + Integration Manager + Stream Server logs and produces the
# same **Section** layout the frontend expects.
# ============================================================================

def _to_level_n(lvl) -> int:
    """Normalize a log level (int/string) to a numeric value: 50=error, 40=warn, 30=info, 0=unknown."""
    if lvl is None or lvl == "":
        return 0
    try:
        return int(lvl)
    except (TypeError, ValueError):
        s = str(lvl).strip().lower()
        return {"fatal": 60, "error": 50, "warn": 40, "warning": 40, "info": 30, "debug": 20, "trace": 10}.get(s, 0)


def _severity_label(level_n: int) -> str:
    if level_n >= 50:
        return "CRITICAL"
    if level_n >= 40:
        return "WARNING"
    return "INFO"


def _ts_sort_key(ts: str) -> str:
    """Lexicographic-safe key for ISO-8601 timestamps. Empty timestamps sort last."""
    return ts or "~"


def _fmt_ts(ts: str) -> str:
    return ts or "(no timestamp)"


def _short_text(s, n: int = 140) -> str:
    if not s:
        return ""
    s = str(s).strip()
    return s if len(s) <= n else s[:n].rstrip() + "…"


def _ts_diff_seconds(a: str, b: str):
    """Best-effort difference (b - a) in seconds for ISO-8601 strings; returns None if not parseable."""
    if not a or not b:
        return None
    from datetime import datetime
    try:
        ta = datetime.fromisoformat(a.replace("Z", "+00:00"))
        tb = datetime.fromisoformat(b.replace("Z", "+00:00"))
        return (tb - ta).total_seconds()
    except (ValueError, TypeError):
        return None


def _normalize_be(logs: list) -> list:
    out = []
    for i, log in enumerate(logs, 1):
        level_n = _to_level_n(log.get("level"))
        out.append({
            "source": "Bot Engine", "src": "BE", "idx": i,
            "ts": log.get("timestamp", ""), "ts_sort": _ts_sort_key(log.get("timestamp", "")),
            "level_n": level_n, "severity": _severity_label(level_n),
            "api": log.get("api_name", "") or "", "method": log.get("method_name", "") or "",
            "module": "", "action": "", "speech": "", "bot_text": "",
            "error_code": log.get("error_code", "") or "",
            "error_message": log.get("error_message", "") or "",
            "message": log.get("message", "") or "",
            "payload_summary": log.get("payload_summary", "") or "",
        })
    return out


def _normalize_im(logs: list) -> list:
    out = []
    for i, log in enumerate(logs, 1):
        level_n = _to_level_n(log.get("level"))
        out.append({
            "source": "Integration Manager", "src": "IM", "idx": i,
            "ts": log.get("timestamp", ""), "ts_sort": _ts_sort_key(log.get("timestamp", "")),
            "level_n": level_n, "severity": _severity_label(level_n),
            "api": log.get("api_name", "") or "", "method": log.get("method_name", "") or "",
            "module": "", "action": "", "speech": "", "bot_text": "",
            "error_code": log.get("error_code", "") or "",
            "error_message": log.get("error_message", "") or "",
            "message": log.get("message", "") or "",
            "payload_summary": log.get("payload_summary", "") or "",
        })
    return out


def _normalize_ss(logs: list) -> list:
    out = []
    for i, log in enumerate(logs, 1):
        level_n = _to_level_n(log.get("level"))
        action = ""
        if log.get("action_type") or log.get("action_subtype"):
            action = f"{log.get('action_type', '')}/{log.get('action_subtype', '')}".strip("/")
        out.append({
            "source": "Stream Server", "src": "SS", "idx": i,
            "ts": log.get("timestamp", ""), "ts_sort": _ts_sort_key(log.get("timestamp", "")),
            "level_n": level_n, "severity": _severity_label(level_n),
            "api": "", "method": "",
            "module": log.get("module_name", "") or "", "action": action,
            "speech": log.get("speech_text", "") or "",
            "bot_text": log.get("action_text", "") or "",
            "error_code": log.get("error_code", "") or "",
            "error_message": log.get("error_message", "") or "",
            "message": log.get("message", "") or "",
            "payload_summary": "",
        })
    return out


def _normalize_nl(logs: list) -> list:
    """Normalise NLP-server records into the merged-feed shape so the LLM can
    cite them inline with BE/IM/SS rows.  NLP rows are LLM-trace events
    (function_active / top_level / function_initial parses), not operational
    errors, so we surface them as INFO-severity rows whose payload captures the
    template_type, the recognised input text, and the LLM's structured output.
    """
    out = []
    for i, log in enumerate(logs, 1):
        level_n = _to_level_n(log.get("level"))
        # NLP records are usually 'INFO' strings; treat unknown/missing as INFO.
        if level_n == 0:
            level_n = 30
        tt = (log.get("template_type") or "").strip()
        text_in = (log.get("text") or "").strip()
        action_out = (log.get("action") or "").strip()
        ad = (log.get("action_data") or "").strip()
        llm_out = (log.get("llm_output") or "").strip()
        exp = (log.get("experience_name") or log.get("experience_id") or "").strip()
        param = (log.get("active_parameter") or "").strip()
        bits: list[str] = []
        if tt:
            bits.append(tt)
        if exp:
            bits.append(f"exp={exp}")
        if param and param.lower() != "none":
            bits.append(f"slot={_cap(param, 60)}")
        if text_in:
            bits.append(f"input='{_cap(text_in, 120)}'")
        if action_out:
            bits.append(f"→ action={action_out}")
        if ad and ad not in ("{}", "null"):
            bits.append(f"data={_cap(ad, 120)}")
        if llm_out and llm_out not in ad:
            bits.append(f"llm={_cap(llm_out, 120)}")
        payload = " | ".join(bits)
        out.append({
            "source": "NLP Server", "src": "NL", "idx": i,
            "ts": log.get("timestamp", ""), "ts_sort": _ts_sort_key(log.get("timestamp", "")),
            "level_n": level_n, "severity": _severity_label(level_n),
            "api": tt, "method": exp,
            "module": "nlp-server", "action": action_out,
            "speech": text_in, "bot_text": "",
            "error_code": "", "error_message": "",
            "message": "", "payload_summary": payload,
        })
    return out


def _entry_summary(e: dict) -> str:
    bits = []
    payload = (e.get("payload_summary") or "").strip()
    if e["src"] in ("BE", "IM"):
        if payload:
            bits.append(payload)
        else:
            if e["api"]:
                bits.append(f"api={_short_text(e['api'], 80)}")
            if e["method"]:
                bits.append(f"method={_short_text(e['method'], 60)}")
    elif e["src"] == "NL":
        # NLP records are LLM-trace events; the precomputed payload_summary
        # already carries template_type / experience / slot / input / action,
        # which is exactly what the LLM needs in-line.
        if payload:
            bits.append(payload)
        else:
            if e["api"]:
                bits.append(f"template={e['api']}")
            if e["action"]:
                bits.append(f"action={e['action']}")
            if e["speech"]:
                bits.append(f'input: "{_short_text(e["speech"], 100)}"')
    else:  # SS
        if e["module"]:
            bits.append(f"module={_short_text(e['module'], 60)}")
        if e["action"]:
            bits.append(f"action={_short_text(e['action'], 60)}")
        if e["speech"]:
            bits.append(f'caller said: "{_short_text(e["speech"], 100)}"')
        if e["bot_text"]:
            bits.append(f'bot said: "{_short_text(e["bot_text"], 100)}"')
    if e["error_code"]:
        bits.append(f"error_code={e['error_code']}")
    if e["error_message"]:
        bits.append(f'error: "{_short_text(e["error_message"], 160)}"')
    elif e["message"] and not (e["speech"] or e["bot_text"]) and not payload:
        bits.append(f'msg: "{_short_text(e["message"], 140)}"')
    return " | ".join(bits) if bits else "(no detail)"


def _describe_impact(e: dict) -> str:
    sev = e["severity"]
    api = (e["api"] or "").lower()
    err_blob = ((e["error_code"] or "") + " " + (e["error_message"] or "")).lower()
    if e["src"] == "IM":
        if "auth" in api or "auth" in err_blob or "401" in err_blob or "token" in err_blob:
            return "Auth/token failure — downstream APIs cannot be called and the bot loses session context."
        if sev == "CRITICAL":
            return "Backend integration failed — the bot cannot fulfil any data/account request that depends on this API."
        if sev == "WARNING":
            return "Backend integration degraded — bot may retry or fall back to a generic response."
    if e["src"] == "BE":
        if sev == "CRITICAL":
            return "Bot Engine could not orchestrate this turn — caller likely heard a generic 'I'm sorry' or silence."
        if sev == "WARNING":
            return "Bot Engine flagged a recoverable issue — caller may experience retries or repeated prompts."
    if e["src"] == "SS":
        mod = (e["module"] or "").lower()
        if "stt" in mod or "speechmatics" in err_blob:
            return "Speech-to-text disruption — caller's input may not have been captured this turn."
        if sev == "CRITICAL":
            return "Stream Server failed during call execution — caller likely heard silence, audio issues, or a dropped call."
        if sev == "WARNING":
            return "Stream Server flagged an audio/action issue — caller may have heard a delayed or off-script prompt."
    return f"Logged at {sev.lower()} severity."


def _format_session_overview(merged: list, be: list, im: list, ss: list, identifiers: dict, sources_with_logs: list, sources_empty: list) -> str:
    out = ["**Session Overview**"]
    out.append(f"Connection ID: {identifiers.get('connection_id') or '(not provided)'}")
    out.append(f"Context ID: {identifiers.get('context_id') or '(not provided)'}")
    out.append(f"APT identifier: {identifiers.get('apt_name') or '(not provided)'}")
    if sources_with_logs:
        out.append(
            f"Sources with logs: {', '.join(sources_with_logs)} "
            f"(total {len(merged)} entries: {len(be)} BE / {len(im)} IM / {len(ss)} SS)"
        )
    else:
        out.append("Sources with logs: none")
    if sources_empty:
        out.append(f"Sources empty / skipped: {', '.join(sources_empty)}")

    if merged:
        first_ts = next((e["ts"] for e in merged if e["ts"]), "")
        last_ts = next((e["ts"] for e in reversed(merged) if e["ts"]), "")
        if first_ts and last_ts:
            span = _ts_diff_seconds(first_ts, last_ts)
            span_txt = f" (span {span:.1f}s)" if span is not None and span >= 0 else ""
            out.append(f"Time window: {first_ts} → {last_ts}{span_txt}")
        elif first_ts:
            out.append(f"Time window: starting {first_ts}")

    apis = sorted({e["api"] for e in merged if e["api"]})
    modules = sorted({e["module"] for e in merged if e["module"]})
    actions = sorted({e["action"] for e in merged if e["action"]})
    if apis:
        out.append(f"APIs called: {', '.join(apis)}")
    if modules:
        out.append(f"Stream Server modules: {', '.join(modules)}")
    if actions:
        out.append(f"Stream Server actions: {', '.join(actions)}")

    flow = []
    for e in merged:
        if e["level_n"] >= 40:
            flow.append(e)
        elif e["src"] == "SS" and (e["speech"] or e["bot_text"]):
            flow.append(e)
        elif e["src"] in ("BE", "IM") and e["api"]:
            flow.append(e)
    if not flow:
        flow = merged[:8]
    flow = flow[:12]
    if flow:
        out.append("")
        out.append("Call flow:")
        for n, e in enumerate(flow, 1):
            out.append(f"{n}. [{e['source']} #{e['idx']} @ {_fmt_ts(e['ts'])}] {_entry_summary(e)}")
    return "\n".join(out)


def _format_issues_found(merged: list) -> str:
    out = ["**Issues Found**"]
    issues = [e for e in merged if e["level_n"] >= 40 or e["error_code"] or e["error_message"]]
    seen = set()
    deduped = []
    for e in issues:
        key = (e["src"], e["error_code"], e["error_message"], e["api"], e["module"], e["action"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(e)
    if not deduped:
        out.append("No issues detected — session completed successfully across all sources.")
        return "\n".join(out)

    soft_terms = ("i'm sorry", "didn't catch", "couldn't understand", "stt timeout", "speechmatics timeout", "low confidence", "let me try that again")
    soft = []
    for e in merged:
        text = " ".join([e["bot_text"], e["message"]]).lower()
        if any(t in text for t in soft_terms):
            soft.append(e)

    for n, e in enumerate(deduped, 1):
        out.append(f"{n}. [{e['severity']}] {e['source']} #{e['idx']} @ {_fmt_ts(e['ts'])}")
        if e["api"] or e["method"]:
            out.append(f"   API: {e['api']}{(' / ' + e['method']) if e['method'] else ''}")
        if e["module"] or e["action"]:
            mod = e["module"] or ""
            act = (" / " + e["action"]) if e["action"] else ""
            out.append(f"   Stream Server: {mod}{act}")
        if e["error_code"]:
            out.append(f"   Error code: {e['error_code']}")
        if e["error_message"]:
            out.append(f"   Error: {_short_text(e['error_message'], 240)}")
        elif e["message"]:
            out.append(f"   Message: {_short_text(e['message'], 240)}")
        out.append(f"   Impact: {_describe_impact(e)}")

    if soft:
        out.append("")
        out.append("Soft issues (caller-facing symptoms):")
        for n, e in enumerate(soft[:6], 1):
            text = e["bot_text"] or e["message"]
            out.append(f"{n}. [{e['source']} #{e['idx']} @ {_fmt_ts(e['ts'])}] \"{_short_text(text, 140)}\"")
    return "\n".join(out)


def _format_cross_correlation(merged: list, be: list, im: list, ss: list, identifiers: dict) -> str:
    out = ["**Cross-Source Correlation**"]
    points: list = []

    im_errors = [e for e in merged if e["src"] == "IM" and e["level_n"] >= 50]
    for ime in im_errors:
        followups = []
        for e in merged:
            if e["src"] in ("BE", "SS") and e["level_n"] >= 40:
                dt = _ts_diff_seconds(ime["ts"], e["ts"])
                if dt is not None and 0 <= dt <= 10:
                    followups.append((dt, e))
        followups.sort(key=lambda p: p[0])
        if followups:
            dt, ne = followups[0]
            sym = ne["error_code"] or _short_text(ne["error_message"] or ne["message"], 80) or "issue"
            points.append(
                f"- IM failure at {_fmt_ts(ime['ts'])} ({ime['error_code'] or _short_text(ime['error_message'], 80) or 'error'}) "
                f"was followed {dt:.1f}s later by {ne['source']} {ne['severity']} #{ne['idx']} ({sym}). "
                "Classic upstream → downstream cascade."
            )

    be_errors = [e for e in merged if e["src"] == "BE" and e["level_n"] >= 50]
    for bee in be_errors:
        for e in merged:
            if e["src"] == "SS" and e["level_n"] >= 40:
                dt = _ts_diff_seconds(bee["ts"], e["ts"])
                if dt is not None and 0 <= dt <= 5:
                    points.append(
                        f"- BE error at {_fmt_ts(bee['ts'])} preceded a Stream Server {e['severity']} "
                        f"({e['action'] or e['module'] or 'event'}) by {dt:.1f}s — "
                        "bot probably could not deliver the planned response."
                    )
                    break

    if len(merged) >= 4:
        for src_label in ("Bot Engine", "Integration Manager", "Stream Server"):
            entries = [e for e in merged if e["source"] == src_label and e["ts"]]
            if len(entries) < 2:
                continue
            biggest_gap = 0.0
            biggest_pair = None
            for a, b in zip(entries, entries[1:]):
                dt = _ts_diff_seconds(a["ts"], b["ts"]) or 0
                if dt > biggest_gap:
                    biggest_gap = dt
                    biggest_pair = (a, b)
            if biggest_pair and biggest_gap >= 8:
                a, b = biggest_pair
                points.append(
                    f"- {src_label} went silent for {biggest_gap:.1f}s between #{a['idx']} ({_fmt_ts(a['ts'])}) and "
                    f"#{b['idx']} ({_fmt_ts(b['ts'])}) — check whether this source crashed or was simply idle."
                )

    drift_notes: list = []
    import re as _re
    uuid_pat = _re.compile(r"[0-9a-fA-F]{8,}-[0-9a-fA-F\-]{8,}")
    for key, label in (("connection_id", "Connection ID"), ("context_id", "Context ID"), ("apt_name", "APT identifier")):
        v = (identifiers.get(key) or "").strip()
        if not v or len(v) < 6:
            continue
        for src_label, src_logs in (("Bot Engine", be), ("Integration Manager", im), ("Stream Server", ss)):
            different: set = set()
            for log in src_logs:
                blob = " ".join(str(log.get(k, "")) for k in ("connection_id", "context_id", "apt_identifier", "apt_name", "message", "error_message"))
                for m in uuid_pat.findall(blob):
                    if m != v and len(m) >= len(v) - 4:
                        different.add(m)
            if different:
                drift_notes.append(
                    f"  · {src_label} mentions {', '.join(sorted(list(different))[:2])} alongside the requested {label}={v}"
                )
    if drift_notes:
        points.append("- Possible identifier drift across sources:")
        points.extend(drift_notes)

    healthy = []
    for src_label, src_entries in (("Bot Engine", be), ("Integration Manager", im), ("Stream Server", ss)):
        if not src_entries:
            continue
        if not any(x["level_n"] >= 40 for x in src_entries):
            healthy.append(src_label)
    if healthy:
        points.append(f"- Clean sources (no warn/error in scope): {', '.join(healthy)}")

    if not points:
        out.append("No notable cross-source patterns detected (no error cascades, no large silence gaps, no identifier drift).")
    else:
        out.extend(points)
    return "\n".join(out)


def _format_root_cause(merged: list):
    errors = [e for e in merged if e["level_n"] >= 50]
    if not errors:
        return None
    src_priority = {"IM": 0, "BE": 1, "SS": 2}
    errors.sort(key=lambda e: (e["ts_sort"], src_priority.get(e["src"], 9)))
    primary = errors[0]
    out = ["**Root Cause**"]
    out.append(
        f"Primary: {primary['source']} #{primary['idx']} @ {_fmt_ts(primary['ts'])} — "
        f"{primary['error_code'] or 'error'}: "
        f"{_short_text(primary['error_message'] or primary['message'], 240) or 'no message'}."
    )
    reason = []
    if primary["api"]:
        reason.append(f"API `{primary['api']}`")
    if primary["method"]:
        reason.append(f"method `{primary['method']}`")
    if primary["module"]:
        reason.append(f"module `{primary['module']}`")
    if primary["action"]:
        reason.append(f"action `{primary['action']}`")
    if reason:
        out.append("Originating point: " + ", ".join(reason) + ".")
    others = errors[1:]
    if others:
        out.append("")
        out.append("Secondary / cascading errors:")
        for n, e in enumerate(others[:8], 1):
            out.append(
                f"{n}. {e['source']} #{e['idx']} @ {_fmt_ts(e['ts'])} — "
                f"{e['error_code'] or 'error'}: {_short_text(e['error_message'] or e['message'], 200) or 'no message'}"
            )
    warn_count = sum(1 for e in merged if e["level_n"] == 40)
    if warn_count:
        out.append("")
        out.append(f"Additional {warn_count} warning(s) across the session — review them in Issues Found.")
    return "\n".join(out)


def _format_verdict(merged: list) -> str:
    out = ["**Verdict**"]
    crit = sum(1 for e in merged if e["level_n"] >= 50)
    warn = sum(1 for e in merged if e["level_n"] == 40)
    if crit > 0:
        out.append(f"FAILURE — {crit} critical error(s) and {warn} warning(s) detected across the session.")
    elif warn > 0:
        out.append(f"DEGRADED SUCCESS — no critical errors but {warn} warning(s) detected; caller may have noticed retries or fallback prompts.")
    else:
        out.append("SUCCESS — no errors or warnings detected; session completed cleanly across all sources in scope.")
    sources_with = len({e["src"] for e in merged})
    total = len(merged)
    if sources_with >= 3 and total >= 30:
        confidence = "HIGH"
    elif sources_with >= 2 and total >= 10:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"
    out.append(f"Confidence: {confidence} (based on {sources_with} source(s) with {total} entries in scope).")
    return "\n".join(out)


def _build_question_log_feed(
    be_logs: list,
    im_logs: list,
    ss_logs: list,
    max_entries: int = 400,
    nl_logs: list | None = None,
) -> tuple[str, dict]:
    """Build a single chronologically-merged compact text feed across BE/IM/SS/NLP for LLM consumption.

    Returns (feed_text, stats) where stats has per-source counts and the trimmed-flag.
    """
    nl_logs = nl_logs or []
    be = _normalize_be(be_logs)
    im = _normalize_im(im_logs)
    ss = _normalize_ss(ss_logs)
    nl = _normalize_nl(nl_logs)
    merged = sorted(be + im + ss + nl, key=lambda e: (e["ts_sort"], e["src"]))
    trimmed = len(merged) > max_entries
    if trimmed:
        merged = merged[:max_entries]
    lines: list = []
    for i, e in enumerate(merged, 1):
        lines.append(
            f"[{i}] {e['ts'] or '?'} {e['source']} {e['severity']} :: {_entry_summary(e)}"
        )
    stats = {
        "be_count": len(be_logs),
        "im_count": len(im_logs),
        "ss_count": len(ss_logs),
        "nl_count": len(nl_logs),
        "merged_count": len(merged),
        "trimmed": trimmed,
        "max_entries": max_entries,
    }
    return "\n".join(lines), stats


def _render_question_driven_analysis(
    be_logs: list,
    im_logs: list,
    ss_logs: list,
    identifiers: dict,
    question: str,
    nl_logs: list | None = None,
) -> tuple[str, str]:
    """LLM-backed question-driven analysis across BE/IM/SS (and optionally NLP) logs.

    Returns (analysis_markdown, provider_key). Raises RuntimeError on LLM failure
    so the caller can decide to fall back to the deterministic analyser.
    """
    from ai_summarizer import llm_call_for_log_analysis

    feed, stats = _build_question_log_feed(be_logs, im_logs, ss_logs, max_entries=400, nl_logs=nl_logs)
    if not feed.strip():
        feed = "(no log entries provided across any of the sources)"

    sources_summary = (
        f"Bot Engine entries: {stats['be_count']}\n"
        f"Integration Manager entries: {stats['im_count']}\n"
        f"Stream Server entries: {stats['ss_count']}\n"
        f"NLP Server entries: {stats.get('nl_count', 0)}\n"
        f"Merged entries presented below: {stats['merged_count']}"
        + (f" (trimmed from full set; first {stats['max_entries']} kept)" if stats["trimmed"] else "")
    )

    user_prompt = (
        "=== IDENTIFIERS ===\n"
        f"Connection ID: {identifiers.get('connection_id') or '(not provided)'}\n"
        f"Context ID: {identifiers.get('context_id') or '(not provided)'}\n"
        f"APT identifier: {identifiers.get('apt_name') or '(not provided)'}\n\n"
        "=== SOURCE COUNTS ===\n"
        f"{sources_summary}\n\n"
        "=== USER QUESTION ===\n"
        f"{question.strip()}\n\n"
        "=== MERGED LOG FEED (sorted by timestamp; one line per event) ===\n"
        f"{feed}\n"
    )

    system_prompt = (
        "You are a senior platform engineer triaging a single voice/chat session across three log "
        "sources: Bot Engine (orchestration & integration-manager-client), Integration Manager "
        "(Symitar/SES/Twilio/mesh integrations server-side), Stream Server (Twilio SIP, "
        "Speechmatics STT, TTS, action execution), and NLP Server (LLM intent/parameter parsing — "
        "function_active / top_level / function_initial templates). Answer the USER QUESTION using "
        "ONLY evidence visible in the merged log feed.\n\n"
        "API SEMANTICS — read this carefully before interpreting any log line:\n"
        "- A Bot Engine row whose payload starts with `message.create email -> <to> from <from> "
        "  ses-id=...` is the IM-client's record that the IM service forwarded the email to AWS SES "
        "  and SES returned a Message-Id. This proves SES ACCEPTED the message; it does NOT prove "
        "  the message was DELIVERED to the recipient mailbox. Bounces, complaints, suppression "
        "  hits, recipient-MX rejection, spam filtering, and broken distribution lists all happen "
        "  AFTER this log line and would NOT appear in any of the three log indexes here.\n"
        "- A Bot Engine row whose payload starts with `message.create sms -> +<E.164> sid=SM...` "
        "  is an SMS send via Twilio Programmable Messaging. Twilio queueing != delivery to handset.\n"
        "- A Bot Engine row whose payload starts with `message.validate phone-lookup +<E.164> -> "
        "  isVoip=… isMobile=… isLandline=…` is a Twilio Lookup / phone-validation call. It is "
        "  NEVER about email validation or callback validation. Treat it as a phone-number check.\n"
        "- A Bot Engine row with `auth.info session-bootstrap` is a session/auth bootstrap call. "
        "  It is unrelated to email, SMS, or callback business logic.\n"
        "- Integration Manager rows whose `msg` is `Controller Success` / `SOAP API Success` only "
        "  prove the IM HTTP/SOAP route returned 200 to its caller. They do NOT prove anything "
        "  about downstream provider delivery.\n"
        "- Stream Server rows with action `io/voice` carry the bot's TTS output. Action `io/parse` "
        "  / `io/gather` carry caller speech. `channel/pause` is a deliberate inter-prompt pause.\n"
        "- NLP Server rows are LLM-trace records: `function_active` parses the input for the "
        "  currently-active experience/parameter; `top_level` classifies the input against the "
        "  global function catalogue; `function_initial` parses the input as the entry parse for a "
        "  candidate target function. Each row carries the recognised input text, the LLM's raw "
        "  JSON output, and the materialised `action`/`action_data`. A `system.input_error` on the "
        "  Stream Server side often correlates with three NLP rows (active/top_level/initial) that "
        "  produced disagreeing decisions on the same `request_id` — that's a conflict-resolution "
        "  signature, not an out-of-grammar problem.\n\n"
        "STRICT RULES:\n"
        "- Cite each piece of evidence with the `[N]` feed index and copy the timestamp, source, "
        "  and the literal payload snippet you are relying on. Never paraphrase a payload into a "
        "  meaning the log itself does not contain.\n"
        "- CHANNEL MATCHING — if the question asks about a specific channel or artefact (email, "
        "  SMS, voice prompt, transfer, callback, validation), only rows whose payload is for that "
        "  exact channel count as supporting evidence. A `message.create email -> ...` row CANNOT "
        "  support a claim about SMS, and vice versa. A `message.validate` (phone lookup) CANNOT "
        "  support a claim that an email or SMS was sent. If the question is about action X and no "
        "  row in the feed actually performs X, the Answer is NO (or INCONCLUSIVE if a partial "
        "  attempt is visible) — do not stretch unrelated rows to fill an evidence bullet.\n"
        "- A bot prompt like 'Shall I send you a text…' is an OFFER, not a send. Treat 'offer' and "
        "  'send' as distinct events; an offer without a matching `message.create sms` row means "
        "  the send did not happen on the platform.\n"
        "- If the question asks about delivery / receipt / inbox / bounce / complaint, REMEMBER "
        "  these logs end at SES/Twilio acceptance. Say so explicitly and route the user to the "
        "  correct off-platform source (AWS SES event destinations / suppression list, Twilio "
        "  message status, recipient mail-server message-trace, distribution-list membership, "
        "  SPF/DKIM/DMARC).\n"
        "- Do NOT claim a row 'processed the callback request' or 'validated the callback request' "
        "  unless the payload literally says that. `auth.info` is bootstrap. `message.validate` is "
        "  phone-lookup. `message.create email` is the actual notification send.\n"
        "- EVIDENCE BREVITY — emit ONLY bullets that directly support or refute the answer; never "
        "  pad with rows you describe as 'unrelated'. 1–6 bullets is normal; 0 bullets is fine if "
        "  the feed is genuinely silent on the question (then Verdict = INCONCLUSIVE).\n"
        "- If the merged feed has no row that directly bears on the question, your Verdict MUST be "
        "  INCONCLUSIVE (or NO if absence of the row IS the answer) with HIGH confidence in the "
        "  absence claim and LOW confidence in everything else.\n"
        "- Be terse. No filler. No restatement of the question.\n\n"
        "Output strictly in this Markdown structure with these exact section headers:\n"
        "**Answer**\n"
        "<2-5 sentence direct answer that respects the API semantics above>\n\n"
        "**Evidence**\n"
        "- [N] @ <timestamp> — <source> — <verbatim payload fragment and what it actually proves>\n"
        "- ... (3-10 bullets, ordered by relevance to the question)\n\n"
        "**Cross-Source Correlation**\n"
        "- 1-3 bullets joining BE↔IM↔SS where relevant (skip the section entirely if N/A).\n\n"
        "**Off-platform checks**\n"
        "- Concrete next steps outside these logs to confirm or extend the answer.\n\n"
        "**Verdict**\n"
        "ANSWER: <YES | NO | PARTIAL | INCONCLUSIVE> — <one-sentence justification grounded in cited evidence>\n"
        "Confidence: <HIGH | MEDIUM | LOW> — <why, in one phrase>\n"
    )

    text, provider_key = llm_call_for_log_analysis(system_prompt, user_prompt, max_tokens=2200)
    return text, provider_key


def _render_combined_analysis(be_logs: list, im_logs: list, ss_logs: list, identifiers: dict) -> str:
    """Deterministic cross-source RCA — no LLM, no token limits, fully offline."""
    be = _normalize_be(be_logs)
    im = _normalize_im(im_logs)
    ss = _normalize_ss(ss_logs)
    merged = sorted(be + im + ss, key=lambda e: (e["ts_sort"], e["src"]))
    sources_with_logs: list = []
    sources_empty: list = []
    for label, src in (("Bot Engine", be), ("Integration Manager", im), ("Stream Server", ss)):
        (sources_with_logs if src else sources_empty).append(label)
    parts = [
        _format_session_overview(merged, be, im, ss, identifiers, sources_with_logs, sources_empty),
        _format_issues_found(merged),
        _format_cross_correlation(merged, be, im, ss, identifiers),
    ]
    rc = _format_root_cause(merged)
    if rc:
        parts.append(rc)
    parts.append(_format_verdict(merged))
    return "\n\n".join(parts)


def _quick_stats(logs: list, src: str) -> dict:
    err = warn = 0
    apis: set = set()
    modules: set = set()
    actions: set = set()
    for log in logs:
        ln = _to_level_n(log.get("level"))
        if ln >= 50:
            err += 1
        elif ln >= 40:
            warn += 1
        if log.get("api_name"):
            apis.add(log["api_name"])
        if log.get("module_name"):
            modules.add(log["module_name"])
        if log.get("action_type") or log.get("action_subtype"):
            label = f"{log.get('action_type', '')}/{log.get('action_subtype', '')}".strip("/")
            if label:
                actions.add(label)
    out: dict = {"errors": err, "warnings": warn}
    if src in ("BE", "IM"):
        out["apis"] = sorted(apis)
    if src == "SS":
        out["modules"] = sorted(modules)
        out["actions"] = sorted(actions)
    return out


@app.route("/api/nlp-server/status")
def api_nlp_server_status():
    """Check if the nlp-server default-logs index is configured and reachable."""
    from ai_summarizer import log_analysis_meta_for_status

    try:
        from opensearch_client import check_nlp_server_default_index
        result = check_nlp_server_default_index()
        meta = log_analysis_meta_for_status()
        return jsonify({"ok": True, **result, **meta})
    except Exception as e:
        meta = log_analysis_meta_for_status()
        return jsonify({"ok": False, "configured": False, "connected": False, "error": str(e), **meta})


@app.route("/api/nlp-server/logs", methods=["POST"])
def api_nlp_server_logs():
    """Fetch nlp-server default logs by metadata.connection_id and/or metadata.request_id."""
    from opensearch_client import query_nlp_server_default_logs

    data = request.get_json() or {}
    connection_id = (data.get("connection_id") or "").strip()
    request_id = (data.get("request_id") or "").strip()
    if not connection_id and not request_id:
        return jsonify({
            "ok": False,
            "error": "connection_id or request_id is required",
        }), 400

    time_minutes = 0
    try:
        time_minutes = max(0, int(data.get("time_minutes", 0)))
    except (TypeError, ValueError):
        pass

    max_logs = min(int(data.get("max_logs", 1000)), 10000)
    time_from = (data.get("time_from") or "").strip() or None
    time_to = (data.get("time_to") or "").strip() or None

    result = query_nlp_server_default_logs(
        connection_id=connection_id or None,
        request_id=request_id or None,
        time_minutes=time_minutes if time_minutes > 0 else None,
        max_logs=max_logs,
        time_from=time_from,
        time_to=time_to,
    )
    if result is None:
        return jsonify({
            "ok": False,
            "error": "NLP-server index not configured (set OPENSEARCH_NLP_SERVER_INDEX in .env / Settings)",
        }), 400
    if result.get("error"):
        status_code = 504 if result.get("timeout") else 500
        return jsonify({"ok": False, **result}), status_code

    return jsonify({
        "ok": True,
        "total": result.get("total", 0),
        "scanned": result.get("scanned", 0),
        "logs": result.get("logs", []),
    })


@app.route("/api/download/nlp-server-logs", methods=["POST"])
def api_download_nlp_server_logs():
    """Download nlp-server default logs by connection_id / request_id as CSV or JSON."""
    import csv
    import io
    import json as json_mod
    from opensearch_client import query_nlp_server_default_logs

    data = request.get_json() or {}
    connection_id = (data.get("connection_id") or "").strip()
    request_id = (data.get("request_id") or "").strip()
    fmt = (data.get("format") or "csv").lower()
    if not connection_id and not request_id:
        return jsonify({"ok": False, "error": "connection_id or request_id is required"}), 400

    time_minutes = 0
    try:
        time_minutes = max(0, int(data.get("time_minutes", 0)))
    except (TypeError, ValueError):
        pass

    max_logs = min(int(data.get("max_logs", 10000)), 10000)
    time_from = (data.get("time_from") or "").strip() or None
    time_to = (data.get("time_to") or "").strip() or None

    result = query_nlp_server_default_logs(
        connection_id=connection_id or None,
        request_id=request_id or None,
        time_minutes=time_minutes if time_minutes > 0 else None,
        max_logs=max_logs,
        time_from=time_from,
        time_to=time_to,
    )
    if result is None:
        return jsonify({"ok": False, "error": "NLP-server index not configured"}), 400
    if result.get("error"):
        return jsonify({"ok": False, **result}), 500

    logs = result.get("logs", [])
    safe_id = (connection_id or request_id or "logs").replace("/", "_").replace("\\", "_")
    base_name = f"nlp_server_logs_{safe_id}_{len(logs)}_rows"

    if fmt == "json":
        body = json_mod.dumps({"logs": logs, "total": result.get("total", 0)}, ensure_ascii=False, indent=2)
        return Response(
            body,
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename={base_name}.json"},
        )

    cols = [
        "timestamp", "level", "tenant_name", "agent_name", "connection_id",
        "session_id", "request_id", "template_type", "experience_id",
        "experience_name", "input_id", "active_parameter", "text", "action",
        "action_data", "llm_output", "model_id", "llm_time_ms",
        "prompt_tokens", "completion_tokens", "total_tokens",
    ]
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(cols)
    for log in logs:
        writer.writerow([log.get(c, "") if log.get(c) is not None else "" for c in cols])
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={base_name}.csv"},
    )


# Column orders for the combined ZIP — kept in lockstep with the per-source CSV
# download endpoints so a downstream consumer can diff per-source CSVs against
# the bundled CSVs and see identical structure.
_COMBINED_BE_COLS = [
    "timestamp", "level", "tenant_name", "connection_id", "context_id",
    "api_name", "method_name", "error_code", "message", "error_message", "error_stack",
]
_COMBINED_IM_COLS = [
    "timestamp", "level", "tenant_name", "connection_id",
    "api_name", "method_name", "error_code", "message", "error_message", "error_stack",
]
_COMBINED_SS_COLS = [
    "timestamp", "level", "tenant_name", "module_name",
    "action_type", "action_subtype", "action_text", "speech_text",
    "context_id", "apt_name", "connection_id", "request_id", "error_code",
    "message", "error_message", "error_stack",
]
_COMBINED_NL_COLS = [
    "timestamp", "level", "tenant_name", "agent_name", "connection_id",
    "session_id", "request_id", "template_type", "experience_id",
    "experience_name", "input_id", "active_parameter", "text", "action",
    "action_data", "llm_output", "model_id", "llm_time_ms",
    "prompt_tokens", "completion_tokens", "total_tokens",
]


def _combined_csv(rows: list, cols: list[str]) -> str:
    """Render a list of dicts to a CSV string using the given column order.

    Newlines in payload fields are flattened so spreadsheet tools don't choke
    on multi-line cells (matches the per-source download behaviour).
    """
    import csv
    import io
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(cols)
    for log in rows or []:
        out_row = []
        for col in cols:
            val = log.get(col, "")
            if val is None:
                val = ""
            if isinstance(val, (dict, list)):
                import json as _json
                val = _json.dumps(val, ensure_ascii=False)
            else:
                val = str(val)
            out_row.append(val.replace("\n", " ").replace("\r", ""))
        writer.writerow(out_row)
    return buf.getvalue()


@app.route("/api/log-analyser/download-all", methods=["POST"])
def api_log_analyser_download_all():
    """Bundle all 4 sources' fetched logs into a single download.

    Body:
      bot_engine_logs, integration_manager_logs, stream_server_logs,
      nlp_server_logs: arrays of already-fetched log rows (no OpenSearch query).
      identifiers: { connection_id, context_id, apt_name } for the manifest.
      format: "zip" (default) or "json".

    Output:
      - format=zip → ZIP of 4 CSVs (one per source, only included when non-empty)
        + manifest.json + raw/<source>.json (full row dicts incl. _raw).
      - format=json → single JSON file with all 4 arrays + identifiers.
    """
    import io
    import json as json_mod
    import zipfile
    from datetime import datetime, timezone

    data = request.get_json() or {}
    be_logs = data.get("bot_engine_logs") or []
    im_logs = data.get("integration_manager_logs") or []
    ss_logs = data.get("stream_server_logs") or []
    nl_logs = data.get("nlp_server_logs") or []
    identifiers = data.get("identifiers") or {}
    fmt = (data.get("format") or "zip").lower()

    arrays = {
        "bot_engine_logs": be_logs,
        "integration_manager_logs": im_logs,
        "stream_server_logs": ss_logs,
        "nlp_server_logs": nl_logs,
    }
    for k, v in arrays.items():
        if not isinstance(v, list):
            return jsonify({"ok": False, "error": f"{k} must be an array"}), 400
    if not any(arrays.values()):
        return jsonify({"ok": False, "error": "No logs provided across any source"}), 400

    cid = (identifiers.get("connection_id") or "").strip()
    ctxid = (identifiers.get("context_id") or "").strip()
    apt = (identifiers.get("apt_name") or "").strip()
    safe_id = (cid or ctxid or apt or "logs").replace("/", "_").replace("\\", "_")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base_name = f"combined_logs_{safe_id}_{stamp}"

    manifest = {
        "title": "Cross-source Log Analyser bundle",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "identifiers": {
            "connection_id": cid or None,
            "context_id": ctxid or None,
            "apt_name": apt or None,
        },
        "counts": {k: len(v) for k, v in arrays.items()},
        "sources": {
            "bot_engine_logs": {
                "count": len(be_logs),
                "csv_columns": _COMBINED_BE_COLS,
                "description": "Bot Engine default logs (orchestration + IM-client).",
            },
            "integration_manager_logs": {
                "count": len(im_logs),
                "csv_columns": _COMBINED_IM_COLS,
                "description": "Integration Manager default logs (Symitar/SES/Twilio/mesh server-side).",
            },
            "stream_server_logs": {
                "count": len(ss_logs),
                "csv_columns": _COMBINED_SS_COLS,
                "description": "Stream Server default logs (Twilio SIP, Speechmatics STT, TTS, action exec).",
            },
            "nlp_server_logs": {
                "count": len(nl_logs),
                "csv_columns": _COMBINED_NL_COLS,
                "description": "NLP Server logs (LLM-trace: function_active / top_level / function_initial parses).",
            },
        },
    }

    if fmt == "json":
        body = json_mod.dumps({
            "manifest": manifest,
            **arrays,
        }, ensure_ascii=False, indent=2)
        return Response(
            body,
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename={base_name}.json"},
        )

    # Default: ZIP
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", json_mod.dumps(manifest, ensure_ascii=False, indent=2))

        if be_logs:
            zf.writestr("bot_engine.csv", _combined_csv(be_logs, _COMBINED_BE_COLS))
            zf.writestr("raw/bot_engine.json", json_mod.dumps(be_logs, ensure_ascii=False, indent=2))
        if im_logs:
            zf.writestr("integration_manager.csv", _combined_csv(im_logs, _COMBINED_IM_COLS))
            zf.writestr("raw/integration_manager.json", json_mod.dumps(im_logs, ensure_ascii=False, indent=2))
        if ss_logs:
            zf.writestr("stream_server.csv", _combined_csv(ss_logs, _COMBINED_SS_COLS))
            zf.writestr("raw/stream_server.json", json_mod.dumps(ss_logs, ensure_ascii=False, indent=2))
        if nl_logs:
            zf.writestr("nlp_server.csv", _combined_csv(nl_logs, _COMBINED_NL_COLS))
            zf.writestr("raw/nlp_server.json", json_mod.dumps(nl_logs, ensure_ascii=False, indent=2))

        readme_lines = [
            f"# Cross-source Log Analyser bundle — {safe_id}",
            f"Generated: {manifest['generated_at_utc']}",
            "",
            "## Identifiers",
            f"- Connection ID: {cid or '(not provided)'}",
            f"- Context ID:    {ctxid or '(not provided)'}",
            f"- APT name:      {apt or '(not provided)'}",
            "",
            "## Counts",
            f"- Bot Engine:          {len(be_logs):,}",
            f"- Integration Manager: {len(im_logs):,}",
            f"- Stream Server:       {len(ss_logs):,}",
            f"- NLP Server:          {len(nl_logs):,}",
            "",
            "## Files",
            "- `<source>.csv` — flattened table view (newlines stripped from cells).",
            "- `raw/<source>.json` — full per-row dicts including the original `_source` payload.",
            "- `manifest.json` — machine-readable summary (counts + column orders + identifiers).",
            "",
            "## Tip",
            "Re-import any of the JSONs into the Log Analyser via the Session RCA agent's",
            "'Paste JSON' mode to re-run analysis without re-querying OpenSearch.",
        ]
        zf.writestr("README.md", "\n".join(readme_lines))

    return Response(
        buf.getvalue(),
        mimetype="application/zip",
        headers={"Content-Disposition": f"attachment; filename={base_name}.zip"},
    )


@app.route("/api/log-analyser/analyse-all", methods=["POST"])
def api_log_analyser_analyse_all():
    """Cross-source RCA across Bot Engine + Integration Manager + Stream Server logs.

    Two modes:
      - `question` empty → deterministic built-in analyser (no LLM, no token limits).
      - `question` set   → LLM answers the user's specific question with evidence cited
                            from the merged log feed. Falls back to the deterministic
                            analyser (with a note) if no LLM provider is configured or
                            if the LLM call fails.
    """
    from ai_summarizer import _get_provider

    data = request.get_json() or {}
    be_logs = data.get("bot_engine_logs") or []
    im_logs = data.get("integration_manager_logs") or []
    ss_logs = data.get("stream_server_logs") or []
    nl_logs = data.get("nlp_server_logs") or []
    identifiers = data.get("identifiers") or {}
    question = (data.get("question") or "").strip()

    if (
        not isinstance(be_logs, list)
        or not isinstance(im_logs, list)
        or not isinstance(ss_logs, list)
        or not isinstance(nl_logs, list)
    ):
        return jsonify({"ok": False, "error": "bot_engine_logs, integration_manager_logs, stream_server_logs, nlp_server_logs must be arrays"}), 400

    if not (be_logs or im_logs or ss_logs or nl_logs):
        return jsonify({"ok": False, "error": "At least one source must have logs to analyse"}), 400

    sources_block = {
        "bot_engine": {"count": len(be_logs), **_quick_stats(be_logs, "BE")},
        "integration_manager": {"count": len(im_logs), **_quick_stats(im_logs, "IM")},
        "stream_server": {"count": len(ss_logs), **_quick_stats(ss_logs, "SS")},
        "nlp_server": {"count": len(nl_logs)},
    }

    if question:
        if _get_provider() == "none":
            try:
                analysis = _render_combined_analysis(be_logs, im_logs, ss_logs, identifiers)
            except Exception as exc:
                return jsonify({"ok": False, "error": str(exc)}), 500
            return jsonify({
                "ok": True,
                "analysis": analysis,
                "log_analysis_llm": "builtin",
                "question": question,
                "note": "no LLM configured — ran deterministic RCA instead; set OPENAI_API_KEY in Settings to answer free-form questions",
                "sources": sources_block,
            })
        try:
            analysis, provider_key = _render_question_driven_analysis(
                be_logs, im_logs, ss_logs, identifiers, question, nl_logs=nl_logs
            )
            return jsonify({
                "ok": True,
                "analysis": analysis,
                "log_analysis_llm": provider_key,
                "question": question,
                "sources": sources_block,
            })
        except Exception as exc:
            try:
                fallback = _render_combined_analysis(be_logs, im_logs, ss_logs, identifiers)
            except Exception as exc2:
                return jsonify({"ok": False, "error": f"LLM error: {exc}; fallback failed: {exc2}"}), 500
            return jsonify({
                "ok": True,
                "analysis": fallback,
                "log_analysis_llm": "builtin",
                "question": question,
                "note": f"LLM call failed ({str(exc)[:200]}) — showing deterministic RCA as fallback",
                "sources": sources_block,
            })

    try:
        analysis = _render_combined_analysis(be_logs, im_logs, ss_logs, identifiers)
        return jsonify({
            "ok": True,
            "analysis": analysis,
            "log_analysis_llm": "builtin",
            "sources": sources_block,
        })
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/api/rephrase", methods=["POST"])
def api_rephrase():
    """Rephrase draft text for customer emails or internal ticket-style updates (OpenAI-compatible API)."""
    from ai_summarizer import llm_call, _get_provider

    data = request.get_json() or {}
    text = (data.get("text") or "").strip()
    mode = (data.get("mode") or "ticket").strip().lower()
    if not text:
        return jsonify({"ok": False, "error": "text is required"}), 400
    if len(text) > 20000:
        return jsonify({"ok": False, "error": "text is too long (max 20,000 characters)"}), 400

    if _get_provider() == "none":
        return jsonify({
            "ok": False,
            "error": "No LLM configured. Set OPENAI_API_KEY or OPENAI_BASE_URL (e.g. local Ollama) in Settings.",
        }), 400

    if mode == "rca":
        system_prompt = (
            "You convert a technical log-analysis writeup into a polished, customer-facing Root "
            "Cause Analysis (RCA) email DRAFT. The recipient is the customer / business stakeholder "
            "who reported the issue; they are NOT engineers and have no visibility into our "
            "internal systems.\n\n"
            "STRICT RULES:\n"
            "- Preserve every factual claim from the input. Do NOT invent timestamps, message-ids, "
            "  recipients, root causes, dates, or commitments that the input does not contain.\n"
            "- Translate internal vocabulary into customer-friendly terms. NEVER mention any of: "
            "  'Bot Engine', 'Integration Manager', 'Stream Server', 'Twilio', 'Speechmatics', "
            "  'AWS SES', 'SES', 'Symitar', 'OpenSearch', 'log line [N]', 'connectionId', "
            "  'contextId', 'APT', 'requestId', 'Pino', or any other internal module/API name. "
            "  Replace them with the user-visible artefact (e.g. 'our notification system', "
            "  'the email delivery service', 'the call platform').\n"
            "- Do NOT include literal log identifiers, UUIDs, message-ids, internal pod names, "
            "  HTTP status codes, or `[N]` evidence-bullet citations. Quote a customer-visible "
            "  detail (caller phone last-4, the recipient mailbox, the time of the call) only when "
            "  it materially clarifies the explanation, and even then keep it minimal.\n"
            "- Distinguish 'sent / accepted by provider' from 'delivered to inbox' carefully. If "
            "  the input states only acceptance, the email must say something like 'our "
            "  notification system accepted the message for delivery; the gap appears to be in the "
            "  recipient mailbox / mail server' — do not promise delivery the input cannot prove.\n"
            "- Use a calm, accountable, action-oriented tone. Avoid blame. Apologise briefly only "
            "  if the input shows an actual customer-impacting problem; do not over-apologise.\n\n"
            "STRUCTURE — output the email body in this order, plain text, no markdown headings:\n"
            "1. Greeting — `Hi <Team / Name>,` (use a generic 'Hi team,' if the input gives no "
            "   recipient).\n"
            "2. One-sentence acknowledgement of the reported issue.\n"
            "3. **What we found** — 2-5 short sentences explaining what happened in plain English, "
            "   sequenced by what the customer would care about (was the request captured? was the "
            "   notification triggered? did it leave our system? where is the gap?).\n"
            "4. **Root cause** — 1-3 sentences naming the most likely cause in customer language, "
            "   using cautious framing if the input is inconclusive ('the most likely cause is …', "
            "   'the evidence we have points to …'). Do not state a cause the input does not "
            "   support.\n"
            "5. **Next steps** — short bullets listing what the team will do (e.g. confirm "
            "   delivery with the recipient mail provider, follow up on the customer request "
            "   manually so nothing is missed, add monitoring). Use only steps the input implies "
            "   or that obviously follow from the cause.\n"
            "6. Closing — short reassurance and an invitation to reply with questions, then a "
            "   neutral sign-off (`Best regards,` followed by `<Your name>` placeholder if no "
            "   sender name is in the input).\n\n"
            "FORMAT:\n"
            "- Plain-text email body only. No subject line. No markdown headings (#). Use bold "
            "  labels in front of `What we found:`, `Root cause:`, `Next steps:` if it improves "
            "  scannability — but no `**` markdown markers; just the words themselves.\n"
            "- Short paragraphs. Bullets only under `Next steps`.\n"
            "- Do NOT mention you are an AI or that the text was generated/rephrased.\n"
        )
        max_tokens = 2200
    elif mode == "email":
        system_prompt = (
            "You rewrite workplace drafts into clear, professional customer-facing emails.\n"
            "Rules:\n"
            "- Preserve every factual claim from the draft; do not invent dates, names, numbers, or commitments.\n"
            "- If something is vague, keep it appropriately cautious rather than making it specific.\n"
            "- Tone: polite, respectful, easy to read. Short paragraphs. No slang.\n"
            "- Output only the email body (no subject line unless the draft clearly includes one you should keep).\n"
            "- Do not mention that you are an AI or that you rephrased the text."
        )
        max_tokens = 2500
    elif mode == "salesforce":
        system_prompt = (
            "You rewrite rough notes into a polished Salesforce-style post suitable for a Case feed comment, "
            "Chatter update, or internal note on a record (plain text that pastes cleanly into Salesforce).\n"
            "Rules:\n"
            "- Preserve every fact from the draft; do not invent case numbers, record IDs, customer details, or commitments.\n"
            "- Structure for quick scanning: short paragraphs or bullet lines — e.g. context / what you did / current state / next step or ask.\n"
            "- Tone: professional, past tense for completed work, clear ownership of actions where the draft implies it.\n"
            "- Do not use markdown headings (#). Plain text only. @mentions: keep only if they appear in the draft; do not add new ones.\n"
            "- Do not mention AI or that the text was rewritten."
        )
        max_tokens = 2000
    elif mode == "grammar":
        system_prompt = (
            "You are a careful copy editor. Improve the text with grammar, spelling, and punctuation fixes, "
            "and swap weak or awkward words for clearer, more natural choices.\n"
            "Rules:\n"
            "- Preserve meaning, facts, names, numbers, and dates. Do not add or remove substantive claims.\n"
            "- Keep the same overall structure (paragraphs, bullets, line breaks) unless a small fix requires a tiny adjustment.\n"
            "- Prefer light edits; do not turn the text into a different genre (e.g. do not make it a formal email unless it already is).\n"
            "- Output only the corrected text — no preface, labels, or explanation.\n"
            "- Do not mention AI."
        )
        max_tokens = 2500
    else:
        if mode != "ticket":
            mode = "ticket"
        system_prompt = (
            "You rewrite rough notes into a concise internal ticket or Slack-style update for engineers and support.\n"
            "Rules:\n"
            "- Keep every fact; do not invent details, owners, or timelines not in the draft.\n"
            "- Prefer bullets or short lines: context, symptoms, what was tried, ask / next step.\n"
            "- Plain language, scannable. No excessive pleasantries.\n"
            "- Do not mention AI."
        )
        max_tokens = 2000

    user_prompt = f"Rewrite the following draft for mode={mode}:\n\n{text}"

    try:
        rephrased = llm_call(system_prompt, user_prompt, max_tokens=max_tokens)
        return jsonify({"ok": True, "mode": mode, "rephrased": rephrased})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/api/download/error-logs", methods=["POST"])
def api_download_error_logs():
    """Fetch all matching error logs from OpenSearch, enrich with connection_id, and return as CSV or JSON."""
    import csv
    import io
    import json as json_mod
    from opensearch_client import query_all_error_logs, lookup_connection_ids

    data = request.get_json() or {}
    error_codes = data.get("error_codes") or []
    try:
        codes = [int(c) for c in error_codes]
    except (TypeError, ValueError):
        codes = []

    time_minutes = 60
    try:
        time_minutes = max(1, min(43200, int(data.get("time_minutes", 60))))
    except (TypeError, ValueError):
        pass

    fmt = (data.get("format") or "csv").strip().lower()
    tenant_filter = data.get("tenant_filter") or None
    result = query_all_error_logs(error_codes=codes or None, time_minutes=time_minutes, tenant_filter=tenant_filter)
    if result is None:
        return jsonify({"ok": False, "error": "OpenSearch not configured"}), 400
    if result.get("error"):
        return jsonify({"ok": False, "error": result["error"]}), 500

    logs = result.get("logs", [])

    req_ids = [log.get("request_id", "") for log in logs if log.get("request_id")]
    conn_id_map = lookup_connection_ids(req_ids) if req_ids else {}

    base_name = f"opensearch_error_logs_{len(logs)}_rows"

    if fmt == "json":
        enriched = []
        for log in logs:
            entry = dict(log)
            req_id = entry.get("request_id", "")
            if req_id and req_id in conn_id_map:
                entry["connection_id"] = conn_id_map[req_id]
            enriched.append(entry)
        content = json_mod.dumps(enriched, indent=2, default=str)
        return Response(
            content,
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename={base_name}.json"},
        )

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["timestamp", "error_code", "tenant_name", "request_id", "connection_id", "context_id", "message", "error_stack", "k8s_version"])
    for log in logs:
        req_id = log.get("request_id", "")
        writer.writerow([
            log.get("timestamp", ""),
            log.get("error_code", ""),
            log.get("tenant_name", ""),
            req_id,
            conn_id_map.get(req_id, ""),
            log.get("context_id", ""),
            str(log.get("message", "")).replace("\n", " ").replace("\r", ""),
            str(log.get("error_stack", "")).replace("\n", " ").replace("\r", ""),
            log.get("k8s_version", ""),
        ])

    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={base_name}.csv"},
    )


@app.route("/api/agent/run", methods=["POST"])
def api_agent_run():
    """Run the alert agent (engine + action rules). Returns result + actions_planned or actions_taken."""
    data = request.get_json() or {}
    error_codes = data.get("error_codes") or []
    try:
        codes = [int(c) for c in error_codes]
    except (TypeError, ValueError):
        codes = []
    ctx = data.get("context") or {}
    ctx["_error_codes"] = codes
    simulate = {}
    if ctx.get("calls_ok") is True:
        simulate["calls_ok"], simulate["calls_fail"] = True, False
    if ctx.get("calls_fail") is True:
        simulate["calls_fail"], simulate["calls_ok"] = True, False
    if "restart_detected" in ctx:
        simulate["restart_detected"] = bool(ctx["restart_detected"])
    if ctx.get("auth_ok") is True:
        simulate["auth_ok"], simulate["auth_fail"] = True, False
    if ctx.get("auth_fail") is True:
        simulate["auth_fail"], simulate["auth_ok"] = True, False
    if simulate:
        preserved = {k: v for k, v in ctx.items() if k.startswith("_")}
        ctx = {"simulate": simulate, **preserved}
    _apply_time_minutes(ctx, data)

    execute = data.get("execute") is True

    try:
        agent = AlertAgent(config_path=CONFIG_PATH)
        result = agent.run(codes, initial_context=ctx or None, execute=execute, quiet=True)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    out_context = result.get("context") or {}
    out_context = {k: v for k, v in out_context.items() if not callable(v)}

    actions = result.get("actions_taken") or result.get("actions_planned") or []
    actions_serializable = []
    for a in actions:
        entry = {"name": a.get("name"), "executed": a.get("executed", False)}
        if a.get("outcome"):
            entry["outcome"] = a["outcome"]
        if a.get("would_do"):
            entry["would_do"] = a["would_do"]
        if a.get("error"):
            entry["error"] = a["error"]
        actions_serializable.append(entry)

    client_error_counts = _client_error_counts_from_context(out_context)

    return jsonify({
        "ok": True,
        "scenario_id": result.get("scenario_id"),
        "conclusion": result.get("conclusion"),
        "next_action": result.get("next_action"),
        "matched_rule": result.get("matched_rule", False),
        "error": result.get("error"),
        "context": out_context,
        "execute": execute,
        "actions": actions_serializable,
        "client_error_counts": client_error_counts,
        "total_error_count": out_context.get("error_count") or out_context.get("opensearch_total"),
        "error_codes_used": codes,
    })


# ============================================================================
# To-Do agent — single-user task manager backed by SQLite (data/todos.db).
# Schema: tasks(id, title, description, priority [low|medium|high],
#               due_date [YYYY-MM-DD], tags [comma-sep], status [open|done],
#               created_at, updated_at, completed_at).
# ============================================================================

import sqlite3
from datetime import datetime, date

_TODOS_DB_DIR = PROJECT_ROOT / "data"
_TODOS_DB_PATH = _TODOS_DB_DIR / "todos.db"
_TODOS_PRIORITIES = ("low", "medium", "high")
_TODOS_STATUSES = ("open", "done")


def _todos_conn() -> sqlite3.Connection:
    """Open a SQLite connection, creating the schema lazily on first use."""
    _TODOS_DB_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_TODOS_DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            priority TEXT NOT NULL DEFAULT 'medium',
            due_date TEXT,
            tags TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'open',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            completed_at TEXT
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS ix_tasks_status ON tasks(status)")
    conn.execute("CREATE INDEX IF NOT EXISTS ix_tasks_due_date ON tasks(due_date)")
    conn.commit()
    return conn


def _todos_now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _todos_normalise_tags(raw) -> str:
    """Accept a list or a comma/space-separated string. Returns a clean comma-separated string of lowercase tags."""
    if raw is None:
        return ""
    if isinstance(raw, list):
        items = raw
    else:
        items = str(raw).replace(";", ",").split(",")
    seen: list = []
    for item in items:
        t = str(item).strip().lower().lstrip("#")
        if t and t not in seen:
            seen.append(t)
    return ",".join(seen[:20])  # cap at 20 tags


def _todos_serialize(row: sqlite3.Row) -> dict:
    tags = [t for t in (row["tags"] or "").split(",") if t]
    overdue = False
    if row["status"] == "open" and row["due_date"]:
        try:
            overdue = date.fromisoformat(row["due_date"]) < date.today()
        except (ValueError, TypeError):
            overdue = False
    return {
        "id": row["id"],
        "title": row["title"],
        "description": row["description"] or "",
        "priority": row["priority"],
        "due_date": row["due_date"],
        "tags": tags,
        "status": row["status"],
        "overdue": overdue,
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "completed_at": row["completed_at"],
    }


def _todos_validate_payload(data: dict, partial: bool = False) -> tuple[dict, str | None]:
    """Validate / sanitize a task payload. Returns (clean_dict, error_message_or_None)."""
    out: dict = {}
    if "title" in data or not partial:
        title = (data.get("title") or "").strip()
        if not partial and not title:
            return {}, "title is required"
        if title:
            if len(title) > 200:
                return {}, "title must be ≤ 200 characters"
            out["title"] = title
    if "description" in data:
        desc = (data.get("description") or "").strip()
        if len(desc) > 4000:
            return {}, "description must be ≤ 4000 characters"
        out["description"] = desc
    if "priority" in data:
        pr = (data.get("priority") or "medium").strip().lower()
        if pr not in _TODOS_PRIORITIES:
            return {}, f"priority must be one of {', '.join(_TODOS_PRIORITIES)}"
        out["priority"] = pr
    if "due_date" in data:
        raw = (data.get("due_date") or "").strip()
        if raw:
            try:
                date.fromisoformat(raw)
            except (ValueError, TypeError):
                return {}, "due_date must be ISO YYYY-MM-DD"
            out["due_date"] = raw
        else:
            out["due_date"] = None
    if "tags" in data:
        out["tags"] = _todos_normalise_tags(data.get("tags"))
    if "status" in data:
        st = (data.get("status") or "open").strip().lower()
        if st not in _TODOS_STATUSES:
            return {}, f"status must be one of {', '.join(_TODOS_STATUSES)}"
        out["status"] = st
    return out, None


@app.route("/api/todos", methods=["GET"])
def api_todos_list():
    """List tasks. Filters: ?status=open|done|all, ?priority=low|medium|high, ?tag=foo, ?search=substring."""
    status = (request.args.get("status") or "all").strip().lower()
    priority = (request.args.get("priority") or "all").strip().lower()
    tag = (request.args.get("tag") or "").strip().lower().lstrip("#")
    search = (request.args.get("search") or "").strip()
    conn = _todos_conn()
    try:
        sql = "SELECT * FROM tasks WHERE 1=1"
        params: list = []
        if status in _TODOS_STATUSES:
            sql += " AND status = ?"
            params.append(status)
        if priority in _TODOS_PRIORITIES:
            sql += " AND priority = ?"
            params.append(priority)
        if tag:
            sql += " AND (',' || tags || ',') LIKE ?"
            params.append(f"%,{tag},%")
        if search:
            sql += " AND (title LIKE ? OR description LIKE ?)"
            like = f"%{search}%"
            params.extend([like, like])
        # Sort: open first, then by overdue (due_date asc nulls last), then priority high>med>low, then created desc.
        sql += (
            " ORDER BY "
            " CASE status WHEN 'open' THEN 0 ELSE 1 END,"
            " CASE WHEN due_date IS NULL OR due_date = '' THEN 1 ELSE 0 END,"
            " due_date ASC,"
            " CASE priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,"
            " created_at DESC"
        )
        rows = conn.execute(sql, params).fetchall()
        items = [_todos_serialize(r) for r in rows]
        return jsonify({"ok": True, "items": items, "count": len(items)})
    finally:
        conn.close()


@app.route("/api/todos", methods=["POST"])
def api_todos_create():
    data = request.get_json() or {}
    clean, err = _todos_validate_payload(data, partial=False)
    if err:
        return jsonify({"ok": False, "error": err}), 400
    now = _todos_now_iso()
    conn = _todos_conn()
    try:
        cur = conn.execute(
            """
            INSERT INTO tasks (title, description, priority, due_date, tags, status, created_at, updated_at, completed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                clean["title"],
                clean.get("description", ""),
                clean.get("priority", "medium"),
                clean.get("due_date"),
                clean.get("tags", ""),
                clean.get("status", "open"),
                now,
                now,
                None,
            ),
        )
        conn.commit()
        new_id = cur.lastrowid
        row = conn.execute("SELECT * FROM tasks WHERE id = ?", (new_id,)).fetchone()
        return jsonify({"ok": True, "item": _todos_serialize(row)})
    finally:
        conn.close()


@app.route("/api/todos/<int:task_id>", methods=["PATCH"])
def api_todos_update(task_id: int):
    data = request.get_json() or {}
    clean, err = _todos_validate_payload(data, partial=True)
    if err:
        return jsonify({"ok": False, "error": err}), 400
    if not clean:
        return jsonify({"ok": False, "error": "no fields to update"}), 400
    conn = _todos_conn()
    try:
        existing = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if not existing:
            return jsonify({"ok": False, "error": "task not found"}), 404
        sets: list = []
        params: list = []
        for k, v in clean.items():
            sets.append(f"{k} = ?")
            params.append(v)
        if "status" in clean:
            sets.append("completed_at = ?")
            params.append(_todos_now_iso() if clean["status"] == "done" else None)
        sets.append("updated_at = ?")
        params.append(_todos_now_iso())
        params.append(task_id)
        conn.execute(f"UPDATE tasks SET {', '.join(sets)} WHERE id = ?", params)
        conn.commit()
        row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        return jsonify({"ok": True, "item": _todos_serialize(row)})
    finally:
        conn.close()


@app.route("/api/todos/<int:task_id>", methods=["DELETE"])
def api_todos_delete(task_id: int):
    conn = _todos_conn()
    try:
        existing = conn.execute("SELECT id FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if not existing:
            return jsonify({"ok": False, "error": "task not found"}), 404
        conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
        conn.commit()
        return jsonify({"ok": True, "deleted_id": task_id})
    finally:
        conn.close()


@app.route("/api/todos/<int:task_id>/toggle", methods=["POST"])
def api_todos_toggle(task_id: int):
    """Quick-toggle status open ↔ done."""
    conn = _todos_conn()
    try:
        row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        if not row:
            return jsonify({"ok": False, "error": "task not found"}), 404
        new_status = "done" if row["status"] == "open" else "open"
        now = _todos_now_iso()
        conn.execute(
            "UPDATE tasks SET status = ?, completed_at = ?, updated_at = ? WHERE id = ?",
            (new_status, now if new_status == "done" else None, now, task_id),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        return jsonify({"ok": True, "item": _todos_serialize(row)})
    finally:
        conn.close()


@app.route("/api/todos/stats", methods=["GET"])
def api_todos_stats():
    conn = _todos_conn()
    try:
        rows = conn.execute("SELECT status, priority, due_date FROM tasks").fetchall()
        total = len(rows)
        open_count = sum(1 for r in rows if r["status"] == "open")
        done_count = total - open_count
        high_open = sum(1 for r in rows if r["status"] == "open" and r["priority"] == "high")
        today = date.today()
        overdue = 0
        for r in rows:
            if r["status"] != "open" or not r["due_date"]:
                continue
            try:
                if date.fromisoformat(r["due_date"]) < today:
                    overdue += 1
            except (ValueError, TypeError):
                pass
        return jsonify({
            "ok": True,
            "total": total,
            "open": open_count,
            "done": done_count,
            "overdue": overdue,
            "high_priority_open": high_open,
        })
    finally:
        conn.close()


def _start_slack_listener():
    """Start the Slack Socket Mode listener if enabled."""
    import os
    if os.environ.get("SLACK_LISTENER_ENABLED", "").strip().lower() != "true":
        return
    try:
        from slack_listener import start_listener
        start_listener()
    except Exception as e:
        print(f"  [app] Failed to start Slack listener: {e}")


# Only start the listener in the Werkzeug child process (WERKZEUG_RUN_MAIN)
# to prevent duplicate listeners when Flask debug reloader forks processes.
# For non-debug (production), it starts in __main__ below.
import os as _os
if _os.environ.get("WERKZEUG_RUN_MAIN") == "true":
    _start_slack_listener()


if __name__ == "__main__":
    port = int(_os.environ.get("PORT", 5000))
    debug = _os.environ.get("FLASK_DEBUG", "1") != "0"
    if not debug:
        _start_slack_listener()
    print(f"\n  Open in browser: http://127.0.0.1:{port}\n")
    app.run(debug=debug, host="0.0.0.0", port=port)
