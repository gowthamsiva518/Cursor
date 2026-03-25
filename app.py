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
    """Fetch Twilio call logs filtered by From number."""
    from twilio_client import query_call_logs

    data = request.get_json() or {}
    from_number = (data.get("from_number") or "").strip()
    if not from_number:
        return jsonify({"ok": False, "error": "from_number is required"}), 400

    time_minutes = 60
    try:
        time_minutes = max(1, min(43200, int(data.get("time_minutes", 60))))
    except (TypeError, ValueError):
        pass

    try:
        result = query_call_logs(time_minutes=time_minutes, from_number=from_number)
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500

    if result.get("error"):
        return jsonify({"ok": False, "error": result["error"]}), 500

    all_calls = result.get("calls", [])
    failed = sum(1 for c in all_calls if c.get("error_code"))

    return jsonify({
        "ok": True,
        "total": len(all_calls),
        "failed_calls": failed,
        "calls": all_calls,
        "accounts_checked": result.get("accounts_checked", []),
    })


@app.route("/api/download/twilio-logs", methods=["POST"])
def api_download_twilio_logs():
    """Download Twilio call logs filtered by From number as CSV or JSON."""
    import csv
    import io
    import json as json_mod
    from twilio_client import query_call_logs

    data = request.get_json() or {}
    from_number = (data.get("from_number") or "").strip()
    if not from_number:
        return jsonify({"ok": False, "error": "from_number is required"}), 400

    time_minutes = 60
    try:
        time_minutes = max(1, min(43200, int(data.get("time_minutes", 60))))
    except (TypeError, ValueError):
        pass

    fmt = (data.get("format") or "csv").strip().lower()

    try:
        result = query_call_logs(time_minutes=time_minutes, from_number=from_number)
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500

    if result.get("error"):
        return jsonify({"ok": False, "error": result["error"]}), 500

    filtered = result.get("calls", [])
    safe_name = re.sub(r"[^\w\-]", "", from_number)
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
    try:
        from opensearch_client import check_bot_engine_index
        result = check_bot_engine_index()
        return jsonify({"ok": True, **result})
    except Exception as e:
        return jsonify({"ok": False, "configured": False, "connected": False, "error": str(e)})


@app.route("/api/bot-engine/logs", methods=["POST"])
def api_bot_engine_logs():
    """Fetch bot engine logs by connectionId."""
    from opensearch_client import query_bot_engine_default_logs

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

    result = query_bot_engine_default_logs(
        connection_id=connection_id,
        time_minutes=time_minutes if time_minutes > 0 else None,
        max_logs=max_logs,
    )
    if result is None:
        return jsonify({"ok": False, "error": "Bot engine index not configured (set OPENSEARCH_BOT_ENGINE_INDEX in .env)"}), 400
    if result.get("error"):
        return jsonify({"ok": False, **result}), 500

    ui_logs = [{k: v for k, v in log.items() if k != "_raw"} for log in result.get("logs", [])]
    return jsonify({"ok": True, "total": result.get("total", 0), "scanned": result.get("scanned", 0), "logs": ui_logs})


@app.route("/api/download/bot-engine-logs", methods=["POST"])
def api_download_bot_engine_logs():
    """Download bot engine logs by connectionId as CSV or JSON."""
    import csv
    import io
    import json as json_mod
    from opensearch_client import query_bot_engine_default_logs

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

    result = query_bot_engine_default_logs(
        connection_id=connection_id,
        time_minutes=time_minutes if time_minutes > 0 else None,
        max_logs=max_logs,
    )
    if result is None:
        return jsonify({"ok": False, "error": "Bot engine index not configured"}), 400
    if result.get("error"):
        return jsonify({"ok": False, "error": result["error"]}), 500

    logs = result.get("logs", [])
    base_name = f"bot_engine_logs_{connection_id}_{len(logs)}_rows"

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


@app.route("/api/bot-engine/analyse", methods=["POST"])
def api_bot_engine_analyse():
    """Analyse bot engine logs using Claude and return a summary of issues."""
    data = request.get_json() or {}
    logs = data.get("logs")
    if not logs or not isinstance(logs, list):
        return jsonify({"ok": False, "error": "logs array is required"}), 400

    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        return jsonify({"ok": False, "error": "ANTHROPIC_API_KEY not configured. Add it to .env"}), 400

    try:
        import anthropic
    except ImportError:
        return jsonify({"ok": False, "error": "anthropic package not installed (pip install anthropic)"}), 500

    log_lines = []
    for i, log in enumerate(logs[:200], 1):
        parts = [f"[{i}]", log.get("timestamp", "")]
        if log.get("level"):
            parts.append(f"level={log['level']}")
        if log.get("api_name"):
            parts.append(f"api={log['api_name']}")
        if log.get("method_name"):
            parts.append(f"method={log['method_name']}")
        if log.get("error_code"):
            parts.append(f"error_code={log['error_code']}")
        if log.get("error_message"):
            parts.append(f"error_msg={log['error_message']}")
        if log.get("message"):
            parts.append(f"msg={log['message']}")
        log_lines.append(" | ".join(parts))

    prompt_data = (
        f"Connection ID: {logs[0].get('connection_id', 'unknown')}\n"
        f"Tenant: {logs[0].get('tenant_name', 'unknown')}\n"
        f"Total logs: {len(logs)}\n"
        f"Time range: {logs[0].get('timestamp', '?')} to {logs[-1].get('timestamp', '?')}\n\n"
        "=== LOG ENTRIES ===\n" + "\n".join(log_lines)
    )

    system_prompt = (
        "You are a senior Bot Engine engineer analysing a sequence of log entries "
        "for a single customer connection (voice/chat session). Your job is to determine "
        "if the session completed successfully or if something went wrong.\n\n"
        "Analyse the log entries and produce a clear report with these sections:\n\n"
        "**Session Overview**: Summarise the session — tenant, connection ID, how many API calls, "
        "time span, and the overall flow (e.g. session create -> auth -> account lookup -> transfer).\n\n"
        "**Issues Found**: List any errors, failures, or anomalies. For each issue, state:\n"
        "  - Which API call / log entry it occurred in\n"
        "  - The error code and message\n"
        "  - The likely impact on the customer experience\n"
        "If no issues are found, say 'No issues detected — session completed successfully.'\n\n"
        "**Flow Analysis**: Was the API call sequence logical and complete? "
        "Were there unexpected repeated calls, missing steps, or unusual timing gaps?\n\n"
        "**Verdict**: One sentence — did this session succeed or fail, and why?\n\n"
        "Rules:\n"
        "- Use the exact timestamps, API names, error codes, and messages from the logs.\n"
        "- Keep each section to 2-4 sentences.\n"
        "- Do NOT use markdown headers (##). Use **Bold** labels only.\n"
        "- Do NOT add disclaimers about being an AI."
    )

    try:
        model = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514").strip()
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model=model,
            system=system_prompt,
            messages=[{"role": "user", "content": prompt_data}],
            temperature=0.3,
            max_tokens=1500,
        )
        analysis = response.content[0].text.strip()
        return jsonify({"ok": True, "analysis": analysis})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500


@app.route("/api/download/error-logs", methods=["POST"])
def api_download_error_logs():
    """Fetch all matching error logs from OpenSearch, enrich with connection_id from conversation logs, and return as CSV."""
    import csv
    import io
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

    tenant_filter = data.get("tenant_filter") or None
    result = query_all_error_logs(error_codes=codes or None, time_minutes=time_minutes, tenant_filter=tenant_filter)
    if result is None:
        return jsonify({"ok": False, "error": "OpenSearch not configured"}), 400
    if result.get("error"):
        return jsonify({"ok": False, "error": result["error"]}), 500

    logs = result.get("logs", [])

    # Look up connection.id from conversation logs for each request_id
    req_ids = [log.get("request_id", "") for log in logs if log.get("request_id")]
    conn_id_map = lookup_connection_ids(req_ids) if req_ids else {}

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

    csv_content = buf.getvalue()
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=opensearch_error_logs_{len(logs)}_rows.csv"},
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
