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

from flask import Flask, Response, jsonify, render_template, request

# Project root = folder containing app.py (so templates/ and stream_server_alerts.yaml are found)
PROJECT_ROOT = Path(__file__).resolve().parent
CONFIG_PATH = PROJECT_ROOT / "stream_server_alerts.yaml"

app = Flask(__name__, template_folder=str(PROJECT_ROOT / "templates"))

# Fail fast if config or templates are missing
if not CONFIG_PATH.exists():
    raise FileNotFoundError(f"Config not found: {CONFIG_PATH}. Run from project folder: {PROJECT_ROOT}")


from alert_engine import run
from agent import AlertAgent


@app.route("/")
def index():
    return render_template("index.html")


def _apply_time_minutes(ctx: dict, data: dict) -> None:
    """Set ctx['_time_minutes'] from request data (1–43200, mirrors OpenSearch Discover)."""
    val = data.get("time_minutes")
    if val is None:
        ctx["_time_minutes"] = 60
        return
    try:
        m = int(val)
        ctx["_time_minutes"] = max(1, min(43200, m))  # 1 min to 30 days (Discover range)
    except (TypeError, ValueError):
        ctx["_time_minutes"] = 60


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
        ctx = {"simulate": simulate}
    _apply_time_minutes(ctx, data)

    try:
        result = run(CONFIG_PATH, codes, initial_context=ctx, quiet=True)
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

    out_context = result.get("context") or {}
    out_context = {k: v for k, v in out_context.items() if not callable(v)}

    # Client-wise (tenant-wise) error counts for UI
    client_error_counts = _client_error_counts_from_context(out_context)

    return jsonify({
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
    })


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

    result = query_all_error_logs(error_codes=codes or None, time_minutes=time_minutes)
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
        ctx = {"simulate": simulate}
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


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  Open in browser: http://127.0.0.1:{port}\n")
    app.run(debug=True, host="0.0.0.0", port=port)
