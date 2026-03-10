"""
Run the alert agent with JSON input on stdin and write JSON result to stdout.
Used by Next.js API route to invoke the agent.

Usage: echo '{"error_codes":[500,503],"context":{},"execute":false}' | python agent_stdin.py

Loads .env from current directory so OPENSEARCH_* are set when connecting to OpenSearch.
"""

import json
import sys
from pathlib import Path

# Load .env so OpenSearch connection uses OPENSEARCH_URL etc.
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent / ".env")
except ImportError:
    pass

# Run from project root (where stream_server_alerts.yaml lives)
if __name__ == "__main__":
    try:
        raw = sys.stdin.read()
        data = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError as e:
        json.dump({"ok": False, "error": f"Invalid JSON: {e}"}, sys.stdout)
        sys.exit(0)

    error_codes = data.get("error_codes") or []
    if not error_codes:
        json.dump({"ok": False, "error": "error_codes required"}, sys.stdout)
        sys.exit(0)

    ctx = data.get("context") or {}
    simulate = {}
    if ctx.get("calls_ok") is True:
        simulate["calls_ok"], simulate["calls_fail"] = True, False
    if ctx.get("calls_fail") is True:
        simulate["calls_fail"], simulate["calls_ok"] = True, False
    if ctx.get("restart_detected") is True:
        simulate["restart_detected"] = True
    if ctx.get("auth_ok") is True:
        simulate["auth_ok"], simulate["auth_fail"] = True, False
    if ctx.get("auth_fail") is True:
        simulate["auth_fail"], simulate["auth_ok"] = True, False
    if simulate:
        ctx = {"simulate": simulate}
    else:
        ctx = {}
    # Time window for OpenSearch (minutes, 1–43200, mirrors Discover)
    try:
        m = int(data.get("time_minutes", 60))
        ctx["_time_minutes"] = max(1, min(43200, m))
    except (TypeError, ValueError):
        ctx["_time_minutes"] = 60

    execute = data.get("execute") is True
    config_path = data.get("config_path") or str(Path(__file__).resolve().parent / "stream_server_alerts.yaml")

    try:
        from agent import AlertAgent

        agent = AlertAgent(config_path=config_path)
        result = agent.run(error_codes, initial_context=ctx or None, execute=execute, quiet=True)
    except Exception as e:
        json.dump({"ok": False, "error": str(e)}, sys.stdout)
        sys.exit(0)

    # Serialize for JSON (drop callables from context)
    out_ctx = result.get("context") or {}
    out_ctx = {k: v for k, v in out_ctx.items() if not callable(v)}

    actions = result.get("actions_taken") or result.get("actions_planned") or []
    actions_ser = []
    for a in actions:
        entry = {"name": a.get("name"), "executed": a.get("executed", False)}
        if a.get("outcome"):
            entry["outcome"] = a["outcome"]
        if a.get("would_do"):
            entry["would_do"] = a["would_do"]
        if a.get("error"):
            entry["error"] = a["error"]
        actions_ser.append(entry)

    out = {
        "ok": True,
        "scenario_id": result.get("scenario_id"),
        "conclusion": result.get("conclusion"),
        "next_action": result.get("next_action"),
        "matched_rule": result.get("matched_rule", False),
        "error": result.get("error"),
        "context": out_ctx,
        "execute": execute,
        "actions": actions_ser,
    }
    json.dump(out, sys.stdout)
