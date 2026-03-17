"""
Slack integration for Stream Server Alerts.

Posts RCA results to a Slack channel using Block Kit formatting,
and verifies incoming Slack slash-command requests.

Configure via environment:
  SLACK_BOT_TOKEN      - Bot User OAuth Token (xoxb-...)
  SLACK_SIGNING_SECRET - Slack app signing secret
  SLACK_CHANNEL        - Channel to post to (e.g. #stream-server-alerts)
  SLACK_ENABLED        - Set to "true" to enable auto-posting
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def _session() -> requests.Session:
    """Return a requests Session with automatic retries for transient errors."""
    s = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s


def _get_token() -> str:
    return os.environ.get("SLACK_BOT_TOKEN", "").strip()


def _get_channel() -> str:
    return os.environ.get("SLACK_CHANNEL", "").strip()


def _get_signing_secret() -> str:
    return os.environ.get("SLACK_SIGNING_SECRET", "").strip()


def is_enabled() -> bool:
    return os.environ.get("SLACK_ENABLED", "").strip().lower() == "true"


def check_connection() -> dict[str, Any]:
    """Verify Slack bot token is valid by calling auth.test."""
    token = _get_token()
    if not token:
        return {"connected": False, "error": "SLACK_BOT_TOKEN not set"}
    try:
        resp = _session().post(
            "https://slack.com/api/auth.test",
            headers={"Authorization": f"Bearer {token}"},
            timeout=30,
        )
        data = resp.json()
        if data.get("ok"):
            return {
                "connected": True,
                "team": data.get("team", ""),
                "user": data.get("user", ""),
                "bot_id": data.get("bot_id", ""),
            }
        return {"connected": False, "error": data.get("error", "unknown")}
    except Exception as e:
        return {"connected": False, "error": str(e)}


def verify_signature(timestamp: str, body: str, signature: str) -> bool:
    """Verify an incoming Slack request signature."""
    secret = _get_signing_secret()
    if not secret:
        return False
    if abs(time.time() - float(timestamp)) > 300:
        return False
    sig_basestring = f"v0:{timestamp}:{body}"
    computed = "v0=" + hmac.new(
        secret.encode(), sig_basestring.encode(), hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(computed, signature)


def _truncate(text: str, max_len: int = 2900) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _build_blocks(rca: dict[str, Any], time_minutes: int = 15) -> tuple[list[dict], list[str]]:
    """Build Slack Block Kit blocks from RCA data. Returns (blocks, critical_tenant_names)."""
    blocks: list[dict] = []

    total_errors = rca.get("total_errors", 0)
    top_tenants = rca.get("top_tenants") or []
    tenant_count = len(top_tenants)
    restart_detected = rca.get("restart_detected", False)

    from datetime import datetime, timezone, timedelta
    ist = timezone(timedelta(hours=5, minutes=30))
    report_time = datetime.now(ist).strftime("%b %d, %Y %I:%M %p IST")

    # Build time window display: show actual range when available, else "X min"
    time_from = rca.get("time_from")
    time_to = rca.get("time_to")
    if time_from and time_to:
        try:
            fmt = "%Y-%m-%dT%H:%M:%S.%fZ"
            t_from = datetime.strptime(time_from, fmt).replace(tzinfo=timezone.utc).astimezone(ist)
            t_to = datetime.strptime(time_to, fmt).replace(tzinfo=timezone.utc).astimezone(ist)
            time_display = f"{t_from.strftime('%I:%M %p')} – {t_to.strftime('%I:%M %p IST')} ({time_minutes} min)"
        except (ValueError, TypeError):
            time_display = f"{time_minutes} min"
    else:
        time_display = f"{time_minutes} min"

    # Header
    blocks.append({
        "type": "header",
        "text": {"type": "plain_text", "text": "Stream Server Alert — RCA Report"}
    })

    # Summary
    restart_text = "Yes" if restart_detected else "No"
    blocks.append({
        "type": "section",
        "text": {"type": "mrkdwn", "text": (
            f"*Total Errors:* {total_errors}  |  "
            f"*Time Window:* {time_display}  |  "
            f"*Tenants:* {tenant_count}  |  "
            f"*Pod Restarts:* {restart_text}\n"
            f"_{report_time}_"
        )}
    })

    blocks.append({"type": "divider"})

    # AI Summary
    ai_summary = rca.get("ai_summary", "")
    if ai_summary:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Summary*\n{_truncate(ai_summary)}"}
        })
        blocks.append({"type": "divider"})

    # Top 3 impacted tenants (display) + check ALL tenants for critical threshold
    error_threshold = int(os.environ.get("SLACK_ERROR_THRESHOLD", "30"))
    critical_tenants = []
    for t in top_tenants:
        if t.get("total_errors", 0) >= error_threshold:
            critical_tenants.append(t.get("tenant_name", "-"))

    if top_tenants:
        tenant_lines = []
        for t in top_tenants[:3]:
            name = t.get("tenant_name", "-")
            errs = t.get("total_errors", 0)
            tw_errs = t.get("twilio_error_count", 0)

            restart_count = t.get("restart_count", 0)
            if restart_count > 0:
                pods = t.get("restart_pods") or []
                pod_names = ", ".join(p.get("name", "?") for p in pods[:2])
                restart_status = f"Yes ({restart_count} pod{'s' if restart_count > 1 else ''}: {pod_names})"
            else:
                restart_status = "No"

            alert_marker = ""
            if errs >= error_threshold:
                alert_marker = "  :rotating_light: *CRITICAL*"

            tenant_lines.append(
                f"*{name}*{alert_marker}\n"
                f"    Errors: {errs}  |  Twilio errors: {tw_errs}\n"
                f"    Bot engine restarts: {restart_status}"
            )

        bot_analysis = rca.get("bot_engine_analysis", "")
        if bot_analysis:
            tenant_lines.append(f"\n*Bot engine analysis:* {_truncate(bot_analysis, 500)}")

        if tenant_count > 3:
            tenant_lines.append(f"_{tenant_count - 3} more in the detailed report_")

        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "*Top Impacted Tenants*\n" + "\n\n".join(tenant_lines)}
        })
        blocks.append({"type": "divider"})

    # --- Error Pattern Analysis ---
    patterns = rca.get("error_patterns") or {}
    if patterns.get("total_analyzed"):
        _append_pattern_blocks(blocks, patterns)

    # Footer with agent link (pass time window so the dashboard mirrors the same range)
    agent_url = os.environ.get("SLACK_AGENT_URL", "http://127.0.0.1:5000")
    separator = "&" if "?" in agent_url else "?"
    dashboard_url = f"{agent_url}{separator}time_minutes={time_minutes}"
    blocks.append({
        "type": "context",
        "elements": [
            {"type": "mrkdwn", "text": f"Full details in the attached report  |  <{dashboard_url}|View Dashboard>  |  Stream Server Alert Engine"}
        ]
    })

    return blocks, critical_tenants


def _append_pattern_blocks(blocks: list[dict], patterns: dict[str, Any]) -> None:
    """Append Error Pattern Analysis blocks to the Slack message."""
    analyzed = patterns.get("total_analyzed", 0)

    # Root Cause Classification
    root_causes = patterns.get("root_causes") or []
    if root_causes:
        severity_icon = {"Critical": ":red_circle:", "High": ":large_orange_circle:", "Medium": ":large_yellow_circle:", "Low": ":white_circle:"}
        rc_lines = []
        for rc in root_causes[:5]:
            icon = severity_icon.get(rc["severity"], ":white_circle:")
            rc_lines.append(
                f"{icon} *{rc['category']}*  —  {rc['count']} errors ({rc['percentage']}%)"
            )
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Root Cause Analysis* ({analyzed} logs)\n" + "\n".join(rc_lines)}
        })
        blocks.append({"type": "divider"})

    # Error Code Distribution + Cross-Tenant
    cross_tenant = patterns.get("cross_tenant") or []
    if cross_tenant:
        ct_lines = []
        for c in cross_tenant:
            scope = ":warning: *SYSTEMIC*" if c.get("systemic") else "tenant-specific"
            tenants = ", ".join(c.get("tenants", [])[:5])
            extra = f" +{c['tenant_count'] - 5} more" if c.get("tenant_count", 0) > 5 else ""
            ct_lines.append(
                f"Error `{c['error_code']}`: {c['tenant_count']} tenants ({scope})\n"
                f"      _{tenants}{extra}_"
            )
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "*Error Code Distribution*\n" + "\n".join(ct_lines)}
        })

    # Top Error Messages (compact)
    top_msgs = patterns.get("top_messages") or []
    if top_msgs:
        msg_lines = []
        for m in top_msgs[:5]:
            msg_text = m["message"][:80] + ("..." if len(m["message"]) > 80 else "")
            msg_lines.append(f"`{m['count']:>3}x`  {msg_text}")
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "*Top Error Messages*\n" + "\n".join(msg_lines)}
        })

    # K8s Version Distribution (compact bar-style)
    k8s = patterns.get("k8s_versions") or []
    if k8s:
        total_k8s = sum(v["count"] for v in k8s) or 1
        ver_lines = []
        for v in k8s[:5]:
            pct = round(v["count"] * 100 / total_k8s)
            bar = "\u2588" * max(1, pct // 5)
            ver_lines.append(f"`{v['version']:<8}` {bar} {v['count']} ({pct}%)")
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "*K8s Version Distribution*\n" + "\n".join(ver_lines)}
        })

    if cross_tenant or top_msgs or k8s:
        blocks.append({"type": "divider"})

    # Connections & Correlations
    conns = patterns.get("connections") or []
    if conns:
        conn_lines = []
        for cn in conns[:3]:
            desc = _truncate(cn["description"], 200)
            conn_lines.append(f":link: *{cn['type']}*\n{desc}")
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "*Correlations*\n" + "\n\n".join(conn_lines)}
        })
        blocks.append({"type": "divider"})


def _build_rca_text(rca: dict[str, Any], time_minutes: int = 15) -> str:
    """Build a detailed plain-text RCA report for file download."""
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("  STREAM SERVER ALERT — DETAILED RCA REPORT")
    lines.append("=" * 60)
    lines.append("")

    from datetime import datetime, timezone, timedelta
    ist = timezone(timedelta(hours=5, minutes=30))
    lines.append(f"Generated : {datetime.now(ist).strftime('%Y-%m-%d %H:%M:%S IST')}")
    lines.append(f"Time window : {time_minutes} minutes")
    lines.append(f"Total errors: {rca.get('total_errors', 0)}")
    lines.append(f"Restarts    : {'Yes' if rca.get('restart_detected') else 'No'}")
    lines.append("")

    ai_summary = rca.get("ai_summary", "")
    if ai_summary:
        lines.append("-" * 60)
        lines.append("AI-POWERED RCA SUMMARY")
        lines.append("-" * 60)
        lines.append(ai_summary)
        lines.append("")

    top_tenants = rca.get("top_tenants") or []
    if top_tenants:
        lines.append("-" * 60)
        lines.append(f"IMPACTED TENANTS ({len(top_tenants)})")
        lines.append("-" * 60)
        lines.append(f"{'Tenant':<30} {'Errors':>8} {'Twilio Err':>11} {'Restarts':>10}")
        lines.append("-" * 60)
        for t in top_tenants:
            name = t.get("tenant_name", "-")
            errs = t.get("total_errors", 0)
            tw_errs = t.get("twilio_error_count", 0)
            restart = "Yes" if t.get("restart_detected") else "No"
            lines.append(f"{name:<30} {errs:>8} {tw_errs:>11} {restart:>10}")
        lines.append("")

    rca_summary = rca.get("rca_summary", "")
    if rca_summary:
        lines.append("-" * 60)
        lines.append("BOT ENGINE RESTARTS")
        lines.append("-" * 60)
        lines.append(rca_summary)
        lines.append("")

    bot_analysis = rca.get("bot_engine_analysis", "")
    if bot_analysis:
        lines.append("-" * 60)
        lines.append("BOT ENGINE ANALYSIS")
        lines.append("-" * 60)
        lines.append(bot_analysis)
        lines.append("")

    twilio_analysis = rca.get("twilio_analysis", "")
    if twilio_analysis and twilio_analysis != "Twilio not configured.":
        lines.append("-" * 60)
        lines.append("TWILIO ANALYSIS")
        lines.append("-" * 60)
        lines.append(twilio_analysis)
        lines.append("")

    details = rca.get("rca_details") or []
    if details:
        lines.append("-" * 60)
        lines.append("RCA DETAILS")
        lines.append("-" * 60)
        for d in details:
            if d.startswith("  •"):
                lines.append(f"  {d.strip()}")
            else:
                lines.append(f"  {d}")
        lines.append("")

    twilio_errors = rca.get("twilio_error_codes") or {}
    if twilio_errors:
        lines.append("-" * 60)
        lines.append("TWILIO ERROR CODES")
        lines.append("-" * 60)
        for code, count in twilio_errors.items():
            lines.append(f"  {code}: {count} calls")
        lines.append("")

    twilio_failed = rca.get("twilio_failed_list") or []
    if twilio_failed:
        lines.append("-" * 60)
        lines.append(f"TWILIO FAILED CALLS ({len(twilio_failed)})")
        lines.append("-" * 60)
        lines.append(f"{'Namespace':<25} {'Status':<15} {'Error Code':<12} {'From':<16} {'To':<16} {'Time'}")
        lines.append("-" * 100)
        for c in twilio_failed[:100]:
            lines.append(
                f"{(c.get('namespace') or '-'):<25} "
                f"{(c.get('status') or '-'):<15} "
                f"{str(c.get('error_code') or '-'):<12} "
                f"{(c.get('from') or '-'):<16} "
                f"{(c.get('to') or '-'):<16} "
                f"{c.get('start_time') or '-'}"
            )
        if len(twilio_failed) > 100:
            lines.append(f"  ... and {len(twilio_failed) - 100} more failed calls")
        lines.append("")

    # Error pattern analysis
    patterns = rca.get("error_patterns") or {}
    if patterns.get("total_analyzed"):
        lines.append("-" * 60)
        lines.append(f"ERROR PATTERN ANALYSIS ({patterns['total_analyzed']} logs analyzed)")
        lines.append("-" * 60)

        top_stacks = patterns.get("top_stacks") or []
        if top_stacks:
            lines.append("\nTop Error Stacks:")
            for s in top_stacks:
                codes = ", ".join(f"{c}({n})" for c, n in (s.get("error_codes") or {}).items())
                tenants = ", ".join(s.get("tenants", []))
                if s.get("tenant_count", 0) > 5:
                    tenants += f" +{s['tenant_count'] - 5} more"
                lines.append(f"  [{s['count']}x] {s['stack']}")
                lines.append(f"         Codes: {codes}  |  Tenants: {tenants or 'unknown'}")

        top_msgs = patterns.get("top_messages") or []
        if top_msgs:
            lines.append("\nTop Error Messages:")
            for m in top_msgs:
                lines.append(f"  [{m['count']:>4}x] {m['message']}")

        k8s = patterns.get("k8s_versions") or []
        if k8s:
            lines.append("\nK8s Version Distribution:")
            for v in k8s:
                lines.append(f"  {v['version']:<20} {v['count']} errors")

        ct = patterns.get("cross_tenant") or []
        if ct:
            lines.append("\nCross-Tenant Patterns:")
            for c in ct:
                scope = "SYSTEMIC" if c.get("systemic") else "tenant-specific"
                lines.append(f"  Error {c['error_code']}: {c['tenant_count']} tenants ({scope})")

        root_causes = patterns.get("root_causes") or []
        if root_causes:
            lines.append("")
            lines.append("-" * 60)
            lines.append("ROOT CAUSE CLASSIFICATION")
            lines.append("-" * 60)
            for rc in root_causes:
                lines.append(f"\n  [{rc['severity']}] {rc['category']}: {rc['count']} errors ({rc['percentage']}%)")
                lines.append(f"    {rc['description']}")
                lines.append(f"    Recommendation: {rc['recommendation']}")

        conns = patterns.get("connections") or []
        if conns:
            lines.append("")
            lines.append("-" * 60)
            lines.append("CONNECTIONS & CORRELATIONS")
            lines.append("-" * 60)
            for cn in conns:
                lines.append(f"\n  [{cn['type']}]")
                lines.append(f"    {cn['description']}")
                lines.append(f"    Impact: {cn['impact']}")
        lines.append("")

    lines.append("=" * 60)
    lines.append("  END OF REPORT")
    lines.append("=" * 60)
    return "\n".join(lines)


def _resolve_channel_id(token: str, channel_name: str) -> str | None:
    """Look up a channel's ID by name, paginating if needed."""
    name = channel_name.lstrip("#")
    if name.startswith("C") and name == name.upper() and len(name) >= 9:
        return name
    s = _session()
    cursor = ""
    while True:
        params: dict[str, Any] = {"types": "public_channel", "limit": 200, "exclude_archived": "true"}
        if cursor:
            params["cursor"] = cursor
        resp = s.get(
            "https://slack.com/api/conversations.list",
            headers={"Authorization": f"Bearer {token}"},
            params=params,
            timeout=30,
        )
        data = resp.json()
        if not data.get("ok"):
            return None
        for ch in data.get("channels", []):
            if ch["name"] == name:
                return ch["id"]
        cursor = data.get("response_metadata", {}).get("next_cursor", "")
        if not cursor:
            return None


def _ensure_in_channel(token: str, channel_id: str) -> bool:
    """Join a channel if not already a member."""
    try:
        resp = _session().post(
            "https://slack.com/api/conversations.join",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"channel": channel_id},
            timeout=30,
        )
        return resp.json().get("ok", False)
    except Exception:
        return False


def _upload_rca_file(
    token: str, channel_id: str, rca: dict[str, Any], time_minutes: int,
    thread_ts: str | None = None,
) -> dict[str, Any] | None:
    """Upload the detailed RCA as a downloadable text file using the new Slack files API."""
    content = _build_rca_text(rca, time_minutes).encode("utf-8")
    from datetime import datetime, timezone, timedelta
    ist = timezone(timedelta(hours=5, minutes=30))
    ts = datetime.now(ist).strftime("%Y%m%d_%H%M%S")
    filename = f"rca_report_{ts}.txt"

    s = _session()
    headers = {"Authorization": f"Bearer {token}"}

    try:
        r1 = s.get(
            "https://slack.com/api/files.getUploadURLExternal",
            headers=headers,
            params={"filename": filename, "length": len(content)},
            timeout=30,
        )
        d1 = r1.json()
        if not d1.get("ok"):
            return d1

        r2 = s.post(d1["upload_url"], data=content, headers={"Content-Type": "application/octet-stream"}, timeout=30)
        if r2.status_code != 200:
            return {"ok": False, "error": f"upload returned {r2.status_code}"}

        complete_payload: dict[str, Any] = {
            "files": [{"id": d1["file_id"], "title": f"Detailed RCA Report ({ts})"}],
            "channel_id": channel_id,
            "initial_comment": "Download the detailed RCA report below.",
        }
        if thread_ts:
            complete_payload["thread_ts"] = thread_ts

        r3 = s.post(
            "https://slack.com/api/files.completeUploadExternal",
            headers={**headers, "Content-Type": "application/json"},
            json=complete_payload,
            timeout=30,
        )
        return r3.json()
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _send_critical_alert(token: str, channel: str, critical_tenants: list[str], thread_ts: str | None = None):
    """Send a separate top-level message tagging the support team for critical tenants."""
    if not critical_tenants:
        return
    error_threshold = int(os.environ.get("SLACK_ERROR_THRESHOLD", "30"))
    tag = os.environ.get("SLACK_SUPPORT_TAG", "@support_team")
    names = ", ".join(critical_tenants)
    text = f":rotating_light: {tag} — *{names}* crossed {error_threshold} errors. Please check immediately."
    payload: dict[str, Any] = {
        "channel": channel,
        "text": text,
        "mrkdwn": True,
    }
    if thread_ts:
        payload["thread_ts"] = thread_ts
    try:
        _session().post(
            "https://slack.com/api/chat.postMessage",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=payload,
            timeout=30,
        )
    except Exception:
        pass


def post_rca_to_slack(
    rca_data: dict[str, Any],
    channel: str | None = None,
    time_minutes: int = 15,
) -> dict[str, Any]:
    """Post formatted RCA results to a Slack channel and upload detailed file."""
    token = _get_token()
    if not token:
        return {"ok": False, "error": "SLACK_BOT_TOKEN not set"}

    target = channel or _get_channel()
    if not target:
        return {"ok": False, "error": "SLACK_CHANNEL not set"}

    # Resolve channel ID and ensure bot is a member (needed for file uploads)
    channel_id = _resolve_channel_id(token, target)
    if channel_id:
        _ensure_in_channel(token, channel_id)

    blocks, critical_tenants = _build_blocks(rca_data, time_minutes)

    total_errors = rca_data.get("total_errors", 0)
    color = "#ef4444" if total_errors > 0 else "#22c55e"

    payload = {
        "channel": channel_id or target,
        "text": f"RCA Report — {total_errors} errors detected",
        "attachments": [
            {
                "color": color,
                "blocks": blocks,
            }
        ],
    }

    try:
        resp = _session().post(
            "https://slack.com/api/chat.postMessage",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=30,
        )
        data = resp.json()
        result = {"ok": data.get("ok", False), "error": data.get("error"), "ts": data.get("ts")}

        if result["ok"] and channel_id:
            _send_critical_alert(token, channel_id, critical_tenants, thread_ts=result.get("ts"))
            _upload_rca_file(token, channel_id, rca_data, time_minutes, thread_ts=result.get("ts"))

        return result
    except Exception as e:
        return {"ok": False, "error": str(e)}


def post_rca_to_thread(
    rca_data: dict[str, Any],
    channel_id: str,
    thread_ts: str,
    time_minutes: int = 15,
) -> dict[str, Any]:
    """Post RCA results as a threaded reply under an existing message."""
    token = _get_token()
    if not token:
        return {"ok": False, "error": "SLACK_BOT_TOKEN not set"}

    _ensure_in_channel(token, channel_id)

    blocks, critical_tenants = _build_blocks(rca_data, time_minutes)

    total_errors = rca_data.get("total_errors", 0)
    color = "#ef4444" if total_errors > 0 else "#22c55e"

    payload = {
        "channel": channel_id,
        "thread_ts": thread_ts,
        "text": f"RCA Report — {total_errors} errors detected",
        "attachments": [
            {
                "color": color,
                "blocks": blocks,
            }
        ],
    }

    try:
        resp = _session().post(
            "https://slack.com/api/chat.postMessage",
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=30,
        )
        data = resp.json()
        result = {"ok": data.get("ok", False), "error": data.get("error"), "ts": data.get("ts")}

        if result["ok"]:
            _send_critical_alert(token, channel_id, critical_tenants, thread_ts=thread_ts)
            _upload_rca_file(token, channel_id, rca_data, time_minutes, thread_ts=thread_ts)

        return result
    except Exception as e:
        return {"ok": False, "error": str(e)}


def post_to_response_url(response_url: str, rca_data: dict[str, Any], time_minutes: int = 15) -> bool:
    """Post RCA results back to a Slack slash-command response_url."""
    blocks, _critical = _build_blocks(rca_data, time_minutes)
    total_errors = rca_data.get("total_errors", 0)
    color = "#ef4444" if total_errors > 0 else "#22c55e"

    payload = {
        "response_type": "in_channel",
        "text": f"RCA Report — {total_errors} errors detected",
        "attachments": [{"color": color, "blocks": blocks}],
    }
    try:
        resp = _session().post(response_url, json=payload, timeout=30)
        return resp.status_code == 200
    except Exception:
        return False
