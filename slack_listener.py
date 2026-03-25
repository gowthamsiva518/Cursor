"""
Slack Socket Mode listener for automatic RCA on alert messages.

Monitors SLACK_LISTEN_CHANNEL (e.g. #stream-prod-alerts) for messages
containing alert keywords, runs the alert engine, and posts the RCA
to SLACK_CHANNEL (e.g. #stream-server-alerts-triage-agent).

Configure via environment:
  SLACK_APP_TOKEN          - App-level token (xapp-...) for Socket Mode
  SLACK_BOT_TOKEN          - Bot token (xoxb-...) for posting replies
  SLACK_LISTENER_ENABLED   - Set to "true" to enable
  SLACK_ALERT_KEYWORDS     - Comma-separated trigger words (optional override)
  SLACK_LISTEN_CHANNEL     - Channel to monitor for alerts (source)
  SLACK_CHANNEL            - Channel to post RCA reports (destination)
"""

from __future__ import annotations

import os
import re
import threading
import time
from pathlib import Path
from typing import Any

import logging

_log = logging.getLogger("slack_listener")
if not _log.handlers:
    _fh = logging.FileHandler(Path(__file__).resolve().parent / "slack_listener.log", encoding="utf-8")
    _fh.setFormatter(logging.Formatter("%(asctime)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
    _log.addHandler(_fh)
    _log.setLevel(logging.DEBUG)

_processed_lock = threading.Lock()
_processed_ts: dict[str, float] = {}
_DEDUP_TTL = 300  # ignore duplicate ts within 5 minutes

DEFAULT_KEYWORDS = {"alert", "error", "incident", "outage", "failure", "down"}


def _get_keywords() -> set[str]:
    raw = os.environ.get("SLACK_ALERT_KEYWORDS", "").strip()
    if raw:
        return {w.strip().lower() for w in raw.split(",") if w.strip()}
    return DEFAULT_KEYWORDS


def _should_trigger(text: str) -> bool:
    """Return True if the message text contains any alert keyword."""
    text_lower = text.lower()
    return any(kw in text_lower for kw in _get_keywords())


def _extract_error_codes(text: str) -> list[int]:
    """Pull HTTP error codes (3-digit, 400-599) from message text.

    Only extracts codes that look like real HTTP status codes to avoid
    picking up noise (years, port numbers, URL fragments, error counts like
    "441 errors in the last 30 minutes", etc.).
    """
    # Strip monitor count patterns ("N errors in the last M min") so the
    # count isn't mistaken for an HTTP code (e.g. "441 errors" → 441 ≠ HTTP 441)
    cleaned = re.sub(r"\b\d+\s+errors?\s+in\s+the\s+last\b", "", text, flags=re.IGNORECASE)
    candidates = re.findall(r"\b([45]\d{2})\b", cleaned)
    seen: set[int] = set()
    codes: list[int] = []
    for c in candidates:
        val = int(c)
        if 400 <= val <= 599 and val not in seen:
            seen.add(val)
            codes.append(val)
    return codes


def _extract_trigger_count(text: str) -> int | None:
    """Extract the monitor's reported error count from 'N errors in the last M minutes'."""
    m = re.search(r"(\d+)\s+errors?\s+in\s+the\s+last\s+\d+\s+min", text, re.IGNORECASE)
    return int(m.group(1)) if m else None


def _extract_dashboard_time_range(text: str) -> dict[str, Any] | None:
    """Extract the absolute time range from alert text.

    Parses ``time:(from:'<ISO>',to:'<ISO>')`` from OpenSearch URLs, or
    falls back to ``Period start`` / ``Period end`` lines.

    Returns ``{"time_from": <ISO>, "time_to": <ISO>, "time_minutes": <int>}``
    or None when no time range can be determined.
    """
    from datetime import datetime, timezone
    import math

    # Try OpenSearch URL pattern first (most precise)
    m = re.search(r"time:\(from:'([^']+)',\s*to:'([^']+)'\)", text)
    if not m:
        m_start = re.search(r"Period start:\s*(\d{4}-\d{2}-\d{2}T[\d:.]+Z)", text)
        m_end = re.search(r"Period end:\s*(\d{4}-\d{2}-\d{2}T[\d:.]+Z)", text)
        if m_start and m_end:
            from_str, to_str = m_start.group(1), m_end.group(1)
        else:
            return None
    else:
        from_str, to_str = m.group(1), m.group(2)

    try:
        fmt = "%Y-%m-%dT%H:%M:%S.%fZ"
        t_from = datetime.strptime(from_str, fmt).replace(tzinfo=timezone.utc)
        t_to = datetime.strptime(to_str, fmt).replace(tzinfo=timezone.utc)
        delta = (t_to - t_from).total_seconds() / 60.0
        mins = max(1, min(43200, math.ceil(delta)))
        return {
            "time_from": from_str,
            "time_to": to_str,
            "time_minutes": mins,
        }
    except (ValueError, OverflowError):
        return None


def _is_duplicate(ts: str) -> bool:
    """Check and register message ts for deduplication."""
    now = time.time()
    with _processed_lock:
        # Prune old entries
        expired = [k for k, v in _processed_ts.items() if now - v > _DEDUP_TTL]
        for k in expired:
            del _processed_ts[k]
        if ts in _processed_ts:
            return True
        _processed_ts[ts] = now
        return False


def _resolve_channel(env_key: str) -> str:
    """Resolve a channel's ID from an environment variable."""
    from slack_notifier import _get_token, _resolve_channel_id
    token = _get_token()
    channel = os.environ.get(env_key, "").strip()
    if not token or not channel:
        return ""
    return _resolve_channel_id(token, channel) or ""


def _handle_alert(event: dict[str, Any], dest_channel_id: str) -> None:
    """Run RCA and post results to the destination channel (with link to source alert)."""
    text = event.get("text", "")
    source_channel = event.get("channel", "")
    alert_ts = event.get("ts", "")

    if not alert_ts:
        return

    _log.info("--- ALERT START (ts=%s) ---", alert_ts)
    _log.info("Message text (first 500 chars): %s", text[:500])

    error_codes = _extract_error_codes(text)
    _log.info("Extracted error_codes: %s", error_codes)

    trigger_count = _extract_trigger_count(text)
    _log.info("Monitor reported error count: %s", trigger_count)

    dashboard = _extract_dashboard_time_range(text)
    default_minutes = int(os.environ.get("SLACK_ALERT_TIME_MINUTES", "15"))

    if dashboard:
        time_minutes = dashboard["time_minutes"]
        time_from = dashboard["time_from"]
        time_to = dashboard["time_to"]
        _log.info("Using dashboard range: %s -> %s (%dm)", time_from, time_to, time_minutes)
    else:
        time_minutes = default_minutes
        time_from = None
        time_to = None
        _log.info("No dashboard range found, using default window: %dm", time_minutes)

    _log.info("Running RCA (codes=%s, window=%dm, time_from=%s, time_to=%s)",
              error_codes, time_minutes, time_from, time_to)

    try:
        from alert_engine import run
        config_path = Path(__file__).resolve().parent / "stream_server_alerts.yaml"
        ctx: dict[str, Any] = {
            "_error_codes": error_codes,
            "_time_minutes": time_minutes,
        }
        if time_from and time_to:
            ctx["_time_from"] = time_from
            ctx["_time_to"] = time_to
        if trigger_count is not None:
            ctx["_monitor_error_count"] = trigger_count

        _log.info("Calling run() with ctx=%s", {k: v for k, v in ctx.items()})
        result = run(config_path, error_codes, initial_context=ctx, quiet=True)
        out_context = result.get("context") or {}
        rca = out_context.get("rca")

        _log.info("RCA result: total_errors=%s, tenants=%s, opensearch_total=%s, opensearch_available=%s",
                   rca.get("total_errors") if rca else "NO_RCA",
                   len(rca.get("top_tenants", [])) if rca else 0,
                   out_context.get("opensearch_total"),
                   out_context.get("opensearch_available"))
        if out_context.get("opensearch_error"):
            _log.warning("OpenSearch error: %s", out_context["opensearch_error"])

        if rca:
            from slack_notifier import post_rca_to_thread
            post_rca_to_thread(
                rca_data=rca,
                channel_id=source_channel,
                thread_ts=alert_ts,
                time_minutes=time_minutes,
            )
            _log.info("RCA posted as thread reply under %s", alert_ts)
        else:
            _log.warning("No RCA generated for alert")
    except Exception as e:
        _log.exception("Error running RCA: %s", e)
    _log.info("--- ALERT END (ts=%s) ---", alert_ts)


def start_listener() -> threading.Thread | None:
    """
    Start the Socket Mode listener in a background daemon thread.
    Returns the thread, or None if not configured.
    """
    app_token = os.environ.get("SLACK_APP_TOKEN", "").strip()
    bot_token = os.environ.get("SLACK_BOT_TOKEN", "").strip()

    if not app_token:
        print("  [slack_listener] SLACK_APP_TOKEN not set, listener disabled")
        return None
    if not bot_token:
        print("  [slack_listener] SLACK_BOT_TOKEN not set, listener disabled")
        return None

    listen_channel_id = _resolve_channel("SLACK_LISTEN_CHANNEL") or _resolve_channel("SLACK_CHANNEL")
    dest_channel_id = _resolve_channel("SLACK_CHANNEL")

    if not listen_channel_id:
        print("  [slack_listener] Could not resolve listen channel, listener disabled")
        return None
    if not dest_channel_id:
        print("  [slack_listener] Could not resolve SLACK_CHANNEL (destination), listener disabled")
        return None

    # Ensure bot is a member of both channels
    from slack_notifier import _get_token, _ensure_in_channel
    token = _get_token()
    if token:
        _ensure_in_channel(token, listen_channel_id)
        _ensure_in_channel(token, dest_channel_id)

    if listen_channel_id == dest_channel_id:
        print(f"  [slack_listener] Monitoring & posting to channel {listen_channel_id}")
    else:
        print(f"  [slack_listener] Monitoring {listen_channel_id} -> posting RCA to {dest_channel_id}")

    def _run():
        try:
            from slack_sdk.socket_mode import SocketModeClient
            from slack_sdk.socket_mode.request import SocketModeRequest
            from slack_sdk.socket_mode.response import SocketModeResponse
            from slack_sdk.web import WebClient

            web_client = WebClient(token=bot_token)
            sm_client = SocketModeClient(
                app_token=app_token,
                web_client=web_client,
            )

            bot_user_id = ""
            _own_bot_id = ""
            try:
                auth = web_client.auth_test()
                bot_user_id = auth.get("user_id", "")
                _own_bot_id = auth.get("bot_id", "")
                _log.info("Bot identity: user_id=%s, bot_id=%s", bot_user_id, _own_bot_id)
            except Exception as e:
                _log.warning("auth_test failed: %s", e)

            def _handler(client: SocketModeClient, req: SocketModeRequest):
                # Always acknowledge
                client.send_socket_mode_response(SocketModeResponse(envelope_id=req.envelope_id))

                if req.type != "events_api":
                    return

                event = (req.payload or {}).get("event", {})
                etype = event.get("type", "")
                subtype = event.get("subtype", "")
                echannel = event.get("channel", "")
                _log.debug("Event: type=%s subtype=%s channel=%s user=%s bot_id=%s",
                           etype, subtype, echannel, event.get("user", ""), event.get("bot_id", ""))

                if etype != "message":
                    return
                # Skip subtypes except bot_message (alert bots like Datadog)
                if subtype and subtype != "bot_message":
                    return
                # Skip messages from this bot (check user_id and bot_id)
                if bot_user_id and event.get("user") == bot_user_id:
                    _log.debug("Skipping own message (user_id match)")
                    return
                msg_bot_id = event.get("bot_id", "")
                if msg_bot_id and msg_bot_id == _own_bot_id:
                    _log.debug("Skipping own message (bot_id match: %s)", msg_bot_id)
                    return
                # Only monitor the listen channel
                if echannel != listen_channel_id:
                    return

                text = event.get("text", "")
                if not _should_trigger(text):
                    return

                msg_ts = event.get("ts", "")
                if _is_duplicate(msg_ts):
                    return

                # Run in a separate thread to avoid blocking the socket handler
                threading.Thread(
                    target=_handle_alert, args=(event, dest_channel_id), daemon=True
                ).start()

            sm_client.socket_mode_request_listeners.append(_handler)
            sm_client.connect()

            print("  [slack_listener] Socket Mode connected, listening for alerts...")

            # Keep the thread alive
            while True:
                time.sleep(1)

        except Exception as e:
            print(f"  [slack_listener] Fatal error: {e}")

    thread = threading.Thread(target=_run, daemon=True, name="slack-listener")
    thread.start()
    return thread
