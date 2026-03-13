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
    """Pull numeric error codes (4-5 digit numbers) from message text."""
    candidates = re.findall(r"\b(\d{4,5})\b", text)
    return [int(c) for c in candidates]


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

    error_codes = _extract_error_codes(text)
    time_minutes = int(os.environ.get("SLACK_ALERT_TIME_MINUTES", "15"))

    print(f"  [slack_listener] Alert detected in source channel, running RCA (codes={error_codes}, window={time_minutes}m)")

    try:
        from alert_engine import run
        config_path = Path(__file__).resolve().parent / "stream_server_alerts.yaml"
        ctx: dict[str, Any] = {
            "_error_codes": error_codes,
            "_time_minutes": time_minutes,
        }
        result = run(config_path, error_codes, initial_context=ctx, quiet=True)
        out_context = result.get("context") or {}
        rca = out_context.get("rca")

        if rca:
            from slack_notifier import post_rca_to_thread
            post_rca_to_thread(
                rca_data=rca,
                channel_id=source_channel,
                thread_ts=alert_ts,
                time_minutes=time_minutes,
            )
            print(f"  [slack_listener] RCA posted as thread reply under {alert_ts}")
        else:
            print(f"  [slack_listener] No RCA generated for alert")
    except Exception as e:
        print(f"  [slack_listener] Error running RCA: {e}")


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
            try:
                auth = web_client.auth_test()
                bot_user_id = auth.get("user_id", "")
            except Exception:
                pass

            def _handler(client: SocketModeClient, req: SocketModeRequest):
                # Always acknowledge
                client.send_socket_mode_response(SocketModeResponse(envelope_id=req.envelope_id))

                if req.type != "events_api":
                    return

                event = (req.payload or {}).get("event", {})
                etype = event.get("type", "")
                subtype = event.get("subtype", "")
                echannel = event.get("channel", "")
                print(f"  [slack_listener] Event: type={etype} subtype={subtype} channel={echannel}")

                if etype != "message":
                    return
                # Skip subtypes except bot_message (alert bots like Datadog)
                if subtype and subtype != "bot_message":
                    return
                # Skip messages from this bot
                if bot_user_id and event.get("user") == bot_user_id:
                    return
                if event.get("bot_id") and event.get("username") == "stream_server_alerts_":
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
