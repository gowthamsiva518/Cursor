---
name: stream-server-default-logs
description: Guides fetching and triaging Stream Server default logs by contextId, APT identifier, and/or Connection ID (OpenSearch). Replays a single voice/chat session OR drills into one Twilio/SIP connection OR pulls every log for one APT (bot) in a time window — bot turns, caller speech, parse decisions, STT events. Use when the user mentions stream-server logs, contextId, APT identifier, connection.id, replay a call, parse / action / repeat issues, hot-key/menu misses, Speechmatics/STT events, rawLog.data.contextId, rawLog.data.action.event.client.data.name, or rawLog.data.action.event.connection.id.
---

# Stream Server Default Logs

## When to Use

Apply when debugging a **single Stream Server session** end-to-end:

- Caller said X but the bot did Y (parse / classification / hot-key issues)
- "I'm sorry…" / repeat actions, action-queue clears, missing prompts
- STT events (Speechmatics partial/final, `EndOfTranscript` timeouts, barge-in)
- Connection lifecycle (Twilio SIP open / close, websocket drops)
- Cross-correlating with Bot Engine and Integration Manager logs for the same call

## Key Links

| Resource | URL / note |
|----------|------------|
| OpenSearch Dashboards – Stream Server (Data Explorer / Discover) | `https://app-opensearch-prod.interface.ai/_dashboards/app/data-explorer/discover#?_a=(discover:(columns:!(_source),isDirty:!f,sort:!()),metadata:(indexPattern:fdf3c370-df3f-11f0-8651-09c57e0237fe,view:discover))&_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now-15m,to:now))&_q=(filters:!(),query:(language:kuery,query:''))` |
| Index pattern for this app | The Discover URL uses a **saved index-pattern id** (`fdf3c370-df3f-11f0-8651-09c57e0237fe`). For `OPENSEARCH_STREAM_SERVER_INDEX`, copy the **actual index pattern string** that index resolves to (e.g. `default.stream-server.*`) from Discover's data source selector or **Stack Management → Index patterns**, not the UUID. If unset, the agent falls back to `OPENSEARCH_INDEX` from the Stream Server Alerts agent. |

## How Logs Are Stored

- **Index:** `OPENSEARCH_STREAM_SERVER_INDEX` in `.env` (same OpenSearch cluster as Bot Engine / IM).
- **Filters:**
  - **Context ID** — `rawLog.data.contextId` (UUIDv4 — *no embedded timestamp*, so a manual time window is required). Drills into a single session.
  - **APT identifier** — `rawLog.data.action.event.client.data.name` (override with `OPENSEARCH_STREAM_SERVER_APT_FIELD`). The voice/chat APT (bot config) name. Lets you scan all sessions for one bot in a window.
  - **Connection ID** — `rawLog.data.action.event.connection.id` (override with `OPENSEARCH_STREAM_SERVER_CONNECTION_FIELD`). The Twilio/SIP connection identifier. Drills into one connection (1:1 with a Twilio call leg, often shared across the whole session).
  - At least one of the three is required. Combine any subset to narrow further (e.g. APT + time-window, or Context ID + Connection ID for a sanity check).
- **Per-document fields:**
  - `@timestamp`, `level` (pino: 30 info, 40 warn, 50 error)
  - `msg` — short event tag, e.g. `Parse: Final voice input`, `Bot-engine action start`, `Output start`, `Actions queued`
  - `rawLog.moduleName` — e.g. `stream-server`, `bot-engine`, `@payjo/stt-speechmatics`, `parse`
  - `rawLog.data.action.{type,subtype}` and `rawLog.data.action.action.data.text` — bot actions (`io/voice`, `io/gather`, `io/parse`, `channel/transfer`, `repeat`)
  - `rawLog.data.action.event.client.data.name` — APT identifier (the bot/client this session is running)
  - `rawLog.data.action.event.connection.id` — Twilio/SIP connection identifier
  - `rawLog.data.data.text` / `.utterance` — caller speech (final / partial)
  - `rawLog.data.error.{name,message,stack}` — error fields
  - `rawLog.data.requestId`, `rawLog.tenantName` — correlation / tenancy
- Logs are routinely duplicated by Fluent Bit / OpenSearch replicas. The agent de-dupes on `(timestamp, msg, requestId|contextId)` before display.

## Workflow

1. Get **contextId** (single-session), **APT identifier** (bot name), and/or **Connection ID** (Twilio/SIP leg) from Stream Server Alerts (`Download JSON`), Bot Engine logs, Twilio call metadata, or the customer ticket.
2. In **Gowtham's Assistant**: open **Log analyser → Stream Server** (`#log-analyser/stream-server` or legacy `#stream-server-logs`).
3. Paste any one (or any combination) of Context ID / APT identifier / Connection ID. Pick the **time window** the call(s) happened in (default: All time → last 30 days), then **Fetch Logs**.
   - Context ID alone → one session replay.
   - Connection ID alone → all logs tied to a single Twilio/SIP connection (typically also one session).
   - APT alone → every session for that bot in the window. Use a tight window — APTs can produce hundreds of sessions/hr.
   - Combinations → scope further (e.g. APT + Connection ID is a great sanity check).
4. Scan the table — `Module`, `Action`, **APT**, and the **caller / bot text** column reconstruct the conversation. Errors are highlighted in red.
5. **Download JSON** for RCA handoff (preserves full `_raw`); **Download Table (CSV)** for spreadsheets.
6. **Analyse Logs** to get a structured AI write-up: Session Overview → Issues Found → Timeline → Root Cause → Verdict. Tuned to flag low-confidence parses, repeat/apology cycles, hot-key/synonym misses, STT timeouts, and barge-in. When multiple sessions are returned (APT-only fetch), findings are grouped by contextId.
7. Cross-reference:
   - **Bot Engine Default Logs** by Connection ID — for the action-queue / decision side.
   - **Integration Manager Default Logs** by Connection ID — for any auth/core/mesh failure that fed bad data to Stream Server.

## Common Patterns to Spot

| Symptom | What to look for in the table |
|---------|--------------------------------|
| Wrong action after a clean utterance | `Parse: Final voice input` (caller text) → next `Bot-engine action start` with mismatched `action.subtype`; check the immediately preceding `Actions queued` for the active hot-key set. |
| "I'm sorry, I had a slight problem…" | A `repeat` action right after a clear cancels 5–7 queued actions. Usually low-confidence STT result OR a phrase that's not in the menu's hot-keys / synonyms. |
| Long silence then `EndOfTranscript` | Speechmatics module logs `connection closed` / partial → final timeout. Often paired with caller-side network or barge-in. |
| Action picked but caller said something else | Check `meta.source` on the parse: `function_initial` = global intent classifier; `function` = scoped slot validator inside a menu. The validator is the usual culprit. |

## RCA Handoff Template

Include: contextId, tenant, time window, what the caller said (quoted), what the bot did (action.type/subtype with text), the failing parse / action node, and the suspected cause (low-confidence classification, missing menu synonym, hot-key gap, STT timeout, TTS/SSML failure, etc.).

## Automation

- Backend: `query_stream_server_default_logs` and `_flatten_stream_server_log` in `opensearch_client.py`.
- HTTP routes: `/api/stream-server-logs/status`, `/api/stream-server-logs/logs`, `/api/download/stream-server-logs`, `/api/stream-server-logs/analyse` in `app.py`.
- UI: `streamServerLogsView` in `templates/index.html` (hash route `#stream-server-logs`).
