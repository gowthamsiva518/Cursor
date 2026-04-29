# Stream Server Alert Triage Agent

Automated Root Cause Analysis (RCA) engine for stream server alerts. Monitors OpenSearch error logs, correlates with Kubernetes pod restarts, Twilio call failures, and bot engine analysis — then generates AI-powered summaries and posts results to Slack in real time.

## Architecture

```
Slack Channel (alerts)
    |
    v
[Slack Listener]  <-- Socket Mode (real-time)
    |
    v
[Alert Engine]  <-- YAML-driven scenarios & decision rules
    |
    +---> OpenSearch ........... error counts, impacted tenants, log download
    +---> Kubernetes (kubectl) . bot engine pod restart detection (by age)
    +---> Twilio API ........... call logs, failed calls, subaccount analysis
    +---> OpenAI-compatible API . AI-powered RCA summary
    |
    v
[Slack Notifier]  --> RCA report + downloadable file + @support_team tagging
[Flask Web UI]    --> http://127.0.0.1:5000
```

## Features

- **OpenSearch Integration** — Query error counts by error code, tenant, and time window. Download up to 10,000 raw error logs as CSV.
- **Kubernetes Pod Monitoring** — Detect recent bot engine pod restarts using pod age within the analysis time window.
- **Twilio Call Analysis** — Parallel analysis of 100+ subaccounts. Identifies failed/busy calls, maps namespaces, and counts errors per tenant.
- **AI-Powered RCA Summary** — Uses an OpenAI-compatible Chat Completions API (configure model host in Settings) for executive summaries covering bot engine restarts, analysis, and Twilio findings.
- **Slack Integration**
  - Auto-monitors a Slack channel for alert keywords and triggers RCA automatically
  - Posts RCA as a threaded reply with Block Kit formatting
  - Uploads downloadable detailed RCA report
  - Tags `@support_team` when any tenant exceeds the error threshold (default: 30)
- **Web UI** — Interactive dashboard with tenant filter dropdown, error code selection, time window presets, and one-click Slack posting.
- **YAML-Driven Scenarios** — Configure alert scenarios, steps, and decision rules in `stream_server_alerts.yaml`.

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env with your credentials
```

Key variables:

| Variable | Description |
|---|---|
| `OPENSEARCH_URL` | OpenSearch cluster URL |
| `OPENSEARCH_INDEX` | Index pattern (e.g. `default.stream-server.*`) |
| `OPENSEARCH_USER` / `OPENSEARCH_PASSWORD` | Basic auth credentials |
| `TWILIO_ACCOUNT_SID` / `TWILIO_AUTH_TOKEN` | Twilio main account |
| `OPENAI_API_KEY` / `OPENAI_BASE_URL` / `OPENAI_MODEL` | LLM — RCA summaries, Email & ticket rephrase, and Bot Engine **Analyse Logs** (OpenAI, Groq, OpenRouter, Ollama, etc.; see `.env.example`) |
| `DATABASE_URL` or `DB_HOST` / `DB_USER` / … | Optional — **Database check** (PostgreSQL) in the assistant UI; see `.env.example` |
| `SLACK_BOT_TOKEN` | Slack bot token (`xoxb-...`) |
| `SLACK_APP_TOKEN` | Slack app-level token (`xapp-...`) for Socket Mode |
| `SLACK_CHANNEL` | Target Slack channel (e.g. `#stream-server-alerts`) |

See `.env.example` for the full list of configuration options.

### 3. Run the server

```bash
python app.py
```

The app starts on `http://127.0.0.1:5000` with:
- Web UI for manual RCA runs
- REST API endpoints
- Slack Socket Mode listener (if `SLACK_LISTENER_ENABLED=true`)

## Project Structure

```
├── app.py                    # Flask app, API endpoints, startup
├── alert_engine.py           # Core RCA engine, scenario execution, decision rules
├── opensearch_client.py      # OpenSearch queries, tenant list, error log download
├── lens_client.py            # Kubernetes pod restart detection via kubectl
├── twilio_client.py          # Twilio call log analysis, subaccount management
├── ai_summarizer.py          # OpenAI-compatible Chat Completions (RCA, rephrase, log analysis)
├── db_client.py              # PostgreSQL connectivity check for Database UI
├── slack_notifier.py         # Slack message builder, file upload, critical alerts
├── slack_listener.py         # Slack Socket Mode listener for auto-RCA
├── stream_server_alerts.yaml # Alert scenarios and decision rules config
├── templates/
│   └── index.html            # Web UI (single-page dashboard)
├── requirements.txt          # Python dependencies
├── .env.example              # Environment variable template
└── .gitignore
```

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Web UI dashboard |
| `GET` | `/api/tenants` | Fetch tenant names from OpenSearch |
| `GET` | `/api/opensearch/status` | Check OpenSearch connectivity |
| `GET` | `/api/twilio/status` | Check Twilio connectivity |
| `GET` | `/api/slack/status` | Check Slack connectivity |
| `POST` | `/api/run` | Run RCA analysis |
| `POST` | `/api/slack/send` | Manually send RCA to Slack |
| `POST` | `/api/slack/command` | Slack slash command handler (`/rca`) |
| `POST` | `/api/download/error-logs` | Download error logs as CSV |

## Slack Setup

1. Create a Slack app at [api.slack.com/apps](https://api.slack.com/apps)
2. Add the following **Bot Token Scopes**:
   - `chat:write`, `chat:write.public`
   - `files:write`
   - `channels:read`, `channels:join`, `channels:history`
   - `usergroups:read` (for `@support_team` tagging)
3. Enable **Socket Mode** and generate an app-level token (`xapp-...`)
4. Install the app to your workspace
5. Add the bot to your alert channel

## Configuration

### Alert Scenarios (`stream_server_alerts.yaml`)

Define scenarios by error code, each with a sequence of analysis steps:

```yaml
scenarios:
  - id: server_errors
    match:
      error_codes: [500, 503]
    steps:
      - check_opensearch
      - get_error_count
      - get_impacted_tenants
      - check_bot_restarts
      - check_twilio_logs
      - escalate_devops
```

### Environment Variables

- **Twilio exclusions**: `TWILIO_EXCLUDE_SUBACCOUNTS=GoAlert,TestAccount`
- **Extra Twilio accounts**: `TWILIO_EXTRA_ACCOUNTS=ACSID1:TOKEN1,ACSID2:TOKEN2`
- **K8s pod exclusions**: `K8S_EXCLUDE_PODS=bot-engine-demo-prod-0`
- **Slack alert keywords**: `SLACK_ALERT_KEYWORDS=alert,error,incident,outage`
- **Critical error threshold**: `SLACK_ERROR_THRESHOLD=30`
- **Support team tag**: `SLACK_SUPPORT_TAG=<!subteam^GROUP_ID>`

## License

Internal use only.
