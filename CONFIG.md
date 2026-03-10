# Configuration reference

What you need to run the Stream Server Alerts engine, agent, and UIs.

---

## Connect with OpenSearch

1. **Create a `.env` file** in the project root (same folder as `app.py`):
   ```bash
   copy .env.example .env
   ```
   (On macOS/Linux: `cp .env.example .env`)

2. **Edit `.env`** and set at least:
   ```
   OPENSEARCH_URL=https://app-opensearch-dev.interface.ai
   ```
   Add `OPENSEARCH_USER` and `OPENSEARCH_PASSWORD` if your cluster uses basic auth.

3. **Install dependencies** (includes `python-dotenv` and `opensearch-py`):
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the app** (Flask or CLI). The app loads `.env` automatically and connects to OpenSearch when you run a scenario:
   ```bash
   python app.py
   ```
   Open http://127.0.0.1:5000 and run with error codes (e.g. 500 503). Errors will be read from OpenSearch.

5. **Verify connection:** Open http://127.0.0.1:5000/api/opensearch/status  
   You should see `"connected": true` and the URL. If `"connected": false`, check URL, auth, and network.

   **Note:** Keep `.env` local and do not commit it (add `.env` to `.gitignore` if needed). Use `.env.example` as a template.

---

## Required (minimum to run)

| What | Required info |
|------|----------------|
| **Engine / Flask / Agent** | Nothing. Works with defaults: uses `stream_server_alerts.yaml` in the project folder and stub step data. |
| **Next.js** | Nothing. Run `npm run dev`; if Python is available it will run the agent via `agent_stdin.py`. |

So **no config is strictly required** to run the app; OpenSearch and other options are optional.

---

## OpenSearch (optional)

To **read errors directly from OpenSearch** instead of stubs:

| Variable | Required? | Description |
|----------|-----------|-------------|
| **OPENSEARCH_URL** | **Yes** (if using OpenSearch) | Base URL, e.g. `https://app-opensearch-dev.interface.ai` |
| OPENSEARCH_INDEX | No | Index pattern; default `stream-*` |
| OPENSEARCH_TIME_FIELD | No | Timestamp field; default `@timestamp` |
| OPENSEARCH_USER | support-user | Basic auth user (if your cluster requires it) |
| OPENSEARCH_PASSWORD | k9Xw!m3Zr@7vQ#pT | Basic auth password |
| OPENSEARCH_VERIFY_SSL | No | Set to `0` to disable certificate verification |

**Required for OpenSearch:** only **OPENSEARCH_URL**. The rest have defaults or are only needed when your cluster uses auth or different index/field names.

**Expected index fields:** `error_code`, `tenant_name` (or `tenant_name.keyword`), and the time field above. Sample errors also use `message` / `error` / `error_message` if present.

---

## Next.js → Flask (optional)

When running the **Next.js** UI but you want the **agent** to be run by **Flask** (instead of Next.js spawning Python):

| Variable | Required? | Description |
|----------|-----------|-------------|
| **AGENT_API_URL** | No | Flask base URL, e.g. `http://127.0.0.1:5000`. If set, Next.js proxies `POST /api/agent/run` to Flask. |

Set this only if you run Flask separately and want Next.js to call it.

---

## YAML config (`stream_server_alerts.yaml`)

This file is **required** in the project root for the engine/agent to run. It defines:

| Section | Purpose |
|---------|---------|
| **scenarios** | List of scenarios, each with `id`, `match.error_codes`, and `steps` (step IDs). |
| **decision_rules** | List of rules: `if` (condition string), `conclusion`, `next_action`. |

No other YAML config is required. Steps and action handlers are implemented in code; the YAML only references them by name.

---

## Summary

- **Minimum:** No env vars. Ensure `stream_server_alerts.yaml` exists and run from the project folder.
- **OpenSearch:** Set **OPENSEARCH_URL** (and optionally index, time field, auth, SSL).
- **Next.js + Flask:** Set **AGENT_API_URL** if you want Next.js to call Flask for the agent.
