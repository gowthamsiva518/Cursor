# Stream Server Alerts – Runner / Engine

Runs the `stream_server_alerts` flow: load config, match scenario by error codes, run steps, evaluate decision rules, output **conclusion** and **next_action**.

## Setup

```bash
pip install -r requirements.txt
```

## Web application

A small web UI runs the engine from the browser:

```bash
flask --app app run
# or: python app.py
```

Then open **http://127.0.0.1:5000**. Enter error codes (e.g. `500 503` or `400`), optionally check context overrides (Calls OK, Restart detected, etc.), and click **Run** to see the scenario, conclusion, and next action.

## Usage

### CLI

```bash
# Default config: stream_server_alerts.yaml
python alert_engine.py 500 503
python alert_engine.py 400

# With context so a decision rule matches (example: 500/503 + calls OK + restart)
python alert_engine.py stream_server_alerts.yaml 500 503 --calls-ok --restart

# 500/503 + calls failing → "active production degradation"
python alert_engine.py stream_server_alerts.yaml 500 503 --calls-fail

# 400 + auth failure
python alert_engine.py stream_server_alerts.yaml 400 --auth-fail
```

**CLI context flags (set booleans for rule evaluation):**

| Flag | Context key |
|------|-------------|
| `--500-spike` | `500_or_503_spike` |
| `--400-spike` | `400_spike` |
| `--calls-ok` | `calls_connect_successfully` |
| `--calls-fail` | `calls_fail` |
| `--restart` | `restart_detected` |
| `--auth-ok` | `auth_successful` |
| `--auth-fail` | `auth_failure` |

`500_or_503_spike` / `400_spike` are set automatically from the matched scenario; override with flags if needed.

### Programmatic

```python
from alert_engine import run, load_config, STEP_REGISTRY

# Minimal: match scenario, run stub steps, evaluate rules
result = run("stream_server_alerts.yaml", [500, 503])

# With context so a rule matches
result = run("stream_server_alerts.yaml", [500, 503], initial_context={
    "calls_connect_successfully": True,
    "restart_detected": True,
})
# result["conclusion"], result["next_action"]
```

### Step implementations

Steps in `alert_engine.py` are implemented and **populate the context** so decision rules can match without CLI flags:

| Step | Sets / uses in context |
|------|-------------------------|
| `get_error_count` | `error_count` |
| `get_impacted_tenants` | `impacted_tenants` |
| `check_prod_connectivity` | `calls_connect_successfully`, `calls_fail` |
| `check_bot_restarts` | `restart_detected` |
| `validate_auth_flow` | `auth_successful`, `auth_failure` |
| Others | Log + optional context keys |

**Override for testing:** pass `simulate` in `initial_context` so steps use your values instead of defaults:

```python
result = run("stream_server_alerts.yaml", [500, 503], initial_context={
    "simulate": {
        "calls_ok": True,
        "calls_fail": False,
        "restart_detected": True,
        "auth_ok": False,
        "auth_fail": True,
    },
})
```

### Replacing with real implementations

Replace steps by assigning to `STEP_REGISTRY`; each step receives `context: dict` and can read/update it:

```python
def my_check_prod_connectivity(context):
    # ... call APIs, check logs ...
    context["calls_connect_successfully"] = True  # or False
    context["calls_fail"] = not context["calls_connect_successfully"]

from alert_engine import STEP_REGISTRY, run
STEP_REGISTRY["check_prod_connectivity"] = my_check_prod_connectivity
result = run("stream_server_alerts.yaml", [500, 503], step_registry=STEP_REGISTRY)
```

## Agent

An **agent** runs the engine and then executes pluggable **follow-up actions** based on the conclusion and next_action (e.g. escalate to DevOps, create RCA task, notify Slack). By default it runs in **dry-run** (report what would be done); use `--execute` to run handlers.

```bash
# Dry-run (planned actions only)
python agent.py stream_server_alerts.yaml 500 503
python agent.py 500 503 --calls-fail

# Execute actions (stubs log; replace with real Slack/Jira/PagerDuty)
python agent.py 500 503 --execute
```

**Programmatic:**

```python
from agent import AlertAgent, DEFAULT_ACTION_RULES

agent = AlertAgent(config_path="stream_server_alerts.yaml")
result = agent.run([500, 503], execute=False)  # dry-run
# result["conclusion"], result["next_action"], result["actions_planned"]

# With custom action rules
agent = AlertAgent(action_rules=my_rules)
result = agent.run([400], initial_context={"simulate": {"auth_fail": True}}, execute=True)
```

**Web app (Flask):** Check **Run as agent (show planned actions)** and click Run to see which actions the agent would take (or call `POST /api/agent/run` with `execute: true` to run them).

**Web app (Next.js):** A Next.js UI for the agent is in `app/`. Run it with:

```bash
npm install
npm run dev
```

Open http://localhost:3000. The page calls `POST /api/agent/run`, which either runs the Python agent via `agent_stdin.py` (requires Python + `pip install -r requirements.txt` in the same project) or proxies to Flask when `AGENT_API_URL` is set (e.g. `AGENT_API_URL=http://127.0.0.1:5000`).

**Custom actions:** Register `(name, matcher, handler)` in `DEFAULT_ACTION_RULES` or pass `action_rules` to `AlertAgent`. Matcher is `(result, context) -> bool`; handler is `(result, context) -> dict` with e.g. `message`, `ok`.

## OpenSearch

When **OpenSearch** is configured, the engine queries it for error count and impacted tenants (by `error_code` and `tenant_name`), and uses that in **get_error_count** and **get_impacted_tenants**. A dedicated step **check_opensearch** runs first in both scenarios.

**Setup:**

1. Install the client: `pip install opensearch-py` (or `pip install -r requirements.txt`).
2. Set environment variables (optional; if not set, steps use stub/demo values):

| Variable | Description |
|----------|-------------|
| `OPENSEARCH_URL` | Base URL (e.g. `https://app-opensearch-dev.interface.ai`) |
| `OPENSEARCH_INDEX` | Index pattern (default: `stream-*`) |
| `OPENSEARCH_TIME_FIELD` | Timestamp field (default: `@timestamp`) |
| `OPENSEARCH_USER` / `OPENSEARCH_PASSWORD` | Basic auth if required |
| `OPENSEARCH_VERIFY_SSL` | Set to `0` to disable certificate verification |

The client queries the last 60 minutes by default, filters by the scenario’s error codes (500/503 or 400), and aggregates by `tenant_name.keyword` (or `tenant_name`). Results are stored in context: `error_count`, `impacted_tenants`, `opensearch_total`, `opensearch_tenants`, `opensearch_available`.

## Output

- **Scenario** and each **step** are printed as they run.
- First **decision_rule** whose `if` condition is satisfied (all tokens true in context) yields **Conclusion** and **Next action**.
- `run()` returns a dict: `scenario_id`, `conclusion`, `next_action`, `context`, `matched_rule`.
