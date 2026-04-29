---
name: integration-manager-logs
description: Guides fetching and triaging Integration Manager default logs by connectionId (OpenSearch, auth/mesh/core flows). Use when the user mentions Integration Manager logs, IM logs, APT/integration auth debugging, or rawLog.context.metadata.connectionId.
---

# Integration Manager Default Logs

## When to Use

Apply when debugging **Integration Manager** behaviour for a session: authentication, Symitar/core calls, mesh errors, or correlating with Bot Engine and Stream Server.

## Key Links

| Resource | URL / note |
|----------|------------|
| OpenSearch Dashboards – IM (Data Explorer / Discover) | `https://app-opensearch-prod.interface.ai/_dashboards/app/data-explorer/discover#?_a=(discover:(columns:!(_source),isDirty:!f,sort:!()),metadata:(indexPattern:a6cffd50-d18c-11ef-ae32-6f5eb69dfd82,view:discover))&_g=(filters:!(),refreshInterval:(pause:!t,value:0),time:(from:now-15m,to:now))&_q=(filters:!(),query:(language:kuery,query:''))` |
| Index pattern for this app | The Discover URL uses a **saved index-pattern id** (`a6cffd50-d18c-11ef-ae32-6f5eb69dfd82`). For `OPENSEARCH_INTEGRATION_MANAGER_INDEX`, copy the **actual index pattern string** that index resolves to (e.g. `default.integration-manager-*`) from Discover’s data source selector or **Stack Management → Index patterns**, not the UUID. |

## How Logs Are Stored

- **Index:** Set `OPENSEARCH_INTEGRATION_MANAGER_INDEX` in `.env` (same OpenSearch cluster as Stream/Bot Engine in typical setups).
- **Connection ID:** Usually `rawLog.data.context.metadata.connectionId`. Some error payloads nest the same metadata under `rawLog.data.message.context.metadata.connectionId`.
- **Time window:** UUIDv1 connection IDs embed a timestamp; the app uses a tight window around that when no manual range is selected (same idea as Bot Engine default logs).

## Workflow

1. Get **connectionId** from Bot Engine logs, conversation metadata, or support tooling.
2. In **Gowtham's Assistant** (this repo): open **Integration Manager Default Logs** (`#integration-manager`), set the index in Settings if needed, paste the Connection ID, **Fetch Logs**.
3. Use **Download JSON/CSV** for RCA handoff; use **Analyse Logs** when an LLM is configured in Settings.
4. Cross-check **Bot Engine Default Logs** for the same connectionId for orchestration vs integration failures.

## RCA Handoff (IM-focused)

Include: connectionId, tenant, time window, failing API or mesh URL, HTTP status or `rawLog.data.status`, and redacted request/response snippets if sharing externally.

## Automation

Backend: `query_integration_manager_default_logs` in `opensearch_client.py`; HTTP routes under `/api/integration-manager/` and `/api/download/integration-manager-logs` in `app.py`.
