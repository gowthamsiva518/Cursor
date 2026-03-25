# AGENTS.md

## Cursor Cloud specific instructions

### Overview

This is the **Stream Server Alert Triage Agent** — a Python/Flask + Next.js application for automated Root Cause Analysis of stream server alerts. See `README.md` for architecture and API docs.

### Services

| Service | Port | Start command |
|---|---|---|
| Flask backend | 5000 | `python3 app.py` |
| Next.js frontend | 3000 | `npm run dev` |

Both can run independently. The Flask UI (`:5000`) is the primary interface; Next.js (`:3000`) is an alternative frontend that calls a Python subprocess or proxies to Flask.

### Key caveats

- **Use `python3` not `python`**: The system does not have a `python` symlink; always use `python3`.
- **External services are optional**: OpenSearch, Twilio, Kubernetes, OpenAI, and Slack all degrade gracefully to stubs when credentials are absent. No `.env` configuration is required to run.
- **`.env` with real credentials can cause hangs**: If `.env` contains `OPENSEARCH_URL` pointing to an unreachable cluster, the `/api/run` endpoint will hang waiting for a connection timeout. For local dev without external access, comment out or remove `OPENSEARCH_URL` from `.env`.
- **Lint**: `npx next lint` (requires ESLint 8 — already installed via `eslint@8` + `eslint-config-next@14`). Config is in `.eslintrc.json`.
- **Build**: `npx next build` (Next.js production build).
- **No automated test suite**: This codebase has no unit/integration tests. Validation is done via API calls and UI interaction.
- **Flask runs in debug mode by default**: Set `FLASK_DEBUG=0` to disable.
