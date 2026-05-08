"""End-to-end smoke test for POST /api/session-rca/analyse via Flask test client.

Uses paste mode so it doesn't depend on OpenSearch. Run from repo root:
    python -m tests.test_session_rca_route
"""
from __future__ import annotations

import io
import json
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import app

FIX = ROOT / "tests" / "fixtures" / "auth_rca"


def _load(name: str) -> list:
    with open(FIX / name, encoding="utf-8") as f:
        return json.load(f)


def main() -> int:
    client = app.test_client()

    payload = {
        "mode": "paste",
        "connection_id": "788825e4-38e2-11f1-be5d-062665ac3593",
        "use_llm": False,
        "question": "Why did this caller fail authentication?",
        "bot_engine_logs": _load("furious_sailfish_96_BE.json"),
        "integration_manager_logs": _load("furious_sailfish_96_IM.json"),
        "stream_server_logs": [],
        "related_calls": [
            {
                "connection_id": "b68320f2-38e1-11f1-be57-062665ac3593",
                "bot_engine_logs": _load("clever_whale_59_BE.json"),
                "integration_manager_logs": _load("clever_whale_59_IM.json"),
                "stream_server_logs": [],
            }
        ],
    }

    r = client.post(
        "/api/session-rca/analyse",
        data=json.dumps(payload),
        content_type="application/json",
    )
    if r.status_code != 200:
        print(f"FAIL: status={r.status_code} body={r.get_data(as_text=True)[:500]}", file=sys.stderr)
        return 1

    body = r.get_json()
    if not body.get("ok"):
        print(f"FAIL: not ok — {body.get('error')}", file=sys.stderr)
        return 1

    expected = {
        "ORG_ONLY_AT_LOGIN",
        "PERSON_STUB_AT_PASSWORD",
        "PASSWORD_LOCAL_FALSE",
        "NO_MATCH",
        "LOCKOUT",
    }
    actual = set(body.get("detected_modes", []))
    missing = expected - actual
    if missing:
        print(f"FAIL: missing modes {sorted(missing)} (got {sorted(actual)})", file=sys.stderr)
        return 1
    print(f"OK detected_modes={sorted(actual)}")

    if body.get("question") != payload["question"]:
        print(f"FAIL: question not echoed: {body.get('question')!r}", file=sys.stderr)
        return 1
    print(f"OK question echoed: {body.get('question')!r}")

    drafts = body.get("drafts") or {}
    for k in ("rca_markdown", "client_markdown", "internal_markdown"):
        v = drafts.get(k) or ""
        if not v:
            print(f"FAIL: empty draft {k}", file=sys.stderr)
            return 1
        if payload["question"] not in v:
            print(f"FAIL: question missing from draft {k}", file=sys.stderr)
            return 1
        print(f"OK draft {k}: {len(v)} chars, starts: {v.splitlines()[0][:80]!r}")

    primary_meta = (body.get("signals") or {}).get("primary", {}).get("metadata", {})
    if "user_phone_raw" in primary_meta:
        print("FAIL: raw phone leaked into response", file=sys.stderr)
        return 1
    print(f"OK raw phone stripped, masked={primary_meta.get('user_phone_masked')!r}")

    print("\nALL ROUTE TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
