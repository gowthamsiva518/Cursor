"""Smoke test for session_rca against the two sample log pairs.

Asserts the deterministic detectors fire on the patterns we hand-RCA'd in chat:
  - clever_whale_59 → ORG_ONLY_AT_LOGIN, NO_MATCH, LOCKOUT
  - furious_sailfish_96 → ORG_ONLY_AT_LOGIN, PASSWORD_LOCAL_FALSE, PERSON_STUB_AT_PASSWORD

Also verifies that a free-form ``question`` parameter is plumbed end-to-end
(stored in scope/result and passed through to the prose renderer).

Fixtures are local-only (gitignored). Run from repo root:
    python -m tests.test_session_rca_smoke
"""
from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import session_rca

FIX = ROOT / "tests" / "fixtures" / "auth_rca"


def _load(name: str) -> list:
    with open(FIX / name, encoding="utf-8") as f:
        return json.load(f)


def _assert_modes(label: str, modes_actual: list[str], modes_expected: set[str]) -> None:
    actual = set(modes_actual)
    missing = modes_expected - actual
    if missing:
        raise AssertionError(
            f"{label}: missing detected modes {sorted(missing)} "
            f"(actual={sorted(actual)})"
        )
    print(f"  OK {label}: {sorted(actual)}")


def smoke_clever_whale() -> dict:
    print("== clever_whale_59 (Mode A — login lockout) ==")
    primary = {
        "connection_id": "b68320f2-38e1-11f1-be57-062665ac3593",
        "be_logs": _load("clever_whale_59_BE.json"),
        "im_logs": _load("clever_whale_59_IM.json"),
    }
    result = session_rca.analyse(primary, related=[], use_llm=False)
    _assert_modes(
        "clever_whale_59",
        result["detected_modes"],
        {"ORG_ONLY_AT_LOGIN", "NO_MATCH", "LOCKOUT"},
    )
    return result


def smoke_furious_sailfish() -> dict:
    print("== furious_sailfish_96 (Mode B — password deadlock) ==")
    primary = {
        "connection_id": "788825e4-38e2-11f1-be5d-062665ac3593",
        "be_logs": _load("furious_sailfish_96_BE.json"),
        "im_logs": _load("furious_sailfish_96_IM.json"),
    }
    result = session_rca.analyse(primary, related=[], use_llm=False)
    _assert_modes(
        "furious_sailfish_96",
        result["detected_modes"],
        {"ORG_ONLY_AT_LOGIN", "PASSWORD_LOCAL_FALSE", "PERSON_STUB_AT_PASSWORD"},
    )
    return result


def smoke_combined_with_question() -> dict:
    print("== combined + free-form question ==")
    primary = {
        "connection_id": "788825e4-38e2-11f1-be5d-062665ac3593",
        "be_logs": _load("furious_sailfish_96_BE.json"),
        "im_logs": _load("furious_sailfish_96_IM.json"),
    }
    related = [{
        "connection_id": "b68320f2-38e1-11f1-be57-062665ac3593",
        "be_logs": _load("clever_whale_59_BE.json"),
        "im_logs": _load("clever_whale_59_IM.json"),
    }]
    question = "Did the caller manage to authenticate, and if not why?"
    result = session_rca.analyse(primary, related=related, question=question, use_llm=False)
    _assert_modes(
        "combined",
        result["detected_modes"],
        {
            "ORG_ONLY_AT_LOGIN",
            "PASSWORD_LOCAL_FALSE",
            "PERSON_STUB_AT_PASSWORD",
            "NO_MATCH",
            "LOCKOUT",
        },
    )
    assert result.get("question") == question, "question not echoed in response"
    assert question in result["drafts"]["rca_markdown"], "question not embedded in fallback prose"
    print(f"  OK question echoed; tenant={result['scope']['tenant']}, masked={result['scope']['user_phone_masked']}")
    return result


def smoke_ss_only_session() -> dict:
    """SS-only synthetic input — verifies the SS extractor and SS_ERROR detector wire up.
    No fixture file needed; we synthesise a tiny SS log array in-process.
    """
    print("== synthetic SS-only session (transcript + error) ==")
    ss_logs = [
        {
            "@timestamp": "2026-04-15T16:00:00.100Z",
            "level": 30,
            "rawLog": {
                "moduleName": "twilio",
                "data": {"action": {"type": "io", "subtype": "voice", "data": {"text": "Welcome to ACME Bank."}}},
            },
        },
        {
            "@timestamp": "2026-04-15T16:00:02.500Z",
            "level": 30,
            "rawLog": {
                "moduleName": "speechmatics",
                "data": {"action": {"type": "io", "subtype": "parse"}, "data": {"text": "I want my balance"}},
            },
        },
        {
            "@timestamp": "2026-04-15T16:00:03.000Z",
            "level": 50,
            "msg": "Speechmatics websocket closed",
            "rawLog": {
                "moduleName": "speechmatics",
                "data": {"error": {"code": "WS_CLOSED", "message": "Speechmatics websocket closed unexpectedly"}},
            },
        },
    ]
    primary = {
        "connection_id": "synthetic-ss-only",
        "be_logs": [],
        "im_logs": [],
        "ss_logs": ss_logs,
    }
    result = session_rca.analyse(primary, related=[], question="Did the bot greet the caller and capture their request?", use_llm=False)
    assert "SS_ERROR" in result["detected_modes"], f"SS_ERROR not detected: {result['detected_modes']}"
    assert "Welcome to ACME Bank" in result["drafts"]["rca_markdown"], "bot transcript missing"
    assert "I want my balance" in result["drafts"]["rca_markdown"], "caller speech missing"
    print(f"  OK SS_ERROR detected; transcript surfaced; modes={result['detected_modes']}")
    return result


def main() -> int:
    if not FIX.exists():
        print(f"ERROR: fixtures dir missing: {FIX}", file=sys.stderr)
        return 2
    smoke_clever_whale()
    smoke_furious_sailfish()
    c = smoke_combined_with_question()
    smoke_ss_only_session()
    print("\n--- Sample drafts (deterministic facts) ---\n")
    print(c["drafts"]["rca_markdown"][:1800])
    if os.environ.get("SESSION_RCA_FULL_DUMP") == "1":
        out = ROOT / "tests" / "fixtures" / "auth_rca" / "_smoke_output.json"
        with open(out, "w", encoding="utf-8") as f:
            json.dump(c, f, indent=2)
        print(f"\nFull combined output written to {out}")
    print("\nALL SMOKE TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
