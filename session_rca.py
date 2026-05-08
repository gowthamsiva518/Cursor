"""
Session RCA agent.

Analyses Bot Engine + Integration Manager + Stream Server logs for one or more
correlated calls/sessions and produces three outputs:

  1. Structured RCA            (timeline, what went wrong, root cause, verdict)
  2. Client-facing ticket draft (PII-redacted prose, FI-admin tone)
  3. Internal engineering ticket (raw IDs, code-level asks, dev tone)

The agent runs in two complementary layers:

  * Deterministic detectors  — high-precision rule-based detectors for known
    failure modes (currently auth: ORG_ONLY_AT_LOGIN, PERSON_STUB_AT_PASSWORD,
    LOCKOUT, NO_MATCH, UPSTREAM_5XX/TIMEOUT, DROPPED_SESSION, PASSWORD_LOCAL_FALSE).
    They fire automatically and become hard evidence for the LLM to cite.

  * LLM narration             — produces the three drafts. When ``question`` is
    provided, the LLM answers that specific question grounded in the facts
    block (BE+IM+SS). When ``question`` is empty, it produces a generic
    structured RCA. Falls back to the deterministic facts block when no LLM
    provider is configured.

Inputs accept either flattened rows from ``opensearch_client`` (with ``_raw``
preserved) or raw OpenSearch ``_source`` docs directly (paste mode) — both
shapes work transparently.
"""

from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _src(log: Any) -> dict:
    """Return the underlying OpenSearch ``_source`` for a log row.

    Accepts either a flattened row (``_raw`` set) or a raw ``_source`` dict.
    """
    if isinstance(log, dict):
        if isinstance(log.get("_raw"), dict):
            return log["_raw"]
        return log
    return {}


def _gn(d: Any, path: str, default: Any = None) -> Any:
    """Nested-key getter mirroring opensearch_client._get_nested."""
    cur: Any = d
    for part in path.split("."):
        if not isinstance(cur, dict):
            return default
        cur = cur.get(part)
    return cur if cur is not None else default


def _mask_phone(p: str) -> str:
    p = (p or "").strip()
    if len(p) >= 4:
        return "*" * max(4, len(p) - 4) + p[-4:]
    return p


def _is_guid(s: Any) -> bool:
    return isinstance(s, str) and len(s) == 36 and s.count("-") == 4


def _to_level_n(level: Any) -> int:
    try:
        return int(level)
    except (TypeError, ValueError):
        s = str(level or "").strip().upper()
        return {"FATAL": 60, "ERROR": 50, "WARN": 40, "INFO": 30, "DEBUG": 20, "TRACE": 10}.get(s, 0)


def _short(text: Any, n: int) -> str:
    s = str(text or "")
    return s if len(s) <= n else s[: n - 1] + "…"


# ---------------------------------------------------------------------------
# BE-side parsers
# ---------------------------------------------------------------------------

def _be_session_metadata(be_logs: list) -> dict:
    """Pull the session-level identifiers from the first BE log that has them.

    Returns both masked and raw phone numbers. The raw phone is intended for
    correlation lookups only and is stripped from API responses.
    """
    out = {
        "connection_id": "", "session_id": "", "client_id": "",
        "tenant": "", "agent_name": "", "channel_type": "",
        "user_phone_masked": "", "user_phone_raw": "",
        "stir_ver_stat": "", "trust_level": None, "trust_source": "",
        "from_address": None, "to_phone": "",
    }
    for log in be_logs:
        s = _src(log)
        meta = _gn(s, "rawLog.data.data.metadata") or {}
        if not meta:
            continue
        if not out["connection_id"]:
            out["connection_id"] = str(meta.get("connectionId") or "")
        if not out["session_id"]:
            out["session_id"] = str(meta.get("sessionId") or "")
        if not out["client_id"]:
            out["client_id"] = str(meta.get("clientId") or "")
        if not out["tenant"]:
            out["tenant"] = str(meta.get("tenantName") or _gn(s, "rawLog.tenantName") or "")
        if not out["agent_name"]:
            out["agent_name"] = str(meta.get("agentName") or "")
        if not out["channel_type"]:
            out["channel_type"] = str(meta.get("channelType") or "")
        if not out["user_phone_raw"] and meta.get("userPhoneNumber"):
            phone = str(meta["userPhoneNumber"])
            out["user_phone_raw"] = phone
            out["user_phone_masked"] = _mask_phone(phone)
        cd = meta.get("callData") or {}
        if not out["stir_ver_stat"]:
            out["stir_ver_stat"] = str(cd.get("stirVerStat") or "")
        if out["trust_level"] is None and meta.get("trustLevel") is not None:
            out["trust_level"] = meta.get("trustLevel")
        if not out["trust_source"]:
            out["trust_source"] = str(meta.get("trustSource") or "")
        if not out["from_address"] and cd.get("fromAddress"):
            out["from_address"] = cd.get("fromAddress")
        if not out["to_phone"]:
            out["to_phone"] = str(cd.get("toPhone") or "")
        if out["connection_id"] and out["tenant"] and out["user_phone_raw"]:
            break
    return out


def _be_auth_config(be_logs: list) -> dict:
    """Extract the auth.get response — the caller-auth policy on the call."""
    for log in be_logs:
        s = _src(log)
        if _gn(s, "rawLog.data.apiName") == "auth" and _gn(s, "rawLog.data.methodName") == "get":
            resp = _gn(s, "rawLog.data.response.authentication") or {}
            data_block = resp.get("data") or {}
            return {
                "level": _gn(s, "rawLog.data.data.authentication.level") or "",
                "login_types": data_block.get("loginType") or [],
                "password_types": data_block.get("passwordType") or [],
                "max_attempts": resp.get("maxAttempts"),
                "ts": _gn(s, "@timestamp") or "",
            }
    return {}


def _be_extract_attempts(be_logs: list) -> list[dict]:
    """Pick the auth.create rows in chronological order; return per-attempt summaries."""
    attempts: list[dict] = []
    for log in be_logs:
        s = _src(log)
        api = str(_gn(s, "rawLog.data.apiName") or "")
        method = str(_gn(s, "rawLog.data.methodName") or "")
        if api != "auth" or method != "create":
            continue
        d = _gn(s, "rawLog.data") or {}
        req_data = _gn(d, "data.authentication.data") or {}
        resp = _gn(d, "response.authentication") or {}
        meta = _gn(d, "data.metadata") or {}
        login_value = req_data.get("login")
        attempts.append({
            "ts": _gn(s, "@timestamp") or "",
            "request_id": str(meta.get("requestId") or ""),
            "login": login_value,
            "login_is_guid": _is_guid(login_value),
            "password_present": bool(req_data.get("password")),
            "status": resp.get("status"),
            "attempts": resp.get("attempts"),
            "max_attempts": resp.get("maxAttempts"),
            "retry_time": resp.get("retryTime"),
            "data_resp": resp.get("data"),
            "account_count": _gn(d, "response.accountCount"),
            "elapsed_ms": d.get("time"),
        })
    attempts.sort(key=lambda a: a["ts"] or "")
    return attempts


def _be_session_create(be_logs: list) -> dict | None:
    """Pick the session.create row, if any."""
    for log in be_logs:
        s = _src(log)
        if _gn(s, "rawLog.data.apiName") == "session" and _gn(s, "rawLog.data.methodName") == "create":
            return {
                "ts": _gn(s, "@timestamp") or "",
                "token": _gn(s, "rawLog.data.response.session.token") or "",
            }
    return None


def _be_errors_warnings(be_logs: list) -> list[dict]:
    """Return non-auth BE error/warn rows for the LLM to consider."""
    out: list[dict] = []
    for log in be_logs:
        s = _src(log)
        lvl = _to_level_n(s.get("level"))
        if lvl < 40:
            continue
        api = str(_gn(s, "rawLog.data.apiName") or "")
        method = str(_gn(s, "rawLog.data.methodName") or "")
        out.append({
            "ts": _gn(s, "@timestamp") or "",
            "level": lvl,
            "api": api,
            "method": method,
            "msg": str(s.get("msg") or s.get("message") or ""),
            "error_code": str(_gn(s, "rawLog.data.error.code") or _gn(s, "rawLog.data.status") or ""),
            "error_message": str(_gn(s, "rawLog.data.error.message") or _gn(s, "rawLog.data.message") or ""),
        })
    out.sort(key=lambda e: e["ts"] or "")
    return out


# ---------------------------------------------------------------------------
# IM-side parsers
# ---------------------------------------------------------------------------

def _im_extract_events(im_logs: list) -> list[dict]:
    """Extract chronologically-ordered IM controller / API events."""
    events: list[dict] = []
    for log in im_logs:
        s = _src(log)
        d = _gn(s, "rawLog.data") or {}
        events.append({
            "ts": _gn(s, "@timestamp") or "",
            "msg": str(s.get("msg") or ""),
            "level": s.get("level"),
            "api_name": str(d.get("apiName") or ""),
            "method_name": str(d.get("methodName") or ""),
            "url": str(_gn(d, "request.url") or ""),
            "request": d.get("request"),
            "response": d.get("response"),
            "session_data": _gn(d, "context.session.data") or {},
            "elapsed_ms": d.get("time"),
        })
    events.sort(key=lambda e: e["ts"] or "")
    return events


def _im_dna_party_lookups(events: list[dict]) -> list[dict]:
    """DNA SearchForParty calls in order, with extracted party metadata."""
    out: list[dict] = []
    for ev in events:
        url = ev.get("url") or ""
        if "SearchForParty" not in url:
            continue
        resp = ev.get("response") or {}
        if not isinstance(resp, dict):
            continue
        body = resp.get("messageBody") or {}
        search_id = str(body.get("searchId") or body.get("id") or "")
        kind = "member" if search_id.startswith("MN:") else (
            "ssn_tin" if search_id.startswith("TN:") else "?"
        )
        items = body.get("partyItems") or []
        items_norm: list[dict] = []
        for it in items:
            items_norm.append({
                "party_id": str(it.get("partyId") or ""),
                "type": str(it.get("type") or ""),
                "name": str(it.get("name") or ""),
                "tax_id_masked": str(it.get("taxIdMasked") or it.get("taxIdRaw") or ""),
                "member_number": str(it.get("memberNumber") or ""),
                "matched_accounts_count": len(it.get("matchedAccounts") or []),
                "matched_items": [
                    {
                        "match": str(mi.get("match") or ""),
                        "score": str(mi.get("weightedScore") or ""),
                    }
                    for mi in (it.get("matchedItems") or [])
                ],
            })
        out.append({
            "ts": ev["ts"],
            "search_kind": kind,
            "search_id": search_id,
            "result_count": len(items),
            "items": items_norm,
        })
    return out


def _im_password_validations(events: list[dict]) -> list[dict]:
    out: list[dict] = []
    for ev in events:
        if ev.get("api_name") != "auth-validate" or ev.get("method_name") != "validatePassword":
            continue
        elapsed = ev.get("elapsed_ms")
        try:
            elapsed_f = float(elapsed) if elapsed is not None else None
        except (TypeError, ValueError):
            elapsed_f = None
        out.append({
            "ts": ev["ts"],
            "response": ev.get("response"),
            "elapsed_ms": elapsed_f,
            "session_data": ev.get("session_data") or {},
        })
    return out


def _im_login_validations(events: list[dict]) -> list[dict]:
    out: list[dict] = []
    for ev in events:
        if ev.get("api_name") != "auth-validate" or ev.get("method_name") != "validateLogin":
            continue
        elapsed = ev.get("elapsed_ms")
        try:
            elapsed_f = float(elapsed) if elapsed is not None else None
        except (TypeError, ValueError):
            elapsed_f = None
        sd = ev.get("session_data") or {}
        login_data = sd.get("loginData") or {}
        out.append({
            "ts": ev["ts"],
            "elapsed_ms": elapsed_f,
            "session_data": sd,
            "errors": login_data.get("errors") or {},
            "success": login_data.get("success") or {},
        })
    return out


def _im_upstream_failures(events: list[dict]) -> list[dict]:
    out: list[dict] = []
    for ev in events:
        url = ev.get("url") or ""
        if not url:
            continue
        resp = ev.get("response")
        status: Any = None
        if isinstance(resp, dict):
            status = resp.get("status") or resp.get("ResponseStatus")
        try:
            status_n = int(status) if status is not None else None
        except (TypeError, ValueError):
            status_n = None
        msg = str(ev.get("msg") or "")
        is_failure_msg = "Failure" in msg
        ok = status_n is not None and 200 <= status_n < 300
        if ok and not is_failure_msg:
            continue
        if status_n is None and not is_failure_msg:
            continue
        out.append({
            "ts": ev["ts"],
            "url": url,
            "status": status_n if status_n is not None else status,
            "msg": msg,
            "elapsed_ms": ev.get("elapsed_ms"),
        })
    return out


# ---------------------------------------------------------------------------
# SS-side parsers (Stream Server)
# ---------------------------------------------------------------------------

def _ss_extract_turns(ss_logs: list) -> list[dict]:
    """Build a chronological transcript of bot/caller turns and notable SS events.

    Each turn is one of:
      - kind="bot"      → bot played a prompt (action.type=='io', action.subtype=='voice')
      - kind="caller"   → caller speech captured (action subtype == 'parse'/'gather' or rawLog.data.data.text)
      - kind="action"   → other action (transfer, hangup, etc.)
      - kind="error"    → SS error/warn row
    """
    out: list[dict] = []
    for log in ss_logs:
        s = _src(log)
        ts = _gn(s, "@timestamp") or ""
        lvl = _to_level_n(s.get("level"))
        d = _gn(s, "rawLog.data") or {}
        a = d.get("action") if isinstance(d, dict) else None
        action_type = ""
        action_subtype = ""
        action_text = ""
        if isinstance(a, dict):
            action_type = str(a.get("type") or "")
            action_subtype = str(a.get("subtype") or "")
            ad = a.get("data")
            if isinstance(ad, dict):
                action_text = str(ad.get("text") or ad.get("utterance") or "")
        inner = d.get("data") if isinstance(d, dict) else None
        speech_text = ""
        if isinstance(inner, dict):
            speech_text = str(inner.get("text") or inner.get("utterance") or "")
        err_msg = str(_gn(s, "rawLog.data.error.message") or "")
        err_code = str(_gn(s, "rawLog.data.error.code") or _gn(s, "rawLog.data.error.name") or "")

        if lvl >= 40:
            out.append({
                "ts": ts,
                "kind": "error",
                "level": lvl,
                "module": str(_gn(s, "rawLog.moduleName") or s.get("moduleName") or ""),
                "action_type": action_type,
                "action_subtype": action_subtype,
                "error_code": err_code,
                "error_message": err_msg,
                "msg": str(s.get("msg") or ""),
            })
            continue

        if speech_text:
            out.append({
                "ts": ts,
                "kind": "caller",
                "text": speech_text,
                "action_type": action_type,
                "action_subtype": action_subtype,
            })
            continue

        if action_text and (action_subtype in ("voice", "say") or action_type == "io"):
            out.append({
                "ts": ts,
                "kind": "bot",
                "text": action_text,
                "action_type": action_type,
                "action_subtype": action_subtype,
            })
            continue

        if action_type and action_type not in ("io",) and action_subtype != "":
            out.append({
                "ts": ts,
                "kind": "action",
                "text": action_text,
                "action_type": action_type,
                "action_subtype": action_subtype,
            })
    out.sort(key=lambda e: e["ts"] or "")
    return out


# ---------------------------------------------------------------------------
# Top-level extractor
# ---------------------------------------------------------------------------

def extract_signals(be_logs: list, im_logs: list, ss_logs: list | None = None) -> dict:
    """Build the structured signals dict for one call (BE + IM + optional SS)."""
    be_logs = be_logs or []
    im_logs = im_logs or []
    ss_logs = ss_logs or []
    metadata = _be_session_metadata(be_logs)
    auth_config = _be_auth_config(be_logs)
    attempts = _be_extract_attempts(be_logs)
    session_create = _be_session_create(be_logs)
    be_errors = _be_errors_warnings(be_logs)
    im_events = _im_extract_events(im_logs)
    party_lookups = _im_dna_party_lookups(im_events)
    pw_validations = _im_password_validations(im_events)
    login_validations = _im_login_validations(im_events)
    upstream_failures = _im_upstream_failures(im_events)
    ss_turns = _ss_extract_turns(ss_logs)
    return {
        "metadata": metadata,
        "auth_config": auth_config,
        "session_create": session_create,
        "attempts": attempts,
        "be_errors": be_errors,
        "im_events_count": len(im_events),
        "party_lookups": party_lookups,
        "password_validations": pw_validations,
        "login_validations": login_validations,
        "upstream_failures": upstream_failures,
        "ss_turn_count": len(ss_turns),
        "ss_turns": ss_turns,
    }


# ---------------------------------------------------------------------------
# Detectors (deterministic)
# ---------------------------------------------------------------------------

DETECTOR_IDS = (
    "ORG_ONLY_AT_LOGIN",
    "PERSON_STUB_AT_PASSWORD",
    "PASSWORD_LOCAL_FALSE",
    "NO_MATCH",
    "LOCKOUT",
    "UPSTREAM_5XX",
    "UPSTREAM_TIMEOUT",
    "DROPPED_SESSION",
    "SS_ERROR",
)


def detect_modes(signals: dict) -> list[dict]:
    """Run deterministic detectors against one call's signals."""
    found: list[dict] = []
    party_lookups = signals.get("party_lookups") or []
    pw_validations = signals.get("password_validations") or []
    attempts = signals.get("attempts") or []
    upstream_failures = signals.get("upstream_failures") or []
    session_create = signals.get("session_create")
    ss_turns = signals.get("ss_turns") or []

    # ORG_ONLY_AT_LOGIN
    for pl in party_lookups:
        if pl["result_count"] >= 1 and all(
            it["type"] == "Organization" for it in pl["items"]
        ):
            ev = "; ".join(
                f"{it['party_id']} '{it['name']}' memberNumber={it['member_number'] or '-'}"
                for it in pl["items"]
            )
            found.append({
                "id": "ORG_ONLY_AT_LOGIN",
                "ts": pl["ts"],
                "evidence": (
                    f"DNA SearchForParty `{pl['search_id']}` returned only "
                    f"Organization-type result(s): {ev}"
                ),
            })

    # NO_MATCH
    for pl in party_lookups:
        if pl["result_count"] == 0:
            found.append({
                "id": "NO_MATCH",
                "ts": pl["ts"],
                "evidence": f"DNA SearchForParty `{pl['search_id']}` returned 0 results.",
            })

    # PASSWORD_LOCAL_FALSE / PERSON_STUB_AT_PASSWORD
    for pwo in pw_validations:
        resp = pwo.get("response")
        if resp is False or resp == "false":
            elapsed = pwo.get("elapsed_ms")
            local_hint = (
                f" in {elapsed:.3f} ms (local-only — no upstream call)"
                if isinstance(elapsed, (int, float)) and elapsed < 50
                else ""
            )
            found.append({
                "id": "PASSWORD_LOCAL_FALSE",
                "ts": pwo["ts"],
                "evidence": f"auth-validate.validatePassword returned `false`{local_hint}",
            })
            sd = pwo.get("session_data") or {}
            login_data = sd.get("loginData") or {}
            success_field = (login_data.get("success") or {}).get("login", {}).get("field") or ""
            if success_field == "ssn":
                last_person = None
                for pl in party_lookups:
                    if pl["ts"] > pwo["ts"]:
                        continue
                    for it in pl["items"]:
                        if it["type"] == "Person":
                            last_person = it
                if last_person and (last_person.get("member_number") or "") in ("0", "*0", ""):
                    found.append({
                        "id": "PERSON_STUB_AT_PASSWORD",
                        "ts": pwo["ts"],
                        "evidence": (
                            f"Resolved Person `{last_person['party_id']}` "
                            f"'{last_person['name']}' has "
                            f"memberNumber=`{last_person['member_number'] or '0'}` "
                            "(administrative stub) — no member#/card on the Person "
                            "for `validatePassword` to compare against."
                        ),
                    })

    # LOCKOUT
    for a in attempts:
        if a.get("status") == "max_attempts":
            ev = (
                f"auth.create #{a.get('attempts')} of {a.get('max_attempts')} → "
                f"status=`max_attempts`"
            )
            if a.get("retry_time"):
                ev += f", retryTime=`{a['retry_time']}`"
            found.append({"id": "LOCKOUT", "ts": a["ts"], "evidence": ev})

    # UPSTREAM_5XX / UPSTREAM_TIMEOUT
    for uf in upstream_failures:
        status = uf.get("status")
        msg = (uf.get("msg") or "").lower()
        looks_timeout = "timeout" in msg or status in (408, 504)
        if looks_timeout:
            found.append({
                "id": "UPSTREAM_TIMEOUT",
                "ts": uf["ts"],
                "evidence": f"Upstream timeout: `{uf['url']}` status=`{status}`",
            })
        elif isinstance(status, int) and status >= 500:
            found.append({
                "id": "UPSTREAM_5XX",
                "ts": uf["ts"],
                "evidence": f"Upstream {status}: `{uf['url']}`",
            })

    # DROPPED_SESSION
    if session_create and not attempts:
        found.append({
            "id": "DROPPED_SESSION",
            "ts": session_create.get("ts") or "",
            "evidence": (
                "session.create succeeded but no auth.create attempts were "
                "logged — caller likely abandoned the call before the auth flow began."
            ),
        })

    # SS_ERROR
    for t in ss_turns:
        if t.get("kind") == "error":
            ev = f"Stream Server {t.get('module') or ''}".strip()
            if t.get("action_type") or t.get("action_subtype"):
                ev += f" action={t.get('action_type')}/{t.get('action_subtype')}"
            if t.get("error_code"):
                ev += f" code=`{t['error_code']}`"
            if t.get("error_message"):
                ev += f" msg=`{_short(t['error_message'], 200)}`"
            found.append({
                "id": "SS_ERROR",
                "ts": t["ts"],
                "evidence": ev,
            })

    seen: set = set()
    out: list[dict] = []
    for f in found:
        key = (f["id"], f["ts"], f["evidence"])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    out.sort(key=lambda f: (f["ts"] or "", f["id"]))
    return out


# ---------------------------------------------------------------------------
# Facts block (deterministic — used as LLM grounding & fallback output)
# ---------------------------------------------------------------------------

def _format_call_block(label: str, conn_id: str, signals: dict, modes: list[dict]) -> str:
    out: list[str] = [f"### {label} — `{conn_id or '(unknown)'}`"]
    atts = signals.get("attempts") or []
    sc = signals.get("session_create")
    ss_turns = signals.get("ss_turns") or []
    be_errors = signals.get("be_errors") or []
    party_lookups = signals.get("party_lookups") or []
    pw_validations = signals.get("password_validations") or []
    upstream_failures = signals.get("upstream_failures") or []
    cfg = signals.get("auth_config") or {}

    timestamps = [t["ts"] for t in ss_turns if t.get("ts")] + [a["ts"] for a in atts if a.get("ts")]
    if timestamps:
        out.append(f"Window: {min(timestamps)} → {max(timestamps)}")

    if sc:
        out.append(f"  • `{sc['ts']}` session.create — token issued")
    if cfg:
        out.append(
            f"  • auth.get → loginType={cfg.get('login_types')}, "
            f"passwordType={cfg.get('password_types')}, "
            f"maxAttempts={cfg.get('max_attempts')}"
        )

    for a in atts:
        login_disp = "—"
        if a.get("login") is not None:
            login_disp = "(GUID)" if a.get("login_is_guid") else str(a["login"])
        line = (
            f"  • `{a['ts']}` auth.create login=`{login_disp}` → "
            f"status=`{a.get('status')}`, "
            f"attempts={a.get('attempts')}/{a.get('max_attempts')}"
        )
        if a.get("retry_time"):
            line += f", retryTime=`{a['retry_time']}`"
        if a.get("password_present"):
            line += "  (password supplied)"
        out.append(line)

    for pl in party_lookups:
        kind = pl.get("search_kind", "?")
        if pl["result_count"] == 0:
            out.append(
                f"  • `{pl['ts']}` SearchForParty ({kind}) `{pl['search_id']}` → 0 results"
            )
        else:
            items_desc = "; ".join(
                (
                    f"{it['type']} `{it['party_id']}` '{it['name']}' "
                    f"memberNumber=`{it['member_number'] or '-'}` "
                    f"taxId=`{it['tax_id_masked'] or '-'}`"
                )
                for it in pl["items"]
            )
            out.append(
                f"  • `{pl['ts']}` SearchForParty ({kind}) `{pl['search_id']}` "
                f"→ {pl['result_count']} hit(s): {items_desc}"
            )

    for pwo in pw_validations:
        elapsed = pwo.get("elapsed_ms")
        elapsed_str = (
            f" ({elapsed:.3f} ms, local-only)"
            if isinstance(elapsed, (int, float)) and elapsed < 50
            else (f" ({elapsed:.1f} ms)" if isinstance(elapsed, (int, float)) else "")
        )
        out.append(
            f"  • `{pwo['ts']}` auth-validate.validatePassword → "
            f"response=`{pwo.get('response')}`{elapsed_str}"
        )

    for uf in upstream_failures:
        out.append(
            f"  • `{uf['ts']}` UPSTREAM FAIL `{uf.get('status')}` `{uf['url']}`"
        )

    for be_err in be_errors[:8]:
        out.append(
            f"  • `{be_err['ts']}` BE {be_err.get('level')} "
            f"api={be_err.get('api') or '-'}/{be_err.get('method') or '-'} "
            f"msg=`{_short(be_err.get('msg'), 160)}`"
        )

    if ss_turns:
        out.append(f"  • Stream Server transcript ({len(ss_turns)} turns):")
        for t in ss_turns[:40]:
            kind = t.get("kind") or ""
            if kind == "bot":
                out.append(f"    - `{t['ts']}` [BOT] \"{_short(t.get('text'), 160)}\"")
            elif kind == "caller":
                out.append(f"    - `{t['ts']}` [CALLER] \"{_short(t.get('text'), 160)}\"")
            elif kind == "error":
                out.append(
                    f"    - `{t['ts']}` [SS ERROR] {t.get('module') or '-'} "
                    f"{t.get('action_type')}/{t.get('action_subtype')} "
                    f"code=`{t.get('error_code') or '-'}` "
                    f"msg=`{_short(t.get('error_message'), 160)}`"
                )
            else:
                out.append(
                    f"    - `{t['ts']}` [{(kind or 'event').upper()}] "
                    f"action={t.get('action_type')}/{t.get('action_subtype')} "
                    f"text=\"{_short(t.get('text'), 120)}\""
                )
        if len(ss_turns) > 40:
            out.append(f"    - … {len(ss_turns) - 40} more turns omitted from preview")

    if modes:
        ids = sorted({m["id"] for m in modes})
        out.append(f"  ⇒ Detected modes: {', '.join(ids)}")
        for m in modes:
            out.append(f"    - [{m['id']}] {m['evidence']}")
    return "\n".join(out)


def build_facts_block(
    primary_signals: dict, primary_modes: list[dict], related_blocks: list[dict]
) -> str:
    """Compose a deterministic, human-readable facts string used both as
    LLM grounding (user prompt body) and as the deterministic fallback output."""
    md = primary_signals.get("metadata") or {}
    cfg = primary_signals.get("auth_config") or {}
    lines: list[str] = ["## Facts (deterministic)\n"]
    lines.append(
        f"- Tenant: `{md.get('tenant') or '?'}`  ·  "
        f"agent: `{md.get('agent_name') or '?'}`  ·  "
        f"channel: `{md.get('channel_type') or '?'}`"
    )
    lines.append(
        f"- Caller (masked): `{md.get('user_phone_masked') or '?'}` → "
        f"`{md.get('to_phone') or '?'}`  ·  "
        f"STIR: `{md.get('stir_ver_stat') or '?'}`  ·  "
        f"trustLevel: `{md.get('trust_level')}` / `{md.get('trust_source') or '?'}`"
    )
    if cfg:
        lines.append(
            f"- Auth config: level=`{cfg.get('level') or '?'}`, "
            f"loginType={cfg.get('login_types')}, "
            f"passwordType={cfg.get('password_types')}, "
            f"maxAttempts={cfg.get('max_attempts')}"
        )
    lines.append("")
    lines.append(_format_call_block(
        "Primary call", md.get("connection_id") or "", primary_signals, primary_modes
    ))
    for b in related_blocks:
        lines.append("")
        lines.append(_format_call_block(
            "Related call",
            b.get("connection_id") or "",
            b.get("signals") or {},
            b.get("detected_modes") or [],
        ))
    return "\n".join(lines)


def _strip_internal_fields(signals: dict) -> dict:
    """Strip server-only fields (e.g. raw phone) before returning to clients."""
    md = dict(signals.get("metadata") or {})
    md.pop("user_phone_raw", None)
    out = dict(signals)
    out["metadata"] = md
    return out


# ---------------------------------------------------------------------------
# LLM renderers
# ---------------------------------------------------------------------------

_RCA_SYSTEM_GENERIC = (
    "You are a senior platform engineer producing a CRISP root-cause analysis for a "
    "single voice/chat session (or a small correlated set of sessions for the same "
    "caller). Use ONLY the facts in the user message — do not invent timestamps, IDs, "
    "or fields.\n\n"
    "Output strictly in this Markdown structure:\n"
    "**Summary** — 2–3 sentences\n"
    "**Timeline** — bulleted, one event per line, copy timestamps verbatim\n"
    "**Issues found** — list every detected mode (e.g. ORG_ONLY_AT_LOGIN, SS_ERROR) "
    "and any error/warn rows; if none, say 'No deterministic issues detected'\n"
    "**Root cause** — 1–2 paragraphs grounded in the facts; cite detector names\n"
    "**Verdict** — ONE line: SUCCESS | FAILURE | PARTIAL — short justification, plus "
    "Confidence: HIGH | MEDIUM | LOW\n"
    "Be terse. No filler. No 'as an AI' disclaimers."
)

_RCA_SYSTEM_QUESTION = (
    "You are a senior platform engineer answering a SPECIFIC USER QUESTION about a "
    "single voice/chat session (or a small correlated set for the same caller), "
    "grounded in the BE+IM+SS log facts in the user message. Use ONLY those facts — "
    "never invent timestamps, IDs, or fields.\n\n"
    "Output strictly in this Markdown structure:\n"
    "**Answer** — 2–5 sentences directly answering the user's question\n"
    "**Evidence** — bulleted timestamped events that support the answer; one line per "
    "event; copy timestamps verbatim and quote payload fragments where useful\n"
    "**Other findings** — list any detected modes (auth or otherwise) that are worth "
    "flagging even if not strictly on-topic; skip the section if there is nothing\n"
    "**Verdict** — ONE line: ANSWER: YES | NO | PARTIAL | INCONCLUSIVE — one-sentence "
    "justification grounded in evidence; plus Confidence: HIGH | MEDIUM | LOW\n"
    "Be terse. No filler. No restating the question."
)

_CLIENT_SYSTEM_GENERIC = (
    "You are writing a ticket UPDATE for a credit-union admin (the FI's support "
    "contact). Tone: professional, concrete, no jargon dumps. Goal: tell them what "
    "went wrong on the call, why, what to fix on their CRM/core side, and what we "
    "are doing on ours.\n\n"
    "Use ONLY the facts in the user message. NEVER quote raw SSNs, full member "
    "numbers, full names, or any value that looks like a card / tax-id digit "
    "string. Generalise to phrases like 'the trust account', 'the LLC', 'the "
    "business account', 'the caller'. You MAY include connectionId values and UTC "
    "timestamps verbatim.\n\n"
    "Output sections (Markdown, in this order):\n"
    "**Status:** one line\n"
    "**Calls reviewed**: bullet per call with connectionId, UTC window, outcome\n"
    "**What we found**: 1–2 short paragraphs grounded in the facts\n"
    "**Recommended action on your side**: short, specific bullets\n"
    "**On our side**: 2–3 bullets\n"
    "End with one line asking them to confirm/re-test."
)

_CLIENT_SYSTEM_QUESTION = (
    "You are writing a ticket UPDATE for a credit-union admin who asked a specific "
    "question about a session. Tone: professional, concrete. Goal: answer their "
    "question first, then explain the supporting evidence in plain terms.\n\n"
    "Use ONLY the facts in the user message. NEVER quote raw SSNs, full member "
    "numbers, full names, card or tax-id digits. Generalise (e.g. 'the trust "
    "account'). connectionIds and UTC timestamps are fine to include verbatim.\n\n"
    "Output sections (Markdown):\n"
    "**Status:** one line answering the question (Yes/No/Partial + 1-line reason)\n"
    "**Calls reviewed**: bullet per call with connectionId, UTC window, outcome\n"
    "**What we found**: 1–2 paragraphs grounded in evidence\n"
    "**Recommended action on your side**: bullets\n"
    "**On our side**: 2–3 bullets\n"
    "End with one line asking them to confirm/re-test."
)

_INTERNAL_SYSTEM_GENERIC = (
    "You are filing an INTERNAL engineering ticket for the squad on call. Tone: "
    "engineer-to-engineer. Keep raw IDs (Person_*, Organization_*, connectionId, "
    "session GUID, tenant, IM image), name controllers (auth.create, "
    "auth-validate.validateLogin, auth-validate.validatePassword, auth.get) and "
    "DNA / mesh endpoints. Be terse. No filler. No restating of the question.\n\n"
    "Use ONLY the facts in the user message.\n\n"
    "Output sections (Markdown):\n"
    "**TL;DR** — 2–4 lines\n"
    "**Evidence** — per-call sub-headings; bulleted timestamped events; call out "
    "the specific controllers, DNA URLs, and SS modules\n"
    "**Hypothesis** — short pseudocode/paragraph for how the failing logic likely works\n"
    "**Asks** — numbered list of specific code-level questions for the squad\n"
    "**Proposed code-side improvements** — small table (id | change | notes)\n"
    "**Logs / artifacts** — connectionIds + an OpenSearch quick-filter line"
)

_INTERNAL_SYSTEM_QUESTION = (
    "You are filing an INTERNAL engineering ticket addressing a specific question "
    "about a session. Tone: engineer-to-engineer. Keep raw IDs, controller names, "
    "DNA URLs, SS modules. Be terse. Use ONLY the facts in the user message.\n\n"
    "Output sections (Markdown):\n"
    "**TL;DR** — direct answer to the question (2–4 lines)\n"
    "**Evidence** — per-call sub-headings; bulleted timestamped events that prove "
    "the answer; cite controllers / URLs / SS modules\n"
    "**Hypothesis** — 1 short block describing what the failing code path likely does\n"
    "**Asks** — numbered specific code-level questions for the squad\n"
    "**Proposed code-side improvements** — small table (id | change | notes)\n"
    "**Logs / artifacts** — connectionIds + an OpenSearch quick-filter line"
)


def _llm_render(system_prompt: str, facts: str, scope: dict, question: str = "") -> dict:
    """Call the configured LLM. Returns ``{text, provider}`` or empty dict on failure."""
    try:
        from ai_summarizer import _get_provider, llm_call_for_log_analysis
    except Exception:
        return {"text": "", "provider": None}
    if _get_provider() == "none":
        return {"text": "", "provider": None}
    parts = [
        "=== SCOPE ===",
        f"Primary connectionId: {scope.get('primary_connection_id') or '(none)'}",
        f"Related connectionIds: {scope.get('related_connection_ids') or '(none)'}",
        f"Tenant: {scope.get('tenant') or '(unknown)'}",
        f"Caller (masked): {scope.get('user_phone_masked') or '(unknown)'}",
        f"UTC window: {scope.get('time_window_utc')}",
        "",
    ]
    if question:
        parts += ["=== USER QUESTION ===", question.strip(), ""]
    parts += [facts]
    user = "\n".join(parts) + "\n"
    try:
        text, provider = llm_call_for_log_analysis(system_prompt, user, max_tokens=1800)
        return {"text": text, "provider": provider}
    except Exception as exc:
        return {"text": "", "provider": None, "error": str(exc)}


def _fallback_block(title: str, facts: str, scope: dict, question: str, footer: str) -> str:
    out = [
        f"# {title}",
        "",
        f"**Scope:** primary `{scope.get('primary_connection_id') or '?'}`  ·  "
        f"related: {scope.get('related_connection_ids') or 'none'}  ·  "
        f"tenant `{scope.get('tenant') or '?'}`  ·  "
        f"caller `{scope.get('user_phone_masked') or '?'}`  ·  "
        f"UTC window {scope.get('time_window_utc')}",
        "",
    ]
    if question:
        out += [f"**Question:** {question}", ""]
    out += [facts, "", f"_{footer}_", ""]
    return "\n".join(out)


def _render(
    system_generic: str,
    system_question: str,
    facts: str,
    scope: dict,
    question: str,
    *,
    use_llm: bool,
    fallback_title: str,
) -> dict:
    if use_llm:
        sys_prompt = system_question if question else system_generic
        out = _llm_render(sys_prompt, facts, scope, question=question)
        if out.get("text"):
            return out
    return {
        "text": _fallback_block(
            fallback_title,
            facts,
            scope,
            question,
            "No LLM provider configured — facts above are the deterministic output. "
            "Set `OPENAI_API_KEY` (or `OPENAI_BASE_URL` for a local model) in Settings "
            "for the polished prose write-up.",
        ),
        "provider": "builtin",
    }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def _compute_time_window(log_groups: list[list]) -> list[str]:
    starts: list[str] = []
    ends: list[str] = []
    for grp in log_groups or []:
        for log in grp or []:
            ts = ""
            if isinstance(log, dict):
                ts = str(log.get("timestamp") or "")
                if not ts:
                    ts = str(_gn(_src(log), "@timestamp") or "")
            if ts:
                starts.append(ts)
                ends.append(ts)
    if not starts:
        return ["", ""]
    return [min(starts), max(ends)]


def analyse(
    primary: dict,
    related: list[dict] | None = None,
    *,
    question: str = "",
    use_llm: bool = True,
) -> dict:
    """Run the full Session RCA pipeline.

    Args:
        primary: ``{"connection_id":..., "be_logs":[...], "im_logs":[...], "ss_logs":[...]}``
        related: list of the same shape — auto-correlated retry calls etc.
        question: optional free-form user question. When set, the LLM answers it
                  grounded in the facts; when empty, produces a generic structured RCA.
        use_llm: if False (or no provider configured), emits the deterministic
                 facts block as the three drafts.

    Returns:
        ``{scope, signals, detected_modes, drafts, log_analysis_llm, question}``
    """
    related = related or []
    question = (question or "").strip()

    primary_be = primary.get("be_logs") or []
    primary_im = primary.get("im_logs") or []
    primary_ss = primary.get("ss_logs") or []
    p_signals = extract_signals(primary_be, primary_im, primary_ss)
    p_modes = detect_modes(p_signals)

    related_blocks: list[dict] = []
    for r in related:
        rs = extract_signals(
            r.get("be_logs") or [], r.get("im_logs") or [], r.get("ss_logs") or []
        )
        rm = detect_modes(rs)
        related_blocks.append({
            "connection_id": (
                r.get("connection_id")
                or rs.get("metadata", {}).get("connection_id")
                or ""
            ),
            "signals": rs,
            "detected_modes": rm,
        })

    primary_cid = (
        primary.get("connection_id")
        or p_signals.get("metadata", {}).get("connection_id")
        or ""
    )
    log_groups = [primary_be, primary_im, primary_ss]
    for r in related:
        log_groups.append(r.get("be_logs") or [])
        log_groups.append(r.get("im_logs") or [])
        log_groups.append(r.get("ss_logs") or [])

    scope = {
        "primary_connection_id": primary_cid,
        "related_connection_ids": [
            b["connection_id"] for b in related_blocks if b.get("connection_id")
        ],
        "tenant": p_signals.get("metadata", {}).get("tenant") or "",
        "user_phone_masked": p_signals.get("metadata", {}).get("user_phone_masked") or "",
        "time_window_utc": _compute_time_window(log_groups),
    }

    facts = build_facts_block(p_signals, p_modes, related_blocks)

    rca = _render(
        _RCA_SYSTEM_GENERIC, _RCA_SYSTEM_QUESTION,
        facts, scope, question, use_llm=use_llm, fallback_title="Session RCA",
    )
    client = _render(
        _CLIENT_SYSTEM_GENERIC, _CLIENT_SYSTEM_QUESTION,
        facts, scope, question, use_llm=use_llm, fallback_title="Client ticket update — facts only",
    )
    internal = _render(
        _INTERNAL_SYSTEM_GENERIC, _INTERNAL_SYSTEM_QUESTION,
        facts, scope, question, use_llm=use_llm, fallback_title="Internal engineering ticket — facts only",
    )

    provider = next(
        (p["provider"] for p in (rca, client, internal) if p.get("provider") and p["provider"] != "builtin"),
        "builtin",
    )

    all_modes = sorted(
        {m["id"] for m in p_modes}
        | {m["id"] for blk in related_blocks for m in blk.get("detected_modes", [])}
    )

    return {
        "scope": scope,
        "question": question,
        "signals": {
            "primary": _strip_internal_fields(p_signals),
            "related": [
                {
                    "connection_id": b["connection_id"],
                    "signals": _strip_internal_fields(b["signals"]),
                    "detected_modes": b["detected_modes"],
                }
                for b in related_blocks
            ],
        },
        "detected_modes": all_modes,
        "drafts": {
            "rca_markdown": rca["text"],
            "client_markdown": client["text"],
            "internal_markdown": internal["text"],
        },
        "log_analysis_llm": provider,
    }
