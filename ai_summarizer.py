"""
AI: OpenAI-compatible Chat Completions for RCA summaries, email/ticket rephrase, and log analysis.

This app cannot use Cursor's in-editor chat as an HTTP backend. You choose the model host:

  OPENAI_API_KEY   — Bearer token (OpenAI, Groq, OpenRouter, etc.). Often omitted for local Ollama.
  OPENAI_BASE_URL  — default https://api.openai.com/v1
                     Groq API: https://api.groq.com/openai/v1 (not console.groq.com / playground)
                     Ollama: http://127.0.0.1:11434/v1
  OPENAI_MODEL     — default gpt-4o-mini on OpenAI; on Groq, OpenAI-style gpt-* ids are replaced by
                     a Groq production model (override with OPENAI_MODEL_GROQ or set OPENAI_MODEL to a Groq id)
  OPENAI_MAX_RETRIES — retries on 429/502/503 (default 5, max 8)
  OPENAI_VERIFY_SSL — set to 0 to skip TLS verify (corporate proxy / broken Windows CA store only; insecure)
"""

from __future__ import annotations

import json
import os
import time
from typing import Any
from urllib.parse import urlparse


def _openai_base_url() -> str:
    """
    Resolve the Chat Completions base URL (no trailing slash, no /chat/completions suffix).

    Groq's browser console/playground URLs are not the API and often cause SSL errors;
    we normalize those to https://api.groq.com/openai/v1.
    """
    default = "https://api.openai.com/v1"
    raw = os.environ.get("OPENAI_BASE_URL", default).strip().rstrip("/")
    if not raw:
        return default.rstrip("/")
    lower = raw.lower()
    if "console.groq.com" in lower or "/playground" in lower:
        return "https://api.groq.com/openai/v1"
    if "groq.com" in lower and "api.groq.com" not in lower:
        return "https://api.groq.com/openai/v1"
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    host = (parsed.hostname or "").lower()
    if host == "api.groq.com":
        path = (parsed.path or "").rstrip("/")
        if path != "/openai/v1":
            return "https://api.groq.com/openai/v1"
    return raw.rstrip("/")


# When OPENAI_BASE_URL is Groq, OpenAI product ids (gpt-*) are not valid; use a GroqCloud chat model.
_GROQ_DEFAULT_CHAT_MODEL = "llama-3.3-70b-versatile"


def _openai_model_name() -> str:
    """Effective chat model: Groq-safe default if base URL is Groq but OPENAI_MODEL is still an OpenAI id."""
    raw = os.environ.get("OPENAI_MODEL", "").strip()
    base = _openai_base_url().lower()
    if "groq.com" not in base:
        return raw or "gpt-4o-mini"
    if not raw or raw.startswith("gpt-"):
        return os.environ.get("OPENAI_MODEL_GROQ", _GROQ_DEFAULT_CHAT_MODEL).strip() or _GROQ_DEFAULT_CHAT_MODEL
    return raw


def _openai_configured() -> bool:
    if os.environ.get("OPENAI_API_KEY", "").strip():
        return True
    base = _openai_base_url().lower()
    if "127.0.0.1" in base or "localhost" in base or "ollama" in base:
        return True
    return False


def _get_provider() -> str:
    """Return 'openai' when Chat Completions can run, else 'none'."""
    return "openai" if _openai_configured() else "none"


def log_analysis_meta_for_status() -> dict[str, str]:
    """Fields merged into /api/bot-engine/status for the UI."""
    ok = _get_provider() != "none"
    return {
        "log_analysis_provider": "openai" if ok else "none",
        "log_analysis_provider_label": "OpenAI-compatible API" if ok else "Not configured",
    }


def _estimate_tokens(text: str) -> int:
    """Cheap token estimate (~4 chars/token works for English + log lines)."""
    if not text:
        return 0
    return max(1, len(text) // 4)


def _llm_tpm_budget() -> int:
    """
    Per-request token budget (input + output) the upstream model is willing
    to accept *right now*.

    Tunable via LLM_TPM_BUDGET. If unset:
      - Groq (api.groq.com): default 5500 — Groq's free/on-demand tier is
        ~6000 TPM for llama-3.1-8b-instant; we leave 500 headroom for the
        200-token system overhead Groq adds.
      - Anything else: 60000 (well below OpenAI's 200k+ context but enough
        for our ~5k-token prompts).
    """
    raw = os.environ.get("LLM_TPM_BUDGET", "").strip()
    if raw:
        try:
            v = int(raw)
            if v > 0:
                return v
        except ValueError:
            pass
    base = _openai_base_url().lower()
    if "groq.com" in base:
        return 5500
    return 60000


_LOG_ENTRIES_MARKER = "=== LOG ENTRIES ==="
_COMBINED_SECTION_MARKERS = (
    "=== BOT ENGINE LOGS ===",
    "=== INTEGRATION MANAGER LOGS ===",
    "=== STREAM SERVER LOGS ===",
)


def _score_log_line(line: str, idx: int, n: int) -> int:
    """Errors/warnings highest, then first/last entries, then info."""
    s = 0
    ll = line.lower()
    if "error_code=" in ll or "error_msg=" in ll:
        s += 1000
    if "level=50" in line or "level=fatal" in ll or "level=error" in ll:
        s += 800
    if "level=40" in line or "level=warn" in ll:
        s += 400
    if idx < 10 or idx >= n - 10:
        s += 100  # keep boundaries
    return s


def _split_combined_sections(body: str) -> list[tuple[str, list[str]]]:
    """Split the combined-RCA body into (section_header_block, lines) pairs.

    Returns at least one entry. The first entry's header_block contains every line up to (and
    including) the first known section marker; subsequent entries each carry one section.
    """
    markers = list(_COMBINED_SECTION_MARKERS)
    indices: list[tuple[int, str]] = []
    for marker in markers:
        i = body.find(marker)
        if i != -1:
            indices.append((i, marker))
    indices.sort()
    if not indices:
        return [("", [ln for ln in body.split("\n")])]
    sections: list[tuple[str, list[str]]] = []
    head = body[: indices[0][0]]
    sections.append((head, []))  # head-only block (identifiers, summary)
    for n, (start, marker) in enumerate(indices):
        end = indices[n + 1][0] if n + 1 < len(indices) else len(body)
        chunk = body[start:end]
        first_nl = chunk.find("\n")
        header = chunk[: first_nl + 1] if first_nl != -1 else chunk
        rest = chunk[first_nl + 1 :] if first_nl != -1 else ""
        lines = [ln for ln in rest.split("\n")]
        sections.append((header, lines))
    return sections


def _trim_lines_to_budget(lines: list[str], token_budget: int) -> tuple[list[str], int]:
    """Pick lines that fit ``token_budget`` (errors/warns first, then boundaries). Returns (kept_in_orig_order, dropped_count)."""
    nonempty = [(i, ln) for i, ln in enumerate(lines) if ln.strip()]
    if not nonempty or token_budget <= 0:
        return [], len(nonempty)
    n = len(nonempty)
    scored = [(orig_i, ln, _score_log_line(ln, idx, n)) for idx, (orig_i, ln) in enumerate(nonempty)]
    scored.sort(key=lambda t: (-t[2], t[0]))
    kept_idx: set[int] = set()
    used = 0
    for orig_i, ln, _s in scored:
        ltok = _estimate_tokens(ln) + 1
        if used + ltok > token_budget:
            continue
        kept_idx.add(orig_i)
        used += ltok
    kept = [ln for i, ln in nonempty if i in kept_idx]
    dropped = n - len(kept)
    return kept, dropped


def _trim_user_prompt_to_budget(
    system_prompt: str,
    user_prompt: str,
    max_tokens: int,
    budget: int | None = None,
) -> tuple[str, int, dict[str, int]]:
    """
    Trim ``user_prompt`` so estimated total tokens (system + user + max_tokens
    + 256 safety) <= ``budget``. Returns (new_user_prompt, adjusted_max_tokens, info).

    Two prompt shapes are supported:
      1) Single-source: keeps the header before "=== LOG ENTRIES ===", trims lines after.
      2) Combined RCA: detects "=== BOT ENGINE LOGS ===", "=== INTEGRATION MANAGER LOGS ===",
         "=== STREAM SERVER LOGS ===" and trims each section's lines proportionally to its size,
         preserving section headers + errors/warnings first.
    """
    if budget is None:
        budget = _llm_tpm_budget()
    safety = 256
    sys_t = _estimate_tokens(system_prompt)
    cur_t = _estimate_tokens(user_prompt)
    total = sys_t + cur_t + max_tokens + safety
    info = {
        "estimated_total": total,
        "system_tokens": sys_t,
        "user_tokens_before": cur_t,
        "user_tokens_after": cur_t,
        "max_tokens_before": max_tokens,
        "max_tokens_after": max_tokens,
        "budget": budget,
        "trimmed_lines": 0,
        "kept_lines": 0,
        "mode": "noop",
    }
    if total <= budget:
        return user_prompt, max_tokens, info

    # Step 1: cap max_tokens so we always leave at least 800 tokens for the answer.
    overflow = total - budget
    if overflow > 0 and max_tokens > 800:
        shrink = min(max_tokens - 800, overflow)
        max_tokens = max_tokens - shrink
        info["max_tokens_after"] = max_tokens
        total -= shrink

    if total <= budget:
        info["mode"] = "max_tokens_only"
        return user_prompt, max_tokens, info

    # Step 2: detect combined-RCA shape (3 source sections) vs single-source.
    is_combined = sum(1 for m in _COMBINED_SECTION_MARKERS if m in user_prompt) >= 2

    if is_combined:
        info["mode"] = "combined"
        sections = _split_combined_sections(user_prompt)
        head_block = sections[0][0]  # IDENTIFIERS + SOURCE SUMMARY
        head_t = _estimate_tokens(head_block)
        per_section_overhead = sum(_estimate_tokens(hdr) for hdr, _ln in sections[1:]) + len(sections[1:]) * 16
        ellipsis_overhead = len(sections[1:]) * 32
        available = budget - sys_t - max_tokens - safety - head_t - per_section_overhead - ellipsis_overhead
        if available < 0:
            available = 0
        # Allocate to each section by line count so big sources lose more lines.
        line_counts = [max(1, len([ln for ln in lines if ln.strip()])) for _hdr, lines in sections[1:]]
        total_lines = sum(line_counts) or 1
        per_section_budget = [max(150, int(available * c / total_lines)) for c in line_counts]
        # Reduce floor if budget can't satisfy them all.
        if sum(per_section_budget) > available and available > 0:
            scale = available / sum(per_section_budget)
            per_section_budget = [max(80, int(b * scale)) for b in per_section_budget]

        rebuilt = [head_block.rstrip("\n")] if head_block.strip() else []
        total_dropped = 0
        total_kept = 0
        for (header, lines), bud in zip(sections[1:], per_section_budget):
            kept, dropped = _trim_lines_to_budget(lines, bud)
            total_dropped += dropped
            total_kept += len(kept)
            block = header.rstrip("\n")
            if kept:
                block += "\n" + "\n".join(kept)
            if dropped > 0:
                block += f"\n... [trimmed {dropped} lower-priority entries to fit token budget; errors/warnings preserved] ..."
            rebuilt.append(block)
        new_user = "\n\n".join(rebuilt) + "\n"
        info["user_tokens_after"] = _estimate_tokens(new_user)
        info["trimmed_lines"] = total_dropped
        info["kept_lines"] = total_kept
        return new_user, max_tokens, info

    # Single-source path: trim below the LOG ENTRIES marker.
    if _LOG_ENTRIES_MARKER in user_prompt:
        head, _, tail = user_prompt.partition(_LOG_ENTRIES_MARKER)
        head_with_marker = head + _LOG_ENTRIES_MARKER + "\n"
    else:
        head_with_marker = ""
        tail = user_prompt

    lines = [ln for ln in tail.split("\n") if ln.strip()]
    if not lines:
        return user_prompt, max_tokens, info

    head_t = _estimate_tokens(head_with_marker)
    available_for_lines = budget - sys_t - max_tokens - safety - head_t - 64
    if available_for_lines < 0:
        available_for_lines = 0

    kept, dropped = _trim_lines_to_budget(lines, available_for_lines)
    if dropped > 0:
        kept = list(kept) + [
            f"... [truncated to fit token budget: dropped {dropped} of {len(lines)} log entries; errors/warnings preserved] ..."
        ]

    new_user = head_with_marker + "\n".join(kept)
    info["user_tokens_after"] = _estimate_tokens(new_user)
    info["trimmed_lines"] = dropped
    info["kept_lines"] = len(kept)
    info["mode"] = "single_source"
    return new_user, max_tokens, info


def _parse_provider_limit(msg: str) -> int | None:
    """Extract the upstream's reported TPM Limit when the body says 'Limit X, Requested Y'."""
    import re as _re
    m = _re.search(r"Limit\s+(\d+)\s*,\s*Requested\s+(\d+)", msg)
    if m:
        return int(m.group(1))
    return None


def llm_call_for_log_analysis(system_prompt: str, user_prompt: str, max_tokens: int = 3000) -> tuple[str, str]:
    """
    Run log analysis with progressive trim retries on HTTP 413 / rate_limit_exceeded.

    Strategy:
      attempt 1: trim to default TPM budget, full max_tokens
      attempt 2 (on 413): trim to 0.80 * provider-reported limit, halve max_tokens
      attempt 3 (still 413): trim to 0.55 * provider-reported limit, max_tokens=800

    Returns (response_text, provider_key).
    """
    if _get_provider() == "none":
        raise RuntimeError(
            "Log analysis needs an LLM. Set OPENAI_API_KEY in Settings, or OPENAI_BASE_URL to a "
            "local OpenAI-compatible server (e.g. Ollama at http://127.0.0.1:11434/v1)."
        )

    trimmed_user, eff_max_tokens, _info = _trim_user_prompt_to_budget(
        system_prompt, user_prompt, max_tokens
    )
    last_exc: RuntimeError | None = None
    last_msg: str = ""
    last_limit: int | None = None
    try:
        text = llm_call(system_prompt, trimmed_user, eff_max_tokens)
        return text, "openai"
    except RuntimeError as exc:
        msg = str(exc)
        if "HTTP 413" not in msg and "rate_limit_exceeded" not in msg:
            raise
        last_exc = exc
        last_msg = msg
        last_limit = _parse_provider_limit(msg)

    # ----- attempt 2: aggressively re-trim
    base_budget = last_limit if last_limit else _llm_tpm_budget()
    new_budget = max(1024, int(base_budget * 0.80))
    retrimmed_user, retry_max_tokens, retry_info = _trim_user_prompt_to_budget(
        system_prompt, user_prompt, max(800, eff_max_tokens // 2), budget=new_budget
    )
    try:
        text = llm_call(system_prompt, retrimmed_user, retry_max_tokens)
        return text, "openai"
    except RuntimeError as exc2:
        msg2 = str(exc2)
        if "HTTP 413" not in msg2 and "rate_limit_exceeded" not in msg2:
            raise
        last_exc = exc2
        last_msg = msg2
        last_limit = _parse_provider_limit(msg2) or last_limit

    # ----- attempt 3: extreme shrink (errors/warnings only)
    limit3 = last_limit or _llm_tpm_budget()
    extreme_budget = max(900, int(limit3 * 0.55))
    final_user, final_max_tokens, final_info = _trim_user_prompt_to_budget(
        system_prompt, user_prompt, 800, budget=extreme_budget
    )
    try:
        text = llm_call(system_prompt, final_user, final_max_tokens)
        return text, "openai"
    except RuntimeError as exc3:
        msg3 = str(exc3)
        if "HTTP 413" in msg3 or "rate_limit_exceeded" in msg3:
            kept = final_info.get("kept_lines", retry_info.get("kept_lines", 0))
            dropped = final_info.get("trimmed_lines", retry_info.get("trimmed_lines", 0))
            hint = (
                f" Auto-trimmed to {kept} lines (dropped {dropped}) and retried 3 times "
                f"(final budget {extreme_budget} TPM, max_tokens {final_max_tokens}), but the provider "
                "still rejected the request. Either fetch fewer logs (tighten the time window or "
                "add Context ID), switch to a model with a larger TPM (Groq llama-3.3-70b-versatile "
                "via OPENAI_MODEL_GROQ, or set OPENAI_BASE_URL to OpenAI / Ollama), or upgrade your "
                "Groq tier at https://console.groq.com/settings/billing."
            )
            raise RuntimeError(str(exc3) + hint) from exc3
        raise


def _requests_verify_bundle():
    """
    What to pass as requests' verify=... argument.
    Uses certifi's Mozilla CA bundle when verification is on (helps Windows Python).
    """
    if os.environ.get("OPENAI_VERIFY_SSL", "1").strip().lower() in ("0", "false", "no"):
        return False
    try:
        import certifi

        return certifi.where()
    except ImportError:
        return True


def _http_retry_sleep_seconds(resp, attempt: int) -> float:
    ra = (resp.headers.get("Retry-After") or "").strip()
    if ra:
        try:
            return min(120.0, float(ra))
        except ValueError:
            pass
    if resp.status_code == 429:
        return min(120.0, max(8.0, 2.0**attempt * 4.0))
    return min(32.0, 2.0**attempt)


def llm_call(system_prompt: str, user_prompt: str, max_tokens: int = 1200) -> str:
    """
    Call an OpenAI-compatible /v1/chat/completions endpoint.
    Retries on HTTP 429 / 502 / 503.
    """
    if not _openai_configured():
        raise RuntimeError(
            "No LLM configured. Set OPENAI_API_KEY in .env or Settings (e.g. from platform.openai.com), "
            "or set OPENAI_BASE_URL to a local OpenAI-compatible server such as "
            "http://127.0.0.1:11434/v1 for Ollama."
        )
    import requests as _req

    base = _openai_base_url()
    model = _openai_model_name()
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    url = f"{base}/chat/completions"
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    payload: dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.3,
        "max_tokens": max_tokens,
    }

    try:
        max_retries = int(os.environ.get("OPENAI_MAX_RETRIES", "5") or "5")
    except ValueError:
        max_retries = 5
    max_retries = max(1, min(8, max_retries))
    retry_statuses = {429, 502, 503}
    verify = _requests_verify_bundle()

    last_status: int | None = None
    last_body = ""
    for attempt in range(max_retries):
        try:
            resp = _req.post(url, json=payload, headers=headers, timeout=120, verify=verify)
        except _req.exceptions.SSLError as exc:
            raise RuntimeError(
                "SSL certificate verification failed when calling the LLM (e.g. Groq). "
                "Try: pip install -U certifi requests, restart the app, and retry. "
                "If you are on a corporate VPN/proxy that inspects HTTPS, set OPENAI_VERIFY_SSL=0 "
                "in Settings (disables TLS verification; use only if you accept that risk). "
                f"Details: {exc}"
            ) from exc
        last_status = resp.status_code
        if resp.ok:
            data = resp.json()
            choices = data.get("choices") or []
            if not choices:
                raise RuntimeError("LLM returned no choices: " + json.dumps(data)[:800])
            msg = choices[0].get("message") or {}
            content = msg.get("content")
            if content is None:
                raise RuntimeError("LLM returned empty message: " + json.dumps(choices[0])[:800])
            return str(content).strip()
        try:
            last_body = (resp.text or "")[:1200]
        except Exception:
            last_body = ""
        if resp.status_code in retry_statuses and attempt < max_retries - 1:
            time.sleep(_http_retry_sleep_seconds(resp, attempt))
            continue
        break

    hint = ""
    if last_status in retry_statuses:
        hint = " The service may be rate-limited or temporarily unavailable — wait and retry, or try another model."
    elif last_status == 404 and "model_not_found" in (last_body or "").lower():
        hint = (
            " The model id is wrong for this API host — set OPENAI_MODEL to one your provider lists "
            "(Groq: e.g. llama-3.3-70b-versatile or llama-3.1-8b-instant; OpenAI: gpt-4o-mini)."
        )
    raise RuntimeError(f"LLM API error HTTP {last_status}.{hint} Details: {last_body or '(empty body)'}")


def summarize_rca(rca_data: dict[str, Any]) -> str | None:
    """
    Send RCA data to the configured model and return a formatted executive summary.
    Returns None if no LLM is configured or the call fails.
    """
    if _get_provider() == "none":
        return None

    prompt_data = _build_prompt_data(rca_data)

    system_prompt = (
        "You are a senior Site Reliability Engineer writing an RCA (Root Cause Analysis) "
        "report for a production incident. Based on the data provided, produce a clear, "
        "easy-to-understand summary organized into the following sections. "
        "Each section MUST appear even if there is nothing notable (say 'No issues detected').\n\n"
        "**Overview**: 1-2 sentences on what happened — total errors, top impacted tenants, time window.\n\n"
        "**Bot Engine Restarts**: Were any bot engine pods restarted recently? "
        "List affected tenants and pod names with their age. "
        "Explain whether the restarts correlate with the errors.\n\n"
        "**Bot Engine Analysis**: What errors were found in bot engine logs? "
        "Highlight specific error codes and counts. "
        "Mention which tenants are affected.\n\n"
        "**Twilio Analysis**: Were there any failed calls or Twilio errors? "
        "Highlight error codes, failed call counts, and affected accounts.\n\n"
        "**Error Patterns**: What are the most common error stacks and messages? "
        "Identify the root cause pattern — is it systemic (affecting many tenants) or tenant-specific? "
        "Mention K8s version correlation if significant.\n\n"
        "**Recommendation**: Concrete next steps to investigate or resolve the issue.\n\n"
        "Rules:\n"
        "- Write in plain, non-technical language so that anyone can understand.\n"
        "- Use the exact tenant names, error codes, and numbers from the data.\n"
        "- Keep each section to 2-3 sentences max.\n"
        "- If there is no clear root cause, say so and suggest investigation steps.\n"
        "- Do NOT use markdown headers (##). Use **Bold** labels only as shown above.\n"
        "- Do NOT add any disclaimers or caveats about being an AI."
    )

    try:
        return llm_call(system_prompt, prompt_data, max_tokens=1200)
    except Exception:
        return None


def _build_prompt_data(rca: dict[str, Any]) -> str:
    """Assemble a structured text block from the RCA dict for the AI prompt."""
    lines: list[str] = []

    # ---- Overview data ----
    lines.append("=== OVERVIEW ===")
    lines.append(f"Total errors: {rca.get('total_errors', 0)}")

    top = rca.get("top_tenants") or []
    if top:
        lines.append("Top impacted tenants:")
        for t in top:
            codes = ", ".join(f"{c['code']} ({c['count']})" for c in (t.get("error_codes") or []))
            lines.append(
                f"  - {t['tenant_name']}: {t['total_errors']} errors"
                + (f", error codes: {codes}" if codes else "")
            )

    summary = rca.get("rca_summary", "")
    if summary:
        lines.append(f"Summary: {summary}")

    # ---- Bot Engine Restarts data ----
    lines.append("\n=== BOT ENGINE RESTARTS ===")
    lines.append(f"Pod restarts detected globally: {'Yes' if rca.get('restart_detected') else 'No'}")
    lines.append(f"Total restart count: {rca.get('total_restarts', 0)}")
    if top:
        for t in top:
            restart = "Yes" if t.get("restart_detected") else "No"
            pods = (t.get("restart_pods") or [])
            pod_info = ", ".join(f"{p['name']} (age {p.get('age', '?')})" for p in pods)
            lines.append(
                f"  - {t['tenant_name']} (namespace: {t.get('namespace', '?')}): "
                f"recent restart = {restart}"
                + (f" — pods: {pod_info}" if pod_info else "")
            )

    # ---- Bot Engine Analysis data ----
    lines.append("\n=== BOT ENGINE ANALYSIS ===")
    be_analysis = rca.get("bot_engine_analysis", "")
    if be_analysis:
        lines.append(f"Analysis: {be_analysis}")

    be_codes = rca.get("bot_engine_error_codes") or {}
    if be_codes:
        codes_str = ", ".join(f"{c} ({n}x)" for c, n in sorted(be_codes.items(), key=lambda x: -x[1]))
        lines.append(f"Error codes found: {codes_str}")
    else:
        lines.append("No bot engine error codes found.")

    be_conn = rca.get("bot_engine_conn_findings") or []
    if be_conn:
        lines.append(f"Connection-level findings: {len(be_conn)} entries")

    # ---- Twilio Analysis data ----
    lines.append("\n=== TWILIO ANALYSIS ===")
    twilio = rca.get("twilio_analysis", "")
    if twilio and twilio not in ("Twilio not configured.",):
        lines.append(f"Analysis: {twilio}")
    else:
        lines.append("Twilio not configured or no data.")

    twilio_total = rca.get("twilio_total_calls", 0)
    twilio_failed = rca.get("twilio_failed_calls", 0)
    if twilio_total:
        lines.append(f"Total calls: {twilio_total}, Failed calls: {twilio_failed}")

    twilio_err = rca.get("twilio_error_codes") or {}
    if twilio_err:
        codes_str = ", ".join(f"{c} ({n}x)" for c, n in sorted(twilio_err.items(), key=lambda x: -x[1]))
        lines.append(f"Twilio error codes: {codes_str}")

    twilio_accounts = rca.get("twilio_accounts_checked", 0)
    if twilio_accounts:
        lines.append(f"Accounts checked: {twilio_accounts}")

    # ---- Error Patterns data ----
    patterns = rca.get("error_patterns") or {}
    if patterns.get("total_analyzed"):
        lines.append(f"\n=== ERROR PATTERNS ({patterns['total_analyzed']} logs analyzed) ===")

        top_stacks = patterns.get("top_stacks") or []
        if top_stacks:
            lines.append("Top error stacks:")
            for s in top_stacks[:7]:
                tenants = ", ".join(s.get("tenants", []))
                if s.get("tenant_count", 0) > 5:
                    tenants += f" +{s['tenant_count'] - 5} more"
                codes = ", ".join(f"{c}({n})" for c, n in (s.get("error_codes") or {}).items())
                lines.append(f"  - [{s['count']}x] {s['stack']}")
                lines.append(f"    Codes: {codes}  |  Tenants: {tenants or 'unknown'}")

        top_msgs = patterns.get("top_messages") or []
        if top_msgs:
            lines.append("Top error messages:")
            for m in top_msgs[:5]:
                lines.append(f"  - [{m['count']}x] {m['message']}")

        k8s = patterns.get("k8s_versions") or []
        if k8s:
            lines.append("K8s version distribution:")
            for v in k8s[:5]:
                lines.append(f"  - {v['version']}: {v['count']} errors")

        ct = patterns.get("cross_tenant") or []
        if ct:
            lines.append("Cross-tenant patterns:")
            for c in ct:
                scope = "SYSTEMIC" if c.get("systemic") else "tenant-specific"
                lines.append(f"  - Error {c['error_code']}: {c['tenant_count']} tenants ({scope})")

    # ---- Root Causes ----
    root_causes = patterns.get("root_causes") or [] if patterns else []
    if root_causes:
        lines.append("\n=== ROOT CAUSE CLASSIFICATION ===")
        for rc in root_causes:
            lines.append(f"  [{rc['severity']}] {rc['category']}: {rc['count']} errors ({rc['percentage']}%)")
            lines.append(f"    Description: {rc['description']}")
            lines.append(f"    Recommendation: {rc['recommendation']}")

    # ---- Connections ----
    conns = patterns.get("connections") or [] if patterns else []
    if conns:
        lines.append("\n=== CONNECTIONS & CORRELATIONS ===")
        for cn in conns:
            lines.append(f"  [{cn['type']}] {cn['description']}")
            lines.append(f"    Impact: {cn['impact']}")

    # ---- Detailed findings ----
    details = rca.get("rca_details") or []
    if details:
        lines.append("\n=== DETAILED FINDINGS ===")
        for d in details:
            lines.append(f"  - {d}")

    return "\n".join(lines)
