"""
AI-powered RCA summarizer using OpenAI GPT-4o-mini.

Takes the raw RCA dict produced by generate_rca() and returns a concise,
executive-style summary covering Impact, Root Cause, Evidence, and
Recommendations.

Configure via environment:
  OPENAI_API_KEY  - OpenAI API key (required)
  OPENAI_MODEL    - Model to use (default: gpt-4o-mini)
"""

from __future__ import annotations

import json
import os
from typing import Any


def summarize_rca(rca_data: dict[str, Any]) -> str | None:
    """
    Send RCA data to OpenAI and return a formatted executive summary.
    Returns None if OpenAI is not configured or the call fails.
    """
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        return None

    try:
        from openai import OpenAI
    except ImportError:
        return None

    model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini").strip()

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
        client = OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt_data},
            ],
            temperature=0.3,
            max_tokens=900,
        )
        return response.choices[0].message.content.strip()
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

    # ---- Detailed findings ----
    details = rca.get("rca_details") or []
    if details:
        lines.append("\n=== DETAILED FINDINGS ===")
        for d in details:
            lines.append(f"  - {d}")

    return "\n".join(lines)
