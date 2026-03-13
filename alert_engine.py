"""
Stream Server Alerts – Runner / engine.

Loads stream_server_alerts.yaml, matches alerts to scenarios by error codes,
runs steps (pluggable), and evaluates decision_rules to output conclusion + next_action.
Loads .env from project folder so OPENSEARCH_* are set when connecting to OpenSearch.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

# Load .env so OPENSEARCH_URL etc. are available (for opensearch_client)
try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent / ".env")
except ImportError:
    pass

try:
    import yaml
except ImportError:
    yaml = None


# -----------------------------------------------------------------------------
# Config loading
# -----------------------------------------------------------------------------

def load_config(path: str | Path) -> dict[str, Any]:
    if yaml is None:
        raise RuntimeError("PyYAML required. Install with: pip install pyyaml  # or: pip install -r requirements.txt")
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Config not found: {path}")
    with open(p, encoding="utf-8") as f:
        return yaml.safe_load(f)


def find_scenario(config: dict[str, Any], error_codes: list[int]) -> dict[str, Any] | None:
    """Find first scenario whose match.error_codes contains any of the given error_codes."""
    codes_set = set(error_codes)
    for scenario in config.get("scenarios", []):
        match = scenario.get("match") or {}
        scenario_codes = match.get("error_codes") or []
        if codes_set & set(scenario_codes):
            return scenario
    return None


# -----------------------------------------------------------------------------
# Step implementations (populate context for decision_rules; replace with real APIs)
# -----------------------------------------------------------------------------

def _get_simulate(ctx: dict[str, Any], key: str, default: Any = None) -> Any:
    """Read optional simulate overrides from context for testing/demo."""
    sim = ctx.get("simulate")
    if isinstance(sim, dict) and key in sim:
        return sim[key]
    return default


def _query_opensearch_once(ctx: dict[str, Any], time_minutes: int | None = None) -> None:
    """Query OpenSearch directly for errors; set opensearch_* and error_count/impacted_tenants from real data."""
    if ctx.get("opensearch_queried"):
        return
    if time_minutes is None:
        time_minutes = max(1, min(43200, int(ctx.get("_time_minutes", 60))))  # 1 min to 30 days (Discover range)
    try:
        from opensearch_client import query_errors
        error_codes = ctx.get("_error_codes") or [500, 503, 400]
        error_names = ctx.get("_error_names") if ctx.get("_error_names") else None
        tenant_filter = ctx.get("_tenant_filter") or None
        result = query_errors(error_codes, time_minutes=time_minutes, sample_size=20, error_names=error_names, tenant_filter=tenant_filter)
        ctx["opensearch_queried"] = True
        if result is None:
            # OpenSearch not configured (no OPENSEARCH_URL)
            ctx["opensearch_available"] = False
            ctx["opensearch_total"] = 0
            ctx["error_count"] = 0
            ctx["opensearch_sample_errors"] = []
            return
        # Use OpenSearch data directly (no stub)
        ctx["opensearch_available"] = "error" not in result
        ctx["opensearch_total"] = result.get("total", 0)
        ctx["opensearch_tenants"] = result.get("tenants", [])
        ctx["error_count"] = result.get("total", 0)
        ctx["impacted_tenants"] = [t.get("name") or "" for t in result.get("tenants", []) if t.get("name")]
        ctx["opensearch_sample_errors"] = result.get("sample", [])
        ctx["opensearch_by_error_name"] = result.get("by_error_name", [])
        ctx["opensearch_error_name_field"] = result.get("error_name_field", "")
        ctx["opensearch_by_error_code"] = result.get("by_error_code", [])
        ctx["opensearch_error_code_field"] = result.get("error_code_field", "")
        ctx["opensearch_by_tenant_error_code"] = result.get("by_tenant_error_code", [])
        if result.get("error"):
            ctx["opensearch_error"] = result["error"]
    except Exception as e:
        ctx["opensearch_queried"] = True
        ctx["opensearch_available"] = False
        ctx["opensearch_error"] = str(e)
        ctx["opensearch_total"] = 0
        ctx["error_count"] = 0
        ctx["impacted_tenants"] = []
        ctx["opensearch_sample_errors"] = []


def step_get_error_count(ctx: dict[str, Any]) -> None:
    """Fetch error count from OpenSearch (if configured) or metrics/logs; store for reporting."""
    print("  [step] get_error_count")
    sim = _get_simulate(ctx, "error_count")
    if sim is not None:
        ctx["error_count"] = sim
        return
    _query_opensearch_once(ctx)
    if "error_count" not in ctx:
        ctx.setdefault("error_count", 0)


def step_get_impacted_tenants(ctx: dict[str, Any]) -> None:
    """Identify impacted tenants/CUs from OpenSearch (if configured) or error logs."""
    print("  [step] get_impacted_tenants")
    sim = _get_simulate(ctx, "impacted_tenants", None)
    if sim is not None:
        ctx["impacted_tenants"] = sim if isinstance(sim, list) else [sim]
        return
    _query_opensearch_once(ctx)
    if "impacted_tenants" not in ctx:
        ctx.setdefault("impacted_tenants", ["tenant-1"])


def step_check_prod_connectivity(ctx: dict[str, Any]) -> None:
    """Check if prod calls connect; sets calls_connect_successfully or calls_fail."""
    print("  [step] check_prod_connectivity")
    sim_ok = _get_simulate(ctx, "calls_ok")
    sim_fail = _get_simulate(ctx, "calls_fail")
    if sim_ok is not None:
        ctx["calls_connect_successfully"] = bool(sim_ok)
    if sim_fail is not None:
        ctx["calls_fail"] = bool(sim_fail)
    if "calls_connect_successfully" not in ctx and "calls_fail" not in ctx:
        # Default demo: assume connectivity OK (so restart rule can match)
        ctx["calls_connect_successfully"] = True
        ctx["calls_fail"] = False


def step_check_bot_restarts(ctx: dict[str, Any]) -> None:
    """Detect bot/pod restarts from Lens (Kubernetes API) and OpenSearch logs."""
    print("  [step] check_bot_restarts")
    sim = _get_simulate(ctx, "restart_detected")
    if sim is not None:
        ctx["restart_detected"] = bool(sim)
        return

    time_minutes = max(1, min(43200, int(ctx.get("_time_minutes", 60))))
    restart_detected = False

    # 1) Query Lens / Kubernetes for pod restart data
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=time_minutes)

    try:
        from lens_client import query_pod_restarts
        k8s_result = query_pod_restarts(time_minutes=time_minutes)
        if k8s_result is not None:
            import os
            _exclude_raw = os.environ.get("K8S_EXCLUDE_PODS", "bot-engine-demo-prod-0")
            _exclude_pods = {n.strip().lower() for n in _exclude_raw.split(",") if n.strip()}
            pods = [
                p for p in k8s_result.get("pods", [])
                if (p.get("name") or "").lower() not in _exclude_pods
            ]
            ctx["lens_pod_restarts"] = pods
            ctx["lens_total_restarts"] = k8s_result.get("total_restarts", 0)
            ctx["lens_pods_with_restarts"] = k8s_result.get("pods_with_restarts", 0)
            ctx["lens_available"] = "error" not in k8s_result
            if k8s_result.get("error"):
                ctx["lens_error"] = k8s_result["error"]

            # Age-based detection: any pod whose created_at is within the
            # time window is considered recently restarted/recreated.
            for p in pods:
                created = p.get("created_at")
                if not created:
                    continue
                try:
                    created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                    if created_dt >= cutoff:
                        restart_detected = True
                        break
                except Exception:
                    pass

            if not restart_detected and k8s_result.get("total_restarts", 0) > 0:
                restart_detected = True
        else:
            ctx["lens_available"] = False
            ctx["lens_pod_restarts"] = []
    except Exception as e:
        ctx["lens_available"] = False
        ctx["lens_pod_restarts"] = []
        ctx["lens_error"] = str(e)

    ctx["restart_detected"] = restart_detected


def step_check_twilio_logs(ctx: dict[str, Any]) -> None:
    """Fetch Twilio call logs and connection status within the time window."""
    print("  [step] check_twilio_logs")
    time_minutes = max(1, min(43200, int(ctx.get("_time_minutes", 60))))

    try:
        from twilio_client import query_call_logs, check_twilio_connection

        conn = check_twilio_connection()
        ctx["twilio_available"] = conn.get("connected", False)
        if not conn.get("connected"):
            ctx["twilio_error"] = conn.get("error", "unknown")
            ctx["twilio_calls"] = []
            ctx["twilio_log_summary"] = "not_configured"
            return

        # Only check Twilio subaccounts matching impacted tenants
        tenant_names = list(set(
            row.get("tenant_name") for row in ctx.get("opensearch_by_tenant_error_code", [])
            if row.get("tenant_name")
        )) or ctx.get("impacted_tenants", [])

        result = query_call_logs(time_minutes=time_minutes, tenant_names=tenant_names or None)
        if result.get("error"):
            ctx["twilio_error"] = result["error"]

        ctx["twilio_calls"] = result.get("calls", [])
        ctx["twilio_total_calls"] = result.get("total_calls", 0)
        ctx["twilio_failed_calls"] = result.get("failed_calls", 0)
        ctx["twilio_error_summary"] = result.get("error_summary", {})
        ctx["twilio_phone_status"] = result.get("phone_status", [])
        ctx["twilio_accounts_checked"] = result.get("accounts_checked", [])
        ctx["twilio_log_summary"] = "checked"

    except ImportError:
        ctx["twilio_available"] = False
        ctx["twilio_error"] = "twilio package not installed"
        ctx["twilio_calls"] = []
        ctx["twilio_log_summary"] = "not_configured"
    except Exception as e:
        ctx["twilio_available"] = False
        ctx["twilio_error"] = str(e)
        ctx["twilio_calls"] = []
        ctx["twilio_log_summary"] = "error"


def step_escalate_devops(ctx: dict[str, Any]) -> None:
    """Escalate to DevOps (ticket, bridge, etc.)."""
    print("  [step] escalate_devops")
    ctx.setdefault("escalation_devops", True)


def step_validate_auth_flow(ctx: dict[str, Any]) -> None:
    """Validate auth flow; sets auth_successful or auth_failure."""
    print("  [step] validate_auth_flow")
    sim_ok = _get_simulate(ctx, "auth_ok")
    sim_fail = _get_simulate(ctx, "auth_fail")
    if sim_ok is not None:
        ctx["auth_successful"] = bool(sim_ok)
    if sim_fail is not None:
        ctx["auth_failure"] = bool(sim_fail)
    if "auth_successful" not in ctx and "auth_failure" not in ctx:
        ctx["auth_successful"] = False
        ctx["auth_failure"] = True  # demo default for 400 path


def step_inspect_apt_logs(ctx: dict[str, Any]) -> None:
    """Inspect APT/auth logs."""
    print("  [step] inspect_apt_logs")
    ctx.setdefault("apt_log_summary", "not_checked")


def step_escalate_dev(ctx: dict[str, Any]) -> None:
    """Escalate to dev team with auth evidence."""
    print("  [step] escalate_dev")
    ctx.setdefault("escalation_dev", True)


def step_check_opensearch(ctx: dict[str, Any]) -> None:
    """Query OpenSearch directly for errors; populates error_count, impacted_tenants, and sample errors."""
    print("  [step] check_opensearch")
    _query_opensearch_once(ctx)
    if ctx.get("opensearch_available"):
        total = ctx.get("opensearch_total", 0)
        tenants = ctx.get("opensearch_tenants") or []
        sample = ctx.get("opensearch_sample_errors") or []
        print(f"    OpenSearch: total={total}, tenants={len(tenants)}, sample_errors={len(sample)}")
    else:
        err = ctx.get("opensearch_error")
        print(f"    OpenSearch: not configured or failed" + (f" ({err})" if err else ""))


STEP_REGISTRY: dict[str, callable] = {
    "check_opensearch": step_check_opensearch,
    "get_error_count": step_get_error_count,
    "get_impacted_tenants": step_get_impacted_tenants,
    "check_prod_connectivity": step_check_prod_connectivity,
    "check_bot_restarts": step_check_bot_restarts,
    "check_twilio_logs": step_check_twilio_logs,
    "escalate_devops": step_escalate_devops,
    "validate_auth_flow": step_validate_auth_flow,
    "inspect_apt_logs": step_inspect_apt_logs,
    "escalate_dev": step_escalate_dev,
}


def run_steps(scenario: dict[str, Any], context: dict[str, Any], registry: dict[str, callable] | None = None) -> None:
    """Run each step for the scenario; steps can read/update context."""
    reg = registry or STEP_REGISTRY
    for step_id in scenario.get("steps") or []:
        fn = reg.get(step_id)
        if fn:
            fn(context)
        else:
            print(f"  [step] {step_id} (no implementation)")


# -----------------------------------------------------------------------------
# Decision rule evaluation
# -----------------------------------------------------------------------------

def _evaluate_condition(condition: str, context: dict[str, Any]) -> bool:
    """Evaluate a single rule 'if' string (AND-only). Tokens are looked up in context as booleans."""
    condition = (condition or "").strip().strip('"\'')
    if not condition:
        return True
    tokens = [t.strip() for t in condition.split(" and ") if t.strip()]
    for token in tokens:
        val = context.get(token)
        if val is None:
            return False
        if not bool(val):
            return False
    return True


def evaluate_rules(config: dict[str, Any], context: dict[str, Any]) -> dict[str, str] | None:
    """Return first matching rule's conclusion and next_action, or None."""
    for rule in config.get("decision_rules") or []:
        if_clause = rule.get("if") or ""
        if _evaluate_condition(if_clause, context):
            return {
                "conclusion": rule.get("conclusion", ""),
                "next_action": rule.get("next_action", ""),
            }
    return None


# -----------------------------------------------------------------------------
# RCA generation
# -----------------------------------------------------------------------------

def generate_rca(ctx: dict[str, Any]) -> dict[str, Any]:
    """
    Build an automated RCA based on:
      1. Top 3 tenants by error count
      2. Whether bot engine restarts were detected
      3. Error log patterns (when no restarts found)
    Returns { top_tenants, restart_detected, rca_summary, rca_details[] }.
    """
    by_tenant_code = ctx.get("opensearch_by_tenant_error_code") or []
    total_errors = ctx.get("opensearch_total") or ctx.get("error_count") or 0

    # --- All tenants by aggregated error count ---
    tenant_totals: dict[str, int] = {}
    for row in by_tenant_code:
        name = row.get("tenant_name") or "-"
        tenant_totals[name] = tenant_totals.get(name, 0) + (row.get("count") or 0)
    sorted_tenants = sorted(tenant_totals.items(), key=lambda x: x[1], reverse=True)
    top_tenants = [{"tenant_name": t[0], "total_errors": t[1]} for t in sorted_tenants]

    # --- Restart analysis ---
    # All pods returned by lens_client are already filtered to the time window.
    # If a tenant's namespace (e.g. {tenant}-prod) matches any pod namespace in
    # the Lens results, we consider that tenant's bot engine was restarted.
    lens_pods = ctx.get("lens_pod_restarts") or []
    time_minutes = max(1, min(43200, int(ctx.get("_time_minutes", 60))))

    # Build namespace -> pod lookup from ALL Lens pods (already time-filtered)
    ns_pod_map: dict[str, list[dict[str, Any]]] = {}
    for p in lens_pods:
        ns = (p.get("namespace") or "").lower()
        ns_pod_map.setdefault(ns, []).append(p)

    # Enrich each top tenant: error codes + matching K8s restart info
    # Match tenant to namespace flexibly: any namespace starting with the
    # tenant name is considered a match (e.g. tenant "dupaco" matches
    # namespace "dupaco-aicc-prod").
    for tt in top_tenants:
        tenant = tt["tenant_name"]
        codes_for_tenant = [
            row for row in by_tenant_code if row.get("tenant_name") == tenant
        ]
        tt["error_codes"] = [
            {"code": r.get("error_code"), "count": r.get("count", 0)} for r in codes_for_tenant
        ]
        tenant_lower = tenant.lower()
        matched_pods: list[dict[str, Any]] = []
        matched_ns = ""
        for ns, pods_in_ns in ns_pod_map.items():
            if ns.startswith(tenant_lower):
                matched_pods.extend(pods_in_ns)
                matched_ns = ns
        tt["namespace"] = matched_ns or f"{tenant_lower}-prod"
        tt["restart_pods"] = [
            {"name": p.get("name", ""), "age": p.get("age", ""),
             "restart_count": p.get("restart_count", 0),
             "created_at": p.get("created_at", "")}
            for p in matched_pods
        ]
        tt["restart_count"] = len(matched_pods)
        tt["restart_detected"] = len(matched_pods) > 0

    tenants_with_restarts = [t for t in top_tenants if t["restart_detected"]]
    tenants_without_restarts = [t for t in top_tenants if not t["restart_detected"]]

    rca_details: list[str] = []

    if tenants_with_restarts:
        rca_summary = "Bot engine pod restarts correlated with tenant errors."
        for t in tenants_with_restarts:
            pod_info = ", ".join(
                f"{p['name']} (age {p['age']})" for p in t["restart_pods"][:3]
            )
            rca_details.append(
                f"Tenant \"{t['tenant_name']}\" ({t['total_errors']} errors) — "
                f"namespace \"{t['namespace']}\" has {t['restart_count']} matching pod(s): {pod_info}. "
                f"Pod restart is the likely cause of these errors."
            )
        _no_restart_tenants = list(tenants_without_restarts)
        rca_details.append(
            "Matching pods in the tenant namespace indicate a restart/rollout. "
            "In-flight requests fail with 5xx errors when pods restart. "
            "Investigate pod restart reason (OOMKilled, CrashLoopBackOff, deployment rollout)."
        )
    elif lens_pods:
        rca_summary = "Bot engine pods found but not matching top tenant namespaces."
        all_ns = sorted(ns_pod_map.keys())[:5]
        rca_details.append(
            f"Pods found in namespace(s): {', '.join(all_ns)}."
        )
        if top_tenants:
            expected = ", ".join(f"{t['tenant_name']} → {t['namespace']}" for t in top_tenants)
            rca_details.append(f"Top error tenants map to: {expected} (no matching pods there).")
        _no_restart_tenants = list(top_tenants)
    else:
        rca_summary = "No bot engine pod restarts detected — analysing error logs for root cause."
        _no_restart_tenants = list(top_tenants)

    # Common analysis for tenants without restarts or when no restarts at all
    if not tenants_with_restarts:
        by_error_code = ctx.get("opensearch_by_error_code") or []

        if top_tenants:
            tenant_list = ", ".join(
                f"{t['tenant_name']} ({t['total_errors']} errors)" for t in top_tenants
            )
            rca_details.append(f"Top impacted tenants: {tenant_list}.")

        if by_error_code:
            code_breakdown = ", ".join(
                f"{b.get('code', '?')} ({b.get('count', 0)})" for b in by_error_code[:5]
            )
            rca_details.append(f"Error code distribution: {code_breakdown}.")

    # --- Bot engine log analysis via context_id (primary log analysis) ---
    bot_engine_findings: list[dict[str, Any]] = []
    bot_engine_error = ""
    bot_engine_analyzed = False
    sample = ctx.get("opensearch_sample_errors") or []
    context_ids = list(set(
        str(e.get("context_id") or "") for e in sample if e.get("context_id")
    ))
    if context_ids:
        try:
            from opensearch_client import query_bot_engine_logs
            time_minutes = max(1, min(43200, int(ctx.get("_time_minutes", 60))))
            be_result = query_bot_engine_logs(context_ids, time_minutes=time_minutes)
            if be_result is not None:
                ctx["bot_engine_logs_total"] = be_result.get("total", 0)
                ctx["bot_engine_logs"] = be_result.get("logs", [])
                ctx["bot_engine_error_logs"] = be_result.get("error_logs", [])
                if be_result.get("error"):
                    bot_engine_error = be_result["error"]

                error_logs = be_result.get("error_logs", [])
                if error_logs:
                    bot_engine_analyzed = True
                    rca_details.append(
                        f"Bot engine log analysis: found {len(error_logs)} error(s) "
                        f"across {len(context_ids)} context ID(s)."
                    )
                    be_patterns: dict[str, int] = {}
                    for lg in error_logs:
                        msg = str(lg.get("message") or lg.get("error_stack") or "")[:200].strip()
                        if not msg:
                            continue
                        key = msg.split("\n")[0][:120]
                        be_patterns[key] = be_patterns.get(key, 0) + 1
                    if be_patterns:
                        sorted_be = sorted(be_patterns.items(), key=lambda x: x[1], reverse=True)
                        rca_details.append("Bot engine error patterns:")
                        for pattern, count in sorted_be[:5]:
                            rca_details.append(f"  \u2022 ({count}x) {pattern}")

                    be_event_types: dict[str, int] = {}
                    for lg in error_logs:
                        evt = str(lg.get("event_type") or "").strip()
                        if evt:
                            be_event_types[evt] = be_event_types.get(evt, 0) + 1
                    if be_event_types:
                        sorted_evt = sorted(be_event_types.items(), key=lambda x: x[1], reverse=True)
                        evt_str = ", ".join(f"{e} ({c})" for e, c in sorted_evt[:5])
                        rca_details.append(f"Bot engine error event types: {evt_str}")

                    bot_engine_findings = [
                        {
                            "context_id": lg.get("context_id", ""),
                            "tenant_name": lg.get("tenant_name", ""),
                            "timestamp": lg.get("timestamp", ""),
                            "level": lg.get("level", ""),
                            "event_type": lg.get("event_type", ""),
                            "message": str(lg.get("message", ""))[:300],
                        }
                        for lg in error_logs[:20]
                    ]
                elif be_result.get("total", 0) > 0:
                    rca_details.append(
                        f"Bot engine logs: {be_result['total']} log(s) found for "
                        f"{len(context_ids)} context ID(s), but none at error level."
                    )
                else:
                    rca_details.append(
                        f"Bot engine logs: no logs found for {len(context_ids)} context ID(s) "
                        f"in the selected time window."
                    )
            else:
                rca_details.append(
                    "Bot engine log lookup skipped (OPENSEARCH_BOT_ENGINE_INDEX not configured)."
                )
        except Exception as e:
            bot_engine_error = str(e)
            rca_details.append(f"Bot engine log lookup failed: {bot_engine_error}")

    # --- Bot engine analysis via request_id → connection_id → connectionId ---
    bot_engine_error_codes: dict[str, int] = {}
    bot_engine_conn_findings: list[dict[str, Any]] = []
    request_ids = list(set(
        str(e.get("request_id") or "") for e in sample if e.get("request_id")
    ))
    if request_ids:
        try:
            from opensearch_client import lookup_connection_ids, query_bot_engine_by_connection
            conn_map = lookup_connection_ids(request_ids)
            connection_ids = list(set(conn_map.values()))
            ctx["rca_request_to_connection"] = conn_map

            if connection_ids:
                time_minutes = max(1, min(43200, int(ctx.get("_time_minutes", 60))))
                be_conn_result = query_bot_engine_by_connection(
                    connection_ids, time_minutes=time_minutes
                )
                if be_conn_result and not be_conn_result.get("error"):
                    bot_engine_error_codes = be_conn_result.get("error_codes", {})
                    be_conn_logs = be_conn_result.get("logs", [])
                    ctx["bot_engine_conn_logs"] = be_conn_logs
                    ctx["bot_engine_error_codes"] = bot_engine_error_codes

                    if bot_engine_error_codes:
                        bot_engine_analyzed = True
                        sorted_codes = sorted(
                            bot_engine_error_codes.items(), key=lambda x: x[1], reverse=True
                        )
                        codes_str = ", ".join(f"{code} ({cnt}x)" for code, cnt in sorted_codes)
                        rca_details.append(
                            f"Bot engine error codes (via connection_id): {codes_str}"
                        )
                        # Build per-connection detail
                        conn_error_map: dict[str, list[str]] = {}
                        for lg in be_conn_logs:
                            cid = lg.get("connection_id", "")
                            ec = lg.get("error_code", "")
                            if cid and ec:
                                conn_error_map.setdefault(cid, []).append(ec)

                        rca_details.append(
                            f"Analysed {len(connection_ids)} connection(s) from "
                            f"{len(request_ids)} request ID(s). "
                            f"Found {be_conn_result.get('total', 0)} bot engine error(s)."
                        )

                        # Error message patterns from bot engine
                        be_msg_patterns: dict[str, int] = {}
                        for lg in be_conn_logs:
                            msg = str(lg.get("message") or lg.get("error_stack") or "")[:200].strip()
                            if not msg:
                                continue
                            key = msg.split("\n")[0][:120]
                            be_msg_patterns[key] = be_msg_patterns.get(key, 0) + 1
                        if be_msg_patterns:
                            sorted_msgs = sorted(be_msg_patterns.items(), key=lambda x: x[1], reverse=True)
                            rca_details.append("Bot engine error messages (by connection_id):")
                            for pattern, count in sorted_msgs[:5]:
                                rca_details.append(f"  \u2022 ({count}x) {pattern}")

                        bot_engine_conn_findings = [
                            {
                                "connection_id": lg.get("connection_id", ""),
                                "tenant_name": lg.get("tenant_name", ""),
                                "timestamp": lg.get("timestamp", ""),
                                "error_code": lg.get("error_code", ""),
                                "event_type": lg.get("event_type", ""),
                                "message": str(lg.get("message", ""))[:300],
                            }
                            for lg in be_conn_logs[:30]
                        ]
                    elif be_conn_result.get("total", 0) == 0:
                        rca_details.append(
                            f"Bot engine (connection_id): no errors with rawLog.data.error.code "
                            f"found for {len(connection_ids)} connection(s)."
                        )
                elif be_conn_result and be_conn_result.get("error"):
                    rca_details.append(
                        f"Bot engine connection lookup error: {be_conn_result['error']}"
                    )
            else:
                rca_details.append(
                    f"No connection_ids found in conversation logs for "
                    f"{len(request_ids)} request ID(s)."
                )
        except Exception as e:
            rca_details.append(f"Bot engine connection analysis failed: {e}")

    # Fallback: stream-server error patterns only if bot engine analysis didn't find anything
    if not bot_engine_analyzed and not tenants_with_restarts:
        error_patterns: dict[str, int] = {}
        for err in sample:
            msg = str(err.get("message") or err.get("error_stack") or "")[:200].strip()
            if not msg:
                continue
            key = msg.split("\n")[0][:120]
            error_patterns[key] = error_patterns.get(key, 0) + 1

        if error_patterns:
            sorted_patterns = sorted(error_patterns.items(), key=lambda x: x[1], reverse=True)
            rca_details.append("Common error patterns from stream-server logs:")
            for pattern, count in sorted_patterns[:5]:
                rca_details.append(f"  \u2022 ({count}x) {pattern}")

        by_error_code = ctx.get("opensearch_by_error_code") or []
        if not error_patterns and not by_error_code:
            rca_details.append(
                "No error log samples available for deeper analysis. "
                "Download error logs (CSV) for manual inspection."
            )

    if total_errors > 0:
        rca_details.append(
            "Recommended: review full error logs for stack traces, "
            "check recent deployments, and verify external service dependencies."
        )

    top_names = ", ".join(t["tenant_name"] for t in top_tenants) if top_tenants else ""
    if bot_engine_error_codes:
        codes_str = ", ".join(
            f"{c} ({n}x)" for c, n in sorted(bot_engine_error_codes.items(), key=lambda x: -x[1])
        )
        bot_engine_analysis = f"Errors found for top tenants ({top_names}): {codes_str}"
    elif top_names:
        bot_engine_analysis = f"No errors found in bot engine logs for the impacted tenants ({top_names})"
    else:
        bot_engine_analysis = "No tenant data available for bot engine analysis."

    # Append detail for tenants that had no matching pods, with
    # per-tenant bot engine analysis.
    for t in _no_restart_tenants:
        tname = t["tenant_name"]
        if bot_engine_error_codes:
            tenant_codes = ", ".join(
                f"{c} ({n}x)" for c, n in sorted(bot_engine_error_codes.items(), key=lambda x: -x[1])
            )
            be_line = f"Errors found in bot engine logs: {tenant_codes}"
        else:
            be_line = f"No errors found in bot engine logs for {tname}"
        rca_details.append(
            f"Tenant \"{tname}\" ({t['total_errors']} errors) — "
            f"namespace \"{t['namespace']}\" has no matching pods. "
            f"Bot Engine Analysis: {be_line}"
        )

    restart_detected = len(lens_pods) > 0
    total_restarts = len(lens_pods)

    # --- Twilio analysis ---
    twilio_total = ctx.get("twilio_total_calls", 0)
    twilio_failed = ctx.get("twilio_failed_calls", 0)
    twilio_error_summary = ctx.get("twilio_error_summary") or {}
    twilio_phone_status = ctx.get("twilio_phone_status") or []
    twilio_accounts_checked = ctx.get("twilio_accounts_checked") or []
    twilio_available = ctx.get("twilio_available", False)
    twilio_calls = ctx.get("twilio_calls") or []

    twilio_failed_list = [c for c in twilio_calls if c.get("error_code") or c.get("status") in ("failed", "busy")]

    # Build namespace → error call count from failed Twilio calls only
    twilio_ns_error_counts: dict[str, int] = {}
    for c in twilio_failed_list:
        ns = (c.get("namespace") or "").strip().lower()
        if ns:
            twilio_ns_error_counts[ns] = twilio_ns_error_counts.get(ns, 0) + 1

    # Enrich each tenant with Twilio error count using flexible matching
    for tt in top_tenants:
        tenant_lower = tt["tenant_name"].lower()
        twilio_err = 0
        for ns, cnt in twilio_ns_error_counts.items():
            if ns.startswith(tenant_lower):
                twilio_err += cnt
        tt["twilio_error_count"] = twilio_err

    # Aggregate Twilio error codes
    twilio_error_codes: dict[str, int] = {}
    for c in twilio_failed_list:
        ec = c.get("error_code")
        if ec:
            key = str(ec)
            twilio_error_codes[key] = twilio_error_codes.get(key, 0) + 1

    if twilio_available and twilio_total > 0:
        if twilio_failed > 0:
            status_str = ", ".join(f"{s}: {n}" for s, n in sorted(twilio_error_summary.items(), key=lambda x: -x[1]))
            error_code_str = ""
            if twilio_error_codes:
                error_code_str = " Error codes: " + ", ".join(
                    f"{c} ({n}x)" for c, n in sorted(twilio_error_codes.items(), key=lambda x: -x[1])
                )
            twilio_analysis = (
                f"Twilio issues detected — {twilio_failed} failed out of {twilio_total} calls. "
                f"Status breakdown: {status_str}.{error_code_str}"
            )
            rca_details.append(
                f"Twilio Analysis: {twilio_failed}/{twilio_total} calls failed within the time window. "
                f"Call status breakdown: {status_str}. "
                "Failed calls may indicate telephony-side issues impacting users."
            )
        else:
            twilio_analysis = f"No Twilio call failures — {twilio_total} calls all successful."
    elif twilio_available:
        twilio_analysis = "No Twilio calls found within the time window."
    else:
        twilio_analysis = ctx.get("twilio_error") or "Twilio not configured."

    rca_result = {
        "top_tenants": top_tenants,
        "restart_detected": restart_detected,
        "total_restarts": total_restarts,
        "total_errors": total_errors,
        "rca_summary": rca_summary,
        "rca_details": rca_details,
        "bot_engine_analysis": bot_engine_analysis,
        "twilio_analysis": twilio_analysis,
        "twilio_total_calls": twilio_total,
        "twilio_failed_calls": twilio_failed,
        "twilio_error_summary": twilio_error_summary,
        "twilio_phone_status": twilio_phone_status,
        "twilio_accounts_checked": twilio_accounts_checked,
        "twilio_error_codes": twilio_error_codes,
        "twilio_failed_list": twilio_failed_list[:50],
        "twilio_ns_error_counts": twilio_ns_error_counts,
        "context_ids_checked": context_ids,
        "bot_engine_findings": bot_engine_findings,
        "bot_engine_error": bot_engine_error,
        "bot_engine_error_codes": bot_engine_error_codes,
        "bot_engine_conn_findings": bot_engine_conn_findings,
    }

    # --- Error pattern analysis ---
    try:
        from opensearch_client import analyze_error_patterns
        error_codes_used = ctx.get("_error_codes") or None
        tenant_filter = ctx.get("_tenant_filter") or None
        patterns = analyze_error_patterns(
            error_codes=error_codes_used,
            time_minutes=time_minutes,
            tenant_filter=tenant_filter,
        )
        if patterns:
            rca_result["error_patterns"] = patterns
    except Exception:
        pass

    # --- AI-powered summary ---
    try:
        from ai_summarizer import summarize_rca
        ai_summary = summarize_rca(rca_result)
        if ai_summary:
            rca_result["ai_summary"] = ai_summary
    except Exception:
        pass

    return rca_result


# -----------------------------------------------------------------------------
# High-level run
# -----------------------------------------------------------------------------

def run(
    config_path: str | Path,
    error_codes: list[int],
    initial_context: dict[str, Any] | None = None,
    step_registry: dict[str, callable] | None = None,
    quiet: bool = False,
) -> dict[str, Any]:
    """
    Load config, match scenario, run steps, evaluate rules.
    Returns dict with keys: scenario_id, conclusion, next_action, context, matched_rule.
    If quiet=True, suppresses print output (for API/web use).
    """
    import io
    if quiet:
        _saved_stdout = sys.stdout
        sys.stdout = io.StringIO()

    try:
        config = load_config(config_path)
        scenario = find_scenario(config, error_codes)

        DEFAULT_STEPS = [
            "check_opensearch",
            "get_error_count",
            "get_impacted_tenants",
            "check_bot_restarts",
            "check_twilio_logs",
        ]

        if not scenario:
            scenario = {"id": "general", "steps": DEFAULT_STEPS}

        context = dict(initial_context or {})

        # Derive spike flags from scenario + error_codes for rule evaluation
        scenario_id = scenario.get("id") or ""
        match_codes = set((scenario.get("match") or {}).get("error_codes") or [])
        if match_codes & {500, 503}:
            context.setdefault("500_or_503_spike", True)
        if match_codes & {400}:
            context.setdefault("400_spike", True)
        # Use request's _error_codes for OpenSearch (matches OPENSEARCH_ERROR_CODE_FIELD); else scenario match
        if initial_context and "_error_codes" in initial_context and initial_context["_error_codes"]:
            context["_error_codes"] = list(initial_context["_error_codes"])
        else:
            context["_error_codes"] = list(match_codes)

        if not quiet:
            print(f"Scenario: {scenario_id}")
        run_steps(scenario, context, step_registry)

        # Generate RCA after all steps complete
        rca = generate_rca(context)
        context["rca"] = rca

        rule_result = evaluate_rules(config, context)
        if rule_result:
            conclusion = rule_result["conclusion"]
            next_action = rule_result["next_action"]
            if not quiet:
                print(f"Conclusion: {conclusion}")
                print(f"Next action: {next_action}")
            return {
                "scenario_id": scenario_id,
                "conclusion": conclusion,
                "next_action": next_action,
                "context": context,
                "matched_rule": True,
            }

        if not quiet:
            print("No decision rule matched.")
        return {
            "scenario_id": scenario_id,
            "conclusion": None,
            "next_action": None,
            "context": context,
            "matched_rule": False,
        }
    finally:
        if quiet:
            sys.stdout = _saved_stdout


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Stream Server Alerts – run scenario and decision rules")
    parser.add_argument("config", nargs="?", default="stream_server_alerts.yaml", help="Path to YAML config")
    parser.add_argument("codes", nargs="+", type=int, metavar="CODE", help="Error codes (e.g. 500 503)")
    parser.add_argument("--500-spike", dest="spike_500", action="store_true", help="Set 500_or_503_spike=True")
    parser.add_argument("--400-spike", dest="spike_400", action="store_true", help="Set 400_spike=True")
    parser.add_argument("--calls-ok", action="store_true", help="Set calls_connect_successfully=True")
    parser.add_argument("--calls-fail", action="store_true", help="Set calls_fail=True")
    parser.add_argument("--restart", action="store_true", help="Set restart_detected=True")
    parser.add_argument("--auth-ok", action="store_true", help="Set auth_successful=True")
    parser.add_argument("--auth-fail", action="store_true", help="Set auth_failure=True")
    args = parser.parse_args()

    ctx = {}
    if args.spike_500:
        ctx["500_or_503_spike"] = True
    if args.spike_400:
        ctx["400_spike"] = True
    if args.calls_ok:
        ctx["calls_connect_successfully"] = True
    if args.calls_fail:
        ctx["calls_fail"] = True
    if args.restart:
        ctx["restart_detected"] = True
    if args.auth_ok:
        ctx["auth_successful"] = True
    if args.auth_fail:
        ctx["auth_failure"] = True

    try:
        run(args.config, args.codes, ctx)
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
