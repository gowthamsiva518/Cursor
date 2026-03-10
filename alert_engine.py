"""
Stream Server Alerts – Runner / engine.

Loads stream_server_alerts.yaml, matches alerts to scenarios by error codes,
runs steps (pluggable), and evaluates decision_rules to output conclusion + next_action.
Loads .env from project folder so OPENSEARCH_* are set when connecting to OpenSearch.
"""

from __future__ import annotations

import argparse
import sys
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
        result = query_errors(error_codes, time_minutes=time_minutes, sample_size=20, error_names=error_names)
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
    """Detect bot/pod restarts in time window; sets restart_detected."""
    print("  [step] check_bot_restarts")
    sim = _get_simulate(ctx, "restart_detected")
    if sim is not None:
        ctx["restart_detected"] = bool(sim)
    else:
        ctx.setdefault("restart_detected", True)  # demo: assume restart detected


def step_check_twilio_logs(ctx: dict[str, Any]) -> None:
    """Inspect Twilio logs for errors/causes."""
    print("  [step] check_twilio_logs")
    # TODO: call Twilio API or log search
    ctx.setdefault("twilio_log_summary", "not_checked")


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
        if not scenario:
            return {
                "scenario_id": None,
                "conclusion": None,
                "next_action": None,
                "context": initial_context or {},
                "matched_rule": False,
                "error": "no matching scenario for error_codes",
            }

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
