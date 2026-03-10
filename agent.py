"""
Stream Server Alerts – Agent.

Runs the alert engine, then executes pluggable follow-up actions based on
conclusion and next_action (notify, escalate, create ticket, etc.).
Supports dry-run (report what would be done) and execute modes.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Callable

from alert_engine import run as engine_run

# Type for (result, context) -> action outcome
ActionHandler = Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]
# Matcher: (result, context) -> bool
ActionMatcher = Callable[[dict[str, Any], dict[str, Any]], bool]


def _match_next_action_contains(*phrases: str) -> ActionMatcher:
    def _match(result: dict[str, Any], context: dict[str, Any]) -> bool:
        na = (result.get("next_action") or "").lower()
        return any(p.lower() in na for p in phrases)
    return _match


def _match_conclusion_contains(*phrases: str) -> ActionMatcher:
    def _match(result: dict[str, Any], context: dict[str, Any]) -> bool:
        c = (result.get("conclusion") or "").lower()
        return any(p.lower() in c for p in phrases)
    return _match


def _match_matched_rule(result: dict[str, Any], context: dict[str, Any]) -> bool:
    return bool(result.get("matched_rule"))


# -----------------------------------------------------------------------------
# Action handlers (stubs; replace with Slack, PagerDuty, Jira, etc.)
# -----------------------------------------------------------------------------

def action_escalate_immediate(result: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    """Open bridge, notify DevOps, create P1 ticket."""
    # TODO: PagerDuty trigger, Slack #incidents, create Jira
    impacted = context.get("impacted_tenants", [])
    return {
        "ok": True,
        "action": "escalate_immediate",
        "message": f"[STUB] Would escalate immediately (impacted: {impacted})",
        "details": {"conclusion": result.get("conclusion"), "next_action": result.get("next_action")},
    }


def action_escalate_devops(result: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    """Notify DevOps, create ticket for infra/restart follow-up."""
    # TODO: Slack #devops, Jira "Infra - Stream server"
    return {
        "ok": True,
        "action": "escalate_devops",
        "message": "[STUB] Would notify DevOps and create follow-up ticket",
        "details": {"next_action": result.get("next_action")},
    }


def action_escalate_dev(result: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    """Notify dev team with auth evidence and impacted CUs."""
    # TODO: Slack #stream-dev, attach auth logs
    return {
        "ok": True,
        "action": "escalate_dev",
        "message": "[STUB] Would escalate to dev with auth evidence",
        "details": {"impacted_tenants": context.get("impacted_tenants")},
    }


def action_collect_rca(result: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    """Create RCA task / runbook: collect restart cause, pod metrics, time window."""
    # TODO: Create Confluence/Jira RCA task, link to dashboard
    return {
        "ok": True,
        "action": "collect_rca",
        "message": "[STUB] Would create RCA task (restart cause, pod metrics, time window)",
        "details": {},
    }


def action_monitor_logs(result: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    """Log for monitoring; optional low-priority ticket."""
    return {
        "ok": True,
        "action": "monitor_logs",
        "message": "[STUB] Would add to monitoring log and collect RCA data",
        "details": {},
    }


def _match_escalate_or_infra(result: dict[str, Any], context: dict[str, Any]) -> bool:
    """Match devops/infra follow-up; skip when 'escalate immediately' (handled by escalate_immediate)."""
    na = (result.get("next_action") or "").lower()
    c = (result.get("conclusion") or "").lower()
    if "escalate immediately" in na or "open bridge" in na:
        return False
    return "escalate" in na or "devops" in na or "infra instability" in c


# Default: which actions to run for which outcomes (order matters; all matching handlers run)
DEFAULT_ACTION_RULES: list[tuple[str, ActionMatcher, ActionHandler]] = [
    ("escalate_immediate", _match_next_action_contains("escalate immediately", "open bridge"), action_escalate_immediate),
    ("escalate_devops", _match_escalate_or_infra, action_escalate_devops),
    ("escalate_dev", _match_next_action_contains("escalate with impacted", "auth evidence"), action_escalate_dev),
    ("collect_rca", _match_next_action_contains("collect restart cause", "pod metrics"), action_collect_rca),
    ("monitor_logs", _match_next_action_contains("monitor logs", "collect RCA"), action_monitor_logs),
]


# -----------------------------------------------------------------------------
# AlertAgent
# -----------------------------------------------------------------------------

class AlertAgent:
    """
    Agent that runs the alert engine and optionally executes follow-up actions.
    """

    def __init__(
        self,
        config_path: str | Path = "stream_server_alerts.yaml",
        step_registry: dict[str, Callable] | None = None,
        action_rules: list[tuple[str, ActionMatcher, ActionHandler]] | None = None,
    ):
        self.config_path = Path(config_path)
        self.step_registry = step_registry
        self.action_rules = action_rules or list(DEFAULT_ACTION_RULES)

    def run(
        self,
        error_codes: list[int],
        initial_context: dict[str, Any] | None = None,
        execute: bool = False,
        quiet: bool = False,
    ) -> dict[str, Any]:
        """
        Run the engine, then evaluate action rules. If execute=True, run handlers;
        otherwise only report what would be done (dry-run).
        Returns engine result plus actions_planned or actions_taken.
        """
        result = engine_run(
            self.config_path,
            error_codes,
            initial_context=initial_context,
            step_registry=self.step_registry,
            quiet=quiet,
        )
        context = result.get("context") or {}
        actions_out: list[dict[str, Any]] = []

        for name, matcher, handler in self.action_rules:
            if not matcher(result, context):
                continue
            if execute:
                try:
                    outcome = handler(result, context)
                    actions_out.append({"name": name, "executed": True, "outcome": outcome})
                except Exception as e:
                    actions_out.append({"name": name, "executed": True, "error": str(e), "outcome": None})
            else:
                # Dry-run: call handler but we could use a no-op wrapper; for stubs they just return message
                try:
                    outcome = handler(result, context)
                    actions_out.append({"name": name, "executed": False, "would_do": outcome.get("message", outcome)})
                except Exception as e:
                    actions_out.append({"name": name, "executed": False, "error": str(e)})

        result["actions_planned" if not execute else "actions_taken"] = actions_out
        return result


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Stream Server Alerts – agent (engine + follow-up actions)")
    parser.add_argument("config", nargs="?", default="stream_server_alerts.yaml", help="Path to YAML config")
    parser.add_argument("codes", nargs="+", type=int, metavar="CODE", help="Error codes (e.g. 500 503)")
    parser.add_argument("--execute", action="store_true", help="Execute actions (default: dry-run)")
    parser.add_argument("--quiet", action="store_true", help="Suppress engine print output")
    parser.add_argument("--calls-ok", action="store_true", help="Context: calls_connect_successfully=True")
    parser.add_argument("--calls-fail", action="store_true", help="Context: calls_fail=True")
    parser.add_argument("--restart", action="store_true", help="Context: restart_detected=True")
    parser.add_argument("--auth-ok", action="store_true", help="Context: auth_successful=True")
    parser.add_argument("--auth-fail", action="store_true", help="Context: auth_failure=True")
    args = parser.parse_args()

    ctx: dict[str, Any] = {}
    if args.calls_ok:
        ctx["simulate"] = ctx.get("simulate") or {}
        ctx["simulate"]["calls_ok"] = True
        ctx["simulate"]["calls_fail"] = False
    if args.calls_fail:
        ctx["simulate"] = ctx.get("simulate") or {}
        ctx["simulate"]["calls_fail"] = True
        ctx["simulate"]["calls_ok"] = False
    if args.restart:
        ctx["simulate"] = ctx.get("simulate") or {}
        ctx["simulate"]["restart_detected"] = True
    if args.auth_ok:
        ctx["simulate"] = ctx.get("simulate") or {}
        ctx["simulate"]["auth_ok"] = True
        ctx["simulate"]["auth_fail"] = False
    if args.auth_fail:
        ctx["simulate"] = ctx.get("simulate") or {}
        ctx["simulate"]["auth_fail"] = True
        ctx["simulate"]["auth_ok"] = False

    try:
        agent = AlertAgent(config_path=args.config)
        result = agent.run(args.codes, initial_context=ctx or None, execute=args.execute, quiet=args.quiet)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    if not args.quiet:
        print(f"Scenario: {result.get('scenario_id')}")
        print(f"Conclusion: {result.get('conclusion')}")
        print(f"Next action: {result.get('next_action')}")
        key = "actions_taken" if args.execute else "actions_planned"
        for a in result.get(key) or []:
            label = "Executed" if a.get("executed") else "Would do"
            msg = (a.get("outcome") or {}).get("message") if a.get("executed") else a.get("would_do")
            err = a.get("error")
            print(f"  [{label}] {a.get('name')}: {msg or err}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
