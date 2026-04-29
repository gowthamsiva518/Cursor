"""
Twilio client for call log retrieval and connection status checks.

Fetches recent call logs (voice calls with statuses, durations, errors) and
verifies Twilio account/number availability.

Configure via environment:
  TWILIO_ACCOUNT_SID    - Twilio Account SID
  TWILIO_AUTH_TOKEN     - Twilio Auth Token
  TWILIO_PHONE_NUMBERS  - Comma-separated phone numbers to check (optional)
"""

from __future__ import annotations

import csv
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any


_sid_namespace_map: dict[str, str] | None = None


def _get_sid_namespace_map() -> dict[str, str]:
    """Load account_sid → namespace mapping from the CSV file (cached)."""
    global _sid_namespace_map
    if _sid_namespace_map is not None:
        return _sid_namespace_map

    mapping: dict[str, str] = {}
    csv_path = os.environ.get(
        "TWILIO_NAMESPACE_CSV",
        os.path.join(os.path.dirname(__file__), "twilio_subaccounts_match_with_BE Name.csv"),
    )
    if not os.path.isfile(csv_path):
        _sid_namespace_map = mapping
        return mapping
    try:
        with open(csv_path, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                sid = (row.get("account_sid") or "").strip()
                ns = (row.get("namespace") or "").strip()
                if sid and ns:
                    mapping[sid] = ns
    except Exception:
        pass
    _sid_namespace_map = mapping
    return mapping


def _get_client():
    """Return an authenticated Twilio REST client, or None if unconfigured."""
    sid = os.environ.get("TWILIO_ACCOUNT_SID", "").strip()
    token = os.environ.get("TWILIO_AUTH_TOKEN", "").strip()
    if not sid or not token:
        return None
    from twilio.rest import Client
    return Client(sid, token)


def _get_exclude_names() -> set[str]:
    """Return lowercased set of subaccount friendly names to exclude."""
    raw = os.environ.get("TWILIO_EXCLUDE_SUBACCOUNTS", "").strip()
    return {n.strip().lower() for n in raw.split(",") if n.strip()}


def _get_excluded_sids() -> set[str]:
    """Return the account SIDs of excluded subaccounts so we can filter their calls."""
    client = _get_client()
    if client is None:
        return set()
    exclude_names = _get_exclude_names()
    if not exclude_names:
        return set()
    try:
        subaccounts = client.api.accounts.list(status="active")
    except Exception:
        return set()
    sids = set()
    for acct in subaccounts:
        name = (acct.friendly_name or "").lower()
        if name in exclude_names:
            sids.add(acct.sid)
    return sids


def _get_extra_account_clients() -> list[tuple[str, Any]]:
    """Parse TWILIO_EXTRA_ACCOUNTS (SID:TOKEN pairs, comma-separated) into clients."""
    raw = os.environ.get("TWILIO_EXTRA_ACCOUNTS", "").strip()
    if not raw:
        return []
    from twilio.rest import Client
    result = []
    for pair in raw.split(","):
        pair = pair.strip()
        if ":" not in pair:
            continue
        sid, token = pair.split(":", 1)
        sid, token = sid.strip(), token.strip()
        if not sid or not token:
            continue
        try:
            cli = Client(sid, token)
            name = sid
            try:
                acct = cli.api.accounts(sid).fetch()
                name = acct.friendly_name or sid
            except Exception:
                pass
            result.append((name, cli))
        except Exception:
            pass
    return result


def _get_subaccount_clients() -> list[tuple[str, Any]]:
    """
    Return a list of (friendly_name, Client) for all active subaccounts
    under the main account, plus any extra accounts from TWILIO_EXTRA_ACCOUNTS.
    """
    client = _get_client()
    if client is None:
        return []
    from twilio.rest import Client
    try:
        subaccounts = client.api.accounts.list(status="active")
    except Exception:
        return []
    main_sid = os.environ.get("TWILIO_ACCOUNT_SID", "").strip()
    exclude_names = _get_exclude_names()
    result = []
    for acct in subaccounts:
        if acct.sid == main_sid:
            continue
        name = acct.friendly_name or acct.sid
        if name.lower() in exclude_names:
            continue
        try:
            sub_client = Client(acct.sid, acct.auth_token)
            result.append((name, sub_client))
        except Exception:
            pass

    result.extend(_get_extra_account_clients())
    return result


def check_twilio_connection() -> dict[str, Any]:
    """Verify Twilio credentials and return account status including subaccounts."""
    client = _get_client()
    if client is None:
        return {"connected": False, "error": "TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN not set"}
    try:
        account = client.api.accounts(client.account_sid).fetch()
        subaccounts = []
        try:
            for acct in client.api.accounts.list(status="active"):
                if acct.sid != client.account_sid:
                    subaccounts.append({
                        "sid": acct.sid,
                        "friendly_name": acct.friendly_name,
                        "status": acct.status,
                    })
        except Exception:
            pass
        return {
            "connected": True,
            "account_sid": account.sid,
            "friendly_name": account.friendly_name,
            "status": account.status,
            "subaccounts": subaccounts,
            "subaccount_count": len(subaccounts),
        }
    except Exception as e:
        return {"connected": False, "error": str(e)}


def _extract_calls(
    calls_iter,
    account_name: str,
    calls: list[dict[str, Any]],
    status_counts: dict[str, int],
    number_stats: dict[str, dict[str, int]],
    excluded_sids: set[str] | None = None,
) -> int:
    """Process a batch of call records. Returns the number of failed calls."""
    ns_map = _get_sid_namespace_map()
    failed = 0
    for c in calls_iter:
        if excluded_sids and hasattr(c, "account_sid") and c.account_sid in excluded_sids:
            continue
        status = c.status or "unknown"
        status_counts[status] = status_counts.get(status, 0) + 1

        error_code = None
        error_message = None
        is_failed = status in ("failed", "busy")

        if hasattr(c, "error_code") and c.error_code:
            error_code = c.error_code
        if hasattr(c, "error_message") and c.error_message:
            error_message = c.error_message

        if is_failed or error_code:
            failed += 1

        call_from = getattr(c, "from_formatted", None) or getattr(c, "from_", None) or ""
        call_to = getattr(c, "to_formatted", None) or getattr(c, "to", None) or ""

        for num in [call_from, call_to]:
            if num:
                stats = number_stats.setdefault(num, {"active_calls": 0, "errors": 0})
                stats["active_calls"] += 1
                if is_failed or error_code:
                    stats["errors"] += 1

        ist = timezone(timedelta(hours=5, minutes=30))

        start_time = ""
        if c.start_time:
            if hasattr(c.start_time, "astimezone"):
                start_time = c.start_time.astimezone(ist).strftime("%Y-%m-%d %H:%M:%S IST")
            else:
                start_time = str(c.start_time)

        end_time = ""
        if hasattr(c, "end_time") and c.end_time:
            if hasattr(c.end_time, "astimezone"):
                end_time = c.end_time.astimezone(ist).strftime("%Y-%m-%d %H:%M:%S IST")
            else:
                end_time = str(c.end_time)

        dur_sec = int(c.duration) if c.duration else 0
        if dur_sec >= 60:
            duration_fmt = f"{dur_sec // 60} min {dur_sec % 60} sec"
        else:
            duration_fmt = f"{dur_sec} sec"

        price = ""
        if hasattr(c, "price") and c.price:
            currency = getattr(c, "price_unit", "USD") or "USD"
            price = f"{c.price} {currency}"

        acct_sid = c.account_sid if hasattr(c, "account_sid") else ""
        namespace = ns_map.get(acct_sid, "")

        from_raw = getattr(c, "_from", None) or getattr(c, "from_", None) or call_from
        to_raw = getattr(c, "to", None) or call_to

        calls.append({
            "sid": c.sid,
            "account_sid": acct_sid,
            "account": account_name,
            "namespace": namespace,
            "from": call_from,
            "from_raw": from_raw,
            "to": call_to,
            "to_raw": to_raw,
            "status": status,
            "direction": c.direction or "",
            "duration": dur_sec,
            "duration_fmt": duration_fmt,
            "start_time": start_time,
            "end_time": end_time,
            "price": price,
            "caller_name": getattr(c, "caller_name", "") or "",
            "error_code": error_code,
            "error_message": error_message,
        })
    return failed


def _filter_subs_by_tenants(
    sub_clients: list[tuple[str, Any]],
    tenant_names: list[str],
) -> list[tuple[str, Any]]:
    """Keep only subaccounts whose namespace matches an impacted tenant."""
    ns_map = _get_sid_namespace_map()
    # Build SID → namespace from the CSV, then reverse: check if any tenant
    # name is a prefix of the namespace.
    tenants_lower = [t.lower() for t in tenant_names if t]
    if not tenants_lower:
        return sub_clients

    # Build set of SIDs whose namespace starts with any tenant name
    matching_sids: set[str] = set()
    for sid, ns in ns_map.items():
        ns_lower = ns.lower()
        if any(ns_lower.startswith(t) for t in tenants_lower):
            matching_sids.add(sid)

    filtered = []
    for name, cli in sub_clients:
        sid = cli.account_sid if hasattr(cli, "account_sid") else ""
        if sid in matching_sids:
            filtered.append((name, cli))
    return filtered


def query_call_logs(
    time_minutes: int = 60,
    phone_numbers: list[str] | None = None,
    limit: int = 200,
    tenant_names: list[str] | None = None,
    from_number: str | None = None,
) -> dict[str, Any]:
    """
    Fetch recent call logs within the time window from all active subaccounts.

    When *from_number* is provided, the Twilio API is queried with a ``from_``
    filter so only calls originating from that number are returned — much faster
    and more complete than post-fetch filtering.

    When *tenant_names* is provided, only subaccounts whose namespace matches
    one of the given tenant names (startswith) are queried — significantly
    reducing API calls and latency.

    Returns {
        calls: [{ sid, account, from, to, status, direction, duration, start_time, error_code, error_message }],
        total_calls, failed_calls, error_summary: { status: count },
        phone_status: [{ number, active_calls, errors }],
        accounts_checked: [str]
    }
    """
    client = _get_client()
    if client is None:
        return {"error": "Twilio not configured", "calls": []}

    start_after = datetime.now(timezone.utc) - timedelta(minutes=time_minutes)

    numbers = phone_numbers or [
        n.strip() for n in os.environ.get("TWILIO_PHONE_NUMBERS", "").split(",") if n.strip()
    ]

    calls: list[dict[str, Any]] = []
    status_counts: dict[str, int] = {}
    failed_calls = 0
    number_stats: dict[str, dict[str, int]] = {}
    accounts_checked: list[str] = []

    # --- Subaccounts only (main account excluded) ---
    sub_clients = _get_subaccount_clients()
    if tenant_names:
        sub_clients = _filter_subs_by_tenants(sub_clients, tenant_names)
    per_sub_limit = max(50, limit // max(len(sub_clients), 1))
    max_workers = int(os.environ.get("TWILIO_WORKERS", "100"))

    def _fetch_sub(args):
        sub_name, sub_client = args
        try:
            list_kwargs = dict(start_time_after=start_after, limit=per_sub_limit)
            if from_number:
                list_kwargs["from_"] = from_number
            sub_calls = sub_client.calls.list(**list_kwargs)
            local_calls: list[dict[str, Any]] = []
            local_status: dict[str, int] = {}
            local_num_stats: dict[str, dict[str, int]] = {}
            failed = _extract_calls(sub_calls, sub_name, local_calls, local_status, local_num_stats)
            return sub_name, local_calls, local_status, local_num_stats, failed, None
        except Exception as e:
            return sub_name, [], {}, {}, 0, str(e)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(_fetch_sub, item) for item in sub_clients]
        for future in as_completed(futures):
            sub_name, sub_calls_list, sub_status, sub_num_stats, sub_failed, err = future.result()
            if err:
                accounts_checked.append(f"{sub_name} (error)")
            else:
                calls.extend(sub_calls_list)
                failed_calls += sub_failed
                for s, n in sub_status.items():
                    status_counts[s] = status_counts.get(s, 0) + n
                for num, stats in sub_num_stats.items():
                    existing = number_stats.setdefault(num, {"active_calls": 0, "errors": 0})
                    existing["active_calls"] += stats["active_calls"]
                    existing["errors"] += stats["errors"]
                accounts_checked.append(sub_name)

    phone_status = []
    if numbers:
        for num in numbers:
            stats = number_stats.get(num, {"active_calls": 0, "errors": 0})
            phone_status.append({"number": num, **stats})
    else:
        for num, stats in sorted(number_stats.items(), key=lambda x: -x[1]["errors"]):
            phone_status.append({"number": num, **stats})

    return {
        "calls": calls,
        "total_calls": len(calls),
        "failed_calls": failed_calls,
        "error_summary": status_counts,
        "phone_status": phone_status[:20],
        "accounts_checked": accounts_checked,
    }


def query_alerts(
    time_minutes: int = 60,
    limit: int = 200,
    tenant_names: list[str] | None = None,
    error_code_filter: str | None = None,
) -> dict[str, Any]:
    """
    Fetch Twilio error logs (Monitor Alerts) within the time window.

    When *tenant_names* is provided, only queries the subaccounts whose
    namespace matches one of the given tenant names.
    When *error_code_filter* is provided, only alerts with that error code are returned.
    """
    client = _get_client()
    if client is None:
        return {"error": "Twilio not configured", "alerts": []}

    start_after = datetime.now(timezone.utc) - timedelta(minutes=time_minutes)
    ist = timezone(timedelta(hours=5, minutes=30))
    ns_map = _get_sid_namespace_map()

    def _fetch_alerts_for_client(cli, acct_name: str) -> list[dict[str, Any]]:
        result = []
        try:
            alerts_iter = cli.monitor.alerts.list(start_date=start_after, limit=limit)
            for a in alerts_iter:
                created = ""
                if a.date_created:
                    if hasattr(a.date_created, "astimezone"):
                        created = a.date_created.astimezone(ist).strftime("%Y-%m-%d %H:%M:%S IST")
                    else:
                        created = str(a.date_created)

                acct_sid = getattr(a, "account_sid", "") or ""
                namespace = ns_map.get(acct_sid, "")

                alert_text = (a.alert_text or "")[:500]
                description = ""
                if a.error_code:
                    ec = str(a.error_code)
                    description = _TWILIO_ERROR_DESCRIPTIONS.get(ec, alert_text)

                result.append({
                    "sid": a.sid,
                    "error_code": str(a.error_code) if a.error_code else "",
                    "log_level": a.log_level or "",
                    "description": description,
                    "alert_text": alert_text,
                    "date_created": created,
                    "resource_sid": a.resource_sid or "",
                    "product": "Programmable Voice",
                    "account": acct_name,
                    "account_sid": acct_sid,
                    "namespace": namespace,
                })
        except Exception:
            pass
        return result

    alerts: list[dict[str, Any]] = []
    accounts_checked: list[str] = []

    sub_clients = _get_subaccount_clients()
    if tenant_names:
        sub_clients = _filter_subs_by_tenants(sub_clients, tenant_names)

    max_workers = int(os.environ.get("TWILIO_WORKERS", "100"))

    def _worker(args):
        name, cli = args
        return name, _fetch_alerts_for_client(cli, name)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(_worker, item) for item in sub_clients]
        for future in as_completed(futures):
            name, sub_alerts = future.result()
            alerts.extend(sub_alerts)
            accounts_checked.append(name)

    if error_code_filter:
        alerts = [a for a in alerts if a.get("error_code") == error_code_filter]

    alerts.sort(key=lambda a: a.get("date_created", ""), reverse=True)

    error_codes: dict[str, int] = {}
    by_account: dict[str, int] = {}
    for a in alerts:
        code = a.get("error_code") or "unknown"
        error_codes[code] = error_codes.get(code, 0) + 1
        acct = a.get("account") or a.get("namespace") or "unknown"
        by_account[acct] = by_account.get(acct, 0) + 1

    return {
        "alerts": alerts,
        "total_alerts": len(alerts),
        "error_codes": error_codes,
        "by_account": by_account,
        "accounts_checked": accounts_checked,
    }


_TWILIO_ERROR_DESCRIPTIONS: dict[str, str] = {
    "11200": "HTTP retrieval failure",
    "11205": "HTTP connection failure",
    "11210": "HTTP bad host name",
    "11215": "HTTP too many redirects",
    "11220": "HTTP timeout",
    "11235": "HTTPS certificate error",
    "11750": "TwiML response body too large",
    "11751": "MMS media too large",
    "12100": "Document parse failure",
    "12200": "Schema validation warning",
    "12300": "Invalid Content-Type",
    "12400": "Internal failure",
    "13221": "Dial: Invalid phone number format",
    "13224": "Dial: Invalid timeout",
    "13225": "Dial: Forbidden phone number",
    "13227": "Dial: Invalid nested TwiML",
    "14101": "Say: Invalid voice",
    "15003": "Call Progress: Warning Response to Callback URL",
    "21201": "No account found",
    "21210": "Phone number not found",
    "21211": "Invalid phone number",
    "21214": "Phone number cannot be reached",
    "21215": "Account not active",
    "21217": "Phone number does not appear valid",
    "21610": "Message undeliverable (blocked)",
    "30001": "Queue overflow",
    "30002": "Account suspended",
    "30003": "Unreachable destination",
    "30004": "Message blocked",
    "30005": "Unknown destination handset",
    "30006": "Landline or unreachable carrier",
    "30007": "Carrier violation",
    "30008": "Unknown error",
    "32205": "Domain SID validation failure",
}
