"""
OpenSearch client for Stream Server Alerts.

Queries OpenSearch for error counts, impacted tenants, and sample logs.
Configure via environment:
  OPENSEARCH_URL               - e.g. https://app-opensearch-prod.interface.ai
  OPENSEARCH_INDEX             - index pattern (default: stream-*)
  OPENSEARCH_TIME_FIELD        - timestamp field (default: @timestamp)
  OPENSEARCH_ERROR_CODE_FIELD  - numeric error code filter (default: error_code)
  OPENSEARCH_ERROR_NAME_FIELD  - error name field, e.g. rawLog.data.error.name
  OPENSEARCH_ERROR_STACK_FIELD - error stack field (default: rawLog.data.error.stack)
  OPENSEARCH_TENANT_FIELD      - tenant aggregation field (default: tenant_name)
  OPENSEARCH_LEVEL_FIELD       - log level field (e.g. level)
  OPENSEARCH_LEVEL_VALUE       - required level value (e.g. 50 for error)
  OPENSEARCH_EXCLUDE_ERROR_STACK - pipe-separated stacks to exclude (must_not)
  OPENSEARCH_K8S_VERSION_PREFIX  - kubernetes.labels.version prefix filter (e.g. v5)
  OPENSEARCH_USER / OPENSEARCH_PASSWORD - basic auth (optional)
  OPENSEARCH_VERIFY_SSL        - set to 0 to disable (optional)

If OPENSEARCH_URL is not set, all functions return None and steps use stubs.

Integration Manager default logs (optional): OPENSEARCH_INTEGRATION_MANAGER_INDEX
(e.g. integration-manager.default-*), same connectionId scan pattern as bot engine.
"""

from __future__ import annotations

import os
from typing import Any

# Optional: use opensearch-py when available
try:
    from opensearchpy import OpenSearch
    _OPENSEARCH_AVAILABLE = True
except ImportError:
    OpenSearch = None  # type: ignore
    _OPENSEARCH_AVAILABLE = False


def _request_timeout(default: float = 60.0) -> float:
    """Return the per-request OpenSearch timeout (seconds).

    Tunable via OPENSEARCH_REQUEST_TIMEOUT in .env. Default 60s — the
    opensearch-py default of 10s is too tight for our scan-and-filter
    queries (bot-engine / integration-manager by connectionId) and for
    APT-wide stream-server searches.
    """
    raw = os.environ.get("OPENSEARCH_REQUEST_TIMEOUT", "").strip()
    if not raw:
        return float(default)
    try:
        v = float(raw)
        return v if v > 0 else float(default)
    except (TypeError, ValueError):
        return float(default)


def _get_client() -> Any | None:
    url = os.environ.get("OPENSEARCH_URL", "").strip()
    if not url or not _OPENSEARCH_AVAILABLE:
        return None
    # Normalize URL: remove path and trailing slash for host
    from urllib.parse import urlparse
    p = urlparse(url)
    host = p.hostname or "localhost"
    port = p.port or (443 if p.scheme == "https" else 9200)
    use_ssl = (p.scheme or "https") == "https"
    verify = os.environ.get("OPENSEARCH_VERIFY_SSL", "1") != "0"
    auth = None
    if os.environ.get("OPENSEARCH_USER") and os.environ.get("OPENSEARCH_PASSWORD"):
        auth = (os.environ["OPENSEARCH_USER"], os.environ["OPENSEARCH_PASSWORD"])
    timeout = _request_timeout()
    try:
        return OpenSearch(
            hosts=[{"host": host, "port": port}],
            http_compress=True,
            use_ssl=use_ssl,
            verify_certs=verify,
            ssl_show_warn=verify,
            http_auth=auth,
            timeout=timeout,
            max_retries=2,
            retry_on_timeout=True,
        )
    except Exception:
        return None


def _time_range(
    time_field: str,
    time_minutes: int,
    time_from: str | None = None,
    time_to: str | None = None,
) -> dict[str, Any]:
    """Build an OpenSearch range filter for the time field.

    When ``time_from`` and ``time_to`` are provided (ISO-8601 strings),
    uses absolute boundaries so the query matches the exact alert window
    even if it runs later.  Otherwise falls back to the usual relative
    ``now-Xm`` range.
    """
    if time_from and time_to:
        return {"range": {time_field: {"gte": time_from, "lte": time_to}}}
    return {"range": {time_field: {"gte": f"now-{time_minutes}m", "lte": "now"}}}


def _get_nested(obj: dict, path: str) -> Any:
    """Get nested key, e.g. rawLog.data.error.name."""
    for part in path.split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(part)
        if obj is None:
            return None
    return obj if not isinstance(obj, dict) else None


def query_errors(
    error_codes: list[int] | None = None,
    time_minutes: int = 60,
    index: str | None = None,
    sample_size: int = 20,
    error_names: list[str] | None = None,
    tenant_filter: str | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
) -> dict[str, Any] | None:
    """
    Query OpenSearch for errors: count, tenants, sample, and optionally by_error_name.
    When OPENSEARCH_ERROR_NAME_FIELD is set (e.g. rawLog.data.error.name), filters/aggregates by error name.
    Returns None only when OpenSearch is not configured.
    """
    client = _get_client()
    if not client:
        return None

    index_pattern = index or os.environ.get("OPENSEARCH_INDEX", "stream-*")
    time_field = os.environ.get("OPENSEARCH_TIME_FIELD", "@timestamp")
    error_code_field = os.environ.get("OPENSEARCH_ERROR_CODE_FIELD", "error_code")
    error_name_field = os.environ.get("OPENSEARCH_ERROR_NAME_FIELD", "").strip()
    error_stack_field = os.environ.get("OPENSEARCH_ERROR_STACK_FIELD", "rawLog.data.error.stack")
    tenant_field = os.environ.get("OPENSEARCH_TENANT_FIELD", "tenant_name")
    tenant_agg_field = f"{tenant_field}.keyword" if "." not in tenant_field else tenant_field

    # Build filter: time range always
    must = [_time_range(time_field, time_minutes, time_from, time_to)]
    must_not: list[dict[str, Any]] = []
    aggs: dict[str, Any] = {}

    # Tenant filter
    if tenant_filter:
        must.append({"term": {tenant_agg_field: tenant_filter}})

    # --- Discover filters (from URL) ---
    # 1) Log level filter (e.g. level=50 for pino error)
    level_field = os.environ.get("OPENSEARCH_LEVEL_FIELD", "").strip()
    level_value = os.environ.get("OPENSEARCH_LEVEL_VALUE", "").strip()
    if level_field and level_value:
        must.append({"match_phrase": {level_field: level_value}})

    # 2) Exclude specific error stacks (pipe-separated)
    exclude_stacks = os.environ.get("OPENSEARCH_EXCLUDE_ERROR_STACK", "").strip()
    if exclude_stacks:
        for stack_text in exclude_stacks.split("|"):
            stack_text = stack_text.strip()
            if stack_text:
                must_not.append({"match_phrase": {error_stack_field: stack_text}})

    # 3) Kubernetes version prefix filter (e.g. kubernetes.labels.version starts with v5)
    k8s_prefix = os.environ.get("OPENSEARCH_K8S_VERSION_PREFIX", "").strip()
    if k8s_prefix:
        must.append({"prefix": {"kubernetes.labels.version": k8s_prefix}})

    # --- Error code / error name filter ---
    # When specific error_codes are provided, filter by them (for accurate per-code counts)
    # When empty (Total errors), just require the error field exists
    if error_codes:
        must.append({"terms": {error_code_field: error_codes}})
    elif error_name_field:
        must.append({"exists": {"field": error_name_field}})
    else:
        must.append({"exists": {"field": error_code_field}})

    # Always aggregate by error_code
    aggs["by_error_code"] = {"terms": {"field": error_code_field, "size": 50, "order": {"_count": "desc"}}}

    aggs["by_tenant"] = {"terms": {"field": tenant_agg_field, "size": 50, "order": {"_count": "desc"}}}

    # Nested: tenant -> error_code breakdown
    aggs["by_tenant_error_code"] = {
        "terms": {"field": tenant_agg_field, "size": 100, "order": {"_count": "desc"}},
        "aggs": {
            "error_codes": {"terms": {"field": error_code_field, "size": 50, "order": {"_count": "desc"}}}
        },
    }
    if error_name_field:
        agg_field = f"{error_name_field}.keyword" if not error_name_field.endswith(".keyword") else error_name_field
        aggs["by_error_name"] = {"terms": {"field": agg_field, "size": 50, "order": {"_count": "desc"}}}

    bool_query: dict[str, Any] = {"filter": must}
    if must_not:
        bool_query["must_not"] = must_not

    query_body: dict[str, Any] = {
        "track_total_hits": True,
        "size": min(max(0, sample_size), 100),
        "query": {"bool": bool_query},
        "sort": [{time_field: {"order": "desc"}}],
        "aggs": aggs,
    }

    def run_search(body: dict[str, Any]) -> dict[str, Any] | None:
        try:
            return client.search(index=index_pattern, body=body, ignore_unavailable=True)
        except Exception:
            return None

    res = run_search(query_body)
    if res is None and error_name_field:
        if "by_error_name" in query_body["aggs"]:
            query_body["aggs"]["by_error_name"]["terms"]["field"] = error_name_field
            res = run_search(query_body)
    if res is None and "by_tenant" in query_body["aggs"]:
        query_body["aggs"]["by_tenant"]["terms"]["field"] = tenant_field
        query_body["aggs"]["by_tenant_error_code"]["terms"]["field"] = tenant_field
        res = run_search(query_body)
    if res is None:
        return {"total": 0, "tenants": [], "sample": [], "by_error_name": [], "by_error_code": [], "error": "OpenSearch query failed (check index/field names or connection)"}

    # If the query succeeded but tenant aggregation is empty despite having hits,
    # retry with the base tenant field (without .keyword suffix)
    _hits_total = (res.get("hits", {}).get("total") or {})
    _total_val = _hits_total.get("value", 0) if isinstance(_hits_total, dict) else (_hits_total or 0)
    _tenant_buckets = (res.get("aggregations", {}).get("by_tenant", {}).get("buckets") or [])
    if _total_val > 0 and not _tenant_buckets and tenant_agg_field != tenant_field:
        query_body["aggs"]["by_tenant"]["terms"]["field"] = tenant_field
        query_body["aggs"]["by_tenant_error_code"]["terms"]["field"] = tenant_field
        retry_res = run_search(query_body)
        if retry_res is not None:
            _retry_buckets = (retry_res.get("aggregations", {}).get("by_tenant", {}).get("buckets") or [])
            if _retry_buckets:
                res = retry_res

    hits = (res or {}).get("hits", {})
    total = hits.get("total") or {}
    if isinstance(total, dict):
        total = total.get("value", 0)
    else:
        total = total or 0

    buckets = (res or {}).get("aggregations", {}).get("by_tenant", {}).get("buckets", [])
    tenants = [{"name": b.get("key", ""), "count": b.get("doc_count", 0)} for b in buckets]
    by_error_name = []
    if error_name_field:
        err_buckets = (res or {}).get("aggregations", {}).get("by_error_name", {}).get("buckets", [])
        by_error_name = [{"name": b.get("key", ""), "count": b.get("doc_count", 0)} for b in err_buckets]
    code_buckets = (res or {}).get("aggregations", {}).get("by_error_code", {}).get("buckets", [])
    by_error_code = [{"code": b.get("key"), "count": b.get("doc_count", 0)} for b in code_buckets]

    # Flatten nested tenant -> error_code aggregation into rows
    by_tenant_error_code = []
    tenant_code_buckets = (res or {}).get("aggregations", {}).get("by_tenant_error_code", {}).get("buckets", [])
    for tb in tenant_code_buckets:
        tenant_name = tb.get("key", "")
        for cb in tb.get("error_codes", {}).get("buckets", []):
            by_tenant_error_code.append({
                "tenant_name": tenant_name,
                "error_code": cb.get("key"),
                "count": cb.get("doc_count", 0),
            })

    def _get(obj: dict, *keys: str) -> Any:
        for k in keys:
            v = _get_nested(obj, k) if "." in k else obj.get(k)
            if v is not None:
                return v
        return None

    hit_list = hits.get("hits", [])
    sample = []
    for h in hit_list:
        src = h.get("_source") or {}
        err_name = _get(src, error_name_field, "rawLog.data.error.name", "error_code", "errorCode", "error_name")
        ts = _get(src, "@timestamp", "timestamp", "time", "created_at")
        msg = _get(src, "msg", "message", "error", "error_message", "rawLog.data.error.message")
        stack = _get(src, error_stack_field, "rawLog.data.error.stack", "error_stack", "stack")
        tenant = _get(src, tenant_field, "tenant_name", "tenant", "tenant_id", "client_id")
        k8s_version = _get(src, "kubernetes.labels.version")
        sample.append({
            "timestamp": ts,
            "error_code": err_name if err_name is not None else _get(src, error_code_field, "error_code", "status_code"),
            "tenant_name": tenant,
            "message": msg,
            "error_name": err_name,
            "error_stack": stack,
            "k8s_version": k8s_version,
        })

    out: dict[str, Any] = {
        "total": total,
        "tenants": tenants,
        "sample": sample,
        "by_error_code": by_error_code,
        "error_code_field": error_code_field,
        "by_error_name": by_error_name,
        "error_name_field": error_name_field or "",
        "by_tenant_error_code": by_tenant_error_code,
    }
    return out


def query_all_error_logs(
    error_codes: list[int] | None = None,
    time_minutes: int = 60,
    index: str | None = None,
    max_logs: int = 10000,
    tenant_filter: str | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
) -> dict[str, Any] | None:
    """
    Fetch ALL matching error log entries (up to max_logs) using the same filters
    as query_errors.  Returns { "total", "logs": [{ timestamp, error_code,
    tenant_name, message, error_stack, k8s_version }] }.
    Returns None when OpenSearch is not configured.
    """
    client = _get_client()
    if not client:
        return None

    index_pattern = index or os.environ.get("OPENSEARCH_INDEX", "stream-*")
    time_field = os.environ.get("OPENSEARCH_TIME_FIELD", "@timestamp")
    error_code_field = os.environ.get("OPENSEARCH_ERROR_CODE_FIELD", "error_code")
    error_name_field = os.environ.get("OPENSEARCH_ERROR_NAME_FIELD", "").strip()
    error_stack_field = os.environ.get("OPENSEARCH_ERROR_STACK_FIELD", "rawLog.data.error.stack")
    tenant_field = os.environ.get("OPENSEARCH_TENANT_FIELD", "tenant_name")
    tenant_agg_field = f"{tenant_field}.keyword" if "." not in tenant_field else tenant_field

    must: list[dict[str, Any]] = [_time_range(time_field, time_minutes, time_from, time_to)]
    must_not: list[dict[str, Any]] = []

    if tenant_filter:
        must.append({"term": {tenant_agg_field: tenant_filter}})

    level_field = os.environ.get("OPENSEARCH_LEVEL_FIELD", "").strip()
    level_value = os.environ.get("OPENSEARCH_LEVEL_VALUE", "").strip()
    if level_field and level_value:
        must.append({"match_phrase": {level_field: level_value}})

    exclude_stacks = os.environ.get("OPENSEARCH_EXCLUDE_ERROR_STACK", "").strip()
    if exclude_stacks:
        for stack_text in exclude_stacks.split("|"):
            stack_text = stack_text.strip()
            if stack_text:
                must_not.append({"match_phrase": {error_stack_field: stack_text}})

    k8s_prefix = os.environ.get("OPENSEARCH_K8S_VERSION_PREFIX", "").strip()
    if k8s_prefix:
        must.append({"prefix": {"kubernetes.labels.version": k8s_prefix}})

    if error_codes:
        must.append({"terms": {error_code_field: error_codes}})
    elif error_name_field:
        must.append({"exists": {"field": error_name_field}})
    else:
        must.append({"exists": {"field": error_code_field}})

    bool_query: dict[str, Any] = {"filter": must}
    if must_not:
        bool_query["must_not"] = must_not

    fetch_size = min(max(1, max_logs), 10000)
    query_body: dict[str, Any] = {
        "track_total_hits": True,
        "size": fetch_size,
        "query": {"bool": bool_query},
        "sort": [{time_field: {"order": "desc"}}],
    }

    try:
        res = client.search(index=index_pattern, body=query_body, ignore_unavailable=True)
    except Exception as exc:
        return {"total": 0, "logs": [], "error": str(exc)}

    hits = (res or {}).get("hits", {})
    total = hits.get("total") or {}
    if isinstance(total, dict):
        total = total.get("value", 0)

    def _src_get(obj: dict, *keys: str) -> Any:
        for k in keys:
            v = _get_nested(obj, k) if "." in k else obj.get(k)
            if v is not None:
                return v
        return None

    logs = []
    for h in hits.get("hits", []):
        src = h.get("_source") or {}
        logs.append({
            "timestamp": _src_get(src, "@timestamp", "timestamp", "time", "created_at") or "",
            "error_code": _src_get(src, error_code_field, "error_code", "status_code") or "",
            "tenant_name": _src_get(src, tenant_field, "tenant_name", "tenant", "tenant_id") or "",
            "request_id": str(_src_get(src, "rawLog.data.requestId", "requestId") or ""),
            "context_id": str(_src_get(src, "rawLog.data.contextId", "contextId") or ""),
            "message": str(_src_get(src, "msg", "message", "error", "error_message", "rawLog.data.error.message") or ""),
            "error_stack": str(_src_get(src, error_stack_field, "rawLog.data.error.stack", "error_stack") or ""),
            "k8s_version": str(_src_get(src, "kubernetes.labels.version") or ""),
        })

    return {"total": total, "logs": logs}


def query_bot_engine_logs(
    context_ids: list[str],
    time_minutes: int = 60,
    index: str | None = None,
    max_logs: int = 200,
    time_from: str | None = None,
    time_to: str | None = None,
) -> dict[str, Any] | None:
    """
    Query bot engine logs by context_id(s) to find errors/events
    related to the same request flow.
    Configure via:
      OPENSEARCH_BOT_ENGINE_INDEX       - index pattern (e.g. default.bot-engine.*)
      OPENSEARCH_BOT_ENGINE_CONTEXT_FIELD - field for contextId
                                            (default: rawLog.data.event.request.meta.contextId)
    Returns None when not configured; otherwise { total, logs[] }.
    """
    if not context_ids:
        return {"total": 0, "logs": []}

    client = _get_client()
    if not client:
        return None

    index_pattern = index or os.environ.get("OPENSEARCH_BOT_ENGINE_INDEX", "").strip()
    if not index_pattern:
        return None

    time_field = os.environ.get("OPENSEARCH_TIME_FIELD", "@timestamp")
    context_field = os.environ.get(
        "OPENSEARCH_BOT_ENGINE_CONTEXT_FIELD",
        "rawLog.data.event.request.meta.contextId",
    )

    unique_ids = list(set(cid for cid in context_ids if cid))[:50]
    if not unique_ids:
        return {"total": 0, "logs": []}

    query_body: dict[str, Any] = {
        "track_total_hits": True,
        "size": min(max(1, max_logs), 10000),
        "query": {
            "bool": {
                "filter": [
                    _time_range(time_field, time_minutes, time_from, time_to),
                    {"terms": {context_field: unique_ids}},
                ],
            }
        },
        "sort": [{time_field: {"order": "desc"}}],
    }

    try:
        res = client.search(index=index_pattern, body=query_body, ignore_unavailable=True)
    except Exception as exc:
        return {"total": 0, "logs": [], "error": str(exc)}

    hits = (res or {}).get("hits", {})
    total = hits.get("total") or {}
    if isinstance(total, dict):
        total = total.get("value", 0)

    def _src_get(obj: dict, *keys: str) -> Any:
        for k in keys:
            v = _get_nested(obj, k) if "." in k else obj.get(k)
            if v is not None:
                return v
        return None

    logs = []
    for h in hits.get("hits", []):
        src = h.get("_source") or {}
        ctx_id = str(_src_get(src, context_field, "rawLog.data.contextId", "contextId") or "")
        level = _src_get(src, "level", "rawLog.level") or ""
        msg = str(_src_get(src, "msg", "message", "rawLog.msg", "rawLog.data.error.message") or "")
        error_stack = str(_src_get(src, "rawLog.data.error.stack", "error_stack") or "")
        event_type = str(_src_get(src, "rawLog.data.event.type", "rawLog.data.eventType") or "")
        ts = _src_get(src, "@timestamp", "timestamp", "time") or ""
        tenant = str(_src_get(src, "tenant_name", "rawLog.data.tenant", "tenant") or "")

        client_id = str(_src_get(src, "rawLog.data.event.client.id", "rawLog.data.clientId") or "")

        logs.append({
            "timestamp": ts,
            "context_id": ctx_id,
            "client_id": client_id,
            "tenant_name": tenant,
            "level": level,
            "event_type": event_type,
            "message": msg,
            "error_stack": error_stack,
        })

    error_logs = [lg for lg in logs if _is_error_level(lg.get("level")) or lg.get("error_stack")]
    return {"total": total, "logs": logs, "error_logs": error_logs}


def lookup_client_ids(
    context_ids: list[str],
    time_minutes: int = 60,
    time_from: str | None = None,
    time_to: str | None = None,
) -> dict[str, str]:
    """
    For a list of context_ids, look up the corresponding client_id
    (rawLog.data.event.client.id) from bot engine logs.
    Uses a terms aggregation per context_id for efficiency.
    Searches a wider time window (3x) since bot engine activity may
    precede the stream-server error.
    Returns a dict mapping context_id -> client_id.
    """
    if not context_ids:
        return {}
    client = _get_client()
    if not client:
        return {}
    index_pattern = os.environ.get("OPENSEARCH_BOT_ENGINE_INDEX", "").strip()
    if not index_pattern:
        return {}

    time_field = os.environ.get("OPENSEARCH_TIME_FIELD", "@timestamp")
    context_field = os.environ.get(
        "OPENSEARCH_BOT_ENGINE_CONTEXT_FIELD",
        "rawLog.data.event.request.meta.contextId",
    )

    unique_ids = list(set(cid for cid in context_ids if cid))
    if not unique_ids:
        return {}

    # Widen time window — bot engine logs may precede the error
    lookup_minutes = min(time_minutes * 3, 43200)

    mapping: dict[str, str] = {}
    batch_size = 50
    for i in range(0, len(unique_ids), batch_size):
        batch = unique_ids[i:i + batch_size]
        # Use bool/should with match_phrase for each context_id (works with
        # non-keyword fields where terms queries may fail).
        should_clauses = [{"match_phrase": {context_field: cid}} for cid in batch]
        query_body: dict[str, Any] = {
            "size": len(batch),
            "query": {
                "bool": {
                    "filter": [
                        _time_range(time_field, lookup_minutes, time_from, time_to),
                        {"exists": {"field": "rawLog.data.event.client.id"}},
                    ],
                    "should": should_clauses,
                    "minimum_should_match": 1,
                }
            },
            "_source": [context_field, "rawLog.data.event.client.id"],
            "sort": [{time_field: {"order": "desc"}}],
        }

        try:
            res = client.search(index=index_pattern, body=query_body, ignore_unavailable=True)
        except Exception:
            continue

        for h in (res or {}).get("hits", {}).get("hits", []):
            src = h.get("_source") or {}
            ctx_id = str(_get_nested(src, context_field) or "")
            cid = str(_get_nested(src, "rawLog.data.event.client.id") or "")
            if ctx_id and cid and ctx_id not in mapping:
                mapping[ctx_id] = cid

    return mapping


def lookup_connection_ids(
    request_ids: list[str],
) -> dict[str, str]:
    """
    For a list of request_ids, look up the corresponding connection.id
    from conversation logs (conversation-* index).
    Configure via:
      OPENSEARCH_CONVERSATION_INDEX  - index pattern (default: conversation-*)
    Returns a dict mapping request_id -> connection_id.
    """
    if not request_ids:
        return {}
    client = _get_client()
    if not client:
        return {}
    index_pattern = os.environ.get("OPENSEARCH_CONVERSATION_INDEX", "conversation-*").strip()
    if not index_pattern:
        return {}

    unique_ids = list(set(rid for rid in request_ids if rid))
    if not unique_ids:
        return {}

    mapping: dict[str, str] = {}
    batch_size = 50
    for i in range(0, len(unique_ids), batch_size):
        batch = unique_ids[i:i + batch_size]
        should_clauses = [{"match_phrase": {"request.id": rid}} for rid in batch]
        query_body: dict[str, Any] = {
            "size": len(batch),
            "query": {
                "bool": {
                    "filter": [
                        {"exists": {"field": "connection.id"}},
                    ],
                    "should": should_clauses,
                    "minimum_should_match": 1,
                }
            },
            "_source": ["request.id", "connection.id"],
        }

        try:
            res = client.search(index=index_pattern, body=query_body, ignore_unavailable=True)
        except Exception:
            continue

        for h in (res or {}).get("hits", {}).get("hits", []):
            src = h.get("_source") or {}
            req = src.get("request", {})
            conn = src.get("connection", {})
            rid = str(req.get("id", "")) if isinstance(req, dict) else ""
            cid = str(conn.get("id", "")) if isinstance(conn, dict) else ""
            if rid and cid and rid not in mapping:
                mapping[rid] = cid

    return mapping


def query_bot_engine_by_connection(
    connection_ids: list[str],
    time_minutes: int = 60,
    max_logs: int = 500,
    time_from: str | None = None,
    time_to: str | None = None,
) -> dict[str, Any] | None:
    """
    Query bot engine logs by rawLog.data.data.metadata.connectionId
    to find errors related to specific connections.
    Extracts rawLog.data.error.code for each matching log.
    Returns { total, logs[], error_codes: { code: count } }.
    """
    if not connection_ids:
        return {"total": 0, "logs": [], "error_codes": {}}
    client = _get_client()
    if not client:
        return None
    index_pattern = os.environ.get("OPENSEARCH_BOT_ENGINE_INDEX", "").strip()
    if not index_pattern:
        return None

    time_field = os.environ.get("OPENSEARCH_TIME_FIELD", "@timestamp")
    conn_field = "rawLog.data.data.metadata.connectionId"

    unique_ids = list(set(cid for cid in connection_ids if cid))[:100]
    if not unique_ids:
        return {"total": 0, "logs": [], "error_codes": {}}

    lookup_minutes = min(time_minutes * 3, 43200)
    should_clauses = [{"match_phrase": {conn_field: cid}} for cid in unique_ids]

    query_body: dict[str, Any] = {
        "track_total_hits": True,
        "size": min(max(1, max_logs), 10000),
        "query": {
            "bool": {
                "filter": [
                    _time_range(time_field, lookup_minutes, time_from, time_to),
                    {"exists": {"field": "rawLog.data.error.code"}},
                ],
                "should": should_clauses,
                "minimum_should_match": 1,
            }
        },
        "sort": [{time_field: {"order": "desc"}}],
    }

    try:
        res = client.search(index=index_pattern, body=query_body, ignore_unavailable=True)
    except Exception as exc:
        return {"total": 0, "logs": [], "error_codes": {}, "error": str(exc)}

    hits = (res or {}).get("hits", {})
    total = hits.get("total") or {}
    if isinstance(total, dict):
        total = total.get("value", 0)

    error_code_counts: dict[str, int] = {}
    logs = []
    for h in hits.get("hits", []):
        src = h.get("_source") or {}
        err_code = str(_get_nested(src, "rawLog.data.error.code") or "")
        conn_id = str(_get_nested(src, conn_field) or "")
        ts = _get_nested(src, "@timestamp") or ""
        msg = str(_get_nested(src, "rawLog.data.error.message") or _get_nested(src, "msg") or _get_nested(src, "message") or "")
        err_stack = str(_get_nested(src, "rawLog.data.error.stack") or "")
        tenant = str(_get_nested(src, "tenant_name") or "")
        event_type = str(_get_nested(src, "rawLog.data.event.type") or "")

        if err_code:
            error_code_counts[err_code] = error_code_counts.get(err_code, 0) + 1

        logs.append({
            "timestamp": ts,
            "connection_id": conn_id,
            "tenant_name": tenant,
            "error_code": err_code,
            "event_type": event_type,
            "message": msg,
            "error_stack": err_stack,
        })

    return {
        "total": total,
        "logs": logs,
        "error_codes": error_code_counts,
    }


def _extract_connection_id(src: dict) -> str:
    """Extract connectionId from rawLog.data.data.metadata.connectionId in _source."""
    try:
        raw = src.get("rawLog")
        if not isinstance(raw, dict):
            return ""
        d1 = raw.get("data")
        if not isinstance(d1, dict):
            return ""
        d2 = d1.get("data")
        if not isinstance(d2, dict):
            return ""
        meta = d2.get("metadata")
        if not isinstance(meta, dict):
            return ""
        return str(meta.get("connectionId") or "")
    except Exception:
        return ""


def _extract_integration_manager_connection_id(src: dict) -> str:
    """Extract connectionId from Integration Manager default logs (_source).

    Typical path: rawLog.data.context.metadata.connectionId.
    Mesh / error payloads may nest under rawLog.data.message.context.metadata.connectionId.
    """
    try:
        raw = src.get("rawLog")
        if not isinstance(raw, dict):
            return ""
        d1 = raw.get("data")
        if not isinstance(d1, dict):
            return ""
        ctx = d1.get("context")
        if isinstance(ctx, dict):
            meta = ctx.get("metadata")
            if isinstance(meta, dict) and meta.get("connectionId"):
                return str(meta.get("connectionId") or "")
        msg = d1.get("message")
        if isinstance(msg, dict):
            ctx2 = msg.get("context")
            if isinstance(ctx2, dict):
                meta2 = ctx2.get("metadata")
                if isinstance(meta2, dict) and meta2.get("connectionId"):
                    return str(meta2.get("connectionId") or "")
        d2 = d1.get("data")
        if isinstance(d2, dict):
            meta3 = d2.get("metadata")
            if isinstance(meta3, dict) and meta3.get("connectionId"):
                return str(meta3.get("connectionId") or "")
        return ""
    except Exception:
        return ""


def _flatten_integration_manager_log(src: dict, doc_cid: str) -> dict[str, Any]:
    """Normalise an Integration Manager _source doc to the same shape as bot engine rows."""
    raw = src.get("rawLog") if isinstance(src.get("rawLog"), dict) else {}
    d = raw.get("data") if isinstance(raw.get("data"), dict) else {}
    api_name = str(d.get("apiName") or _get_nested(src, "rawLog.data.message.request.url") or "")
    method_name = str(d.get("methodName") or _get_nested(src, "rawLog.data.message.request.method") or "")
    code = str(_get_nested(src, "rawLog.data.error.code") or "")
    if not code and d.get("status") is not None:
        code = str(d.get("status") or "")
    err_msg = str(_get_nested(src, "rawLog.data.error.message") or "")
    if not err_msg:
        m = d.get("message")
        if isinstance(m, str):
            err_msg = m
        elif isinstance(m, dict):
            err_msg = str(m.get("error") or m.get("response") or "")[:2000]
    if not err_msg:
        err_msg = str(src.get("msg") or "")
    stack = str(_get_nested(src, "rawLog.data.error.stack") or _get_nested(src, "rawLog.data.stack") or "")
    line_msg = str(src.get("msg") or src.get("message") or "")
    return {
        "timestamp": _get_nested(src, "@timestamp") or src.get("@timestamp") or "",
        "level": src.get("level") or "",
        "tenant_name": str(_get_nested(src, "rawLog.tenantName") or src.get("tenant_name") or ""),
        "api_name": api_name,
        "method_name": method_name,
        "connection_id": doc_cid,
        "message": line_msg,
        "error_code": code,
        "error_stack": stack,
        "error_message": err_msg,
        "_raw": src,
    }


def _uuid1_to_datetime(uid_str: str):
    """Extract the embedded timestamp from a UUIDv1 string.

    Returns a datetime (UTC) or None if the string is not a valid UUIDv1.
    """
    import uuid as _uuid
    from datetime import datetime, timezone
    try:
        u = _uuid.UUID(uid_str)
        if u.version != 1:
            return None
        epoch_ns = (u.time - 0x01B21DD213814000) * 100
        return datetime.fromtimestamp(epoch_ns / 1e9, tz=timezone.utc)
    except Exception:
        return None


def query_bot_engine_default_logs(
    connection_id: str | None = None,
    time_minutes: int | None = None,
    index: str | None = None,
    max_logs: int = 500,
    context_id: str | None = None,
) -> dict[str, Any] | None:
    """
    Query bot engine default logs by Connection ID and/or Context ID.

    Filters:
      - ``connection_id`` → ``rawLog.data.data.metadata.connectionId`` — stored in ``_source``
        but NOT indexed by OpenSearch. We fetch docs and filter by connectionId in Python.
      - ``context_id`` is matched against any of the indexed contextId paths configured in
        ``OPENSEARCH_BOT_ENGINE_CONTEXT_FIELD`` (comma-separated; defaults to both
        ``rawLog.data.event.request.meta.contextId`` and ``rawLog.data.contextId`` because
        bot-engine emits the contextId at one of those two locations depending on the
        moduleName).  A ``bool/should`` ``match_phrase`` clause is added so any match
        across the configured paths returns the doc.

    At least one of the two is required.

    Time window logic:
      - If a UUIDv1 ``connection_id`` is provided, derive a tight ±2-hour window from
        the UUID timestamp (much faster than scanning from newest docs).
      - Else if ``time_minutes`` > 0, use the user-selected window.
      - Else (e.g. context_id only and no manual window), no time filter — context_id
        is selective enough on its own.

    Returns None when the bot engine index is not configured; otherwise
    { total, logs[], scanned }.
    """
    cid = (connection_id or "").strip()
    ctx_id = (context_id or "").strip()
    if not cid and not ctx_id:
        return {"total": 0, "logs": [], "error": "connection_id or context_id is required"}

    client = _get_client()
    if not client:
        return None

    index_pattern = index or os.environ.get("OPENSEARCH_BOT_ENGINE_INDEX", "").strip()
    if not index_pattern:
        return None

    time_field = os.environ.get("OPENSEARCH_TIME_FIELD", "@timestamp")
    context_field_raw = os.environ.get(
        "OPENSEARCH_BOT_ENGINE_CONTEXT_FIELD",
        "rawLog.data.event.request.meta.contextId,rawLog.data.contextId",
    )
    _well_known_ctx_paths = [
        "rawLog.data.event.request.meta.contextId",
        "rawLog.data.contextId",
    ]
    context_fields: list[str] = []
    for p in (context_field_raw.split(",") + _well_known_ctx_paths):
        p = p.strip()
        if p and p not in context_fields:
            context_fields.append(p)
    if not context_fields:
        context_fields = list(_well_known_ctx_paths)

    uuid_dt = _uuid1_to_datetime(cid) if cid else None
    if uuid_dt:
        from datetime import timedelta
        window_start = (uuid_dt - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        window_end = (uuid_dt + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        time_filter = {"range": {time_field: {"gte": window_start, "lte": window_end}}}
    elif time_minutes and time_minutes > 0:
        time_filter = _time_range(time_field, time_minutes)
    else:
        time_filter = None

    base_filters: list[dict[str, Any]] = []
    if time_filter:
        base_filters.append(time_filter)
    if ctx_id:
        if len(context_fields) == 1:
            base_filters.append({"match_phrase": {context_fields[0]: ctx_id}})
        else:
            base_filters.append({
                "bool": {
                    "should": [{"match_phrase": {fp: ctx_id}} for fp in context_fields],
                    "minimum_should_match": 1,
                }
            })

    # When context_id is provided we already filter server-side, so we don't need a
    # large scan budget. When only connection_id is provided, the field is not indexed
    # so we have to scan-and-filter.
    batch_size = 2000
    matched: list[dict[str, Any]] = []
    search_after = None
    scanned = 0
    max_scan = 200000 if cid else 20000

    while scanned < max_scan and len(matched) < max_logs:
        query_body: dict[str, Any] = {
            "size": batch_size,
            "query": {"bool": {"filter": base_filters}} if base_filters else {"match_all": {}},
            "sort": [{time_field: {"order": "asc"}}, {"_id": "asc"}],
        }
        if search_after:
            query_body["search_after"] = search_after

        try:
            res = client.search(index=index_pattern, body=query_body, ignore_unavailable=True)
        except Exception as exc:
            return {"total": len(matched), "logs": matched, "error": str(exc)}

        hits_list = (res or {}).get("hits", {}).get("hits", [])
        if not hits_list:
            break

        for h in hits_list:
            src = h.get("_source") or {}
            doc_cid = _extract_connection_id(src)
            # When connection_id is provided, only keep docs whose extracted cid matches.
            # When only context_id is provided, server-side match_phrase already scoped
            # the result set, so accept every hit.
            if cid and doc_cid != cid:
                continue
            doc_ctx = ""
            for fp in context_fields:
                v = _get_nested(src, fp)
                if v:
                    doc_ctx = str(v)
                    break
            if not doc_ctx:
                doc_ctx = str(_get_nested(src, "rawLog.data.contextId") or "")
            matched.append({
                "timestamp": _get_nested(src, "@timestamp") or src.get("@timestamp") or "",
                "level": src.get("level") or "",
                "tenant_name": str(_get_nested(src, "rawLog.tenantName") or src.get("tenant_name") or ""),
                "api_name": str(_get_nested(src, "rawLog.data.apiName") or ""),
                "method_name": str(_get_nested(src, "rawLog.data.methodName") or ""),
                "connection_id": doc_cid,
                "context_id": doc_ctx,
                "message": str(src.get("msg") or src.get("message") or ""),
                "error_code": str(_get_nested(src, "rawLog.data.error.code") or _get_nested(src, "rawLog.data.status") or ""),
                "error_stack": str(_get_nested(src, "rawLog.data.error.stack") or _get_nested(src, "rawLog.data.stack") or ""),
                "error_message": str(_get_nested(src, "rawLog.data.error.message") or _get_nested(src, "rawLog.data.message") or ""),
                "_raw": src,
            })
            if len(matched) >= max_logs:
                break

        scanned += len(hits_list)
        search_after = hits_list[-1].get("sort")
        if not search_after:
            break

    matched.sort(key=lambda l: l.get("timestamp") or "")

    diagnostics: dict[str, Any] | None = None
    if ctx_id and not matched:
        diagnostics = {
            "context_field_counts": {},
            "context_fields_searched": list(context_fields),
        }
        for fp in context_fields:
            try:
                cnt_res = client.count(
                    index=index_pattern,
                    body={"query": {"match_phrase": {fp: ctx_id}}},
                    ignore_unavailable=True,
                )
                diagnostics["context_field_counts"][fp] = int((cnt_res or {}).get("count", 0))
            except Exception as exc:
                diagnostics["context_field_counts"][fp] = f"error: {exc}"
        try:
            any_res = client.count(
                index=index_pattern,
                body={"query": {"query_string": {"query": '"' + ctx_id.replace('"', '') + '"'}}},
                ignore_unavailable=True,
            )
            diagnostics["any_text_match"] = int((any_res or {}).get("count", 0))
        except Exception as exc:
            diagnostics["any_text_match"] = f"error: {exc}"

    out: dict[str, Any] = {"total": len(matched), "logs": matched, "scanned": scanned}
    if diagnostics is not None:
        out["diagnostics"] = diagnostics
    return out


def query_integration_manager_default_logs(
    connection_id: str,
    time_minutes: int | None = None,
    index: str | None = None,
    max_logs: int = 500,
) -> dict[str, Any] | None:
    """
    Query Integration Manager default logs by connectionId (same scan strategy as
    query_bot_engine_default_logs, different _source paths).

    connectionId is read from rawLog.data.context.metadata.connectionId or
    rawLog.data.message.context.metadata.connectionId when nested under errors.

    Returns None when OPENSEARCH_INTEGRATION_MANAGER_INDEX is not set; otherwise
    { total, logs[], scanned }.
    """
    if not connection_id or not connection_id.strip():
        return {"total": 0, "logs": [], "error": "connection_id is required"}

    client = _get_client()
    if not client:
        return None

    index_pattern = index or os.environ.get("OPENSEARCH_INTEGRATION_MANAGER_INDEX", "").strip()
    if not index_pattern:
        return None

    time_field = os.environ.get("OPENSEARCH_TIME_FIELD", "@timestamp")
    cid = connection_id.strip()

    uuid_dt = _uuid1_to_datetime(cid)
    if uuid_dt:
        from datetime import timedelta
        window_start = (uuid_dt - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        window_end = (uuid_dt + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        time_filter = {"range": {time_field: {"gte": window_start, "lte": window_end}}}
    elif time_minutes and time_minutes > 0:
        time_filter = _time_range(time_field, time_minutes)
    else:
        time_filter = None

    batch_size = 2000
    matched: list[dict[str, Any]] = []
    search_after = None
    scanned = 0
    max_scan = 200000

    while scanned < max_scan and len(matched) < max_logs:
        filters = [time_filter] if time_filter else []
        query_body: dict[str, Any] = {
            "size": batch_size,
            "query": {"bool": {"filter": filters}} if filters else {"match_all": {}},
            "sort": [{time_field: {"order": "asc"}}, {"_id": "asc"}],
        }
        if search_after:
            query_body["search_after"] = search_after

        try:
            res = client.search(index=index_pattern, body=query_body, ignore_unavailable=True)
        except Exception as exc:
            return {"total": len(matched), "logs": matched, "error": str(exc)}

        hits_list = (res or {}).get("hits", {}).get("hits", [])
        if not hits_list:
            break

        for h in hits_list:
            src = h.get("_source") or {}
            doc_cid = _extract_integration_manager_connection_id(src)
            if doc_cid == cid:
                matched.append(_flatten_integration_manager_log(src, doc_cid))
                if len(matched) >= max_logs:
                    break

        scanned += len(hits_list)
        search_after = hits_list[-1].get("sort")
        if not search_after:
            break

    matched.sort(key=lambda l: l.get("timestamp") or "")

    return {"total": len(matched), "logs": matched, "scanned": scanned}


def _flatten_stream_server_log(src: dict, doc_cid: str) -> dict[str, Any]:
    """Normalise a stream-server _source doc to the same shape as bot-engine / IM rows.

    Stream-server logs are richer: they contain bot turns (action.type/subtype), caller
    speech (rawLog.data.data.text), STT events, and connection/Twilio metadata in addition
    to errors.  We surface the most useful fields for the table view and keep the full
    `_raw` so the Analyse step (and JSON download) still see everything.
    """
    raw = src.get("rawLog") if isinstance(src.get("rawLog"), dict) else {}
    d = raw.get("data") if isinstance(raw.get("data"), dict) else {}

    module_name = str(raw.get("moduleName") or src.get("moduleName") or "")

    action_type = ""
    action_subtype = ""
    action_text = ""
    a = d.get("action") if isinstance(d, dict) else None
    if isinstance(a, dict):
        action_type = str(a.get("type") or "")
        action_subtype = str(a.get("subtype") or "")
        ad = a.get("data")
        if isinstance(ad, dict):
            action_text = str(ad.get("text") or ad.get("utterance") or ad.get("targetName") or ad.get("extension") or "")
        nested = a.get("action") if isinstance(a, dict) else None
        if isinstance(nested, dict):
            if not action_type:
                action_type = str(nested.get("type") or "")
            if not action_subtype:
                action_subtype = str(nested.get("subtype") or "")
            nd = nested.get("data")
            if isinstance(nd, dict) and not action_text:
                action_text = str(nd.get("text") or nd.get("utterance") or "")

    inner = d.get("data") if isinstance(d, dict) else None
    speech_text = ""
    if isinstance(inner, dict):
        speech_text = str(inner.get("text") or inner.get("utterance") or "")

    err_code = str(_get_nested(src, "rawLog.data.error.name") or _get_nested(src, "rawLog.data.error.code") or "")
    err_msg = str(_get_nested(src, "rawLog.data.error.message") or "")
    err_stack = str(_get_nested(src, "rawLog.data.error.stack") or "")

    line_msg = str(src.get("msg") or src.get("message") or "")

    apt_field = os.environ.get(
        "OPENSEARCH_STREAM_SERVER_APT_FIELD",
        "rawLog.data.action.event.client.data.name",
    )
    apt_name = str(
        _get_nested(src, apt_field)
        or _get_nested(src, "rawLog.data.action.event.client.data.name")
        or _get_nested(src, "rawLog.data.event.client.data.name")
        or _get_nested(src, "rawLog.data.client.name")
        or ""
    )

    conn_field = os.environ.get(
        "OPENSEARCH_STREAM_SERVER_CONNECTION_FIELD",
        "rawLog.data.action.event.connection.id",
    )
    connection_id = str(
        _get_nested(src, conn_field)
        or _get_nested(src, "rawLog.data.action.event.connection.id")
        or _get_nested(src, "rawLog.data.event.connection.id")
        or _get_nested(src, "rawLog.data.connection.id")
        or _get_nested(src, "rawLog.data.connectionId")
        or ""
    )

    return {
        "timestamp": _get_nested(src, "@timestamp") or src.get("@timestamp") or src.get("time") or "",
        "level": src.get("level") or _get_nested(src, "rawLog.level") or "",
        "tenant_name": str(_get_nested(src, "rawLog.tenantName") or src.get("tenant_name") or ""),
        "module_name": module_name,
        "action_type": action_type,
        "action_subtype": action_subtype,
        "action_text": action_text,
        "speech_text": speech_text,
        "context_id": doc_cid,
        "apt_name": apt_name,
        "connection_id": connection_id,
        "request_id": str(_get_nested(src, "rawLog.data.requestId") or ""),
        "message": line_msg,
        "error_code": err_code,
        "error_message": err_msg,
        "error_stack": err_stack,
        "_raw": src,
    }


def query_stream_server_default_logs(
    context_id: str | None = None,
    time_minutes: int | None = None,
    index: str | None = None,
    max_logs: int = 1000,
    time_from: str | None = None,
    time_to: str | None = None,
    apt_name: str | None = None,
    connection_id: str | None = None,
) -> dict[str, Any] | None:
    """
    Query stream-server default logs by rawLog.data.contextId, APT identifier
    (rawLog.data.action.event.client.data.name), and/or Connection ID
    (rawLog.data.action.event.connection.id).  At least one of ``context_id``,
    ``apt_name``, or ``connection_id`` is required.

    Unlike bot-engine / IM logs (where connectionId is in _source only and not searchable),
    contextId, APT name, and the stream-server connection.id are indexed and searchable
    via match_phrase, so we issue a direct filter query — much faster than a scan.

    Time window:
      - If ``time_from`` / ``time_to`` are provided, uses absolute boundaries.
      - Else if ``time_minutes`` > 0, uses now-Xm to now.
      - Else searches the last 30 days (sensible default since contextId is UUIDv4
        and has no embedded timestamp we can derive a tight window from).

    Returns None when OPENSEARCH_STREAM_SERVER_INDEX is not set; otherwise
    { total, logs[], scanned }.
    """
    cid = (context_id or "").strip()
    apt = (apt_name or "").strip()
    conn = (connection_id or "").strip()
    if not cid and not apt and not conn:
        return {
            "total": 0,
            "logs": [],
            "error": "context_id, apt_name, or connection_id is required",
        }

    client = _get_client()
    if not client:
        return None

    index_pattern = index or os.environ.get("OPENSEARCH_STREAM_SERVER_INDEX", "").strip()
    if not index_pattern:
        # Fall back to the main stream-server index used for alerts (OPENSEARCH_INDEX)
        index_pattern = os.environ.get("OPENSEARCH_INDEX", "").strip()
    if not index_pattern:
        return None

    time_field = os.environ.get("OPENSEARCH_TIME_FIELD", "@timestamp")
    context_field = os.environ.get(
        "OPENSEARCH_STREAM_SERVER_CONTEXT_FIELD",
        "rawLog.data.contextId",
    )
    apt_field = os.environ.get(
        "OPENSEARCH_STREAM_SERVER_APT_FIELD",
        "rawLog.data.action.event.client.data.name",
    )
    conn_field = os.environ.get(
        "OPENSEARCH_STREAM_SERVER_CONNECTION_FIELD",
        "rawLog.data.action.event.connection.id",
    )

    if time_from and time_to:
        time_filter = {"range": {time_field: {"gte": time_from, "lte": time_to}}}
    elif time_minutes and time_minutes > 0:
        time_filter = _time_range(time_field, time_minutes)
    else:
        time_filter = _time_range(time_field, 60 * 24 * 30)  # default: last 30 days

    filters: list[dict[str, Any]] = [time_filter]
    if cid:
        filters.append({"match_phrase": {context_field: cid}})
    if apt:
        filters.append({"match_phrase": {apt_field: apt}})
    if conn:
        filters.append({"match_phrase": {conn_field: conn}})

    fetch_size = min(max(1, int(max_logs or 1000)), 10000)
    query_body: dict[str, Any] = {
        "track_total_hits": True,
        "size": fetch_size,
        "query": {"bool": {"filter": filters}},
        "sort": [{time_field: {"order": "asc"}}, {"_id": "asc"}],
    }

    # APT-only fetches across a wide window can be expensive; allow a longer
    # per-request timeout (still capped by OPENSEARCH_REQUEST_TIMEOUT_LONG).
    long_timeout = _request_timeout(default=120.0)
    if "_REQUEST_TIMEOUT_LONG" in os.environ:
        try:
            long_timeout = float(os.environ["OPENSEARCH_REQUEST_TIMEOUT_LONG"])
        except (TypeError, ValueError):
            pass

    try:
        res = client.search(
            index=index_pattern,
            body=query_body,
            ignore_unavailable=True,
            request_timeout=long_timeout,
        )
    except Exception as exc:
        # opensearchpy.exceptions.ConnectionTimeout subclasses TransportError;
        # we keep the import lazy so this module still loads if the client is missing.
        try:
            from opensearchpy.exceptions import ConnectionTimeout as _OSConnTimeout
        except Exception:
            _OSConnTimeout = None  # type: ignore
        is_timeout = bool(_OSConnTimeout and isinstance(exc, _OSConnTimeout))
        if not is_timeout:
            is_timeout = "timed out" in str(exc).lower() or "ReadTimeoutError" in str(exc)
        if is_timeout:
            hint = (
                f"OpenSearch read timed out after {long_timeout:.0f}s. "
                "Narrow the time window, add a Context ID or Connection ID alongside APT, "
                "or raise OPENSEARCH_REQUEST_TIMEOUT (Settings → OpenSearch)."
            )
            return {"total": 0, "logs": [], "error": hint, "timeout": True}
        return {"total": 0, "logs": [], "error": str(exc)}

    hits = (res or {}).get("hits", {})
    total = hits.get("total") or {}
    if isinstance(total, dict):
        total = total.get("value", 0)

    matched: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for h in hits.get("hits", []):
        src = h.get("_source") or {}
        doc_cid = str(_get_nested(src, context_field) or "")
        if not doc_cid and cid:
            doc_cid = cid
        flat = _flatten_stream_server_log(src, doc_cid)
        # Stream-server logs are often duplicated by Fluent Bit / OpenSearch replicas;
        # de-dup on (timestamp, msg, request_id) so the table view is readable.
        # When filtering by APT/Connection ID only, request_id may be empty for some lines;
        # fall back to context_id, then connection_id, so different sessions don't
        # collapse into one row.
        key = (
            str(flat.get("timestamp") or ""),
            str(flat.get("message") or ""),
            str(
                flat.get("request_id")
                or flat.get("context_id")
                or flat.get("connection_id")
                or ""
            ),
        )
        if key in seen:
            continue
        seen.add(key)
        matched.append(flat)

    matched.sort(key=lambda l: l.get("timestamp") or "")

    return {"total": total, "logs": matched, "scanned": len(hits.get("hits", []))}


def check_stream_server_default_index() -> dict[str, Any]:
    """Check if the stream-server default-logs index is configured and reachable."""
    index_pattern = os.environ.get("OPENSEARCH_STREAM_SERVER_INDEX", "").strip()
    if not index_pattern:
        # Fall back to the main alerts index so this agent works out-of-the-box
        # when the dedicated env var hasn't been set yet.
        index_pattern = os.environ.get("OPENSEARCH_INDEX", "").strip()
        if not index_pattern:
            return {
                "configured": False,
                "connected": False,
                "message": "OPENSEARCH_STREAM_SERVER_INDEX (or OPENSEARCH_INDEX) not set in .env",
            }
        fallback = True
    else:
        fallback = False
    client = _get_client()
    if not client:
        return {"configured": True, "connected": False, "message": "OpenSearch client not available"}
    try:
        res = client.count(index=index_pattern, body={"query": {"match_all": {}}}, ignore_unavailable=True)
        count = res.get("count", 0)
        out = {"configured": True, "connected": True, "index": index_pattern, "doc_count": count}
        if fallback:
            out["fallback"] = True
            out["message"] = "Using OPENSEARCH_INDEX (set OPENSEARCH_STREAM_SERVER_INDEX to override)"
        return out
    except Exception as e:
        return {"configured": True, "connected": False, "index": index_pattern, "error": str(e)}


def check_bot_engine_index() -> dict[str, Any]:
    """Check if the bot engine OpenSearch index is configured and reachable."""
    index_pattern = os.environ.get("OPENSEARCH_BOT_ENGINE_INDEX", "").strip()
    if not index_pattern:
        return {"configured": False, "connected": False, "message": "OPENSEARCH_BOT_ENGINE_INDEX not set in .env"}
    client = _get_client()
    if not client:
        return {"configured": True, "connected": False, "message": "OpenSearch client not available"}
    try:
        res = client.count(index=index_pattern, body={"query": {"match_all": {}}}, ignore_unavailable=True)
        count = res.get("count", 0)
        return {"configured": True, "connected": True, "index": index_pattern, "doc_count": count}
    except Exception as e:
        return {"configured": True, "connected": False, "index": index_pattern, "error": str(e)}


def check_integration_manager_index() -> dict[str, Any]:
    """Check if the Integration Manager OpenSearch index is configured and reachable."""
    index_pattern = os.environ.get("OPENSEARCH_INTEGRATION_MANAGER_INDEX", "").strip()
    if not index_pattern:
        return {"configured": False, "connected": False, "message": "OPENSEARCH_INTEGRATION_MANAGER_INDEX not set in .env"}
    client = _get_client()
    if not client:
        return {"configured": True, "connected": False, "message": "OpenSearch client not available"}
    try:
        res = client.count(index=index_pattern, body={"query": {"match_all": {}}}, ignore_unavailable=True)
        count = res.get("count", 0)
        return {"configured": True, "connected": True, "index": index_pattern, "doc_count": count}
    except Exception as e:
        return {"configured": True, "connected": False, "index": index_pattern, "error": str(e)}


def _is_error_level(level: Any) -> bool:
    """Check if a log level indicates an error (pino level >= 50 or string match)."""
    if level is None:
        return False
    try:
        return int(level) >= 50
    except (TypeError, ValueError):
        return str(level).lower() in ("error", "fatal", "err")


def query_restart_logs(
    time_minutes: int = 60,
    index: str | None = None,
    size: int = 50,
    search_term: str | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
) -> dict[str, Any] | None:
    """
    Query OpenSearch for log entries that indicate bot engine restarts (e.g. message contains "restart").
    Set OPENSEARCH_RESTART_SEARCH_TERM in .env to customize (default: restart). Searches msg, message, log, rawLog.*.
    Returns None when OpenSearch is not configured; otherwise { "total", "logs": [{ "timestamp", "message", ... }] }.
    """
    client = _get_client()
    if not client:
        return None

    index_pattern = index or os.environ.get("OPENSEARCH_INDEX", "stream-*")
    time_field = os.environ.get("OPENSEARCH_TIME_FIELD", "@timestamp")
    term = (search_term or os.environ.get("OPENSEARCH_RESTART_SEARCH_TERM", "restart")).strip()
    if not term:
        return {"total": 0, "logs": []}

    # Search for term in common log message fields (Lens / stream-server style logs)
    query_body: dict[str, Any] = {
        "track_total_hits": True,
        "size": min(max(0, size), 200),
        "query": {
            "bool": {
                "filter": [
                    _time_range(time_field, time_minutes, time_from, time_to),
                ],
                "must": [
                    {
                        "simple_query_string": {
                            "query": term,
                            "fields": ["msg^2", "message^2", "log", "text", "rawLog.data.action.action.data.text", "rawLog.data.error.message"],
                            "default_operator": "OR",
                            "lenient": True,
                        }
                    }
                ],
            }
        },
        "sort": [{time_field: {"order": "desc"}}],
    }

    try:
        res = client.search(index=index_pattern, body=query_body, ignore_unavailable=True)
    except Exception:
        return {"total": 0, "logs": [], "error": "OpenSearch restart logs query failed"}

    hits = (res or {}).get("hits", {})
    total = hits.get("total") or {}
    if isinstance(total, dict):
        total = total.get("value", 0)
    else:
        total = total or 0

    hit_list = hits.get("hits", [])
    logs = []
    for h in hit_list:
        src = h.get("_source") or {}
        ts = _get_nested(src, time_field) or src.get("@timestamp") or src.get("timestamp") or src.get("time")
        msg = src.get("msg") or src.get("message") or _get_nested(src, "rawLog.data.action.action.data.text") or _get_nested(src, "rawLog.data.error.message") or src.get("log") or ""
        if not msg and isinstance(src.get("rawLog"), dict):
            import json
            msg = json.dumps(src.get("rawLog", {}))[:500]
        logs.append({
            "timestamp": ts,
            "message": msg if isinstance(msg, str) else str(msg)[:1000],
            "rawLog": src.get("rawLog"),
        })

    return {"total": total, "logs": logs}


def query_tenant_list(time_minutes: int = 1440) -> list[str]:
    """Fetch distinct tenant names from OpenSearch within the time window."""
    client = _get_client()
    if not client:
        return []
    index_pattern = os.environ.get("OPENSEARCH_INDEX", "stream-*")
    time_field = os.environ.get("OPENSEARCH_TIME_FIELD", "@timestamp")
    tenant_field = os.environ.get("OPENSEARCH_TENANT_FIELD", "tenant_name")
    tenant_agg_field = f"{tenant_field}.keyword" if "." not in tenant_field else tenant_field

    query_body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {time_field: {"gte": f"now-{time_minutes}m", "lte": "now"}}},
                    {"exists": {"field": tenant_field}},
                ]
            }
        },
        "aggs": {
            "tenants": {"terms": {"field": tenant_agg_field, "size": 500, "order": {"_key": "asc"}}}
        },
    }
    try:
        resp = client.search(index=index_pattern, body=query_body)
        buckets = resp.get("aggregations", {}).get("tenants", {}).get("buckets", [])
        return [b["key"] for b in buckets if b.get("key")]
    except Exception:
        return []


def analyze_error_patterns(
    error_codes: list[int] | None = None,
    time_minutes: int = 15,
    tenant_filter: str | None = None,
    max_logs: int = 2000,
    time_from: str | None = None,
    time_to: str | None = None,
) -> dict[str, Any] | None:
    """Analyze error log patterns: stack traces, messages, k8s versions, cross-tenant."""
    result = query_all_error_logs(
        error_codes=error_codes, time_minutes=time_minutes,
        tenant_filter=tenant_filter, max_logs=max_logs,
        time_from=time_from, time_to=time_to,
    )
    if not result:
        return None

    logs = result.get("logs", [])
    if not logs:
        return {"total_analyzed": 0, "top_stacks": [], "top_messages": [],
                "k8s_versions": [], "cross_tenant": []}

    from collections import Counter, defaultdict

    stack_counter: Counter = Counter()
    message_counter: Counter = Counter()
    stack_codes: dict[str, Counter] = defaultdict(Counter)
    stack_tenants: dict[str, set] = defaultdict(set)
    k8s_counter: Counter = Counter()
    code_tenants: dict[str, set] = defaultdict(set)

    for log in logs:
        raw_stack = (log.get("error_stack") or "").strip()
        msg = (log.get("message") or "").strip()
        code = str(log.get("error_code", ""))
        tenant = log.get("tenant_name") or ""
        k8s_ver = log.get("k8s_version") or ""

        stack_key = raw_stack.split("\n")[0][:200] if raw_stack else "(no stack trace)"
        msg_key = msg[:200] if msg else "(no message)"

        stack_counter[stack_key] += 1
        message_counter[msg_key] += 1
        stack_codes[stack_key][code] += 1
        if tenant:
            stack_tenants[stack_key].add(tenant)
        if k8s_ver:
            k8s_counter[k8s_ver] += 1
        if code and tenant:
            code_tenants[code].add(tenant)

    top_stacks = []
    for stack, count in stack_counter.most_common(10):
        codes = dict(stack_codes[stack])
        tenants = sorted(stack_tenants[stack])
        top_stacks.append({
            "stack": stack, "count": count,
            "error_codes": codes,
            "tenants": tenants[:5],
            "tenant_count": len(tenants),
        })

    top_messages = [
        {"message": msg, "count": count}
        for msg, count in message_counter.most_common(10)
    ]

    k8s_versions = [
        {"version": ver, "count": count}
        for ver, count in k8s_counter.most_common(10)
    ]

    cross_tenant = []
    for code, tenants in sorted(code_tenants.items(), key=lambda x: len(x[1]), reverse=True):
        cross_tenant.append({
            "error_code": code, "tenant_count": len(tenants),
            "systemic": len(tenants) >= 3,
            "tenants": sorted(tenants)[:5],
        })

    # --- Root cause classification ---
    root_causes = _classify_root_causes(logs, top_stacks, top_messages, k8s_counter, cross_tenant)

    # --- Connection / correlation analysis ---
    connections = _find_connections(logs, stack_counter, message_counter, k8s_counter, code_tenants)

    return {
        "total_analyzed": len(logs),
        "top_stacks": top_stacks,
        "top_messages": top_messages,
        "k8s_versions": k8s_versions,
        "cross_tenant": cross_tenant,
        "root_causes": root_causes,
        "connections": connections,
    }


def _classify_root_causes(
    logs: list[dict], top_stacks: list[dict], top_messages: list[dict],
    k8s_counter: Any, cross_tenant: list[dict],
) -> list[dict[str, Any]]:
    """Classify errors into root cause categories with severity and recommendations."""
    from collections import Counter, defaultdict
    total = len(logs) or 1
    causes: list[dict[str, Any]] = []

    msg_lower_counter: Counter = Counter()
    stack_lower_counter: Counter = Counter()
    code_counter: Counter = Counter()
    tenant_code_pair: dict[str, set] = defaultdict(set)

    for log in logs:
        msg = (log.get("message") or "").lower()
        stack = (log.get("error_stack") or "").lower()
        code = str(log.get("error_code", ""))
        tenant = log.get("tenant_name") or ""
        for kw in ["timeout", "parse", "action", "ssml", "tts", "speech",
                    "websocket", "connection", "503", "502", "memory", "oom"]:
            if kw in msg or kw in stack:
                msg_lower_counter[kw] += 1
        if code:
            code_counter[code] += 1
        if tenant and code:
            tenant_code_pair[tenant].add(code)

    # 1. Parser Timeout
    timeout_count = msg_lower_counter.get("timeout", 0)
    if timeout_count > 0:
        pct = round(timeout_count * 100 / total, 1)
        causes.append({
            "category": "Parser Timeout",
            "count": timeout_count,
            "percentage": pct,
            "severity": "Critical" if pct > 30 else "High" if pct > 10 else "Medium",
            "description": "Bot engine's input parser is timing out while processing audio stream data. "
                           "This typically happens when the bot engine is CPU-bound or the audio stream is delayed/fragmented.",
            "recommendation": "Check bot engine pod CPU utilization during peak hours. "
                              "Consider increasing parser timeout threshold or adding retry logic in the stream server.",
        })

    # 2. Bot Engine Action Errors
    action_count = msg_lower_counter.get("action", 0)
    if action_count > 0:
        pct = round(action_count * 100 / total, 1)
        causes.append({
            "category": "Bot Engine Action Failure",
            "count": action_count,
            "percentage": pct,
            "severity": "Critical" if pct > 30 else "High" if pct > 10 else "Medium",
            "description": "Bot engine fails to execute actions during call processing. "
                           "Often paired with parser timeouts, indicating the action handler catches timeout exceptions.",
            "recommendation": "Investigate if action errors are a downstream effect of parser timeouts. "
                              "Add structured error codes to distinguish timeout-triggered vs. logic-triggered action failures.",
        })

    # 3. Service Unavailable (503)
    svc_count = code_counter.get("503", 0)
    if svc_count > 0:
        pct = round(svc_count * 100 / total, 1)
        # Find which tenants have disproportionate 503s
        t503_tenants = []
        for t, codes in tenant_code_pair.items():
            if "503" in codes:
                t503_tenants.append(t)
        causes.append({
            "category": "Service Unavailable (503)",
            "count": svc_count,
            "percentage": pct,
            "severity": "Critical" if pct > 15 else "High" if pct > 5 else "Medium",
            "description": "Bot engine pods returning 503, indicating they are overloaded, restarting, or temporarily unavailable. "
                           f"Affects {len(t503_tenants)} tenant(s). "
                           "May indicate resource exhaustion (CPU/memory limits), OOMKill events, or deployment rollouts.",
            "recommendation": "Check pod resource limits and actual usage. Look for OOMKilled events in kubectl describe pod. "
                              "Consider scaling up affected pods or increasing resource limits.",
        })

    # 4. TTS/SSML Errors
    tts_count = msg_lower_counter.get("tts", 0) + msg_lower_counter.get("ssml", 0) + msg_lower_counter.get("speech", 0)
    tts_count = tts_count // 3 if tts_count > 0 else 0  # deduplicate triple-counting
    actual_tts = sum(1 for l in logs if any(k in (l.get("message") or "").lower() for k in ("tts", "ssml", "speech")))
    if actual_tts > 0:
        pct = round(actual_tts * 100 / total, 1)
        causes.append({
            "category": "TTS / SSML Generation Failure",
            "count": actual_tts,
            "percentage": pct,
            "severity": "High" if pct > 10 else "Medium" if pct > 3 else "Low",
            "description": "Text-to-speech engine receives malformed SSML from the bot engine. "
                           "Likely caused by unescaped special characters or invalid XML in bot response text.",
            "recommendation": "Add SSML sanitization before passing text to the TTS engine. "
                              "Check if specific bot flows generate edge-case text with special characters.",
        })

    # 5. WebSocket / Connection Errors
    ws_count = msg_lower_counter.get("websocket", 0) + msg_lower_counter.get("connection", 0)
    if ws_count > 0:
        pct = round(ws_count * 100 / total, 1)
        causes.append({
            "category": "WebSocket / Connection Error",
            "count": ws_count,
            "percentage": pct,
            "severity": "High" if pct > 10 else "Medium" if pct > 3 else "Low",
            "description": "WebSocket connection between stream server and bot engine is dropping or failing. "
                           "May indicate network instability, pod restarts, or connection pool exhaustion.",
            "recommendation": "Check network stability between stream server and bot engine pods. "
                              "Review WebSocket connection lifecycle and reconnection logic.",
        })

    # 6. Parse Errors (non-timeout)
    parse_count = msg_lower_counter.get("parse", 0) - timeout_count
    if parse_count > 0:
        pct = round(parse_count * 100 / total, 1)
        causes.append({
            "category": "Input Parse Failure",
            "count": parse_count,
            "percentage": pct,
            "severity": "Medium" if pct > 5 else "Low",
            "description": "Bot engine cannot parse the input data from the stream server. "
                           "This may indicate corrupted audio frames, encoding mismatches, or protocol changes.",
            "recommendation": "Review input validation in the bot engine /stream/input endpoint. "
                              "Check for audio encoding compatibility between stream server and bot engine.",
        })

    # 7. K8s version correlation
    if k8s_counter:
        total_k8s = sum(k8s_counter.values())
        top_ver, top_count = k8s_counter.most_common(1)[0]
        top_pct = round(top_count * 100 / total_k8s, 1) if total_k8s else 0
        num_versions = len(k8s_counter)
        if top_pct > 40 and num_versions > 2:
            causes.append({
                "category": "Version-Specific Concentration",
                "count": top_count,
                "percentage": top_pct,
                "severity": "Medium",
                "description": f"K8s version {top_ver} accounts for {top_pct}% of all errors across {num_versions} deployed versions. "
                               "This disproportionate error rate may indicate a version-specific bug or that more tenants are deployed on this version.",
                "recommendation": f"Compare error rates per-pod across versions. If {top_ver} has a higher per-pod error rate, "
                                  "consider upgrading affected tenants to a newer version.",
            })

    causes.sort(key=lambda c: c["count"], reverse=True)
    return causes


def _find_connections(
    logs: list[dict], stack_counter: Any, message_counter: Any,
    k8s_counter: Any, code_tenants: dict[str, set],
) -> list[dict[str, str]]:
    """Find connections and correlations between error patterns."""
    from collections import Counter, defaultdict
    connections: list[dict[str, str]] = []
    total = len(logs) or 1

    # 1. Paired errors: same tenant + same timestamp = linked errors
    ts_tenant_msgs: dict[str, list[str]] = defaultdict(list)
    for log in logs:
        ts = (log.get("timestamp") or "")[:23]  # millisecond precision
        tenant = log.get("tenant_name") or "unknown"
        msg = (log.get("message") or "")[:100]
        if ts:
            ts_tenant_msgs[f"{ts}|{tenant}"].append(msg)

    paired_count = sum(1 for msgs in ts_tenant_msgs.values() if len(msgs) >= 2)
    if paired_count > 0:
        sample_pair = None
        for key, msgs in ts_tenant_msgs.items():
            if len(msgs) >= 2:
                unique = list(set(msgs))
                if len(unique) >= 2:
                    sample_pair = unique[:2]
                    break
        desc = (f"{paired_count} error pairs detected at the same millisecond for the same tenant, "
                "indicating these are the same failure logged twice from different code paths.")
        if sample_pair:
            desc += f' Example pair: "{sample_pair[0]}" + "{sample_pair[1]}".'
        connections.append({
            "type": "Paired Errors",
            "description": desc,
            "impact": f"Actual unique failures may be ~{total - paired_count} (not {total}), "
                      "since each failure generates 2 log entries.",
        })

    # 2. Cross-code correlation: tenants with multiple error codes
    multi_code_tenants = {t: codes for t, codes in code_tenants.items() if len(codes) > 1}
    if multi_code_tenants:
        all_have_same = True
        common_codes = None
        for t, codes in multi_code_tenants.items():
            if common_codes is None:
                common_codes = codes
            elif codes != common_codes:
                all_have_same = False
                break
        if all_have_same and common_codes and len(multi_code_tenants) >= 3:
            connections.append({
                "type": "Uniform Multi-Code Pattern",
                "description": f"All {len(multi_code_tenants)} affected tenants show the exact same error code combination "
                               f"({', '.join(sorted(common_codes))}). This uniformity confirms a platform-level issue, "
                               "not tenant-specific configuration problems.",
                "impact": "Fix should target the shared platform layer (stream server or bot engine core), "
                          "not individual tenant configurations.",
            })
        elif len(multi_code_tenants) >= 2:
            connections.append({
                "type": "Multi-Code Tenants",
                "description": f"{len(multi_code_tenants)} tenants have multiple error types (400+503), "
                               "suggesting a compound failure: the primary error (400 timeout) may cascade "
                               "into secondary errors (503 overload) under high load.",
                "impact": "Fixing the primary 400 timeout issue may also reduce 503 errors.",
            })

    # 3. Time-based correlation: errors spike together
    hourly: Counter = Counter()
    hourly_by_code: dict[str, Counter] = defaultdict(Counter)
    for log in logs:
        ts = (log.get("timestamp") or "")[:13]
        code = str(log.get("error_code", ""))
        if ts:
            hourly[ts] += 1
            hourly_by_code[ts][code] += 1

    if len(hourly) >= 3:
        counts = sorted(hourly.values())
        peak = counts[-1]
        low = counts[0]
        if peak > low * 3 and peak > 20:
            peak_hour = max(hourly, key=hourly.get)
            connections.append({
                "type": "Traffic-Correlated Errors",
                "description": f"Error rate varies {peak // max(low, 1)}x between peak ({peak} errors at {peak_hour}) "
                               f"and low ({low} errors). Errors scale with call volume, confirming the issue "
                               "is triggered per-call rather than being a background/batch process failure.",
                "impact": "Error count will increase proportionally with traffic. "
                          "The fix must handle per-call load, not just idle-state bugs.",
            })

    # 4. Version-error correlation
    if k8s_counter and len(k8s_counter) >= 2:
        ver_list = k8s_counter.most_common()
        top_ver, top_count = ver_list[0]
        bottom_ver, bottom_count = ver_list[-1]
        if top_count > bottom_count * 5:
            connections.append({
                "type": "Version Disparity",
                "description": f"Version {top_ver} has {top_count} errors vs {bottom_ver} with only {bottom_count}. "
                               "This may indicate a version-specific bug, or simply that more tenants run on the higher-error version.",
                "impact": "Investigate per-pod error rate for each version to determine if the version itself is problematic.",
            })

    # 5. 400 -> 503 cascade pattern
    tenant_400: Counter = Counter()
    tenant_503: Counter = Counter()
    for log in logs:
        code = str(log.get("error_code", ""))
        tenant = log.get("tenant_name") or ""
        if tenant:
            if code == "400":
                tenant_400[tenant] += 1
            elif code == "503":
                tenant_503[tenant] += 1
    cascade_tenants = []
    for t in tenant_503:
        if t in tenant_400 and tenant_503[t] > 0:
            ratio_503 = tenant_503[t] / (tenant_400[t] + tenant_503[t]) * 100
            if ratio_503 > 20:
                cascade_tenants.append((t, tenant_400[t], tenant_503[t], round(ratio_503, 1)))
    if cascade_tenants:
        cascade_tenants.sort(key=lambda x: x[3], reverse=True)
        desc_parts = [f"{t} (400:{c4}, 503:{c5}, {r}% are 503)" for t, c4, c5, r in cascade_tenants[:3]]
        connections.append({
            "type": "400 to 503 Cascade",
            "description": f"Some tenants show disproportionately high 503 rates alongside 400 errors: "
                           + ", ".join(desc_parts) + ". "
                           "When bot engine pods are overwhelmed by 400 errors, they may start returning 503 (Service Unavailable) "
                           "as a secondary symptom of resource exhaustion.",
            "impact": "These tenants may need higher pod resource limits or dedicated scaling rules.",
        })

    return connections


def check_opensearch_connection() -> bool:
    """Return True if OpenSearch is configured and reachable."""
    client = _get_client()
    if not client:
        return False
    try:
        client.ping()
        return True
    except Exception:
        return False
