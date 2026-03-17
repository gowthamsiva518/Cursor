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
    try:
        return OpenSearch(
            hosts=[{"host": host, "port": port}],
            http_compress=True,
            use_ssl=use_ssl,
            verify_certs=verify,
            ssl_show_warn=verify,
            http_auth=auth,
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
        obj = (obj or {}).get(part)
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
        # Try without .keyword for aggregation (e.g. if field is already keyword)
        if "by_error_name" in query_body["aggs"]:
            query_body["aggs"]["by_error_name"]["terms"]["field"] = error_name_field
            res = run_search(query_body)
    if res is None and "by_tenant" in query_body["aggs"]:
        query_body["aggs"]["by_tenant"]["terms"]["field"] = tenant_field
        res = run_search(query_body)
    if res is None:
        return {"total": 0, "tenants": [], "sample": [], "by_error_name": [], "by_error_code": [], "error": "OpenSearch query failed (check index/field names or connection)"}

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
