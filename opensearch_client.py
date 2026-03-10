"""
OpenSearch client for Stream Server Alerts.

Queries OpenSearch (Prod) for error counts and impacted tenants by error_code
and optional time range. Configure via environment:
  OPENSEARCH_URL     - e.g. https://app-opensearch-dev.interface.ai
  OPENSEARCH_INDEX   - index pattern (optional, default: stream-*; use default.stream-server.* for Discover)
  OPENSEARCH_TIME_FIELD - timestamp field (default: @timestamp)
  OPENSEARCH_ERROR_CODE_FIELD - field for numeric error code filter (default: error_code)
  OPENSEARCH_ERROR_NAME_FIELD - field for error name, e.g. rawLog.data.error.name (optional; when set, query by names)
  OPENSEARCH_TENANT_FIELD - field for tenant/aggregation (default: tenant_name)
  OPENSEARCH_USER    - basic auth user (optional)
  OPENSEARCH_PASSWORD - basic auth password (optional)
  OPENSEARCH_VERIFY_SSL - set to 0 to disable (optional)

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
    tenant_field = os.environ.get("OPENSEARCH_TENANT_FIELD", "tenant_name")
    tenant_agg_field = f"{tenant_field}.keyword" if "." not in tenant_field else tenant_field

    # Build filter: time range always
    must = [{"range": {time_field: {"gte": f"now-{time_minutes}m", "lte": "now"}}}]
    aggs: dict[str, Any] = {}
    if error_name_field:
        # Index uses error name (e.g. default.stream-server.* with rawLog.data.error.name)
        if error_names:
            must.append({"terms": {f"{error_name_field}.keyword" if not error_name_field.endswith(".keyword") else error_name_field: error_names}})
        else:
            must.append({"exists": {"field": error_name_field}})
    else:
        codes = error_codes or [500, 503, 400]
        must.append({"terms": {error_code_field: codes}})
        aggs["by_error_code"] = {"terms": {"field": error_code_field, "size": 50, "order": {"_count": "desc"}}}

    aggs["by_tenant"] = {"terms": {"field": tenant_agg_field, "size": 50, "order": {"_count": "desc"}}}
    if error_name_field:
        agg_field = f"{error_name_field}.keyword" if not error_name_field.endswith(".keyword") else error_name_field
        aggs["by_error_name"] = {"terms": {"field": agg_field, "size": 50, "order": {"_count": "desc"}}}

    query_body: dict[str, Any] = {
        "track_total_hits": True,
        "size": min(max(0, sample_size), 100),
        "query": {"bool": {"filter": must}},
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
    by_error_code = []
    if not error_name_field:
        code_buckets = (res or {}).get("aggregations", {}).get("by_error_code", {}).get("buckets", [])
        by_error_code = [{"code": b.get("key"), "count": b.get("doc_count", 0)} for b in code_buckets]

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
        # Prefer nested rawLog.data.error.* and msg for stream-server index
        err_name = _get(src, error_name_field, "rawLog.data.error.name", "error_code", "errorCode", "error_name")
        ts = _get(src, "@timestamp", "timestamp", "time", "created_at")
        msg = _get(src, "msg", "message", "error", "error_message", "rawLog.data.error.message")
        stack = _get(src, "rawLog.data.error.stack", "error_stack", "stack")
        tenant = _get(src, tenant_field, "tenant_name", "tenant", "tenant_id", "client_id")
        sample.append({
            "timestamp": ts,
            "error_code": err_name if err_name is not None else _get(src, error_code_field, "error_code", "status_code"),
            "tenant_name": tenant,
            "message": msg,
            "error_name": err_name,
            "error_stack": stack,
        })

    out: dict[str, Any] = {"total": total, "tenants": tenants, "sample": sample}
    if error_name_field:
        out["by_error_name"] = by_error_name
        out["error_name_field"] = error_name_field
    else:
        out["by_error_code"] = by_error_code
        out["error_code_field"] = error_code_field  # e.g. error_code or rawLog.data.error.code
    if by_error_name and not error_name_field:
        out["by_error_name"] = by_error_name
    return out


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
