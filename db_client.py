"""Read-only PostgreSQL connectivity check for the assistant UI."""

from __future__ import annotations

import os
import time
from typing import Any


def _is_configured() -> bool:
    if os.environ.get("DATABASE_URL", "").strip():
        return True
    host = os.environ.get("DB_HOST", "").strip()
    user = os.environ.get("DB_USER", "").strip()
    return bool(host and user)


def check_database_status() -> dict[str, Any]:
    """
    Connect (read-only queries) and return server / database facts.
    Uses DATABASE_URL if set; otherwise DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD, DB_SSLMODE.
    """
    try:
        import psycopg2
    except ImportError:
        return {
            "ok": False,
            "configured": False,
            "connected": False,
            "error": "PostgreSQL driver not installed. Run: pip install psycopg2-binary",
        }

    if not _is_configured():
        return {
            "ok": True,
            "configured": False,
            "connected": False,
            "message": "Set DATABASE_URL or DB_HOST + DB_USER (+ DB_NAME, DB_PASSWORD as needed) in .env or Settings.",
        }

    url = os.environ.get("DATABASE_URL", "").strip()
    connect_timeout = 12

    t0 = time.perf_counter()
    conn = None
    try:
        if url:
            conn = psycopg2.connect(url, connect_timeout=connect_timeout)
        else:
            host = os.environ.get("DB_HOST", "").strip()
            user = os.environ.get("DB_USER", "").strip()
            try:
                port = int(os.environ.get("DB_PORT", "5432") or "5432")
            except ValueError:
                port = 5432
            dbname = (os.environ.get("DB_NAME", "postgres") or "postgres").strip()
            password = os.environ.get("DB_PASSWORD", "")
            sslmode = (os.environ.get("DB_SSLMODE", "prefer") or "prefer").strip()
            conn = psycopg2.connect(
                host=host,
                port=port,
                dbname=dbname,
                user=user,
                password=password,
                sslmode=sslmode,
                connect_timeout=connect_timeout,
            )
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)

        with conn.cursor() as cur:
            cur.execute("SELECT version()")
            version = (cur.fetchone() or ("",))[0]

            cur.execute("SELECT current_database(), current_user, now()")
            row = cur.fetchone() or ("", "", None)
            database, db_user, server_time = row[0], row[1], row[2]

            public_tables = 0
            try:
                cur.execute(
                    """
                    SELECT COUNT(*) FROM information_schema.tables
                    WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
                    """
                )
                public_tables = int((cur.fetchone() or (0,))[0])
            except Exception:
                pass

            extensions: list[str] = []
            try:
                cur.execute("SELECT extname FROM pg_extension ORDER BY 1 LIMIT 25")
                extensions = [r[0] for r in cur.fetchall() if r and r[0]]
            except Exception:
                pass

        conn.close()
        return {
            "ok": True,
            "configured": True,
            "connected": True,
            "latency_ms": latency_ms,
            "server_version": version,
            "database": database,
            "user": db_user,
            "server_time": str(server_time) if server_time is not None else "",
            "public_table_count": public_tables,
            "extensions": extensions,
        }
    except Exception as exc:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        return {
            "ok": False,
            "configured": True,
            "connected": False,
            "error": str(exc),
        }
