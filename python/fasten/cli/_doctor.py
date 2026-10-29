"""
`fasten doctor` — verify init config + store + correlation wiring.

Read-only diagnostic: it opens stores without creating or altering anything. Runs each check, prints status + message, returns
exit-code = number of failures. Six checks today:

  1. env vars (FASTEN_SERVICE_ID, FASTEN_NODE_ID required; tenant + dsn optional)
  2. audit DSN — parseable, connectable, table exists, returns count
  3. api DSN — configured? (informational; default ring-only is fine)
  4. catalog — codes registered, domains discovered
  5. shims — `fasten.shim.http` importable (correlation prerequisite)
  6. correlation — current_request_id() returns sane value when set

Sample-emit roundtrip is deliberately *not* a doctor check — it would
write a synthetic row into the production audit log. Tests in P0-1 cover
the emit path.
"""
from __future__ import annotations

import importlib
import json
import os
import re
import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote_plus, unquote, urlencode, urlsplit, urlunsplit


@dataclass
class CheckResult:
    name: str
    status: str       # "ok" | "warn" | "fail"
    message: str
    detail: dict[str, Any] | None = None


# A libpq key=value DSN ("host=db password=...") has no scheme; init would
# take it for a SQLite path, so doctor neither prints nor opens it.
_KEYWORD_DSN = "unrecognised DSN (not shown; use a postgres:// URL)"
_TABLE_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?")


def _describe(dsn: str, is_postgres: bool) -> str:
    """Backend and, for SQLite, the file path. Never the DSN itself."""
    if is_postgres:
        return "postgres"
    if "@" in dsn:
        return "sqlite (path hidden: the DSN has credentials)"
    if "://" not in dsn and ("=" in dsn or any(c.isspace() for c in dsn)):
        return _KEYWORD_DSN
    try:
        path = urlsplit(dsn).path
    except ValueError:
        return "unparseable DSN"
    return f"sqlite {path or '(no path)'}"


def _error_text(e: Exception, dsn: str) -> str:
    """``type: message``, unless the message may contain a DSN secret."""
    try:
        u = urlsplit(dsn)
        secrets = [u.password or ""] + [
            v for k, vs in parse_qs(u.query).items()
            if k.lower() in ("password", "sslpassword") for v in vs]
    except ValueError:
        u, secrets = None, []
    rest = dsn.partition("://")[2]
    # With no password or a raw @ in it, drivers may split it differently.
    unknown = u is None or (not u.password and "@" in rest) or rest.count("@") > 1
    text = f"{type(e).__name__}: {e}"
    forms = {f for s in secrets if s
             for f in (s, unquote(s), quote_plus(s), repr(s)[1:-1])}
    if unknown or any(f in text for f in forms):
        return f"{type(e).__name__} (details hidden: they may include the DSN password)"
    return text.replace(dsn, "<dsn>")


def _probe(dsn: str, is_postgres: bool, sqlite_path: str, default_table: str) -> int:
    """Rows a one-row sample of the table returns. Unlike the store
    constructors, it creates no file and no table and alters nothing."""
    u = urlsplit(dsn)
    query = parse_qs(u.query)
    table = query.pop("table", [default_table])[0]
    if not _TABLE_RE.fullmatch(table):
        raise ValueError("invalid table name")
    if is_postgres:
        import psycopg
        conninfo = urlunsplit(u._replace(query=urlencode(query, doseq=True)))
        with psycopg.connect(conninfo, connect_timeout=5) as conn:
            return len(conn.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchall())
    if not sqlite_path or not os.path.isfile(sqlite_path):
        raise FileNotFoundError("SQLite file not found")
    lite = sqlite3.connect(Path(sqlite_path).resolve().as_uri() + "?mode=ro", uri=True)
    try:
        return len(lite.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchall())
    finally:
        lite.close()


def _check_store(name: str, dsn: str, is_postgres: bool, sqlite_path: str,
                 default_table: str) -> CheckResult:
    backend = _describe(dsn, is_postgres)
    if backend == _KEYWORD_DSN:
        return CheckResult(name=name, status="fail", message=backend)
    try:
        rows = _probe(dsn, is_postgres, sqlite_path, default_table)
    except Exception as e:  # noqa: BLE001 — diagnostic context, all failures relevant
        return CheckResult(name=name, status="fail", message=f"{backend}: {_error_text(e, dsn)}")
    return CheckResult(
        name=name, status="ok",
        message=f"{backend} (connected, sample query returned {rows} row[s])",
        detail={"backend": backend, "sample_rows": rows},
    )


def _glyph(status: str) -> str:
    return {"ok": "✓", "warn": "⚠", "fail": "✗"}[status]


def _check_env() -> CheckResult:
    sid = os.environ.get("FASTEN_SERVICE_ID")
    nid = os.environ.get("FASTEN_NODE_ID")
    tid = os.environ.get("FASTEN_TENANT_ID")
    if not sid or not nid:
        missing = [v for v, k in [("FASTEN_SERVICE_ID", sid), ("FASTEN_NODE_ID", nid)] if not k]
        return CheckResult(
            name="env",
            status="fail",
            message=f"missing required env: {', '.join(missing)}",
        )
    return CheckResult(
        name="env",
        status="ok",
        message=f"service_id={sid}, node_id={nid}" + (f", tenant_id={tid}" if tid else ""),
        detail={"service_id": sid, "node_id": nid, "tenant_id": tid},
    )


def _check_audit_dsn() -> CheckResult:
    dsn = os.environ.get("FASTEN_AUDIT_DSN")
    if not dsn:
        return CheckResult(
            name="audit_dsn",
            status="fail",
            message="not set: audit rows go to stdout only. Set FASTEN_AUDIT_DSN for durable storage.",
        )
    # Same scheme test and SQLite path as the engine's audit store.
    try:
        path = urlsplit(dsn).path.lstrip("/")
    except ValueError:
        path = ""
    return _check_store("audit_dsn", dsn, dsn.startswith(("postgres://", "postgresql://")),
                        path, "audit_log")


def _check_api_dsn() -> CheckResult:
    dsn = os.environ.get("FASTEN_API_DSN")
    if not dsn:
        return CheckResult(
            name="api_dsn",
            status="ok",
            message="not configured — ring-buffer only (default; persist via FASTEN_API_DSN if needed)",
        )
    # Same scheme test and SQLite path as the engine's stream store.
    try:
        u = urlsplit(dsn)
    except ValueError:
        return CheckResult(name="api_dsn", status="fail", message="unparseable DSN")
    scheme = u.scheme.lower()
    if scheme not in ("sqlite", "postgres", "postgresql", ""):
        return CheckResult(name="api_dsn", status="fail",
                           message=f"unsupported DSN scheme {scheme!r}")
    path = u.path[1:] if scheme and u.path.startswith("/") else u.path
    return _check_store("api_dsn", dsn, scheme in ("postgres", "postgresql"), path, "api_log")


def _check_catalog() -> CheckResult:
    from ..codes import registry
    reg = registry()
    if not reg:
        return CheckResult(
            name="catalog",
            status="warn",
            message="no codes registered — call fasten.codes.register(...) before emit()",
        )
    domains = sorted({m.domain for m in reg.values()})
    return CheckResult(
        name="catalog",
        status="ok",
        message=f"{len(reg)} codes across {len(domains)} domains: {', '.join(domains)}",
        detail={"codes": len(reg), "domains": domains},
    )


def _check_shim_http() -> CheckResult:
    try:
        importlib.import_module("fasten.shim.http")
        return CheckResult(
            name="shim_http",
            status="ok",
            message="fasten.shim.http importable (X-Request-ID correlation available)",
        )
    except ImportError as e:
        return CheckResult(
            name="shim_http",
            status="warn",
            message=f"fasten.shim.http not importable: {e} (HTTP correlation will not auto-propagate)",
        )


def _check_correlation() -> CheckResult:
    from ..context import current_request_id
    rid = current_request_id()
    if rid is None:
        return CheckResult(
            name="correlation",
            status="ok",
            message="current_request_id() = None (no active request scope — expected for CLI invocation)",
        )
    return CheckResult(
        name="correlation",
        status="ok",
        message=f"current_request_id() = {rid}",
        detail={"request_id": rid},
    )


_CHECKS = (
    _check_env,
    _check_audit_dsn,
    _check_api_dsn,
    _check_catalog,
    _check_shim_http,
    _check_correlation,
)


def run(as_json: bool = False) -> int:
    results = [check() for check in _CHECKS]
    failures = sum(1 for r in results if r.status == "fail")

    if as_json:
        print(json.dumps(
            {
                "results": [
                    {"name": r.name, "status": r.status, "message": r.message, "detail": r.detail}
                    for r in results
                ],
                "failures": failures,
            },
            indent=2,
        ))
    else:
        sys.stdout.write("fasten doctor\n")
        for r in results:
            sys.stdout.write(f"  {_glyph(r.status)} {r.name:13s} {r.message}\n")
        sys.stdout.write(
            f"\n{len(results) - failures}/{len(results)} checks passed"
            + (f" — {failures} failure(s)" if failures else "")
            + "\n"
        )

    return 1 if failures else 0
