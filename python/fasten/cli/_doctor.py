"""
`fasten doctor` — verify init config + store + correlation wiring.

Read-only diagnostic. Runs each check, prints status + message, returns
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
import sys
from dataclasses import dataclass
from typing import Any


@dataclass
class CheckResult:
    name: str
    status: str       # "ok" | "warn" | "fail"
    message: str
    detail: dict[str, Any] | None = None


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
            message="not set — fasten.init() will REFUSE TO START. Set FASTEN_AUDIT_DSN to durable storage.",
        )
    try:
        from ..store.sqlite import SQLiteStore
        store = SQLiteStore.from_dsn(dsn)
        rows = store.query(limit=1)
        return CheckResult(
            name="audit_dsn",
            status="ok",
            message=f"{dsn} (connected, table accessible, sample query returned {len(rows)} row[s])",
            detail={"dsn": dsn, "sample_rows": len(rows)},
        )
    except Exception as e:  # noqa: BLE001 — diagnostic context, all failures relevant
        return CheckResult(
            name="audit_dsn",
            status="fail",
            message=f"{dsn} → {type(e).__name__}: {e}",
        )


def _check_api_dsn() -> CheckResult:
    dsn = os.environ.get("FASTEN_API_DSN")
    if not dsn:
        return CheckResult(
            name="api_dsn",
            status="ok",
            message="not configured — ring-buffer only (default; persist via FASTEN_API_DSN if needed)",
        )
    try:
        from ..store.sqlite import SQLiteStore
        store = SQLiteStore.from_dsn(dsn)
        rows = store.query(limit=1)
        return CheckResult(
            name="api_dsn",
            status="ok",
            message=f"{dsn} (connected, accessible, {len(rows)} sample row[s])",
            detail={"dsn": dsn},
        )
    except Exception as e:  # noqa: BLE001
        return CheckResult(name="api_dsn", status="fail", message=f"{dsn} → {type(e).__name__}: {e}")


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
