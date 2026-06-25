"""
Mountable /logs/{sys,api,audit} router.

Framework-agnostic core + FastAPI adapter. Adopters on other frameworks
(Flask, Sanic, aiohttp) wrap the core handler functions.

Usage — recommended (gated with adopter auth):

    import fasten
    from fasten.reader import router
    from fastapi import Depends

    fasten.init()  # reads env: FASTEN_SERVICE_ID, FASTEN_NODE_ID, FASTEN_AUDIT_DSN

    app.include_router(
        router(dependencies=[Depends(require_admin)]),
        prefix="/api/v1/logs",
    )

Usage — internal / trusted-network only:

    app.include_router(router(), prefix="/api/v1/logs")

The router pulls the audit store + transport from ``fasten.init()`` at
request time. Pass ``store=`` / ``transport=`` to ``router()`` to
override (tests, read-replica, multi-store).

WARNING: This router has no built-in authentication. /sys, /api, and
/audit return data to any caller who can reach them. Always pass
``dependencies=[Depends(...)]`` or mount behind a trusted-network boundary.
"""
from __future__ import annotations

import dataclasses
import os
from datetime import datetime, timezone
from typing import Any, Optional

from .. import audit_store as _active_audit_store
from .. import redactor as _active_redactor
from .. import transport as _active_transport


def router(
    dependencies: list[Any] | None = None,
    *,
    store: Any = None,
    transport: Any = None,
    persist_streams: frozenset[str] | None = None,
) -> Any:
    """Build a FastAPI APIRouter exposing /sys, /api, /audit sub-paths.

    Args:
        dependencies: FastAPI dependencies applied to every route, e.g.
            ``[Depends(require_admin)]``. None means no auth — only use
            that behind a trusted-network boundary.
        store: Optional AuditRepository override. Default: pulled from
            ``fasten.init()`` at request time via ``fasten.audit_store()``.
        transport: Optional StdoutTransport override. Default: same.
        persist_streams: Streams backed by the durable store rather than a
            bounded ring. Drives the per-stream ``completeness`` flag on
            every read (``store`` vs ``ring``). Default ``{"audit"}`` —
            audit is the only store-backed stream today, api/sys are rings.
            Phase 1 wires this from config once api/sys can persist.
    """
    try:
        from fastapi import APIRouter, Query
    except ImportError as e:
        raise RuntimeError(
            "fasten.reader.router() requires fastapi; install fasten[fastapi]"
        ) from e

    r = APIRouter(dependencies=dependencies or [])

    _persisted = persist_streams if persist_streams is not None else frozenset({"audit"})

    def _store() -> Any:
        return store if store is not None else _active_audit_store()

    def _transport() -> Any:
        return transport if transport is not None else _active_transport()

    def _source(stream: str) -> str:
        """Report whether a stream is backed by the durable store or a bounded
        ring — its configured durability class, not the provenance of any
        single response — so consumers stay honest about gaps."""
        return "store" if stream in _persisted else "ring"

    @r.get("/sys")
    def get_sys(
        level: Optional[str] = Query(default=None),
        request_id: Optional[str] = Query(default=None),
        service_id: Optional[str] = Query(default=None),
        limit: int = Query(default=100, le=1000),
    ) -> dict[str, Any]:
        t = _transport()
        if t is None:
            return {
                "rows": [],
                "completeness": {"sys": _source("sys")},
                "error": "transport not initialised — call fasten.init() first",
            }
        rows = t.query_syslog(
            limit=limit,
            level=level,
            request_id=request_id,
            service_id=service_id,
        )
        return {"rows": rows, "completeness": {"sys": _source("sys")}}

    @r.get("/api")
    def get_api(
        method: Optional[str] = Query(default=None),
        path: Optional[str] = Query(default=None),
        request_id: Optional[str] = Query(default=None),
        limit: int = Query(default=100, le=1000),
    ) -> dict[str, Any]:
        t = _transport()
        if t is None:
            return {
                "rows": [],
                "completeness": {"api": _source("api")},
                "error": "transport not initialised — call fasten.init() first",
            }
        rows = t.query_api(
            limit=limit,
            method=method,
            path=path,
            request_id=request_id,
        )
        return {"rows": rows, "completeness": {"api": _source("api")}}

    @r.get("/audit")
    def get_audit(
        request_id: Optional[str] = Query(default=None),
        code: Optional[str] = Query(default=None),
        domain: Optional[str] = Query(default=None),
        source_node_id: Optional[str] = Query(default=None),
        tenant_id: Optional[str] = Query(default=None),
        actor: Optional[str] = Query(default=None),
        target: Optional[str] = Query(default=None),
        since: Optional[datetime] = Query(default=None),
        until: Optional[datetime] = Query(default=None),
        limit: int = Query(default=100, le=1000),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        s = _store()
        if s is None:
            return {
                "rows": [],
                "total": 0,
                "completeness": {"audit": _source("audit")},
                "error": "audit store not initialised — call fasten.init() first",
            }
        filters = dict(
            request_id=request_id, code=code, domain=domain,
            source_node_id=source_node_id, tenant_id=tenant_id,
            actor=actor, target=target,
            since=since, until=until,
        )
        rows = s.query(limit=limit, offset=offset, **filters)
        total = s.count(**filters) if hasattr(s, "count") else len(rows)
        return {
            "rows": [dataclasses.asdict(row) for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
            "completeness": {"audit": _source("audit")},
        }

    @r.get("/topology")
    def get_topology(
        since: Optional[datetime] = Query(default=None),
        until: Optional[datetime] = Query(default=None),
    ) -> dict[str, Any]:
        """Fleet topology — who is emitting into this store.

        Groups the audit rows by ``(source_node_id, service_id,
        tenant_id)`` and returns the per-source row counts and
        first/last-seen timestamps, plus distinct node/service/tenant
        counts. No separate topology table: the fleet view falls out of
        the rows already recorded, so it can never drift from reality.

        Same auth as ``/audit`` (router-level dependencies). Optional
        ``since``/``until`` window the aggregation.
        """
        empty = {"sources": [], "nodes": 0, "services": 0, "tenants": 0}
        s = _store()
        if s is None:
            return {**empty, "error": "audit store not initialised — call fasten.init() first"}
        if not hasattr(s, "sources"):
            return {**empty, "error": "store does not support topology aggregation"}
        sources = s.sources(since=since, until=until)
        return {
            "sources": sources,
            "nodes": len({x["source_node_id"] for x in sources}),
            "services": len({x["service_id"] for x in sources}),
            "tenants": len({x["tenant_id"] for x in sources if x["tenant_id"]}),
        }

    @r.get("/audit/doctor")
    def get_audit_doctor() -> dict[str, Any]:
        """P1-15: read-side audit-pipeline health snapshot.

        Same auth as ``/audit`` (router-level dependencies). Use cases:

        - Compliance auditor: "is your audit pipeline healthy?" — one curl.
        - k8s liveness: parse ``store.reachable && queue.retry_count_active``.
        - Status page: red/yellow/green tiles from this single payload.
        """
        from ..emitter import _default as _default_engine

        s = _store()
        store_block: dict[str, Any] = {
            "kind": type(s).__name__ if s is not None else None,
            "reachable": False,
            "rows": None,
            "last_insert_at": None,
            "last_error": None,
        }
        if s is not None:
            try:
                # Cheap reachability check — count() is supported by the
                # built-in SQLite + Postgres stores; adopters who plug a
                # custom store without count() get reachable=true and
                # rows=null (good enough for the probe).
                if hasattr(s, "count"):
                    store_block["rows"] = s.count()
                store_block["reachable"] = True
            except Exception as e:  # noqa: BLE001
                store_block["reachable"] = False
                store_block["last_error"] = f"{type(e).__name__}: {e}"

        queue_block: Optional[dict[str, Any]] = _default_engine.queue_stats()

        t = _transport()
        transport_block = {
            "stdout_active": t is not None,
            "syslog_ring_depth": (
                len(t._syslog._buf) if t is not None else 0
            ),
            "api_ring_depth": (
                len(t._api._buf) if t is not None else 0
            ),
        }

        rd = _active_redactor()
        # Redactor stores a single compiled regex; surface presence only.
        redactor_block = {
            "active": rd is not None,
        }

        init_block = {
            "service_id": _default_engine._service_id or None,
            "node_id": _default_engine._node_id or None,
            "tenant_id": _default_engine._tenant_id,
            "failure_strategy": _default_engine._failure_strategy,
            # P1-19: multi-worker awareness — callers can confirm which
            # OS process they are hitting (relevant under uvicorn --workers N).
            "worker_pid": os.getpid(),
        }

        # P1-23: hash chain verification — spot-check latest 50 rows.
        chain_block: dict[str, Any] = {
            "verified": None,
            "breaks": 0,
            "last_verified_at": None,
        }
        if s is not None and hasattr(s, "query"):
            try:
                from ..engine import verify_chain
                recent = s.query(
                    source_node_id=_default_engine._node_id or None,
                    limit=50,
                )
                if recent:
                    result = verify_chain(recent)
                    chain_block = {
                        "verified": result.ok,
                        "breaks": 0 if result.ok else 1,
                        "first_break_at": result.first_break_at,
                        "reason": result.reason,
                        "last_verified_at": datetime.now(timezone.utc).isoformat(
                            timespec="milliseconds"
                        ),
                    }
            except Exception:  # noqa: BLE001
                pass

        return {
            "store": store_block,
            "queue": queue_block,
            "transport": transport_block,
            "redactor": redactor_block,
            "init": init_block,
            "chain": chain_block,
        }

    return r
