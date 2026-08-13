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
from .. import persisted_streams as _active_persisted_streams
from .. import redactor as _active_redactor
from .. import search_enabled as _active_search_enabled
from .. import transport as _active_transport


def router(
    dependencies: list[Any] | None = None,
    *,
    store: Any = None,
    transport: Any = None,
    persist_streams: frozenset[str] | None = None,
    search_enabled: bool | None = None,
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
            every read (``store`` vs ``ring``). Default: resolved per request
            from the live engine config (``fasten.persisted_streams()``) —
            ``audit`` always, plus ``api``/``sys`` when a stream store is
            configured. Pass an explicit set to override.
    """
    try:
        from fastapi import APIRouter, HTTPException, Query
    except ImportError as e:
        raise RuntimeError(
            "fasten.reader.router() requires fastapi; install fasten[fastapi]"
        ) from e

    r = APIRouter(dependencies=dependencies or [])

    def _store() -> Any:
        return store if store is not None else _active_audit_store()

    def _transport() -> Any:
        return transport if transport is not None else _active_transport()

    def _search_on() -> bool:
        return search_enabled if search_enabled is not None else _active_search_enabled()

    def _search_guard(q: Optional[str], since: Optional[str]) -> Optional[str]:
        """Shared FR3 preconditions: search must be enabled and time-bounded.
        Returns an error message when a ``q=`` read is not allowed, else None."""
        if not _search_on():
            return (
                "search disabled — set search.enabled "
                "(FASTEN_SEARCH_ENABLED=true) to enable free-text q="
            )
        if not since:
            return "q= search requires a 'since' bound (no unbounded scans)"
        return None

    def _audit_degraded() -> bool:
        """Audit durable history has known holes when either the audit store
        swallowed a persist failure (sync fallback path) or the drainer
        dead-lettered at least one row (async path). Unlike api/sys, audit
        durability spans the store *and* the drainer, so both are consulted."""
        s = _store()
        if s is not None and getattr(s, "degraded", False):
            return True
        from ..emitter import _default as _default_engine
        stats = _default_engine.queue_stats()
        if stats and stats.get("dead_lettered_total", 0) > 0:
            return True
        return False

    def _source(stream: str) -> str:
        """Report whether a stream is backed by the durable store or a bounded
        ring — its configured durability class, not a per-response gap signal.

        It says whether the stream *can* lose rows, never whether *this*
        response did: a ring that overflowed and evicted older matching rows
        still reports ``ring``, identical to an empty ring that lost nothing.
        There is no truncation flag here — for ``/correlate``, the
        totals-vs-counts pair is the per-response truncation signal. When
        ``persist_streams`` is not pinned, resolve it from the live engine
        config so the flag tracks which streams actually persist (FR1).

        A store-backed stream whose sink has swallowed at least one persist
        failure reports ``store-degraded``: reads are still served from the
        store, but durable history has known holes (rows that live only in
        the ring, which store-backed reads never consult), so plain ``store``
        would assert a durability the data no longer has. Sticky for the
        store's lifetime."""
        persisted = persist_streams if persist_streams is not None else _active_persisted_streams()
        if stream not in persisted:
            return "ring"
        if stream == "audit":
            # Audit is not a transport stream — its degraded signal comes from
            # the audit store + drainer, not transport.stream_degraded (api/sys).
            return "store-degraded" if _audit_degraded() else "store"
        t = _transport()
        if t is not None and getattr(t, "stream_degraded", None) and t.stream_degraded(stream):
            return "store-degraded"
        return "store"

    @r.get("/sys")
    def get_sys(
        level: Optional[str] = Query(default=None),
        request_id: Optional[str] = Query(default=None),
        service_id: Optional[str] = Query(default=None),
        event: Optional[str] = Query(default=None),
        q: Optional[str] = Query(default=None, min_length=1),
        since: Optional[str] = Query(default=None),
        until: Optional[str] = Query(default=None),
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> dict[str, Any]:
        t = _transport()
        if t is None:
            return {
                "rows": [],
                "completeness": {"sys": _source("sys")},
                "error": "transport not initialised — call fasten.init() first",
            }
        if q is not None:
            # FR3 escape hatch on the sys read: gated + time-bounded (§4.1).
            err = _search_guard(q, since)
            if err is not None:
                return {"rows": [], "completeness": {"sys": _source("sys")}, "error": err}
            rows = t.search_syslog(q=q, since=since, until=until, limit=min(limit, 200))
            if rows is None:
                return {
                    "rows": [],
                    "completeness": {"sys": _source("sys")},
                    "error": "search requires sys persistence — configure a syslog store (FR1)",
                }
            return {"rows": rows, "completeness": {"sys": _source("sys")}}
        rows = t.query_syslog(
            limit=limit,
            level=level,
            request_id=request_id,
            service_id=service_id,
            event=event,
            since=since,
            until=until,
        )
        return {"rows": rows, "completeness": {"sys": _source("sys")}}

    @r.get("/api")
    def get_api(
        method: Optional[str] = Query(default=None),
        path: Optional[str] = Query(default=None),
        request_id: Optional[str] = Query(default=None),
        status: Optional[int] = Query(default=None),
        since: Optional[str] = Query(default=None),
        until: Optional[str] = Query(default=None),
        limit: int = Query(default=100, ge=1, le=1000),
        q: Optional[str] = Query(default=None),
    ) -> dict[str, Any]:
        if q is not None:
            # Free-text search is sys-only in v1 (§9). Reject rather than
            # silently drop, so callers (and copy-pasted handlers) can't
            # assume q= works on the api stream.
            raise HTTPException(
                status_code=400,
                detail="free-text q= is sys-only in v1 — use /logs/sys?q=",
            )
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
            status=status,
            since=since,
            until=until,
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
        limit: int = Query(default=100, ge=1, le=1000),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        s = _store()
        if s is None:
            return {
                "rows": [],
                "total": 0,
                "limit": limit,
                "offset": offset,
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

    @r.get("/correlate")
    def get_correlate(
        request_id: str = Query(..., min_length=1),
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> dict[str, Any]:
        """Unified correlation read — every stream for one ``request_id``.

        Fans out to the existing per-stream query paths (audit store + sys/api
        rings-or-stores) and assembles them, so a consumer holding a
        ``request_id`` gets the whole operation in one call instead of
        stitching three. Adds no new query semantics beyond fan-out +
        assembly. ``completeness`` reports each stream's durability class,
        and ``totals`` reports how many matching rows the backing source
        holds — ``counts`` is how many this capped response returned, so
        ``counts < totals`` means the response is truncated (raise ``limit``
        or page the per-stream endpoints).
        """
        s = _store()
        t = _transport()
        audit = (
            [dataclasses.asdict(row) for row in s.query(limit=limit, request_id=request_id)]
            if s is not None else []
        )
        api = t.query_api(limit=limit, request_id=request_id) if t is not None else []
        sys = t.query_syslog(limit=limit, request_id=request_id) if t is not None else []
        audit_total = (
            s.count(request_id=request_id)
            if s is not None and hasattr(s, "count") else len(audit)
        )
        return {
            "request_id": request_id,
            "audit": audit,
            "api": api,
            "sys": sys,
            "counts": {"audit": len(audit), "api": len(api), "sys": len(sys)},
            "totals": {
                "audit": audit_total,
                "api": t.count_api(request_id=request_id) if t is not None else 0,
                "sys": t.count_syslog(request_id=request_id) if t is not None else 0,
            },
            "completeness": {
                "audit": _source("audit"),
                "api": _source("api"),
                "sys": _source("sys"),
            },
        }

    @r.get("/search")
    def get_search(
        q: str = Query(..., min_length=1),
        since: str = Query(...),
        until: Optional[str] = Query(default=None),
        limit: int = Query(default=50, ge=1, le=200),
    ) -> dict[str, Any]:
        """FR3 free-text search — the sys-only, time-bounded escape hatch (§4.1).

        For "I only have an error string": a case-insensitive substring scan over
        persisted sys history, returning each match's ``request_id`` so a consumer
        can hand it to ``/correlate``. Deliberately constrained — opt-in
        (``search.enabled``), ``since`` mandatory (no unbounded scans), hard
        result cap, and **no relevance ranking** (newest-first). Not a log query
        language; structured field reads are the primary discovery path.
        """
        empty = {"matches": [], "counts": {"sys": 0}, "completeness": {"sys": _source("sys")}}
        err = _search_guard(q, since)
        if err is not None:
            return {**empty, "error": err}
        t = _transport()
        if t is None:
            return {**empty, "error": "transport not initialised — call fasten.init() first"}
        rows = t.search_syslog(q=q, since=since, until=until, limit=limit)
        if rows is None:
            return {**empty, "error": "search requires sys persistence — configure a syslog store (FR1)"}
        matches = [
            {
                "stream": "sys",
                "request_id": row.get("request_id"),
                "ts": row.get("timestamp"),
                "summary": row.get("event"),
                "row": row,
            }
            for row in rows
        ]
        return {
            "matches": matches,
            "counts": {"sys": len(matches)},
            "completeness": {"sys": _source("sys")},
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
