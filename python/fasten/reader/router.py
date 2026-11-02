"""FastAPI router for /logs/{sys,api,audit} and the related reads.

With your own auth:

    import fasten
    from fasten.reader import router
    from fastapi import Depends

    fasten.init()

    app.include_router(
        router(dependencies=[Depends(require_admin)]),
        prefix="/api/v1/logs",
    )

Without auth, on a trusted network only:

    app.include_router(router(dependencies=[]), prefix="/api/v1/logs")

The store and transport come from the default Engine at request time unless
``store=`` or ``transport=`` is passed. The router has no auth of its own.
"""
from __future__ import annotations

import dataclasses
import os
from datetime import datetime
from typing import Any, Optional

from ..canonical_ts import canonical_now, canonical_ts
from .. import audit_store as _active_audit_store
from .. import persisted_streams as _active_persisted_streams
from .. import redactor as _active_redactor
from .. import search_enabled as _active_search_enabled

# Imported at module level so FastAPI can resolve the string annotation
# `request: Request`; otherwise it treats `request` as a query parameter.
try:
    from starlette.requests import Request
except ImportError:  # pragma: no cover  fastapi missing; router() raises anyway
    pass
from .. import transport as _active_transport


_UNSET: Any = object()


def router(
    dependencies: list[Any] | None = _UNSET,  # required; [] for no auth
    *,
    store: Any = None,
    transport: Any = None,
    persist_streams: frozenset[str] | None = None,
    search_enabled: bool | None = None,
    tenant_scope: Any = None,
    enforce_tenant_isolation: bool = False,
) -> Any:
    """Build a FastAPI APIRouter exposing /sys, /api, /audit sub-paths.

    Args:
        dependencies: FastAPI dependencies for every route, e.g.
            ``[Depends(require_admin)]``. Required, so a missing auth hook
            fails at startup. Pass ``[]`` for the no-auth case.
        store: AuditRepository to read. Default: ``fasten.audit_store()``
            at request time.
        transport: StdoutTransport to read. Default: ``fasten.transport()``.
        persist_streams: Streams reported as ``store`` rather than ``ring``
            in ``completeness``. Default: ``fasten.persisted_streams()`` at
            request time.
        tenant_scope: Callable ``(request) -> str | None`` invoked per
            request to resolve the caller's tenant from the (already-
            authenticated) request. When supplied, EVERY reader endpoint
            (``/audit``, ``/correlate``, ``/search``, ``/topology``)
            injects the resolved tenant into the store filter and
            **ignores** any ``?tenant_id=`` from the caller. Returning
            ``None`` (unauthenticated / no scope) rejects the request
            with 401. Without this hook, ``?tenant_id=`` is honoured
            as-is — safe for single-tenant deployments, unsafe on any
            shared-store multi-tenant deployment.
        enforce_tenant_isolation: When True, refuse to construct the
            router unless ``tenant_scope`` is wired. Set this on any
            shared-store multi-tenant deployment so a mis-configured
            reader can't ship without tenant enforcement.
    """
    try:
        from fastapi import APIRouter, HTTPException, Query
    except ImportError as e:
        raise RuntimeError(
            "fasten.reader.router() requires fastapi; install fasten[fastapi]"
        ) from e

    if dependencies is None:
        raise RuntimeError(
            "fasten.reader.router: `dependencies=None` is not a valid no-auth "
            "opt-in; it is treated as unset. Pass "
            "`dependencies=[]` to deliberately mount without auth, or an auth "
            "hook such as `[Depends(require_admin)]`."
        )
    if dependencies is _UNSET:
        raise RuntimeError(
            "fasten.reader.router: `dependencies=` is required. Pass an "
            "auth hook, e.g. `[Depends(require_admin)]` or the bundled "
            "helper `fasten.reader.require_bearer()`, or pass "
            "`dependencies=[]` to opt into unauthenticated mode "
            "explicitly (dev / localhost / a proxy that enforces auth "
            "already). No default so a mis-configured production deploy "
            "can't ship an unauthenticated audit reader."
        )

    if enforce_tenant_isolation and tenant_scope is None:
        raise RuntimeError(
            "fasten.reader.router(enforce_tenant_isolation=True) requires a "
            "tenant_scope callable. Wire (request) -> str | None from your "
            "auth layer, or pass enforce_tenant_isolation=False for a "
            "single-tenant deployment."
        )

    r = APIRouter(dependencies=dependencies or [])

    def _resolve_tenant(request: "Request") -> Optional[str]:
        """Return the tenant scope for this request, or raise 401 when a
        scope hook was wired but resolved to None. Returns None when no
        hook is wired (single-tenant mode)."""
        if tenant_scope is None:
            return None
        t = tenant_scope(request)
        if not t:
            # `not t`, NOT `t is None`: an empty string is a resolved-but-blank
            # scope, and the store treats a falsy tenant_id as "no filter"
            # (sqlite.py `if tenant_id:`). Letting "" through the gate turns
            # tenant isolation into a full cross-tenant read. Fail closed.
            raise HTTPException(status_code=401, detail="unauthenticated: tenant scope unresolved")
        return t

    def _scope_stream_rows(rows: list[dict[str, Any]], scope: Optional[str]) -> list[dict[str, Any]]:
        """Post-filter sys/api stream rows by tenant. sys/api rows are
        freeform dicts with an optional ``tenant_id`` key — not a lifted
        index column — so we can't push this down to the store the way
        we can for audit. Post-filter is defensive: rows without a
        tenant_id are dropped when a scope is active (fail-closed:
        undated-tenant rows are ambiguous, and returning them to a
        scoped caller would leak). Scope=None (single-tenant mode)
        returns rows unchanged.

        This is the enforcement point for /logs/sys, /logs/api,
        /correlate api+sys, and /search api+sys."""
        if scope is None:
            return rows
        return [r for r in rows if r.get("tenant_id") == scope]

    def _store() -> Any:
        return store if store is not None else _active_audit_store()

    def _transport() -> Any:
        return transport if transport is not None else _active_transport()

    def _search_on() -> bool:
        return search_enabled if search_enabled is not None else _active_search_enabled()

    def _parse_window_ts(name: str, s: Optional[str]) -> Optional[str]:
        """Convert ``?since=`` / ``?until=`` to the canonical timestamp form,
        since stored timestamps are compared as strings. Empty gives None;
        anything that is not RFC 3339 raises a 422."""
        if s is None or s == "":
            return None
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError as e:
            raise HTTPException(
                status_code=422,
                detail=f"{name} must be RFC3339 (e.g. 2026-08-21T10:00:00Z): {e}",
            )
        return canonical_ts(dt)

    def _search_guard(q: Optional[str], since: Optional[str]) -> Optional[str]:
        """Return an error message if a ``q=`` read is not allowed (search
        disabled, or no ``since``), else None."""
        if not _search_on():
            return (
                "search disabled — set search.enabled "
                "(FASTEN_SEARCH_ENABLED=true) to enable free-text q="
            )
        if not since:
            return "q= search requires a 'since' bound (no unbounded scans)"
        return None

    def _audit_degraded() -> bool:
        """True if stored audit history has gaps: an insert failed and was
        dropped (engine or store flag), or the drainer dead-lettered a row."""
        from ..emitter import _default as _default_engine
        if _default_engine.audit_write_swallowed():
            return True
        s = _store()
        if s is not None and getattr(s, "degraded", False):
            return True
        stats = _default_engine.queue_stats()
        if stats and stats.get("dead_lettered_total", 0) > 0:
            return True
        return False

    def _source(stream: str) -> str:
        """``ring``, ``store`` or ``store-degraded`` for a stream.

        This says whether the stream can lose rows, not whether this response
        did; /correlate reports truncation separately. ``store-degraded``
        means a write to the store failed at some point, so its history has
        gaps.
        """
        persisted = persist_streams if persist_streams is not None else _active_persisted_streams()
        if stream not in persisted:
            return "ring"
        if stream == "audit":
            return "store-degraded" if _audit_degraded() else "store"
        t = _transport()
        if t is not None and getattr(t, "stream_degraded", None) and t.stream_degraded(stream):
            return "store-degraded"
        return "store"

    @r.get("/sys")
    def get_sys(
        request: Request,
        level: Optional[str] = Query(default=None),
        request_id: Optional[str] = Query(default=None),
        service_id: Optional[str] = Query(default=None),
        event: Optional[str] = Query(default=None),
        q: Optional[str] = Query(default=None, min_length=1, max_length=1024),
        since: Optional[str] = Query(default=None),
        until: Optional[str] = Query(default=None),
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> dict[str, Any]:
        tenant = _resolve_tenant(request)
        t = _transport()
        if t is None:
            return {
                "rows": [],
                "completeness": {"sys": _source("sys")},
                "error": "transport not initialised — call fasten.init() first",
            }
        since = _parse_window_ts("since", since)
        until = _parse_window_ts("until", until)
        if q is not None:
            err = _search_guard(q, since)
            if err is not None:
                return {"rows": [], "completeness": {"sys": _source("sys")}, "error": err}
            # q= cannot be combined with filters; reject rather than ignore them.
            dropped = [
                name for name, val in (
                    ("level", level), ("request_id", request_id),
                    ("service_id", service_id), ("event", event),
                ) if val is not None
            ]
            if dropped:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "q= is a free-text search and cannot be combined with "
                        f"structured filters ({', '.join(dropped)}). Use one or "
                        "the other — structured filters run over the store index; "
                        "q= runs over the raw payload."
                    ),
                )
            rows = t.search_syslog(q=q, since=since, until=until, limit=min(limit, 200))
            if rows is None:
                return {
                    "rows": [],
                    "completeness": {"sys": _source("sys")},
                    "error": "search requires sys persistence: configure a syslog store",
                }
            return {"rows": _scope_stream_rows(rows, tenant),
                    "completeness": {"sys": _source("sys")}}
        rows = t.query_syslog(
            limit=limit,
            level=level,
            request_id=request_id,
            service_id=service_id,
            event=event,
            since=since,
            until=until,
        )
        return {"rows": _scope_stream_rows(rows, tenant),
                "completeness": {"sys": _source("sys")}}

    @r.get("/api")
    def get_api(
        request: Request,
        method: Optional[str] = Query(default=None),
        path: Optional[str] = Query(default=None),
        request_id: Optional[str] = Query(default=None),
        status: Optional[int] = Query(default=None),
        since: Optional[str] = Query(default=None),
        until: Optional[str] = Query(default=None),
        limit: int = Query(default=100, ge=1, le=1000),
        q: Optional[str] = Query(default=None, max_length=1024),
    ) -> dict[str, Any]:
        tenant = _resolve_tenant(request)
        if q is not None:
            # Free-text search on api goes through /search.
            raise HTTPException(
                status_code=400,
                detail=(
                    "free-text q= not accepted on /api — use "
                    "/search?streams=api (or /logs/sys?q= for syslog only)"
                ),
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
            since=_parse_window_ts("since", since),
            until=_parse_window_ts("until", until),
        )
        return {"rows": _scope_stream_rows(rows, tenant),
                "completeness": {"api": _source("api")}}

    @r.get("/audit")
    def get_audit(
        request: Request,
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
        after: Optional[int] = Query(default=None, ge=1),
    ) -> dict[str, Any]:
        # When tenant_scope is wired, IGNORE any ?tenant_id= from
        # the caller and inject the resolved scope. Without the hook,
        # ?tenant_id= is honoured as-is (single-tenant deployments and
        # legacy call sites).
        tenant = _resolve_tenant(request)
        if tenant is not None:
            tenant_id = tenant
        s = _store()
        if s is None:
            return {
                "rows": [],
                "total": 0,
                "limit": limit,
                "offset": offset,
                "next_after": None,
                "completeness": {"audit": _source("audit")},
                "error": "audit store not initialised — call fasten.init() first",
            }
        filters = dict(
            request_id=request_id, code=code, domain=domain,
            source_node_id=source_node_id, tenant_id=tenant_id,
            actor=actor, target=target,
            since=since, until=until,
        )
        rows = s.query(limit=limit, offset=offset, after_seq=(after or 0), **filters)
        # total is None if the store has no count() or it fails. len(rows)
        # would be wrong (it is capped at limit), and a 500 would lose the
        # rows. Go's handleAudit does the same.
        total: int | None = None
        if hasattr(s, "count"):
            try:
                total = s.count(**filters)
            except Exception:  # noqa: BLE001
                total = None
        # Offset paging (total/limit/offset) and cursor paging (next_after)
        # are both returned. Rows are newest first, so next_after is the
        # smallest monotonic_seq; pass it back as ?after=.
        next_after = rows[-1].monotonic_seq if rows else None
        return {
            "rows": [dataclasses.asdict(row) for row in rows],
            "total": total,
            "limit": limit,
            "offset": offset,
            "next_after": next_after,
            "completeness": {"audit": _source("audit")},
        }

    @r.get("/correlate")
    def get_correlate(
        request: Request,
        request_id: str = Query(..., min_length=1),
        limit: int = Query(default=100, ge=1, le=1000),
    ) -> dict[str, Any]:
        """Rows from every stream for one ``request_id``.

        ``counts`` is how many rows this response holds per stream and
        ``totals`` how many match; ``truncated`` is ``counts < totals`` (None
        when the total is unknown).

        When ``tenant_scope`` is wired, every stream is scoped to
        the caller's tenant. Otherwise the ``X-Request-ID`` header a
        tenant sends could be used to pivot into another tenant's rows
        via a known/guessed request_id.
        """
        tenant = _resolve_tenant(request)
        s = _store()
        t = _transport()
        audit = (
            [dataclasses.asdict(row) for row in s.query(limit=limit, request_id=request_id,
                                                       tenant_id=tenant)]
            if s is not None else []
        )
        api = _scope_stream_rows(
            t.query_api(limit=limit, request_id=request_id) if t is not None else [],
            tenant,
        )
        sys = _scope_stream_rows(
            t.query_syslog(limit=limit, request_id=request_id) if t is not None else [],
            tenant,
        )
        audit_total: int | None = None
        if s is not None and hasattr(s, "count"):
            try:
                audit_total = s.count(request_id=request_id, tenant_id=tenant)
            except Exception:  # noqa: BLE001
                audit_total = None
        counts = {"audit": len(audit), "api": len(api), "sys": len(sys)}
        # Stream count APIs don't take tenant_id; when a scope is active
        # the totals for api/sys are the visible-after-post-filter len,
        # not the unfiltered store count. Post-filter is a defensive
        # over-count avoidance — the response truncated boolean below
        # reads consistently with what the caller actually sees.
        totals = {
            "audit": audit_total,
            "api": len(api) if tenant is not None
            else (t.count_api(request_id=request_id) if t is not None else 0),
            "sys": len(sys) if tenant is not None
            else (t.count_syslog(request_id=request_id) if t is not None else 0),
        }
        # None when the total is unknown (audit store without count()).
        def _trunc(k: str) -> Optional[bool]:
            total = totals[k]
            return None if total is None else counts[k] < total
        truncated = {k: _trunc(k) for k in ("audit", "api", "sys")}
        return {
            "request_id": request_id,
            "audit": audit,
            "api": api,
            "sys": sys,
            "counts": counts,
            "totals": totals,
            "truncated": truncated,
            "completeness": {
                "audit": _source("audit"),
                "api": _source("api"),
                "sys": _source("sys"),
            },
        }

    _VALID_SEARCH_STREAMS = frozenset({"audit", "api", "sys"})

    @r.get("/search")
    def get_search(
        request: Request,
        q: str = Query(..., min_length=1, max_length=1024),
        since: str = Query(...),
        until: Optional[str] = Query(default=None),
        limit: int = Query(default=50, ge=1, le=200),
        streams: Optional[str] = Query(default=None),
    ) -> dict[str, Any]:
        """Case-insensitive substring search over stored rows, newest first.

        Needs search enabled and a ``since`` bound. ``streams=`` is a
        comma-separated subset of audit, api and sys (default sys). A stream
        without a store gets an entry in ``errors`` rather than no matches.
        Each match carries its ``request_id`` for /correlate.
        """
        tenant = _resolve_tenant(request)
        # Validate streams before the search guard so a bad value gets a 400.
        requested = streams.split(",") if streams else ["sys"]
        parsed = {s.strip() for s in requested if s.strip()}
        unknown = parsed - _VALID_SEARCH_STREAMS
        if unknown:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"streams={sorted(parsed)}: unknown stream(s) {sorted(unknown)}. "
                    f"Valid: {sorted(_VALID_SEARCH_STREAMS)}."
                ),
            )
        if not parsed:
            parsed = {"sys"}

        completeness = {s: _source(s) for s in parsed}
        empty_counts = {s: 0 for s in parsed}
        # since="" passes Query(...), so the guard has to catch it.
        since = _parse_window_ts("since", since) or ""
        until = _parse_window_ts("until", until)
        err = _search_guard(q, since)
        if err is not None:
            return {"matches": [], "counts": empty_counts,
                    "completeness": completeness, "error": err}

        t = _transport()
        s = _store()
        if t is None:
            return {"matches": [], "counts": empty_counts,
                    "completeness": completeness,
                    "error": "transport not initialised — call fasten.init() first"}

        matches: list[dict[str, Any]] = []
        counts: dict[str, int] = {}
        errors: dict[str, str] = {}
        # Fixed order: sys, api, audit.
        for stream in ("sys", "api", "audit"):
            if stream not in parsed:
                continue
            if stream == "sys":
                rows = t.search_syslog(q=q, since=since, until=until, limit=limit)
                if rows is None:
                    errors["sys"] = "requires sys persistence: configure a syslog store"
                    counts["sys"] = 0
                    continue
                rows = _scope_stream_rows(rows, tenant)
                counts["sys"] = len(rows)
                for row in rows:
                    matches.append({
                        "stream": "sys",
                        "request_id": row.get("request_id"),
                        "ts": row.get("timestamp"),
                        "summary": row.get("event"),
                        "row": row,
                    })
            elif stream == "api":
                rows = t.search_api(q=q, since=since, until=until, limit=limit)
                if rows is None:
                    errors["api"] = "requires api persistence: configure an api store"
                    counts["api"] = 0
                    continue
                rows = _scope_stream_rows(rows, tenant)
                counts["api"] = len(rows)
                for row in rows:
                    matches.append({
                        "stream": "api",
                        "request_id": row.get("request_id"),
                        "ts": row.get("timestamp"),
                        "summary": f"{row.get('method','')} {row.get('path','')}".strip(),
                        "row": row,
                    })
            elif stream == "audit":
                if s is None or not hasattr(s, "search"):
                    errors["audit"] = "requires an audit store with a search method"
                    counts["audit"] = 0
                    continue
                # Tenant scope pushed into the store (SQL WHERE tenant_id=?),
                # not post-filtered — the store now accepts it as a kwarg.
                rows = s.search(q=q, since=since, until=until, limit=limit, tenant_id=tenant)
                counts["audit"] = len(rows)
                for row in rows:
                    matches.append({
                        "stream": "audit",
                        "request_id": row.request_id,
                        "ts": canonical_ts(row.timestamp) if row.timestamp else None,
                        "summary": row.code,
                        "row": dataclasses.asdict(row),
                    })

        resp: dict[str, Any] = {
            "matches": matches,
            "counts": counts,
            "completeness": completeness,
        }
        if errors:
            resp["errors"] = errors
        return resp

    @r.get("/topology")
    def get_topology(
        request: Request,
        since: Optional[datetime] = Query(default=None),
        until: Optional[datetime] = Query(default=None),
    ) -> dict[str, Any]:
        """Who is writing to this store.

        Audit rows grouped by ``(source_node_id, service_id, tenant_id)``
        with row counts and first/last seen times, plus distinct node,
        service and tenant counts. Optional
        ``since``/``until`` window the aggregation. When
        ``tenant_scope`` is wired, the aggregation is post-filtered to
        the resolved tenant only — mild fleet enumeration
        (`service_id` / `node_id` values of other tenants) is not
        available across the tenant boundary.
        """
        tenant = _resolve_tenant(request)
        empty = {"sources": [], "nodes": 0, "services": 0, "tenants": 0}
        s = _store()
        if s is None:
            return {**empty, "error": "audit store not initialised — call fasten.init() first"}
        if not hasattr(s, "sources"):
            return {**empty, "error": "store does not support topology aggregation"}
        sources = s.sources(since=since, until=until)
        if tenant is not None:
            sources = [x for x in sources if x.get("tenant_id") == tenant]
        return {
            "sources": sources,
            "nodes": len({x["source_node_id"] for x in sources}),
            "services": len({x["service_id"] for x in sources}),
            "tenants": len({x["tenant_id"] for x in sources if x["tenant_id"]}),
        }

    @r.get("/audit/doctor")
    def get_audit_doctor(request: "Request") -> dict[str, Any]:
        """Read-side audit-pipeline health snapshot.

        Takes ``request`` and calls ``_resolve_tenant`` like every other
        handler. It previously took no argument, so it could not scope and
        returned 200 to a caller that every other route 401s — leaking the
        global row count, the host tenant_id, a cross-tenant chain sample and
        raw driver errors carrying DSN host/user.

        Same auth as ``/audit`` (router-level dependencies). Use cases:

        - Compliance auditor: "is your audit pipeline healthy?" — one curl.
        - k8s liveness: parse ``store.reachable && queue.retry_count_active``.
        - Status page: red/yellow/green tiles from this single payload.
        """
        from ..emitter import _default as _default_engine

        # 401s when isolation is on and the scope is unresolved/blank.
        tenant = _resolve_tenant(request)

        # #5: the engine sets this when a store lacks §2.1 allocation, so rows
        # go in unsealed. verify_chain SKIPS hashless rows, so without surfacing
        # it here doctor reports verified=true over a fully unchained table.
        chain_unavailable = bool(
            getattr(_default_engine, "_audit_chain_unavailable", False))

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
                    # Scoped. An unscoped count() here reported the GLOBAL row
                    # total to a tenant-scoped caller — the data half of the
                    # leak that resolving the tenant only half-closed.
                    store_block["rows"] = (
                        s.count(tenant_id=tenant) if tenant is not None
                        else s.count()
                    )
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
            # Multi-worker awareness: callers can confirm which
            # OS process they are hitting (relevant under uvicorn --workers N).
            "worker_pid": os.getpid(),
        }

        # Hash chain verification: spot-check latest 50 rows.
        # breaks is None until verification actually runs; 0 when the chain is
        # clean, 1+ when broken. Never report 0 for "we didn't check", which
        # would read as green on a status page colouring on this field.
        chain_block: dict[str, Any] = {
            "verified": None,
            "breaks": None,
            "last_verified_at": None,
            # #5: true when the store cannot chain (no §2.1 allocation), so
            # rows are written unsealed. verify_chain SKIPS hashless rows, so
            # "verified": true would otherwise be reported over a table that
            # carries no tamper evidence at all.
            "chain_unavailable": chain_unavailable,
        }
        if s is not None and hasattr(s, "query"):
            try:
                from ..engine import verify_chain
                recent = s.query(
                    source_node_id=_default_engine._node_id or None,
                    limit=50,
                )
                if recent:
                    recent.reverse()  # verify_chain requires oldest-first traversal
                    result = verify_chain(recent)
                    chain_block = {
                        # An unchained store can never be "verified".
                        "verified": (False if chain_unavailable else result.ok),
                        "breaks": None if chain_unavailable else (0 if result.ok else 1),
                        "first_break_at": result.first_break_at,
                        "reason": result.reason,
                        "last_verified_at": canonical_now(),
                    }
            except Exception as e:  # noqa: BLE001
                # Never collapse a failed check into breaks: 0. Surface the
                # error so operators can see verification is broken rather
                # than seeing a green status page.
                chain_block = {
                    "verified": None,
                    "breaks": None,
                    "error": type(e).__name__,
                    "reason": str(e),
                    "last_verified_at": None,
                }

        return {
            "store": store_block,
            "queue": queue_block,
            "transport": transport_block,
            "redactor": redactor_block,
            "init": init_block,
            "chain": chain_block,
        }

    return r
