"""
Mountable /logs/{sys,api,audit} router.

Framework-agnostic core + FastAPI adapter. Adopters on other frameworks
(Flask, Sanic, aiohttp) wrap the core handler functions.

Usage:
    from fasten.reader import router, init as init_reader
    init_reader(fasten._get_audit_store(), fasten._get_stdout())
    app.include_router(router(), prefix="/api/v1/logs")
"""
from __future__ import annotations

import dataclasses
from datetime import datetime
from typing import Any, Optional

_store: Any = None       # AuditRepository (sqlite / postgres)
_transport: Any = None   # StdoutTransport — carries syslog + api ring buffers


def init(store: Any, transport: Any = None) -> None:
    """Inject audit store and stdout transport so route handlers can query them."""
    global _store, _transport
    _store = store
    _transport = transport


def router() -> Any:
    """Build a FastAPI APIRouter exposing /sys, /api, /audit sub-paths."""
    try:
        from fastapi import APIRouter, Query
    except ImportError as e:
        raise RuntimeError(
            "fasten.reader.router() requires fastapi; install fasten[fastapi]"
        ) from e

    r = APIRouter()

    @r.get("/sys")
    def get_sys(
        level: Optional[str] = Query(default=None),
        request_id: Optional[str] = Query(default=None),
        service_id: Optional[str] = Query(default=None),
        limit: int = Query(default=100, le=1000),
    ) -> dict[str, Any]:
        if _transport is None:
            return {"rows": [], "error": "transport not initialised — call init() first"}
        rows = _transport.query_syslog(
            limit=limit,
            level=level,
            request_id=request_id,
            service_id=service_id,
        )
        return {"rows": rows}

    @r.get("/api")
    def get_api(
        method: Optional[str] = Query(default=None),
        path: Optional[str] = Query(default=None),
        request_id: Optional[str] = Query(default=None),
        limit: int = Query(default=100, le=1000),
    ) -> dict[str, Any]:
        if _transport is None:
            return {"rows": [], "error": "transport not initialised — call init() first"}
        rows = _transport.query_api(
            limit=limit,
            method=method,
            path=path,
            request_id=request_id,
        )
        return {"rows": rows}

    @r.get("/audit")
    def get_audit(
        request_id: Optional[str] = Query(default=None),
        code: Optional[str] = Query(default=None),
        domain: Optional[str] = Query(default=None),
        source_node_id: Optional[str] = Query(default=None),
        since: Optional[datetime] = Query(default=None),
        until: Optional[datetime] = Query(default=None),
        limit: int = Query(default=100, le=1000),
    ) -> dict[str, Any]:
        if _store is None:
            return {"rows": [], "error": "audit store not initialised — call init() first"}
        rows = _store.query(
            request_id=request_id,
            code=code,
            domain=domain,
            source_node_id=source_node_id,
            since=since,
            until=until,
            limit=limit,
        )
        return {"rows": [dataclasses.asdict(r) for r in rows]}

    return r
