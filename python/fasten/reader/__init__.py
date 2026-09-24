"""
Reader — mountable /logs/{api,sys,audit} handler, framework-agnostic.

Usage (FastAPI/Starlette):
    from fastapi import Depends
    from fasten.reader import router, require_bearer

    app.include_router(
        router(dependencies=[Depends(require_bearer())]),
        prefix="/api/v1/logs",
    )

Returns canonical rows filterable by request_id, code, domain, since/until,
level, service_id, etc.
"""
from __future__ import annotations

from .auth import require_bearer
from .router import router

__all__ = ["router", "require_bearer"]
