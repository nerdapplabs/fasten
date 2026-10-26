"""FastAPI router serving /logs/{api,sys,audit} and related reads.

    from fastapi import Depends
    from fasten.reader import router, require_bearer

    app.include_router(
        router(dependencies=[Depends(require_bearer())]),
        prefix="/api/v1/logs",
    )
"""
from __future__ import annotations

from .auth import require_bearer
from .router import router

__all__ = ["router", "require_bearer"]
