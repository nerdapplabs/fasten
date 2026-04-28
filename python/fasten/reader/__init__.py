"""
Reader — mountable /logs/{api,sys,audit} handler, framework-agnostic.

Usage (FastAPI/Starlette):
    app.mount("/api/v1/logs", fasten.reader.router())

Returns canonical rows filterable by request_id, code, domain, since/until,
level, service_id, etc.
"""
from __future__ import annotations

from .router import router, init

__all__ = ["router", "init"]
