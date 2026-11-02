"""A simple auth dependency for the reader router.

A shared bearer token from the environment suits a single internal service.
Anything shared, multi-tenant or public should use its own auth.
"""
from __future__ import annotations

import hmac
import os
from typing import Any


def require_bearer(token_env: str = "FASTEN_READER_TOKEN") -> Any:
    """FastAPI dependency requiring ``Authorization: Bearer <token>``.

    The token is read from ``token_env`` when this is called; if that is unset
    or empty it raises RuntimeError rather than allowing every request. A
    missing or wrong token gets the same 401, compared in constant time.

    Usage:
        from fasten.reader import router, require_bearer
        app.include_router(
            router(dependencies=[Depends(require_bearer())]),
            prefix="/api/v1/logs",
        )
    """
    try:
        from fastapi import Header, HTTPException
    except ImportError as e:
        raise RuntimeError(
            "fasten.reader.require_bearer requires fastapi; install fasten[fastapi]"
        ) from e

    expected = os.environ.get(token_env, "")
    if not expected:
        raise RuntimeError(
            f"fasten.reader.require_bearer: ${token_env} is unset or empty. "
            "Set it to the shared bearer token, or wire your own auth "
            "dependency (this helper is opinionated, env-var only)."
        )

    async def dep(authorization: str = Header(default="")) -> None:
        prefix = "Bearer "
        if not authorization.startswith(prefix):
            raise HTTPException(status_code=401, detail="unauthenticated")
        # Compare bytes: compare_digest() raises TypeError for a str with
        # non-ASCII characters, which a latin-1 decoded header can contain.
        presented = authorization[len(prefix):].encode("utf-8", "surrogateescape")
        if not hmac.compare_digest(presented, expected.encode("utf-8")):
            raise HTTPException(status_code=401, detail="unauthenticated")

    return dep
