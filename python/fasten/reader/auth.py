"""
Bundled auth hooks for the reader router.

These are convenience defaults so callers who don't yet have an auth
system can hand the reader a valid `dependencies=` argument without
writing their own hook. Not a replacement for a real IdP — an
environment-variable-loaded bearer token is fine for a single-node
internal deployment; anything shared, multi-tenant, or public-facing
belongs behind the caller's own auth layer (see P1-45).
"""
from __future__ import annotations

import hmac
import os
from typing import Any


def require_bearer(token_env: str = "FASTEN_READER_TOKEN") -> Any:
    """FastAPI dependency that enforces `Authorization: Bearer <token>`.

    The expected token is read from the environment variable named by
    ``token_env`` (default ``FASTEN_READER_TOKEN``). The env var must be
    set to a non-empty value at import/wire time — an unset or empty env
    fails loudly rather than defaulting to "no token required", which is
    the mis-configuration this helper exists to prevent.

    Comparison is constant-time (``hmac.compare_digest``). Missing or
    malformed ``Authorization`` header rejects with 401; token mismatch
    rejects with 401. Both messages are deliberately generic — no leak
    of "header present but token wrong" vs "no header at all".

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
            "dependency (this helper is opinionated — env-var only)."
        )

    async def dep(authorization: str = Header(default="")) -> None:
        prefix = "Bearer "
        if not authorization.startswith(prefix):
            raise HTTPException(status_code=401, detail="unauthenticated")
        presented = authorization[len(prefix):]
        if not hmac.compare_digest(presented, expected):
            raise HTTPException(status_code=401, detail="unauthenticated")

    return dep
