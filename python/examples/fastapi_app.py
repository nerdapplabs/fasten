"""
Minimal FastAPI service wired to fasten.

What it shows in 60 lines:

  - fasten.init() reading env vars (FASTEN_SERVICE_ID, FASTEN_NODE_ID,
    FASTEN_AUDIT_DSN) — required for every adopter app.
  - One audit code (USER_CREATED) registered at startup.
  - RequestIDMiddleware mints / honours X-Request-ID per request.
  - APILogger pushes one api-log row per request (no extra wiring).
  - POST /users emits an audit row with the in-context request_id.
  - GET  /users/<id> emits a read-side audit row + a structured sys log.
  - The mountable /logs/{audit,sys,api} reader is wired under /logs.

Run:

    pip install ./python[fastapi] uvicorn
    FASTEN_SERVICE_ID=demo FASTEN_NODE_ID=host-01 \\
      FASTEN_AUDIT_DSN=sqlite:///./demo-audit.db \\
      uvicorn examples.fastapi_app:app --port 8000

    curl -X POST http://localhost:8000/users \\
         -H 'content-type: application/json' \\
         -d '{"email":"alice@example.com"}'
    curl http://localhost:8000/users/u-42
    curl http://localhost:8000/logs/audit
"""
from __future__ import annotations

import os

import fasten
from fasten.codes import register, Meta, Severity, RetentionClass
from fasten.shim.http import RequestIDMiddleware, APILogger
from fasten.reader import router as reader_router

from fastapi import FastAPI, Request

# ── Code catalog (register once at startup) ────────────────────────────────

register("user", {
    "USER_CREATED": Meta(
        domain="user", category="account", action="create",
        severity=Severity.INFO,
        description="New user account created",
        emitter="demo-svc",
        retention_class=RetentionClass.LONG,
    ),
    "USER_VIEWED": Meta(
        domain="user", category="account", action="view",
        severity=Severity.INFO,
        description="User profile read",
        emitter="demo-svc",
        retention_class=RetentionClass.SHORT,
    ),
})

fasten.init()  # reads FASTEN_SERVICE_ID / FASTEN_NODE_ID / FASTEN_AUDIT_DSN

app = FastAPI(title="fasten demo")
app.add_middleware(RequestIDMiddleware)                       # mints / honours X-Request-ID
app.add_middleware(APILogger, skip={"/health", "/metrics"})   # one api-log row per req
app.include_router(reader_router(), prefix="/logs")           # /logs/{audit,sys,api}


@app.post("/users")
async def create_user(req: Request):
    body = await req.json()
    email = body.get("email", "")
    user_id = f"u-{abs(hash(email)) % 10_000:04d}"
    fasten.emit(
        code="USER_CREATED",
        target=user_id,
        actor="admin",                              # adopter-supplied; usually from auth
        detail={"email": email},                    # PII redacted by default rules
    )
    return {"user_id": user_id}


@app.get("/users/{user_id}")
def read_user(user_id: str):
    fasten.emit(code="USER_VIEWED", target=user_id, actor="admin")
    fasten.log.info("user_lookup", user_id=user_id, source="demo")
    return {"user_id": user_id, "exists": True}


@app.get("/health")
def health():
    return {"ok": True}


@app.on_event("shutdown")
def _shutdown():
    """Drain pending audit rows before the process exits."""
    fasten.flush(timeout=5.0)
