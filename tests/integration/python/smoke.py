"""Python smoke: register, init, log.info (sys), emit (audit) with PII detail."""
import os

import fasten
from fasten.codes import register, Meta, Severity, RetentionClass

# Relative SQLite path — store lands in the smoke's CWD (no need to mkdir).
# The SDK's SQLiteStore.from_dsn lstrip("/") interprets sqlite:///audit.db as
# relative to cwd; that's the form the docs and quickstart show.
os.environ.setdefault("FASTEN_SERVICE_ID", "itest-python")
os.environ.setdefault("FASTEN_NODE_ID", "host-itest")
os.environ.setdefault("FASTEN_AUDIT_DSN", "sqlite:///audit.db")

register("user", [
    ("USER_CREATED", Meta(
        id="USER_CREATED", domain="user", category="account",
        action="create", severity=Severity.INFO,
        description="New user account created", emitter="auth-service",
        retention_class=RetentionClass.LONG,
    )),
])

fasten.init()

# 1. sys row
fasten.log.info("startup_ok", lang="python")

# 2. audit row with PII detail
fasten.emit(
    code="USER_CREATED",
    target="u-42",
    actor="admin",
    detail={
        "email": "alice@acme.com",
        "api_key": "sk-secret-abc",
        "nested": {"token": "xyz", "preserved": "ok"},
    },
)
