"""Python smoke: sys log, audit emit (PII redaction), api row, structlog shim."""
import os
from datetime import datetime, timezone

import fasten
from fasten.codes import register, Meta, Severity, RetentionClass

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

# 1. sys row — fasten's own structured syslog; stamps request_id automatically.
fasten.log.info("startup_ok", lang="python")

# 2. audit row with PII detail — redaction exercised.
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

# 3. api row — what an access-log middleware emits after each HTTP request.
#    In production this is written by RequestIDMiddleware (or a thin wrapper);
#    here we call write_api directly to keep the smoke dep-free.
fasten.transport().write_api({
    "method": "POST",
    "path": "/api/users",
    "status": 201,
    "ms": 14,
    "request_id": fasten.mint_id(),
    "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
})

# 4. structlog shim — adopters already on structlog route their events through
#    make_fasten_processor(), which buffers each log line into fasten's syslog
#    ring (for /logs/sys) without touching stdout (structlog owns stdout).
#    Adopters on this path never call fasten.log directly.
try:
    import structlog
    from fasten.shim.structlog import make_fasten_processor

    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            make_fasten_processor(),       # buffer into fasten ring; stdout untouched
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(0),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
    )
    structlog.get_logger().info("structlog_ok", lang="python")

    ring = fasten.transport().query_syslog(limit=20)
    assert any(r.get("event") == "structlog_ok" for r in ring), (
        "structlog shim: 'structlog_ok' not found in syslog ring buffer"
    )
except ImportError:
    pass  # structlog is optional — skip when not installed
