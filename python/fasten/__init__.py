"""
fasten — audit + correlation SDK.

Kernel:
  - `request_id` context carrier (ambient across every emission)
  - `emit(code, target, ...)` contract enforcing 6 anchors (5 Ws + H) + correlation
  - `AuditRepository` interface + SQLite / Postgres implementations
  - Redaction processor for secret-shaped keys

Opt-in:
  - `shim.http`, `shim.mqtt`, `shim.scheduler`, `shim.deploy_pipeline`
  - `transport.stdout` (default), `transport.filerotate` (future)
  - `reader.router()` — mountable /logs/{api,sys,audit}

See ../README.md for the full design.
"""
from __future__ import annotations

from .attrs import Anchor, AuditRow
from .codes import Code, Domain, Meta, Severity, register, registry
from .context import (
    MintID,
    WithRequestID,
    current_request_id,
    with_request_id,
)
from .emit import emit, init, log, _get_audit_store, _get_stdout, _get_redactor

__all__ = [
    "Anchor",
    "AuditRow",
    "Code",
    "Domain",
    "Meta",
    "Severity",
    "MintID",
    "WithRequestID",
    "current_request_id",
    "with_request_id",
    "emit",
    "init",
    "log",
    "register",
    "registry",
    "_get_audit_store",
    "_get_stdout",
    "_get_redactor",
]

__version__ = "0.1.0"
