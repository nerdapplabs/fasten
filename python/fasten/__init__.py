"""
fasten — audit + correlation SDK.

Kernel:
  - `request_id` context carrier (ambient across every emission)
  - `emit(code, target, ...)` — enforces 6 anchors (5 Ws + H) + correlation
  - `AuditRepository` protocol — pluggable storage backend
  - Redactor — secret-key scrubbing before emit

Opt-in:
  - `shim.http`, `shim.mqtt`, `shim.scheduler`
  - `transport.stdout` (default)
  - `reader.router()` — mountable /logs/{api,sys,audit}

See README.md for the full design.
"""
from __future__ import annotations

from .attrs import Anchor, AuditRow
from .audit_queue import AuditStoreError, flush, queue_stats
from .codes import AuditCatalogError, Domain, Meta, RetentionClass, Severity, register, registry
from .context import current_request_id, mint_id, with_request_id
from .emit import audit_store, emit, init, log, redactor, transport
from .store.repo import AuditRepository

__all__ = [
    # row shape
    "Anchor",
    "AuditRow",
    # catalog
    "AuditCatalogError",
    "Domain",
    "Meta",
    "RetentionClass",
    "Severity",
    "register",
    "registry",
    # storage protocol
    "AuditRepository",
    # P1-15: audit-store failure handling
    "AuditStoreError",
    "flush",
    "queue_stats",
    # context
    "current_request_id",
    "mint_id",
    "with_request_id",
    # core
    "emit",
    "init",
    "log",
    # adopter hooks
    "audit_store",
    "redactor",
    "transport",
]

__version__ = "1.0.0b0"
