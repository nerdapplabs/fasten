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
from .codes import AuditCatalogError, Domain, Meta, RetentionClass, Severity, register, registry
from .context import current_request_id, mint_id, with_request_id
from .emit import emit, init, log
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
    # context
    "current_request_id",
    "mint_id",
    "with_request_id",
    # core
    "emit",
    "init",
    "log",
]

__version__ = "1.0.0b0"
