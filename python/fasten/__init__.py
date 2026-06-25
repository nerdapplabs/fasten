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
from .chain import ChainVerifyResult, seal, verify_chain
from .codes import AuditCatalogError, Domain, Meta, RetentionClass, Severity, register, registry
from .context import (
    current_request_id,
    is_sentinel,
    mint_id,
    mint_sentinel,
    request_id_kind,
    with_request_id,
)
from .emitter import (
    audit_store,
    emit,
    flush,
    ingest_replicated,
    init,
    init_config,
    list_unshipped,
    log,
    mark_shipped,
    persisted_streams,
    queue_stats,
    redactor,
    start,
    transport,
)
from .engine import AuditStoreError, Engine, FastenConfig
from . import replication
from .store.repo import AuditChainError, AuditRepository, IngestResult

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
    "AuditChainError",
    "IngestResult",
    # replication / outbox helpers (delegate to the default engine's store)
    "list_unshipped",
    "mark_shipped",
    "ingest_replicated",
    # store-scoped replication ingest (no Engine / fasten.init() required)
    "replication",
    # multi-tenant / isolated engine
    "Engine",
    # config dataclass
    "FastenConfig",
    # hash chain verification
    "ChainVerifyResult",
    "verify_chain",
    "seal",
    # audit-store failure handling
    "AuditStoreError",
    "flush",
    "queue_stats",
    # context
    "current_request_id",
    "is_sentinel",
    "mint_id",
    "mint_sentinel",
    "request_id_kind",
    "with_request_id",
    # core
    "emit",
    "init",
    "init_config",
    "start",
    "log",
    # adopter hooks
    "audit_store",
    "persisted_streams",
    "redactor",
    "transport",
]

__version__ = "1.0.0b0"
