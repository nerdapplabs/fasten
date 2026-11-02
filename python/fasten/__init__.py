"""fasten audit and correlation SDK.

``emit()`` writes audit rows carrying the ambient ``request_id``. Storage is
pluggable through ``AuditRepository``; HTTP/MQTT/scheduler shims and the
``/logs`` reader router are opt-in. See README.md.
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
    background,
    emit,
    flush,
    go,
    ingest_replicated,
    init,
    init_config,
    list_unshipped,
    log,
    mark_shipped,
    persisted_streams,
    queue_stats,
    redactor,
    search_enabled,
    start,
    transport,
)
from .engine import AuditStoreError, Engine, FastenConfig
from .query import Chips, RuleTranslator, Translator, translate as translate_query
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
    # background-work correlation (bg- sentinel context)
    "background",
    "go",
    # adopter hooks
    "audit_store",
    "persisted_streams",
    "search_enabled",
    "redactor",
    "transport",
    # query translation (search box text to structured chips)
    "Chips",
    "Translator",
    "RuleTranslator",
    "translate_query",
]

__version__ = "1.0.0b0"
