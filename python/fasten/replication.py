"""
Replication ingest — decoupled from the Engine.

A replication sink (an upstream aggregator receiving rows reverse-synced from a
node) needs only a store. It does NOT need ``fasten.init()``, a service identity,
a redactor, or a drainer. This module exposes that store-scoped path directly:

    from fasten.replication import ingest
    result = ingest(my_store, rows)   # no fasten.init() required

``fasten.ingest_replicated(rows)`` remains as a convenience that delegates to the
default Engine's store, for adopters who already run a configured engine — but it
is no longer the only path.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .store.repo import IngestResult, ingest_replicated_into

if TYPE_CHECKING:
    from .attrs import AuditRow
    from .store.repo import AuditRepository

__all__ = ["ingest", "IngestResult"]


def ingest(store: "AuditRepository", rows: "list[AuditRow]") -> IngestResult:
    """Verify + insert the verified prefix of a replicated batch into ``store``.

    Uses the store's own transactional verified-prefix path when it exposes one
    (SQLiteStore / PostgresStore implement ``ingest_replicated`` with real
    single-transaction atomicity); otherwise falls back to the shared
    row-by-row verified-prefix insert. Never raises on a chain break — the
    returned :class:`IngestResult` carries ``rejected_from_seq`` so the sender
    resyncs from the break.

    No Engine, no ``fasten.init()``: a sink constructs a store and calls this.
    """
    store_ingest = getattr(store, "ingest_replicated", None)
    if callable(store_ingest):
        return store_ingest(rows)
    return ingest_replicated_into(store, rows)
