"""Replication ingest for a store, without an Engine.

An aggregator receiving rows from nodes only needs a store:

    from fasten.replication import ingest
    result = ingest(my_store, rows)

``fasten.ingest_replicated(rows)`` does the same with the default Engine's store.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .store.repo import IngestResult, ingest_replicated_into

if TYPE_CHECKING:
    from .attrs import AuditRow
    from .store.repo import AuditRepository

__all__ = ["ingest", "IngestResult"]


def ingest(store: "AuditRepository", rows: "list[AuditRow]") -> IngestResult:
    """Verify a replicated batch and insert its verified prefix into ``store``.

    Uses ``store.ingest_replicated`` (one transaction in SQLiteStore and
    PostgresStore) when present, otherwise inserts row by row. Does not raise
    on a chain break; :class:`IngestResult` carries ``rejected_from_seq``, the
    seq to resend from.
    """
    store_ingest = getattr(store, "ingest_replicated", None)
    if callable(store_ingest):
        return store_ingest(rows)
    return ingest_replicated_into(store, rows)
