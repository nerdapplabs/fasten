"""Replication ingest for a store, without an Engine.

An aggregator receiving rows from nodes only needs a store:

    from fasten.replication import ingest
    result = ingest(my_store, rows)

``fasten.ingest_replicated(rows)`` does the same with the default Engine's
store, passing that Engine's node_id as ``local_node_id``.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from .store.repo import IngestResult, ingest_replicated_into, ingest_without_local_node

if TYPE_CHECKING:
    from .attrs import AuditRow
    from .store.repo import AuditRepository

__all__ = ["ingest", "IngestResult"]


def ingest(
    store: "AuditRepository", rows: "list[AuditRow]", local_node_id: str | None = None,
) -> IngestResult:
    """Verify a replicated batch and insert its verified prefix into ``store``.

    Uses ``store.ingest_replicated`` (one transaction in SQLiteStore and
    PostgresStore) when present, otherwise inserts row by row. Does not raise
    on a chain break; :class:`IngestResult` carries ``rejected_from_seq``, the
    seq to resend from.

    Pass the receiving node's id as ``local_node_id``: ingest then stops at the
    first row from that node and reports it as the break (see
    ``repo.ingest_without_local_node``). Without it, no such check is made.
    """
    store_ingest = getattr(store, "ingest_replicated", None)
    if not callable(store_ingest):
        return ingest_replicated_into(store, rows, local_node_id)
    # Cut here rather than pass local_node_id on, so stores whose
    # ingest_replicated predates the argument keep working.
    return ingest_without_local_node(store_ingest, rows, local_node_id)
