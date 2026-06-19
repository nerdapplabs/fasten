"""
AuditRepository + AuditOutboxRepository — the pluggable storage contracts.

Every bundled or adopter-built store implements one of these.
"""
from __future__ import annotations

import dataclasses
from datetime import datetime
from typing import Protocol, runtime_checkable

from ..attrs import AuditRow
from ..chain import verify_chain


@dataclasses.dataclass
class IngestResult:
    """Result of ingest_replicated() — how many rows were inserted.

    ingest_replicated inserts the longest VERIFIED prefix of the batch (from the
    chain start up to, but not including, the first break) and never raises on a
    chain break. ``inserted`` counts the rows offered to the idempotent insert.

    When the chain breaks partway, ``rejected_from_seq`` carries the
    ``monotonic_seq`` of the first broken row (the rows at/after it are NOT
    inserted) and ``reason`` explains where it diverged, so the sender can resync
    from that point instead of re-shipping the poison-pilled batch forever. On a
    fully-verified batch ``rejected_from_seq`` is None and ``reason`` is None.
    """
    inserted: int
    rejected_from_seq: int | None = None
    reason: str | None = None


@runtime_checkable
class AuditRepository(Protocol):
    """Long-term audit store — edge (config.db), EM (Postgres), adopter's choice."""

    def insert(self, row: AuditRow) -> None:
        """Thin alias for insert_originated — the engine emit/drainer path."""
        ...

    def insert_originated(self, row: AuditRow) -> None:
        """Insert a row this node ORIGINATED (origin_id == id)."""
        ...

    def insert_replicated(self, row: AuditRow) -> None:
        """Insert a sealed row replicated from another origin (after the chain
        verifies in ingest_replicated)."""
        ...

    def query(
        self,
        *,
        request_id: str | None = None,
        code: str | None = None,
        domain: str | None = None,
        source_node_id: str | None = None,
        actor: str | None = None,
        target: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditRow]: ...

    def count(
        self,
        *,
        request_id: str | None = None,
        code: str | None = None,
        domain: str | None = None,
        source_node_id: str | None = None,
        actor: str | None = None,
        target: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> int:
        """Total rows matching the same filter as query() — for pagination."""
        ...

    def sources(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[dict[str, object]]:
        """Fleet topology aggregated from stored rows.

        One entry per distinct ``(source_node_id, service_id, tenant_id)``
        with ``rows``/``first_seen``/``last_seen``. Optional — the reader's
        /topology route hasattr-guards this, so adopter stores may omit it.
        """
        ...

    def list_unshipped(self, limit: int = 100) -> list[AuditRow]: ...
    def mark_shipped(self, ids: list[str]) -> None: ...
    def purge(self, *, before: datetime, respect_unshipped: bool = True) -> int: ...

    def ingest_replicated(self, rows: list[AuditRow]) -> "IngestResult":
        """Verify the chain of replicated rows, then insert the verified prefix.

        Verifies the per-row hash chain first. If it is intact, every row is
        inserted in a single transaction (so a crash mid-batch leaves nothing
        partially committed) via the idempotent insert(), making re-delivery a
        no-op. If the chain breaks partway, only the verified prefix (rows before
        the first break) is inserted — never raises — and the returned
        IngestResult carries ``rejected_from_seq`` so the sender resyncs from the
        break instead of re-shipping a poison-pilled batch forever. Used by
        replication sinks — an upstream aggregator receiving rows reverse-synced
        from a node.
        """
        ...


class AuditChainError(RuntimeError):
    """Raised by ingest_replicated() when the incoming chain fails verification.

    Carries the monotonic_seq of the first broken row so the caller can log /
    surface exactly where the replicated batch diverged.
    """

    def __init__(self, message: str, first_break_at: int | None) -> None:
        super().__init__(message)
        self.first_break_at = first_break_at


def verified_prefix(
    rows: list[AuditRow],
) -> tuple[list[AuditRow], int | None, str]:
    """Pure helper: the longest VERIFIED run of ``rows`` from the chain start.

    Sorts ``rows`` by ``monotonic_seq`` and verifies the per-row hash chain.

    - Chain intact → ``(all_rows_sorted, None, "")``.
    - Chain broken → ``(rows with monotonic_seq < first_break_at, first_break_at,
      reason)`` — the prefix is everything strictly before the first broken row,
      so the verified portion can be inserted while the break and everything
      after it is rejected.

    No I/O — callers insert the prefix and report ``first_break_at`` as
    ``rejected_from_seq`` so the sender resyncs from the break.
    """
    sorted_rows = sorted(rows, key=lambda r: r.monotonic_seq)
    result = verify_chain(sorted_rows)
    if result.ok:
        return sorted_rows, None, ""
    # verify_chain always sets first_break_at when ok is False; the `is not None`
    # keeps the comparison type-safe (mypy) without assuming the invariant.
    break_at = result.first_break_at
    prefix = [r for r in sorted_rows
              if break_at is not None and r.monotonic_seq < break_at]
    return prefix, break_at, result.reason or ""


def _insert_one_replicated(store: "AuditRepository", row: AuditRow) -> None:
    """Route one replicated row through insert_replicated when available.

    Replicated rows keep their origin's identity (origin_id may differ from id),
    so insert_replicated — which asserts the row is sealed rather than asserting
    origin_id == id — is preferred. Falls back to insert() for adopter stores
    that predate the originated/replicated split.
    """
    insert_replicated = getattr(store, "insert_replicated", None)
    if callable(insert_replicated):
        insert_replicated(row)
    else:
        store.insert(row)


def ingest_replicated_into(store: "AuditRepository", rows: list[AuditRow]) -> IngestResult:
    """Shared ingest_replicated fallback for stores without a transactional path.

    Computes the verified prefix and inserts it row-by-row via the idempotent
    insert. SQLiteStore and PostgresStore override this with a single-transaction
    implementation (real atomicity); this loop-insert variant is the safe default
    for adopter stores that don't expose a transaction. Never raises on a chain
    break — rejected rows surface via ``rejected_from_seq``.
    """
    prefix, rejected_from_seq, reason = verified_prefix(rows)
    inserted = 0
    for row in prefix:
        _insert_one_replicated(store, row)
        inserted += 1
    return IngestResult(
        inserted=inserted,
        rejected_from_seq=rejected_from_seq,
        reason=reason or None,
    )


@runtime_checkable
class AuditOutboxRepository(Protocol):
    """Drain-to-remote outbox — edge-sync and similar relay patterns."""

    def enqueue(self, row: AuditRow) -> None: ...
    def next_batch(self, n: int = 100) -> list[AuditRow]: ...
    def ack(self, ids: list[str]) -> None: ...
    def requeue(self, ids: list[str]) -> None: ...
    def depth(self) -> int: ...
