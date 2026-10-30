"""
AuditRepository + AuditOutboxRepository — the pluggable storage contracts.

Every bundled or adopter-built store implements one of these.
"""
from __future__ import annotations

import dataclasses
from datetime import datetime
from typing import Callable, Protocol, runtime_checkable

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

    def allocate_and_insert_originated(self, row: AuditRow) -> AuditRow:
        """Allocate monotonic_seq + prev_hash and insert atomically (spec §2.1).

        Returns the SEALED row. Implementations MUST serialise concurrent
        allocations for the same source_node_id, so that N writers on one node
        produce ONE verifiable chain rather than N rows claiming seq 1.
        """
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
        # Declared because the reader passes it UNCONDITIONALLY (router.py
        # /logs/audit, /correlate, /search). A third-party store implementing
        # this Protocol without it raises TypeError on every scoped request.
        tenant_id: str | None = None,
    ) -> list[AuditRow]: ...

    def search(
        self,
        *,
        q: str,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 100,
        tenant_id: str | None = None,
    ) -> list[AuditRow]:
        """Free-text search. Declared because the reader calls it when
        search is enabled; an undeclared method meant every third-party store
        either 500'd or silently degraded to "no Search method"."""
        ...

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
        # Declared because the reader passes it unconditionally
        # (router.py /audit, /search, /audit/doctor). A store built
        # to this Protocol without it raises TypeError per request.
        tenant_id: str | None = None,
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


def stored_conflict(
    prefix: list[AuditRow],
    by_id: Callable[[str], "str | None"],
    at_seq: Callable[[str, int], "tuple[str, str, str] | None"],
) -> tuple[int, str] | None:
    """The first row of a verified prefix that disagrees with what the store
    already holds (spec §4), as ``(monotonic_seq, reason)``; None if none does.

    ``by_id(id)`` returns the stored row's hash, ``at_seq(node, seq)`` the
    stored ``(id, hash, prev_hash)`` at that position; each None if absent.
    A row already stored with the same hash is a re-delivery, not a conflict.
    """
    # The stored neighbours are checked even when the batch holds one too: the
    # batch neighbour may be cut by a later break, and if both are kept they
    # must agree anyway.
    seen: dict[str, tuple[str, int]] = {}
    for row in sorted(prefix, key=lambda r: (r.monotonic_seq, r.source_node_id)):
        node, seq = row.source_node_id, row.monotonic_seq
        # id is unique, so the store could keep only one row with it.
        if row.id in seen:
            n, s = seen[row.id]
            return seq, f"row {row.id}: also in this batch at seq {s} on node {n!r}"
        seen[row.id] = (node, seq)
        held = by_id(row.id)
        if held is not None:
            if held != row.hash:
                return seq, f"row {row.id}: differs from the stored row with that id"
            continue
        other = at_seq(node, seq)
        if other is not None:
            return seq, f"row {row.id}: seq {seq} on node {node!r} is stored as row {other[0]}"
        before = at_seq(node, seq - 1)
        # After an unsealed row the store links to "genesis" (spec §2).
        if before is not None and row.prev_hash != (before[1] or "genesis"):
            return seq, f"row {row.id}: prev_hash does not match stored row {before[0]}"
        after = at_seq(node, seq + 1)
        if after is not None and after[2] != row.hash:
            return seq, f"row {row.id}: stored row {after[0]} does not link to it"
    return None


class StoredMeanwhile(Exception):
    """Another writer stored a row with this id after the stored-row checks
    ran, so the insert was skipped. The caller rolls back and checks again."""


def check_inserted(count: int, row: AuditRow, by_id: Callable[[str], "str | None"]) -> None:
    """Raise StoredMeanwhile if the insert of ``row`` was skipped for a row
    other than the same one already stored (a re-delivery)."""
    if count == 0 and by_id(row.id) != row.hash:
        raise StoredMeanwhile(row.id)


def cut_at_conflict(
    prefix: list[AuditRow], rejected_from_seq: int | None, reason: str,
    conflict: tuple[int, str] | None,
) -> tuple[list[AuditRow], int | None, str]:
    """Shorten a verified prefix to the rows before a stored conflict."""
    if conflict is None:
        return prefix, rejected_from_seq, reason
    seq, why = conflict
    return [r for r in prefix if r.monotonic_seq < seq], seq, why


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
    for adopter stores that don't expose a transaction. It cannot look up what
    the store already holds, so it does not check for stored conflicts (spec
    §4); SQLiteStore and PostgresStore do. Never raises on a chain break —
    rejected rows surface via ``rejected_from_seq``.
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
