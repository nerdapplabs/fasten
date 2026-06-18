"""
AuditRepository + AuditOutboxRepository — the pluggable storage contracts.

Every bundled or adopter-built store implements one of these.
"""
from __future__ import annotations

import dataclasses
from datetime import datetime
from typing import Protocol, runtime_checkable

from ..attrs import AuditRow


@dataclasses.dataclass
class IngestResult:
    """Result of ingest_replicated() — how many rows were inserted.

    A broken chain rejects the whole batch (insert nothing) and raises before
    an IngestResult is produced, so a returned result always means the chain
    verified and every row was offered to the idempotent insert.
    """
    inserted: int


@runtime_checkable
class AuditRepository(Protocol):
    """Long-term audit store — edge (config.db), EM (Postgres), adopter's choice."""

    def insert(self, row: AuditRow) -> None: ...

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
        """Verify the chain of replicated rows, then insert all-or-nothing.

        Verifies the per-row hash chain first; a break rejects the whole batch
        (inserts nothing) and raises. Otherwise every row is inserted via the
        idempotent insert() so re-delivery is a no-op. Used by replication
        sinks — edge-manager receiving rows reverse-synced from an edge node.
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


def ingest_replicated_into(store: "AuditRepository", rows: list[AuditRow]) -> IngestResult:
    """Shared ingest_replicated implementation for any store with insert().

    Verifies the chain first (reject + insert nothing on a break), then loops
    the idempotent ``store.insert``. Kept here so SQLiteStore and PostgresStore
    share one code path.
    """
    # Imported lazily to avoid an import cycle (engine imports stores lazily).
    from ..engine import verify_chain

    result = verify_chain(rows)
    if not result.ok:
        raise AuditChainError(
            f"fasten ingest_replicated: chain verification failed at "
            f"monotonic_seq {result.first_break_at}: {result.reason}",
            first_break_at=result.first_break_at,
        )
    inserted = 0
    for row in rows:
        store.insert(row)
        inserted += 1
    return IngestResult(inserted=inserted)


@runtime_checkable
class AuditOutboxRepository(Protocol):
    """Drain-to-remote outbox — edge-sync and similar relay patterns."""

    def enqueue(self, row: AuditRow) -> None: ...
    def next_batch(self, n: int = 100) -> list[AuditRow]: ...
    def ack(self, ids: list[str]) -> None: ...
    def requeue(self, ids: list[str]) -> None: ...
    def depth(self) -> int: ...
