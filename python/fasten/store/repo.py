"""
AuditRepository + AuditOutboxRepository — the pluggable storage contracts.

Every bundled or adopter-built store implements one of these.
"""
from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable

from ..attrs import AuditRow


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


@runtime_checkable
class AuditOutboxRepository(Protocol):
    """Drain-to-remote outbox — edge-sync and similar relay patterns."""

    def enqueue(self, row: AuditRow) -> None: ...
    def next_batch(self, n: int = 100) -> list[AuditRow]: ...
    def ack(self, ids: list[str]) -> None: ...
    def requeue(self, ids: list[str]) -> None: ...
    def depth(self) -> int: ...
