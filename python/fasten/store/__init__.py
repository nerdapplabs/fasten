"""
Store — where audit rows persist.

Interfaces:
  - AuditRepository            (long-term store: edge, EM, adopter default)
  - AuditOutboxRepository      (drain-to-remote: edge-sync, relay patterns)

Bundled implementations: SQLite, Postgres. Adopters plug in ClickHouse /
DynamoDB / Kinesis / whatever by implementing the interface.
"""
from __future__ import annotations

from .repo import (
    AuditChainError,
    AuditOutboxRepository,
    AuditRepository,
    IngestResult,
    verified_prefix,
)

__all__ = [
    "AuditRepository",
    "AuditOutboxRepository",
    "AuditChainError",
    "IngestResult",
    "verified_prefix",
]
