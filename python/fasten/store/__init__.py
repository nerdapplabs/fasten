"""
Store — where audit rows persist.

Interfaces:
  - AuditRepository            (long-term store: edge, EM, adopter default)
  - AuditOutboxRepository      (drain-to-remote: edge-sync, relay patterns)

Bundled implementations: SQLite, Postgres. Adopters plug in ClickHouse /
DynamoDB / Kinesis / whatever by implementing the interface.
"""
from __future__ import annotations

from .repo import AuditOutboxRepository, AuditRepository

__all__ = ["AuditRepository", "AuditOutboxRepository"]
