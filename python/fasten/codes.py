"""
Audit code catalog — typed constants + per-code metadata.

Adopter registers their own domain with `register(domain, codes)`; library
enforces no duplicates, valid severity/retention_class, etc.

`fasten dump` CLI prints `id,domain,severity` sorted — feeds the cross-language
consistency gate.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

# Domain is a plain string — adopters define their own vocabulary.
# Examples: "user", "billing", "device", "order" — fasten has no opinions.
Domain = str


class Severity(str, Enum):
    DEBUG    = "debug"
    INFO     = "info"
    WARN     = "warn"
    ERROR    = "error"
    CRITICAL = "critical"

    def __str__(self) -> str:
        return self.value


class RetentionClass(str, Enum):
    SHORT  = "short"    # 30d default
    MEDIUM = "medium"   # 180d default
    LONG   = "long"     # 1095d (3y) default

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class Meta:
    """Per-code metadata declared alongside every audit code."""

    id: str
    domain: str               # adopter-defined, e.g. "user", "billing", "node"
    category: str
    action: str
    severity: Severity
    description: str
    emitter: str
    retention_class: RetentionClass = RetentionClass.MEDIUM
    high_volume: bool = False
    pii_in_detail: bool = False
    declared_unused: bool = False


class AuditCatalogError(Exception):
    """Raised at registration time for duplicate codes or bad metadata."""


_registry: dict[str, Meta] = {}


def register(domain: Domain, codes: Iterable[tuple[str, Meta]]) -> None:
    """
    Register a batch of codes for a domain.

    Raises AuditCatalogError on duplicates or domain mismatch.
    """
    for name, meta in codes:
        if name in _registry:
            raise AuditCatalogError(f"duplicate code: {name}")
        if meta.id != name:
            raise AuditCatalogError(
                f"code {name!r} has meta.id={meta.id!r} — they must match"
            )
        if meta.domain != domain:
            raise AuditCatalogError(
                f"code {name} declares domain={meta.domain!r} "
                f"but registered under {domain!r}"
            )
        _registry[name] = meta


def registry() -> dict[str, Meta]:
    """Return a copy of the current catalog."""
    return dict(_registry)


def dump() -> str:
    """`id,domain,severity` sorted one-per-line — feeds cross-language consistency gate."""
    rows = sorted(
        (m.id, m.domain, str(m.severity)) for m in _registry.values()
    )
    return "\n".join(f"{i},{d},{s}" for (i, d, s) in rows)
