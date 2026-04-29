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


# ── FASTEN GENERATED ─ source: spec/row-schema.json ─ run: python spec/codegen.py ──
class Severity(str, Enum):
    """Ascending severity. Wire value: lowercase string."""
    DEBUG    = "debug"  # Low-level diagnostic, filtered in production
    INFO     = "info"  # Normal operational event
    WARN     = "warn"  # Potentially problematic, not yet an error
    ERROR    = "error"  # Operation failed, requires attention
    CRITICAL = "critical"  # Severe failure, may impact availability

    def __str__(self) -> str: return self.value

class RetentionClass(str, Enum):
    """Row retention bucket. Wire value: lowercase string."""
    SHORT  = "short"  # Default 30 days
    MEDIUM = "medium"  # Default 180 days
    LONG   = "long"  # Default 1095 days (3 years)

    def __str__(self) -> str: return self.value

class ActorKind(str, Enum):
    """WHO anchor — who initiated the action. Wire value: lowercase string."""
    USER     = "user"  # Human user (browser, mobile, CLI on behalf of a user)
    SERVICE  = "service"  # Internal service or daemon
    SCHEDULE = "schedule"  # Cron job or task scheduler
    AGENT    = "agent"  # AI agent

    def __str__(self) -> str: return self.value

class Method(str, Enum):
    """HOW anchor — how the event was triggered. Wire value: lowercase string."""
    HTTP       = "http"  # HTTP/HTTPS request (REST, GraphQL, gRPC-web, webhook)
    MQTT       = "mqtt"  # MQTT message (IoT telemetry, device command)
    CLI        = "cli"  # CLI command typed by a human
    SCHEDULER  = "scheduler"  # Automated cron or task scheduler
    UI         = "ui"  # Web or desktop UI action, human-initiated
    AGENT_TOOL = "agent_tool"  # AI agent tool call
    SDK        = "sdk"  # Direct SDK call, no transport shim active. Default.

    def __str__(self) -> str: return self.value

_REDACT_REPLACEMENT = '***'
_REDACT_PATTERNS = (
    'api[_-]?key',
    'password',
    'passwd',
    'token',
    'secret',
    'authorization',
    'bearer',
    'm2m[_-]?key',
    'cert[_-]?private',
    'private[_-]?key',
    'access_key',
    'session_id',
    'cookie',
    'credential',
    'auth',
)
# ── END FASTEN GENERATED ──────────────────────────────────────────────────


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
