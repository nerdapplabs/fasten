"""
Audit code catalog — typed constants + per-code metadata.

Adopter registers their own domain with `register(domain, codes)`; library
enforces no duplicates, valid severity/retention_class, etc.

`fasten dump` CLI prints `id,domain,severity` sorted — feeds the cross-language
consistency gate.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, replace
from enum import Enum
from typing import Mapping

_logger = logging.getLogger("fasten")

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
)
# ── END FASTEN GENERATED ──────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class Meta:
    """Per-code metadata declared alongside every audit code.

    ``id`` is optional in user code — ``register()`` fills it from the
    dict key. Setting ``id`` explicitly is allowed but must match the key
    (raises on mismatch — that's a typo, never a feature).

    ``pii_in_detail=True`` carries three enforced runtime effects (P1-5):

    1. ``retention_class`` is forced to :attr:`RetentionClass.SHORT` at
       register-time. A WARNING is logged if the adopter declared anything
       else — they almost certainly didn't mean for PII to live for years.
    2. The ``detail`` payload is force-redacted on emit, regardless of
       key names: by default the whole map becomes
       ``{"_redacted": "***", "_pii_in_detail": True}``. Adopters who
       genuinely need fields preserved declare them in
       :attr:`detail_passthrough_keys`.
    3. Audit rows carry a ``pii_in_detail`` column so retention sweeps
       and compliance reports can filter PII rows distinctly.
    """

    domain: str               # adopter-defined, e.g. "user", "billing", "node"
    category: str
    action: str
    severity: Severity
    description: str
    emitter: str
    id: str = ""              # filled from the dict key by register()
    retention_class: RetentionClass = RetentionClass.MEDIUM
    high_volume: bool = False
    pii_in_detail: bool = False
    declared_unused: bool = False
    # When pii_in_detail=True, only these keys (if any) survive emit.
    # Everything else is replaced. Empty tuple = scrub everything.
    detail_passthrough_keys: tuple[str, ...] = ()


class AuditCatalogError(Exception):
    """Raised at registration time for duplicate codes or bad metadata."""


_registry: dict[str, Meta] = {}

_CODE_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


def register(domain: Domain, codes: Mapping[str, Meta]) -> None:
    """Register a batch of codes for a domain.

        register("user", {
            "USER_CREATED": Meta(domain="user", action="create", ...),
            "USER_DELETED": Meta(domain="user", action="delete", ...),
        })

    Validation (raises ``AuditCatalogError`` with a fix-it message):
      - key shape: UPPER_SNAKE_CASE identifier
      - ``Meta.id`` empty → fill from key; set → must match key
      - ``Meta.domain`` must match ``domain``
      - duplicate code across registrations
    """
    for name, meta in codes.items():
        if not _CODE_KEY_RE.match(name):
            raise AuditCatalogError(
                f"register: code key {name!r} must be UPPER_SNAKE_CASE "
                f"(letters, digits, underscores; starts with a letter). "
                f"Got {name!r}."
            )

        if not meta.id:
            meta = replace(meta, id=name)
        elif meta.id != name:
            raise AuditCatalogError(
                f"register: dict key {name!r} disagrees with Meta.id={meta.id!r}. "
                f"Drop Meta.id (it fills from the key) or fix the mismatch."
            )

        if meta.domain != domain:
            raise AuditCatalogError(
                f"register: code {name!r} declares domain={meta.domain!r} "
                f"but registered under {domain!r}."
            )

        # P1-5 #1: pii_in_detail forces RetentionClass.SHORT.
        if meta.pii_in_detail and meta.retention_class is not RetentionClass.SHORT:
            _logger.warning(
                "fasten: code %s has pii_in_detail=True; "
                "retention_class forced to SHORT (was %s).",
                name, meta.retention_class.value.upper(),
            )
            meta = replace(meta, retention_class=RetentionClass.SHORT)

        if name in _registry:
            raise AuditCatalogError(f"register: duplicate code {name!r}")

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


# ── Optional yaml catalog (P1-11) ─────────────────────────────────────────
# Re-export lazy: pyyaml is only imported when load() / reload() runs.
# Adopters who stay on programmatic register() never pay the dep.

def load(path: str) -> None:
    """Load a catalog yaml file (see ``fasten/codes_yaml.py`` for full docs).

    Lazy import — pyyaml is loaded only when this is called. Errors raise
    loudly (startup, restart-safe).
    """
    from .codes_yaml import load as _load
    _load(path)


def reload() -> None:
    """Re-read all previously-loaded yaml paths and atomically swap the registry.

    Fault-tolerant — if parsing or validation fails, the previous catalog
    stays active and the error is raised. No partial state.
    """
    from .codes_yaml import reload as _reload
    _reload()
