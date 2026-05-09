"""
Audit code catalog — typed constants + per-code metadata.

Public API (unchanged from pre-FFI):
  register(domain, codes)  — validate + store via fasten-core Rust engine
  registry()               — return a copy of the current catalog (Python-side cache)
  dump()                   — sorted `id,domain,severity` CSV via Rust
  meta_of(code)            — single-code lookup
  load(path)               — load a catalog yaml file
  reload()                 — re-read previously-loaded yaml paths

All validation logic (UPPER_SNAKE_CASE, duplicate detection, domain checks,
pii_in_detail → retention SHORT enforcement) lives in fasten-core.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Optional

from . import core_ffi

_logger = logging.getLogger("fasten")

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
    """Per-code metadata declared alongside every audit code."""

    domain: str
    category: str
    action: str
    severity: Severity
    description: str
    emitter: str
    id: str = ""
    retention_class: RetentionClass = RetentionClass.MEDIUM
    high_volume: bool = False
    pii_in_detail: bool = False
    declared_unused: bool = False
    detail_passthrough_keys: tuple[str, ...] = ()


class AuditCatalogError(Exception):
    """Raised at registration time for duplicate codes or bad metadata."""


# ── Python-side cache (populated through Rust validation) ────────────────────

_registry: dict[str, Meta] = {}


def _meta_to_dict(name: str, meta: Meta) -> dict:
    """Convert a Meta object to a JSON-serialisable dict for fasten_register_codes."""
    return {
        "domain":                 meta.domain,
        "category":               meta.category,
        "action":                 meta.action,
        "severity":               str(meta.severity),
        "description":            meta.description,
        "emitter":                meta.emitter,
        "id":                     meta.id or name,
        "retention_class":        str(meta.retention_class),
        "high_volume":            meta.high_volume,
        "pii_in_detail":          meta.pii_in_detail,
        "declared_unused":        meta.declared_unused,
        "detail_passthrough_keys": list(meta.detail_passthrough_keys),
    }


def _dict_to_meta(d: dict) -> Meta:
    """Reconstruct a Python Meta from a Rust JSON dict."""
    return Meta(
        domain=d["domain"],
        category=d["category"],
        action=d["action"],
        severity=Severity(d["severity"]),
        description=d["description"],
        emitter=d["emitter"],
        id=d.get("id", ""),
        retention_class=RetentionClass(d.get("retention_class", "medium")),
        high_volume=bool(d.get("high_volume", False)),
        pii_in_detail=bool(d.get("pii_in_detail", False)),
        declared_unused=bool(d.get("declared_unused", False)),
        detail_passthrough_keys=tuple(d.get("detail_passthrough_keys", [])),
    )


def register(domain: Domain, codes: Mapping[str, Meta]) -> None:
    """Register a batch of codes for a domain.

    Validation is delegated to fasten-core (Rust):
      - key shape: UPPER_SNAKE_CASE
      - Meta.id empty → filled from key; set → must match key
      - Meta.domain must match domain
      - duplicate code across registrations
      - pii_in_detail=True forces retention_class=SHORT

    Raises AuditCatalogError on any violation.
    """
    # Emit the pii_in_detail warning in Python before Rust silently forces SHORT.
    for name, meta in codes.items():
        if meta.pii_in_detail and meta.retention_class is not RetentionClass.SHORT:
            _logger.warning(
                "fasten: code %s has pii_in_detail=True; "
                "retention_class forced to SHORT (was %s).",
                name, meta.retention_class.value.upper(),
            )
    codes_dict = {name: _meta_to_dict(name, meta) for name, meta in codes.items()}
    # Raises AuditCatalogError on validation failure (mapped from Rust error codes).
    core_ffi.register_codes(domain, json.dumps(codes_dict))
    # Populate Python cache from the Rust-validated state.
    for name in codes:
        meta_json = core_ffi.meta_of_json(name)
        if meta_json and meta_json != "{}":
            _registry[name] = _dict_to_meta(json.loads(meta_json))


def meta_of(code: str) -> Optional[Meta]:
    """Return the Meta for `code`, or None if not registered."""
    return _registry.get(code)


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

def load(path: str) -> None:
    """Load a catalog yaml file (see ``fasten/codes_yaml.py`` for full docs)."""
    from .codes_yaml import load as _load
    _load(path)


def reload() -> None:
    """Re-read all previously-loaded yaml paths and atomically swap the registry."""
    from .codes_yaml import reload as _reload
    _reload()
