"""
The 6 audit anchors (5 Ws + H) + correlation, as a typed row.

An emission refuses to construct without the required anchors.
Most are auto-filled from ctx/config; caller supplies code + target + detail.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class Anchor(str, Enum):
    """Classical audit vocabulary — 5 Ws + H + correlation."""

    WHO         = "who"          # actor, actor_kind
    WHAT        = "what"         # code, action
    WHEN        = "when"         # timestamp, monotonic_seq
    WHERE       = "where"        # source_node_id, service_id, tenant_id
    WHOM        = "whom"         # target, category, domain
    HOW         = "how"          # method ∈ {http, mqtt, cli, scheduler, ui, agent_tool}
    CORRELATION = "correlation"  # request_id

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class AuditRow:
    """
    Canonical audit row — the shape every AuditRepository returns.

    Lossless conversion to CloudEvent and OpenTelemetry LogRecord; see
    README.md §2.3 for the bridges.
    """

    # ordering / identity
    id: str            # UUID4-based event id, prefixed "evt-"
    origin_id: str     # origin service row id; dedup key when rows replicate upstream
    monotonic_seq: int # per-node counter; resolves same-ms ties

    # WHEN
    timestamp: datetime  # UTC, ms precision

    # WHAT
    code: str      # SCREAMING_SNAKE
    action: str    # denormalised from code.Meta
    severity: str  # debug | info | warn | error | critical

    # WHERE
    service_id: str
    source_node_id: str
    tenant_id: Optional[str] = None

    # WHO
    actor: str = "system"
    actor_kind: str = "service"  # user | service | schedule | agent

    # WHOM / OBJECT
    target: str = ""
    category: str = ""  # denormalised
    domain: str = ""    # denormalised

    # HOW
    method: str = "http"  # http | mqtt | cli | scheduler | ui | agent_tool

    # CORRELATION
    request_id: str = ""

    # payload
    detail: dict[str, Any] = field(default_factory=dict)

    # replication marker (edge only)
    shipped_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        if not self.code:
            raise ValueError("audit row requires WHAT: code")
        if not self.request_id:
            raise ValueError("audit row requires CORRELATION: request_id")
        if not self.service_id or not self.source_node_id:
            raise ValueError("audit row requires WHERE: service_id + source_node_id")

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict of the row."""
        return dataclasses.asdict(self)

    def to_cloud_event(self) -> dict[str, Any]:
        """CloudEvent 1.0 shape — id / source / type / time / data."""
        return {
            "specversion": "1.0",
            "id": self.id,
            "source": self.source_node_id,
            "type": self.code,
            "time": self.timestamp.astimezone(timezone.utc).isoformat(),
            "data": {
                **self.detail,
                "actor": self.actor,
                "actor_kind": self.actor_kind,
                "target": self.target,
                "method": self.method,
                "request_id": self.request_id,
            },
        }
