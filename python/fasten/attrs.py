"""The audit row type and its anchors (who, what, when, where, whom, how,
and the correlating request_id)."""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional


class Anchor(str, Enum):
    """Audit anchors and the row fields that carry them."""

    WHO         = "who"          # actor, actor_kind
    WHAT        = "what"         # code, action
    WHEN        = "when"         # timestamp, monotonic_seq
    WHERE       = "where"        # source_node_id, service_id, tenant_id
    WHOM        = "whom"         # target, category, domain
    HOW         = "how"          # method
    CORRELATION = "correlation"  # request_id

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class AuditRow:
    """An audit row, as written by emit() and returned by every
    AuditRepository. Construction fails without code, request_id,
    service_id and source_node_id."""

    # ordering / identity
    id: str            # UUID4-based event id, prefixed "evt-"
    origin_id: str     # origin service row id; dedup key when rows replicate upstream
    monotonic_seq: int # per-node counter; resolves same-ms ties

    # WHEN
    timestamp: datetime  # UTC, microsecond precision

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
    method: str = "sdk"   # http | mqtt | cli | scheduler | ui | agent_tool | sdk

    # CORRELATION
    request_id: str = ""

    # None after redaction (spec 7.1).
    detail: Optional[dict[str, Any]] = field(default_factory=dict)

    # Readers should accept higher versions on a best-effort basis.
    wire_version: str = "1"

    # replication marker (edge only)
    shipped_at: Optional[datetime] = None

    # Hash form this row was sealed with. seal() stamps the current form
    # ("2"); the default only applies to unsealed rows. See fasten.chain.
    canonical_form_id: str = "1"

    # prev_hash: hash of the previous row from the same source_node_id, or
    # "genesis" for the first. hash: sha256 of this row in its canonical form.
    prev_hash: str = "genesis"
    hash: str = ""

    # Form "2" hashes detail_commitment instead of detail (spec 1.4).
    # detail_salt is cleared on redaction; both are None on form "1" rows.
    detail_salt: Optional[str] = None
    detail_commitment: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.code:
            raise ValueError("audit row requires WHAT: code")
        if not self.request_id:
            raise ValueError("audit row requires CORRELATION: request_id")
        if not self.service_id or not self.source_node_id:
            raise ValueError("audit row requires WHERE: service_id + source_node_id")

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable dict, with timestamps from canonical_ts()."""
        from .canonical_ts import canonical_ts
        d = dataclasses.asdict(self)
        d["timestamp"] = canonical_ts(self.timestamp)
        if self.shipped_at is not None:
            d["shipped_at"] = canonical_ts(self.shipped_at)
        return d

    def to_cloud_event(self) -> dict[str, Any]:
        """The row as a CloudEvents 1.0 dict."""
        from .canonical_ts import canonical_ts
        return {
            "specversion": "1.0",
            "id": self.id,
            "source": self.source_node_id,
            "type": self.code,
            "time": canonical_ts(self.timestamp),
            "data": {
                # detail is None on a redacted row.
                **(self.detail or {}),
                "actor": self.actor,
                "actor_kind": self.actor_kind,
                "target": self.target,
                "method": self.method,
                "request_id": self.request_id,
            },
        }
