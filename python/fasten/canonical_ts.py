"""The timestamp format fasten writes everywhere (spec 4.3).

RFC 3339 in UTC with exactly six fractional digits and a ``Z`` suffix:

    2026-08-21T10:00:00.000000Z

The fixed width makes string order match time order. go/canonical_ts.go
writes the same bytes.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

__all__ = ["canonical_ts", "canonical_now", "parse_canonical"]


def canonical_ts(dt: datetime) -> str:
    """Format ``dt`` in the canonical form. Naive datetimes are taken as UTC."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat(timespec="microseconds").replace("+00:00", "Z")


def canonical_now() -> str:
    """The current time in the canonical form."""
    return canonical_ts(datetime.now(timezone.utc))


_CANONICAL_TS_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$"
)


def parse_canonical(s: str) -> datetime:
    """Parse a canonical timestamp into an aware datetime. Raises ValueError
    for anything else."""
    if not _CANONICAL_TS_RE.match(s):
        raise ValueError(f"not the canonical timestamp form: {s!r}")
    # fromisoformat() only accepts "Z" from Python 3.11.
    return datetime.fromisoformat(s[:-1] + "+00:00")
