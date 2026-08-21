"""Canonical timestamp form for cross-SDK lexicographic windows.

Spec §4.3 mandates `[since, until]` lexicographic comparison and states
callers MUST keep one canonical form. Historically Go stamped
``time.RFC3339Nano`` (`2026-08-21T10:00:00Z`, trailing zeros stripped)
while Python stamped ``isoformat(timespec="milliseconds")``
(`2026-08-21T10:00:00.500+00:00`) — the two disagreed byte-for-byte on
the same instant, so windowed reads on tables with both writers silently
truncated at boundary instants, and a Go-only same-second ordering case
inverted (`'Z'` 0x5A > `'.'` 0x2E).

**Canonical form:** RFC3339 with a **fixed six-digit sub-second** and an
always-`Z` suffix (never `+00:00`, never a trailing-zero-stripped whole
second):

    2026-08-21T10:00:00.000000Z
    2026-08-21T10:00:00.500000Z

Fixed-width guarantees every stamp has the fractional dot at byte 19, so
`.NNNNNNZ` sorts as digits and never as `Z` > `.`. Microsecond precision
matches Postgres `timestamptz` default resolution + Python's stdlib
default; anything finer (nanoseconds) has no cross-runtime carrier.

Every outbound fasten timestamp (audit / api / sys rows, purge cutoffs,
drainer sys log entries, reader `last_verified_at`, retention loop
cutoff) must go through ``canonical_ts``. See the sibling
``go/canonical_ts.go`` for the Go writer helper; a conformance corpus
row in ``spec/timestamp-canonical.md`` pins byte-identical output on the
same instant across the two SDKs.

Parsing stays permissive — ``datetime.fromisoformat`` (via
``parse_canonical_or_legacy``) accepts both the canonical form and the
older RFC3339Nano / millisecond forms already in the wild, so a read on
a store written before this release never rejects a historical row."""
from __future__ import annotations

from datetime import datetime, timezone

__all__ = ["canonical_ts", "canonical_now", "parse_canonical_or_legacy"]


def canonical_ts(dt: datetime) -> str:
    """Stamp `dt` in the canonical form. Naive datetimes are assumed UTC
    (a naive `datetime.utcnow()` is treated as UTC, not local — the
    project has never stamped local time on the wire and never should)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat(timespec="microseconds").replace("+00:00", "Z")


def canonical_now() -> str:
    """Shortcut: canonical_ts(datetime.now(timezone.utc))."""
    return canonical_ts(datetime.now(timezone.utc))


def parse_canonical_or_legacy(s: str) -> datetime:
    """Parse a timestamp string emitted by either the canonical form or
    an older RFC3339Nano / millisecond form. Returns a tz-aware UTC
    datetime. Historical rows in stores written before the canonical-form
    rollout must still read back cleanly."""
    # Python 3.11+'s fromisoformat handles 'Z' natively; the .replace keeps
    # 3.10 (dev target) working too.
    return datetime.fromisoformat(s.replace("Z", "+00:00"))
