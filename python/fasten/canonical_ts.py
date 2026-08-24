"""Canonical timestamp form for cross-SDK lexicographic windows (spec §4.3).

**One form, one parser.** Every outbound fasten timestamp — audit rows,
stream rows, purge cutoffs, drainer sys events, `last_verified_at`,
retention cutoffs — is stamped as RFC3339 with a **fixed six-digit
sub-second and an always-`Z`** suffix:

    2026-08-21T10:00:00.000000Z
    2026-08-21T10:00:00.500000Z

Fixed width places the fractional dot at byte 19 for every stamp, so
`.NNNNNNZ` sorts as digits and `'Z'` (0x5A) never appears where `'.'`
(0x2E) does — the specific inversion that let whole-second stamps sort
above fractional stamps in the same second under the older
`RFC3339Nano` writer that stripped trailing zeros. Six digits matches
Postgres `timestamptz` default resolution + Python stdlib default; no
sub-microsecond carrier exists across runtimes.

`canonical_ts` writes it; `parse_canonical` reads it. Both are strict —
any other form is a bug at the source and must not silently round-trip.
The sibling `go/canonical_ts.go` is the parallel Go writer + strict
parser; parallel conformance tests in each SDK pin byte-identical output
on the same instant."""
from __future__ import annotations

import re
from datetime import datetime, timezone

__all__ = ["canonical_ts", "canonical_now", "parse_canonical"]


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


# The one form the writer emits. 27 chars, fixed six-digit sub-second, Z
# suffix. Anything else is not a fasten stamp.
_CANONICAL_TS_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$"
)


def parse_canonical(s: str) -> datetime:
    """Parse a canonical UTC timestamp back into a tz-aware datetime.
    Strict — only the exact 27-char `YYYY-MM-DDTHH:MM:SS.NNNNNNZ` form
    is accepted; anything else raises ``ValueError``. Nothing in fasten
    should ever hand this a non-canonical string, so a mismatch is a
    bug at the source, not something to swallow."""
    if not _CANONICAL_TS_RE.match(s):
        raise ValueError(f"not the canonical timestamp form: {s!r}")
    # Python 3.10's ``datetime.fromisoformat`` doesn't accept the ``Z``
    # suffix natively; swap for ``+00:00`` (a stdlib-version shim, not
    # a legacy compat layer — the string is fully canonical either way).
    return datetime.fromisoformat(s[:-1] + "+00:00")
