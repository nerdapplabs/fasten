"""Canonical timestamp form (spec §4.3) — cross-SDK byte-identical output.

These pins are hardcoded against the exact same instants tested in the Go
SDK's TestCanonicalTS_ByteIdentical (go/canonical_ts_test.go). If a change
in either SDK drifts, both tests fail with the same expected bytes."""
from datetime import datetime, timedelta, timezone

import pytest

from fasten.canonical_ts import canonical_ts, parse_canonical


# ── conformance pins (must match go/canonical_ts_test.go byte-for-byte) ──

@pytest.mark.parametrize("dt, want", [
    # Whole seconds — the bug case (Go RFC3339Nano stripped .000000)
    (datetime(2026, 8, 21, 10, 0, 0, tzinfo=timezone.utc),
     "2026-08-21T10:00:00.000000Z"),
    # Half second — matches Python's earlier ".500+00:00" case
    (datetime(2026, 8, 21, 10, 0, 0, 500_000, tzinfo=timezone.utc),
     "2026-08-21T10:00:00.500000Z"),
    # Microsecond precision
    (datetime(2026, 8, 21, 10, 0, 0, 123_456, tzinfo=timezone.utc),
     "2026-08-21T10:00:00.123456Z"),
    # Non-UTC input → converted to UTC
    (datetime(2026, 8, 21, 15, 30, 0, 0,
              tzinfo=timezone(timedelta(hours=5, minutes=30))),
     "2026-08-21T10:00:00.000000Z"),
])
def test_canonical_ts_byte_identical(dt, want):
    """Every stamp fasten writes must render exactly this way — 26 chars,
    always Z, always six fractional digits, always UTC."""
    assert canonical_ts(dt) == want


def test_canonical_ts_length_is_stable():
    """Fixed-width guarantee: every canonical stamp is exactly 27 chars
    (`YYYY-MM-DDTHH:MM:SS.ffffffZ`). This is what makes lexicographic
    compare byte-for-byte match wall-clock order — a trailing-zero-stripped
    variant put whole seconds above fractional seconds in the same second
    (the Go-only bug §4.3 flagged)."""
    stamps = [canonical_ts(datetime(2026, 8, 21, 10, 0, s, us, tzinfo=timezone.utc))
              for s in (0, 30, 59) for us in (0, 1, 100_000, 999_999)]
    assert all(len(s) == 27 for s in stamps), stamps


def test_canonical_ts_lex_order_matches_time_order():
    """Same instant + 1µs must sort ABOVE the same instant — the property
    the entire §4.3 window compare depends on."""
    base = datetime(2026, 8, 21, 10, 0, 0, tzinfo=timezone.utc)
    for us_a, us_b in [(0, 1), (0, 500_000), (500_000, 999_999), (0, 999_999)]:
        a = canonical_ts(base.replace(microsecond=us_a))
        b = canonical_ts(base.replace(microsecond=us_b))
        assert a < b, f"{a!r} should sort below {b!r}"

    # Cross-second boundary — the historical Go bug: `Z` (0x5A) > `.` (0x2E)
    # made 10:00:00Z sort ABOVE 10:00:00.5Z. Canonical form fixes it.
    whole = canonical_ts(base)  # 10:00:00.000000Z
    half = canonical_ts(base.replace(microsecond=500_000))
    assert whole < half, f"whole second {whole!r} must sort below half {half!r}"


# ── parser is strict (one form, one parser) ─────────────────────────────

def test_parse_canonical_round_trips_writer():
    """The writer stamps canonical; the parser round-trips it back to the
    exact input datetime. That is the only round-trip we owe."""
    dt = datetime(2026, 8, 21, 10, 0, 0, 500_000, tzinfo=timezone.utc)
    assert parse_canonical(canonical_ts(dt)) == dt


@pytest.mark.parametrize("bad", [
    "2026-08-21T10:00:00Z",              # whole-second Go RFC3339Nano — 20 chars
    "2026-08-21T10:00:00.500+00:00",      # Python isoformat(ms) — offset form
    "2026-08-21T10:00:00.123456+00:00",   # Python isoformat(µs) — offset form
    "2026-08-21T10:00:00.500Z",           # short fractional — 3 digits
    "2026-08-21T10:00:00.123456+05:30",   # non-UTC offset
    "",                                    # empty
    "not-a-timestamp",                    # garbage
])
def test_parse_rejects_anything_but_canonical(bad):
    """Strict: only the exact 27-char canonical form is accepted. Anything
    else means a writer bypassed canonical_ts — a bug at the source, must
    fail loudly instead of silently round-tripping."""
    with pytest.raises(ValueError):
        parse_canonical(bad)
