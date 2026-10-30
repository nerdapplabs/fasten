"""Canonical timestamp form (spec §4.3): byte-identical output across SDKs.

The same instants are pinned in Go's TestCanonicalTS_ByteIdentical
(go/canonical_ts_test.go)."""
from datetime import datetime, timedelta, timezone

import pytest

from fasten.canonical_ts import canonical_ts, parse_canonical


# Must match go/canonical_ts_test.go byte for byte.

@pytest.mark.parametrize("dt, want", [
    # Whole seconds (Go RFC3339Nano would strip .000000)
    (datetime(2026, 8, 21, 10, 0, 0, tzinfo=timezone.utc),
     "2026-08-21T10:00:00.000000Z"),
    # Half second
    (datetime(2026, 8, 21, 10, 0, 0, 500_000, tzinfo=timezone.utc),
     "2026-08-21T10:00:00.500000Z"),
    # Microsecond precision
    (datetime(2026, 8, 21, 10, 0, 0, 123_456, tzinfo=timezone.utc),
     "2026-08-21T10:00:00.123456Z"),
    # Non-UTC input is converted to UTC
    (datetime(2026, 8, 21, 15, 30, 0, 0,
              tzinfo=timezone(timedelta(hours=5, minutes=30))),
     "2026-08-21T10:00:00.000000Z"),
])
def test_canonical_ts_byte_identical(dt, want):
    """27 chars, six fractional digits, UTC, Z suffix."""
    assert canonical_ts(dt) == want


def test_canonical_ts_length_is_stable():
    """Every stamp is 27 chars (`YYYY-MM-DDTHH:MM:SS.ffffffZ`), so string
    order matches time order. With trailing zeros stripped, a whole second
    would sort above fractional seconds in the same second."""
    stamps = [canonical_ts(datetime(2026, 8, 21, 10, 0, s, us, tzinfo=timezone.utc))
              for s in (0, 30, 59) for us in (0, 1, 100_000, 999_999)]
    assert all(len(s) == 27 for s in stamps), stamps


def test_canonical_ts_lex_order_matches_time_order():
    """A later instant sorts higher. The §4.3 window compare depends on it."""
    base = datetime(2026, 8, 21, 10, 0, 0, tzinfo=timezone.utc)
    for us_a, us_b in [(0, 1), (0, 500_000), (500_000, 999_999), (0, 999_999)]:
        a = canonical_ts(base.replace(microsecond=us_a))
        b = canonical_ts(base.replace(microsecond=us_b))
        assert a < b, f"{a!r} should sort below {b!r}"

    # Without fixed width, `Z` (0x5A) > `.` (0x2E) would sort 10:00:00Z
    # above 10:00:00.5Z.
    whole = canonical_ts(base)  # 10:00:00.000000Z
    half = canonical_ts(base.replace(microsecond=500_000))
    assert whole < half, f"whole second {whole!r} must sort below half {half!r}"


# The parser accepts only the canonical form.

def test_parse_canonical_round_trips_writer():
    """parse_canonical(canonical_ts(dt)) == dt."""
    dt = datetime(2026, 8, 21, 10, 0, 0, 500_000, tzinfo=timezone.utc)
    assert parse_canonical(canonical_ts(dt)) == dt


@pytest.mark.parametrize("bad", [
    "2026-08-21T10:00:00Z",              # whole-second Go RFC3339Nano, 20 chars
    "2026-08-21T10:00:00.500+00:00",      # Python isoformat(ms), offset form
    "2026-08-21T10:00:00.123456+00:00",   # Python isoformat(µs), offset form
    "2026-08-21T10:00:00.500Z",           # 3 fractional digits
    "2026-08-21T10:00:00.123456+05:30",   # non-UTC offset
    "",                                    # empty
    "not-a-timestamp",                    # garbage
])
def test_parse_rejects_anything_but_canonical(bad):
    """Anything else means a writer did not use canonical_ts, so fail loudly."""
    with pytest.raises(ValueError):
        parse_canonical(bad)
