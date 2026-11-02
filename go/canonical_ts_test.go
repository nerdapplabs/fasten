package fasten

import (
	"testing"
	"time"
)

// Canonical timestamp form (spec §4.3), byte-identical across SDKs. These
// are the same instants as the Python SDK's tests/test_canonical_ts.py.

func TestCanonicalTS_ByteIdentical(t *testing.T) {
	cases := []struct {
		name string
		t    time.Time
		want string
	}{
		{
			// Whole seconds: RFC3339Nano would drop the .000000.
			"whole_second_utc",
			time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC),
			"2026-08-21T10:00:00.000000Z",
		},
		{
			"half_second_utc",
			time.Date(2026, 8, 21, 10, 0, 0, 500_000_000, time.UTC), // 500ms in nanos
			"2026-08-21T10:00:00.500000Z",
		},
		{
			"microsecond_utc",
			time.Date(2026, 8, 21, 10, 0, 0, 123_456_000, time.UTC), // 123456µs in nanos
			"2026-08-21T10:00:00.123456Z",
		},
		{
			// Non-UTC input is converted to UTC before formatting.
			"non_utc_input_converted",
			time.Date(2026, 8, 21, 15, 30, 0, 0,
				time.FixedZone("IST", int((5*time.Hour+30*time.Minute).Seconds()))),
			"2026-08-21T10:00:00.000000Z",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := canonicalTS(c.t)
			if got != c.want {
				t.Errorf("canonicalTS(%v) = %q, want %q", c.t, got, c.want)
			}
		})
	}
}

func TestCanonicalTS_LengthIsStable(t *testing.T) {
	// Every canonical stamp is exactly 27 chars (YYYY-MM-DDTHH:MM:SS.ffffffZ),
	// so lexical order matches wall-clock order.
	base := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	for _, s := range []int{0, 30, 59} {
		for _, ns := range []int{0, 1_000, 100_000_000, 999_999_000} {
			ts := base.Add(time.Duration(s) * time.Second).Add(time.Duration(ns))
			if got := canonicalTS(ts); len(got) != 27 {
				t.Errorf("canonicalTS(%v) = %q (len %d), want length 27",
					ts, got, len(got))
			}
		}
	}
}

func TestCanonicalTS_LexOrderMatchesTimeOrder(t *testing.T) {
	base := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	pairs := []struct{ aNs, bNs int }{
		{0, 1_000},
		{0, 500_000_000},
		{500_000_000, 999_999_000},
		{0, 999_999_000},
	}
	for _, p := range pairs {
		a := canonicalTS(base.Add(time.Duration(p.aNs)))
		b := canonicalTS(base.Add(time.Duration(p.bNs)))
		if !(a < b) {
			t.Errorf("%q should sort below %q", a, b)
		}
	}
	// Cross-second boundary: without the fixed fraction, 'Z' (0x5A) > '.'
	// (0x2E) would sort 10:00:00Z above 10:00:00.5Z.
	whole := canonicalTS(base)
	half := canonicalTS(base.Add(500 * time.Millisecond))
	if !(whole < half) {
		t.Errorf("whole second %q must sort below half %q", whole, half)
	}
}

func TestParseCanonicalTS_RoundTripsWriter(t *testing.T) {
	// The strict parser round-trips exactly what canonicalTS writes.
	want := time.Date(2026, 8, 21, 10, 0, 0, 500_000_000, time.UTC)
	got, err := parseCanonicalTS(canonicalTS(want))
	if err != nil {
		t.Fatalf("strict parser rejected canonical form: %v", err)
	}
	if !got.Equal(want) {
		t.Errorf("roundtrip lost precision: got %v, want %v", got, want)
	}
}

func TestParseCanonicalTS_RejectsAnythingElse(t *testing.T) {
	// Only the exact 27-char canonical form is accepted. Anything else means
	// a writer skipped canonicalTS, and that should fail loudly.
	bad := []string{
		"2026-08-21T10:00:00Z",             // whole-second RFC3339Nano (20 chars)
		"2026-08-21T10:00:00.500Z",         // short fractional (3 digits)
		"2026-08-21T10:00:00.500+00:00",    // offset form, not Z
		"2026-08-21T10:00:00.123456+05:30", // non-UTC offset
		"",                                 // empty
		"not-a-timestamp",                  // garbage
	}
	for _, s := range bad {
		if _, err := parseCanonicalTS(s); err == nil {
			t.Errorf("parseCanonicalTS(%q) accepted; must reject non-canonical", s)
		}
	}
}
