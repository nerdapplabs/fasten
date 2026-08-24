package fasten

import (
	"fmt"
	"time"
)

// Canonical timestamp form for cross-SDK lexicographic windows (spec §4.3).
//
// One form, one parser. Every outbound fasten timestamp — audit rows,
// stream rows, purge cutoffs, drainer sys events, last_verified_at,
// retention cutoffs — is stamped as RFC3339 with a fixed six-digit
// sub-second and an always-Z suffix:
//
//	2026-08-21T10:00:00.000000Z
//	2026-08-21T10:00:00.500000Z
//
// Fixed width places the fractional dot at byte 19 for every stamp, so
// .NNNNNNZ sorts as digits and 'Z' (0x5A) never appears where '.'
// (0x2E) does — the specific inversion the older time.RFC3339Nano
// writer caused by stripping trailing zeros. Six digits matches
// Postgres timestamptz default resolution + Python stdlib default; no
// sub-microsecond carrier exists across runtimes.
//
// canonicalTS writes it; time.Parse(canonicalTSLayout, ...) reads it.
// Both are strict — any other form is a bug at the source and must
// fail rather than silently round-trip. See the sibling
// python/fasten/canonical_ts.py; parallel conformance tests in each
// SDK pin byte-identical output on the same instant.
const canonicalTSLayout = "2006-01-02T15:04:05.000000Z"

// canonicalTS stamps t in the canonical form. Naive UTC assumption: if
// t.Location() is not UTC, it's converted before formatting (fasten has
// never stamped local time on the wire and never should).
func canonicalTS(t time.Time) string {
	return t.UTC().Format(canonicalTSLayout)
}

// canonicalNow is the ubiquitous canonicalTS(time.Now()) shortcut.
func canonicalNow() string {
	return canonicalTS(time.Now())
}

// parseCanonicalTS parses a canonical UTC timestamp back into a time.Time.
// Strict — only the exact 27-char YYYY-MM-DDTHH:MM:SS.NNNNNNZ form is
// accepted; anything else returns a formatted error. Nothing in fasten
// should ever hand this a non-canonical string.
func parseCanonicalTS(s string) (time.Time, error) {
	t, err := time.Parse(canonicalTSLayout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("not the canonical timestamp form: %q: %w", s, err)
	}
	return t, nil
}
