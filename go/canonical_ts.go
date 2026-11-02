package fasten

import (
	"fmt"
	"time"
)

// canonicalTSLayout is the one timestamp form fasten writes (spec §4.3):
// UTC, six fractional digits, Z suffix, e.g. 2026-08-21T10:00:00.500000Z.
// The fixed width keeps timestamps sortable as strings; RFC3339Nano drops
// trailing zeros and breaks that. Six digits is the resolution of Postgres
// and Python.
const canonicalTSLayout = "2006-01-02T15:04:05.000000Z"

// canonicalTS formats t in UTC.
func canonicalTS(t time.Time) string {
	return t.UTC().Format(canonicalTSLayout)
}

// canonicalNow is canonicalTS(time.Now()).
func canonicalNow() string {
	return canonicalTS(time.Now())
}

// parseCanonicalTS parses a timestamp in the canonical form and rejects
// any other form.
func parseCanonicalTS(s string) (time.Time, error) {
	t, err := time.Parse(canonicalTSLayout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("not the canonical timestamp form: %q: %w", s, err)
	}
	return t, nil
}
