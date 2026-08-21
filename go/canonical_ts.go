package fasten

import "time"

// Canonical timestamp form for cross-SDK lexicographic windows.
//
// Spec §4.3 mandates [since, until] lexicographic comparison and states
// callers MUST keep one canonical form. Historically Go stamped
// time.RFC3339Nano (2026-08-21T10:00:00Z, trailing zeros stripped) while
// Python stamped isoformat(timespec="milliseconds")
// (2026-08-21T10:00:00.500+00:00) — the two disagreed byte-for-byte on
// the same instant, so windowed reads on tables with both writers
// silently truncated at boundary instants, and a Go-only same-second
// ordering case inverted ('Z' 0x5A > '.' 0x2E).
//
// Canonical form: RFC3339 with a fixed six-digit sub-second and an
// always-Z suffix (never a trailing-zero-stripped whole second):
//
//	2026-08-21T10:00:00.000000Z
//	2026-08-21T10:00:00.500000Z
//
// Fixed-width guarantees every stamp has the fractional dot at byte 19,
// so .NNNNNNZ sorts as digits and never as Z > `.`. Microsecond precision
// matches Postgres timestamptz default resolution + Python's stdlib
// default; anything finer (nanoseconds) has no cross-runtime carrier.
//
// Every outbound fasten timestamp (audit / api / sys rows, purge cutoffs,
// drainer sys log entries, reader last_verified_at, retention cutoff)
// goes through canonicalTS or canonicalNow. See the sibling
// python/fasten/canonical_ts.py.
//
// Parsing (via time.Parse(time.RFC3339Nano, ...)) already accepts both
// the canonical form and the older stripped form, so historical rows in
// stores written before this rollout read back cleanly with no changes.
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
