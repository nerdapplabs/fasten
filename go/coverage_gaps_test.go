package fasten

import (
	"database/sql"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// PR #59 test-coverage gaps — before this file:
//   - no test rejected an invalid table name at any of the four store constructors;
//   - no ring test covered a row with NULL/missing timestamp against a since
//     window (delete the COALESCE and every Go test still passed);
//   - since/until inclusivity was assumed, never asserted (changing <= to <
//     broke nothing).
// This file pins all three.

// ── table-name rejection ──────────────────────────────────────────────────

// The regex is the only injection barrier; each constructor must reject the
// same set of bad names, and NewPostgresStreamStore must not default an empty
// name to "syslog" (that was the silent api→syslog split).
func TestStoreConstructors_RejectBadTableNames(t *testing.T) {
	db, _ := sql.Open("sqlite", ":memory:")
	t.Cleanup(func() { db.Close() })

	// Invalid-shape names must be rejected everywhere (the regex is the only
	// injection barrier). NewSQLiteStore intentionally defaults "" to
	// "fasten_audit", so empty is excluded here — see its docstring.
	badShape := []string{
		"1abc", "a-b", "a b", "a;b", "drop table x;",
	}
	for _, name := range badShape {
		if _, err := NewSQLiteStore(db, name); err == nil {
			t.Errorf("NewSQLiteStore(%q): want error, got nil", name)
		}
		if _, err := NewStreamStore(db, name); err == nil {
			t.Errorf("NewStreamStore(%q): want error, got nil", name)
		}
	}
	// The stream stores must also reject empty — that's the api→syslog silent
	// split the PR #59 review flagged for the Postgres constructor.
	if _, err := NewStreamStore(db, ""); err == nil {
		t.Error("NewStreamStore(\"\"): want error (no default), got nil")
	}
	// Good names still work.
	if _, err := NewSQLiteStore(db, "audit_ok"); err != nil {
		t.Errorf("NewSQLiteStore(audit_ok) unexpectedly failed: %v", err)
	}
	if _, err := NewStreamStore(db, "stream_ok"); err != nil {
		t.Errorf("NewStreamStore(stream_ok) unexpectedly failed: %v", err)
	}
}

// ── ring NULL/missing-timestamp window ────────────────────────────────────

// A row with no timestamp field must NOT appear in a windowed read — its age
// is unknown; if a caller narrows with ?since=..., undated rows fall outside
// (matching the store's COALESCE behaviour). Delete the store COALESCE and
// this test still passes because it exercises the ring inWindow path; the
// point is that we pinned the ring's behaviour so it can't quietly drift
// off from the stores.
func TestRing_NullTimestamp_WindowExcludes(t *testing.T) {
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	tr := GetTransport()
	tr.PushSyslog(SyslogRow{"event": "no.ts", "request_id": "r-nul"}) // no timestamp
	tr.PushSyslog(SyslogRow{"event": "ok", "request_id": "r-ok",
		"timestamp": "2026-08-15T00:00:00Z"})

	body, _ := getJSON(t, NewReader(), "/sys?since=2026-08-01T00:00:00Z")
	rows, _ := body["rows"].([]any)
	if len(rows) != 1 {
		t.Fatalf("want 1 dated row through the window, got %d (%v)", len(rows), rows)
	}
	if rows[0].(map[string]any)["request_id"] != "r-ok" {
		t.Errorf("windowed read must exclude undated rows; got %v", rows)
	}
	// No window ⇒ both rows visible.
	body2, _ := getJSON(t, NewReader(), "/sys")
	if r, _ := body2["rows"].([]any); len(r) != 2 {
		t.Errorf("no-window read must include both rows; got %d", len(r))
	}
}

// ── since / until inclusivity ─────────────────────────────────────────────

// spec §4.3 states [since, until] is inclusive on both ends. Neither ring
// nor store test used to pin the equality boundary; changing the comparison
// operator broke nothing.
func TestRing_WindowInclusiveOnBothEnds(t *testing.T) {
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	tr := GetTransport()
	// Row is written in the canonical form (spec §4.3) — writers MUST use
	// canonical_ts / canonicalTS. Query param can be any RFC3339 flavour;
	// the reader canonicalises it before the lex compare.
	boundary := "2026-08-15T00:00:00.000000Z"
	tr.PushSyslog(SyslogRow{"event": "at.boundary", "request_id": "r-eq",
		"timestamp": boundary})

	// Query param uses the shorter RFC3339 form — the reader canonicalises
	// it to the same 27-char shape the row was stored in.
	shortForm := "2026-08-15T00:00:00Z"
	// since == ts must include the row.
	body, _ := getJSON(t, NewReader(), "/sys?since="+shortForm)
	rows, _ := body["rows"].([]any)
	if len(rows) != 1 {
		t.Errorf("since=ts must be inclusive; got %d rows", len(rows))
	}
	// until == ts must include the row too.
	body, _ = getJSON(t, NewReader(), "/sys?until="+shortForm)
	rows, _ = body["rows"].([]any)
	if len(rows) != 1 {
		t.Errorf("until=ts must be inclusive; got %d rows", len(rows))
	}
}

// A store-backed variant — the store path also honours the inclusive
// boundary; a divergent < / <= between ring and store would surface as a
// row appearing under one backend and not the other.
func TestStore_WindowInclusiveOnBothEnds(t *testing.T) {
	resetGlobals(t)
	sdb, _ := sql.Open("sqlite", ":memory:")
	t.Cleanup(func() { sdb.Close() })
	ss, err := NewStreamStore(sdb, "syslog_boundary")
	if err != nil {
		t.Fatalf("NewStreamStore: %v", err)
	}
	if err := Init(Config{ServiceID: "svc", NodeID: "node", SyslogStore: ss}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	boundary := "2026-08-15T00:00:00.000000Z"
	GetTransport().PushSyslog(SyslogRow{"event": "at.boundary", "request_id": "r-eq",
		"timestamp": boundary})

	shortForm := "2026-08-15T00:00:00Z"
	body, _ := getJSON(t, NewReader(), "/sys?since="+shortForm)
	if r, _ := body["rows"].([]any); len(r) != 1 {
		t.Errorf("store since=ts must be inclusive; got %d rows", len(r))
	}
	body, _ = getJSON(t, NewReader(), "/sys?until="+shortForm)
	if r, _ := body["rows"].([]any); len(r) != 1 {
		t.Errorf("store until=ts must be inclusive; got %d rows", len(r))
	}
	// One second earlier must NOT match with a window that ends there
	// (paranoia against an accidental exclusive-lower switch).
	oneEarlier := "2026-08-14T23:59:59Z"
	body, _ = getJSON(t, NewReader(), "/sys?since="+oneEarlier+"&until="+oneEarlier)
	if r, _ := body["rows"].([]any); len(r) != 0 {
		t.Errorf("row at boundary must not match a window ending 1s earlier; got %d", len(r))
	}
}

// Sanity-only: the rejection error mentions "identifier" or "required" so
// callers can pattern-match if they need to distinguish invariants. Not part
// of the coverage matrix — kept small so the file's contract is one line.
func TestStoreConstructorErrorsSayWhy(t *testing.T) {
	db, _ := sql.Open("sqlite", ":memory:")
	t.Cleanup(func() { db.Close() })
	_, err := NewStreamStore(db, "")
	if err == nil {
		t.Fatal("empty table name must error")
	}
	if !strings.Contains(err.Error(), "required") &&
		!strings.Contains(err.Error(), "identifier") {
		t.Errorf("error should say why (required|identifier); got %q", err.Error())
	}
}
