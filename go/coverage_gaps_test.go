package fasten

import (
	"database/sql"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// Table-name validation, undated rows in windowed ring reads, and since/until
// inclusivity.

// The regex is the only injection barrier; each constructor must reject the
// same set of bad names, and the stream stores must not default an empty
// name to "syslog".
func TestStoreConstructors_RejectBadTableNames(t *testing.T) {
	db, _ := sql.Open("sqlite", ":memory:")
	t.Cleanup(func() { db.Close() })

	// Invalid-shape names must be rejected everywhere (the regex is the only
	// injection barrier). NewSQLiteStore defaults "" to "fasten_audit", so
	// empty is excluded here.
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
	// The stream stores must also reject an empty name.
	if _, err := NewStreamStore(db, ""); err == nil {
		t.Error("NewStreamStore(\"\"): want error (no default), got nil")
	}
	if _, err := NewSQLiteStore(db, "audit_ok"); err != nil {
		t.Errorf("NewSQLiteStore(audit_ok) unexpectedly failed: %v", err)
	}
	if _, err := NewStreamStore(db, "stream_ok"); err != nil {
		t.Errorf("NewStreamStore(stream_ok) unexpectedly failed: %v", err)
	}
}

// A row with no timestamp has an unknown age, so it is left out of any
// windowed read. The stores do the same through COALESCE; this pins the
// ring's inWindow path to match.
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
	// No window: both rows visible.
	body2, _ := getJSON(t, NewReader(), "/sys")
	if r, _ := body2["rows"].([]any); len(r) != 2 {
		t.Errorf("no-window read must include both rows; got %d", len(r))
	}
}

// spec §4.3: [since, until] is inclusive on both ends.
func TestRing_WindowInclusiveOnBothEnds(t *testing.T) {
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	tr := GetTransport()
	// Rows are written in the canonical form (spec §4.3). The query param can
	// be any RFC3339 flavour; the reader canonicalises it before comparing.
	boundary := "2026-08-15T00:00:00.000000Z"
	tr.PushSyslog(SyslogRow{"event": "at.boundary", "request_id": "r-eq",
		"timestamp": boundary})

	// The reader canonicalises the short RFC3339 form to the same 27-char
	// shape the row was stored in.
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

// Same boundary check through the store path, so ring and store agree.
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
	// A window ending one second earlier must not match.
	oneEarlier := "2026-08-14T23:59:59Z"
	body, _ = getJSON(t, NewReader(), "/sys?since="+oneEarlier+"&until="+oneEarlier)
	if r, _ := body["rows"].([]any); len(r) != 0 {
		t.Errorf("row at boundary must not match a window ending 1s earlier; got %d", len(r))
	}
}

// The rejection error mentions "identifier" or "required" so callers can
// tell the cases apart.
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
