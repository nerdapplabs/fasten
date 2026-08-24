//go:build integration

package fasten

import "testing"

// PostgresStreamStore parity with the SQLite StreamStore (FR1). Integration-only
// (needs a Postgres via FASTEN_TEST_POSTGRES_DSN and the lib/pq driver, as with
// the audit Postgres tests): go test -tags integration ./...

func TestPostgresStreamStore_Parity(t *testing.T) {
	db := pgDB(t)
	table := uniqueTable("sst")
	s, err := NewPostgresStreamStore(db, table)
	if err != nil {
		t.Fatalf("NewPostgresStreamStore: %v", err)
	}
	t.Cleanup(func() { dropTable(t, db, table) })

	must(t, s.Insert(map[string]any{"level": "error", "event": "db.timeout", "service_id": "svc",
		"message": "connection reset by peer", "timestamp": "2026-08-01T00:00:00Z", "request_id": "r-1"}))
	must(t, s.Insert(map[string]any{"level": "info", "event": "ok", "service_id": "svc",
		"timestamp": "2026-08-01T00:00:01Z", "request_id": "r-2"}))
	must(t, s.Insert(map[string]any{"method": "POST", "path": "/x", "status": 502,
		"timestamp": "2026-08-01T00:00:02Z", "request_id": "r-3"}))

	// newest-first (seq DESC)
	rows, err := s.Query(10, nil, "", "")
	must(t, err)
	if len(rows) != 3 || rows[0]["request_id"] != "r-3" {
		t.Fatalf("query order: %v", rows)
	}

	// structured exact-match
	rows, err = s.Query(10, map[string]string{"level": "error"}, "", "")
	must(t, err)
	if len(rows) != 1 || rows[0]["request_id"] != "r-1" {
		t.Errorf("level filter: %v", rows)
	}
	if r, _ := s.Query(10, map[string]string{"level": "ERROR"}, "", ""); len(r) != 0 {
		t.Errorf("level filter should be exact-match: %v", r)
	}

	// status compared numerically (parsed to int) — the text-in-eq path
	rows, err = s.Query(10, map[string]string{"status": "502"}, "", "")
	must(t, err)
	if len(rows) != 1 || rows[0]["request_id"] != "r-3" {
		t.Errorf("status filter: %v", rows)
	}
	// non-canonical numeric form must still match the integer column (FR5-10;
	// parity with the Python SDK, which binds status as int).
	rows, err = s.Query(10, map[string]string{"status": "0502"}, "", "")
	must(t, err)
	if len(rows) != 1 || rows[0]["request_id"] != "r-3" {
		t.Errorf("status=0502 should match integer 502 (parity with Python): %v", rows)
	}
	if r, _ := s.Query(10, map[string]string{"status": "50"}, "", ""); len(r) != 0 {
		t.Errorf("status=50 must not match 502: %v", r)
	}

	// time window
	rows, err = s.Query(10, nil, "2026-08-01T00:00:01Z", "")
	must(t, err)
	if len(rows) != 2 {
		t.Errorf("since window: got %d, want 2 (r-2,r-3)", len(rows))
	}

	// counts
	if c, err := s.Count(); err != nil || c != 3 {
		t.Errorf("count=%d err=%v, want 3", c, err)
	}
	if c, err := s.CountMatching(map[string]string{"level": "error"}, "", ""); err != nil || c != 1 {
		t.Errorf("count_matching=%d err=%v, want 1", c, err)
	}

	// purge (NULL-timestamp rows never purged; here all have timestamps)
	must(t, s.Insert(map[string]any{"event": "old", "timestamp": "2026-01-01T00:00:00Z", "request_id": "r-old"}))
	n, err := s.Purge("2026-06-01T00:00:00Z")
	must(t, err)
	if n != 1 {
		t.Errorf("purge=%d, want 1", n)
	}

	// search: case-insensitive + literal % (wildcard escaped)
	must(t, s.Insert(map[string]any{"event": "100%done", "timestamp": "2026-08-01T00:00:05Z", "request_id": "r-w"}))
	must(t, s.Insert(map[string]any{"event": "100XYZdone", "timestamp": "2026-08-01T00:00:06Z", "request_id": "r-x"}))
	hits, err := s.Search("RESET BY PEER", "2026-01-01T00:00:00Z", "", 50)
	must(t, err)
	if len(hits) != 1 || hits[0]["request_id"] != "r-1" {
		t.Errorf("search case-insensitive: %v", hits)
	}
	esc, err := s.Search("100%done", "2026-01-01T00:00:00Z", "", 50)
	must(t, err)
	if len(esc) != 1 || esc[0]["request_id"] != "r-w" {
		t.Errorf("search escape: %v", esc)
	}

	// PR #59 test-coverage gap: the ESCAPE E'\\' construction that spec §9
	// singles out is exercised only for % — but Postgres LIKE treats _ as a
	// single-char wildcard, and \ becomes a metacharacter under that ESCAPE
	// clause. If the query for either isn't escaped, they match too much.
	must(t, s.Insert(map[string]any{"event": "a_b", "timestamp": "2026-08-01T00:00:07Z", "request_id": "r-u1"}))
	must(t, s.Insert(map[string]any{"event": "aXb", "timestamp": "2026-08-01T00:00:08Z", "request_id": "r-u2"}))
	uh, err := s.Search("a_b", "2026-01-01T00:00:00Z", "", 50)
	must(t, err)
	if len(uh) != 1 || uh[0]["request_id"] != "r-u1" {
		t.Errorf("search underscore literal: got %v, want only r-u1 (aXb must not match a_b)", uh)
	}
	// event c\d is stored in the JSON payload as c\\d (json.Marshal escapes the
	// backslash), so the substring query over the payload carries two
	// backslashes; each is escaped so it matches as data, not as the ESCAPE
	// metacharacter. cXd must NOT match.
	must(t, s.Insert(map[string]any{"event": "c\\d", "timestamp": "2026-08-01T00:00:09Z", "request_id": "r-bs"}))
	must(t, s.Insert(map[string]any{"event": "cXd", "timestamp": "2026-08-01T00:00:10Z", "request_id": "r-bs2"}))
	bh, err := s.Search("c\\\\d", "2026-01-01T00:00:00Z", "", 50)
	must(t, err)
	if len(bh) != 1 || bh[0]["request_id"] != "r-bs" {
		t.Errorf("search backslash literal: got %v, want only r-bs (cXd must not match c\\d)", bh)
	}

	// degraded flag
	if s.Degraded() {
		t.Error("degraded should start false")
	}
	s.NoteWriteFailure()
	if !s.Degraded() {
		t.Error("degraded should be true after a swallowed failure")
	}
}

// TestPostgresStreamStore_SatisfiesInterface pins that the Postgres store can be
// used anywhere a StreamRepository is expected (Config/Transport).
func TestPostgresStreamStore_SatisfiesInterface(t *testing.T) {
	var _ StreamRepository = (*PostgresStreamStore)(nil)
}
