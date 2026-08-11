package fasten

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// Per-stream retention pruning (FR1): StreamStore.Purge trims history by age.
// A timestamp-less row has unknown age and is kept, not silently dropped.

func TestStreamStore_PurgeRemovesOldRows(t *testing.T) {
	s := newStreamStore(t, "ret")
	must(t, s.Insert(map[string]any{"request_id": "old", "timestamp": "2026-01-01T00:00:00Z", "event": "a"}))
	must(t, s.Insert(map[string]any{"request_id": "new", "timestamp": "2026-08-01T00:00:00Z", "event": "b"}))
	must(t, s.Insert(map[string]any{"request_id": "nots", "event": "c"})) // no timestamp

	n, err := s.Purge("2026-06-01T00:00:00Z")
	must(t, err)
	if n != 1 {
		t.Fatalf("purge removed %d, want 1", n)
	}

	rows, err := s.Query(10, nil, "", "")
	must(t, err)
	got := map[string]bool{}
	for _, r := range rows {
		id, _ := r["request_id"].(string)
		got[id] = true
	}
	if got["old"] || !got["new"] || !got["nots"] {
		t.Errorf("after purge got %v, want old gone and new+nots kept", got)
	}
}

func TestStreamStore_PurgeNoneWhenAllNewer(t *testing.T) {
	s := newStreamStore(t, "ret2")
	must(t, s.Insert(map[string]any{"request_id": "x", "timestamp": "2026-08-10T00:00:00Z"}))
	n, err := s.Purge("2026-01-01T00:00:00Z")
	must(t, err)
	if n != 0 {
		t.Fatalf("purge removed %d, want 0", n)
	}
	rows, err := s.Query(10, nil, "", "")
	must(t, err)
	if len(rows) != 1 {
		t.Errorf("got %d rows, want 1", len(rows))
	}
}

// TestStreamStore_PurgeReflectedInReads is the functional path: rows written
// through the transport persist to the stream store, and purging old history
// removes them from a subsequent reader read served from that store.
func TestStreamStore_PurgeReflectedInReads(t *testing.T) {
	resetGlobals(t)
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	syslogStore, err := NewStreamStore(db, "syslog")
	if err != nil {
		t.Fatalf("NewStreamStore: %v", err)
	}
	if err := Init(Config{ServiceID: "svc", NodeID: "node", SyslogStore: syslogStore}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	tr := GetTransport()
	tr.PushSyslog(SyslogRow{"level": "info", "event": "old", "timestamp": "2026-01-01T00:00:00Z", "request_id": "r1"})
	tr.PushSyslog(SyslogRow{"level": "info", "event": "new", "timestamp": "2026-08-01T00:00:00Z", "request_id": "r2"})

	rows, err := tr.QuerySyslog(10, StreamQuery{})
	must(t, err)
	if len(rows) != 2 {
		t.Fatalf("pre-purge got %d rows, want 2", len(rows))
	}

	n, err := syslogStore.Purge("2026-06-01T00:00:00Z")
	must(t, err)
	if n != 1 {
		t.Fatalf("purge removed %d, want 1", n)
	}

	rows, err = tr.QuerySyslog(10, StreamQuery{})
	must(t, err)
	if len(rows) != 1 || rows[0]["event"] != "new" {
		t.Errorf("post-purge rows = %v, want only the 'new' event", rows)
	}
}
