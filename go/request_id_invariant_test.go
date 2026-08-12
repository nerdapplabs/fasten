package fasten

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// §8.7 conformance — every persisted sys row carries a request_id. Drives a
// service through boot -> first request -> background tick -> shutdown and
// asserts every sys row in the persisted store has a non-empty request_id (real
// inside a request, sentinel outside). Mirrors the Python
// test_every_persisted_sys_row_has_request_id.

func TestRequestIDInvariant_EveryPersistedSysRow(t *testing.T) {
	resetGlobals(t)
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	ss, err := NewStreamStore(db, "syslog")
	if err != nil {
		t.Fatalf("NewStreamStore: %v", err)
	}
	if err := Init(Config{ServiceID: "svc", NodeID: "node", SyslogStore: ss}); err != nil {
		t.Fatalf("Init: %v", err)
	}

	Default.LogSys(context.Background(), "info", "boot.init", nil)                          // boot
	Default.LogSys(WithRequestID(context.Background(), "req-abc123def"), "info", "handling", nil) // first request
	Default.LogSys(context.Background(), "info", "bg.tick", nil)                            // background
	Default.LogSys(context.Background(), "info", "shutdown", nil)                           // shutdown

	rows, err := ss.Query(100, nil, "", "")
	must(t, err)
	if len(rows) != 4 {
		t.Fatalf("got %d persisted sys rows, want 4", len(rows))
	}
	kind := map[string]string{}
	for _, r := range rows {
		rid, _ := r["request_id"].(string)
		if rid == "" {
			t.Errorf("persisted sys row missing request_id: %v", r)
		}
		ev, _ := r["event"].(string)
		kind[ev] = RequestIDKind(rid)
	}
	if kind["boot.init"] != "boot" {
		t.Errorf("boot.init kind=%q, want boot", kind["boot.init"])
	}
	if kind["handling"] != "request" {
		t.Errorf("handling kind=%q, want request", kind["handling"])
	}
	if kind["bg.tick"] != "orphan" {
		t.Errorf("bg.tick kind=%q, want orphan", kind["bg.tick"])
	}
	if kind["shutdown"] != "orphan" {
		t.Errorf("shutdown kind=%q, want orphan", kind["shutdown"])
	}
}
