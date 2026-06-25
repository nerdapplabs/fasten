package fasten

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// §3.4 — indexed structured-field filters on the sys/api reader endpoints:
// event (sys), status (api), and since/until windows, honoured identically
// whether the stream is ring-only or persisted.

func seedFilterRows(tr *Transport) {
	tr.PushSyslog(SyslogRow{"level": "error", "event": "db.timeout", "request_id": "r1", "timestamp": "2026-06-25T10:00:00Z"})
	tr.PushSyslog(SyslogRow{"level": "info", "event": "cache.miss", "request_id": "r2", "timestamp": "2026-06-25T12:00:00Z"})
	tr.PushAPI(APIRow{"method": "POST", "path": "/checkout", "status": 502, "request_id": "r1", "timestamp": "2026-06-25T10:00:00Z"})
	tr.PushAPI(APIRow{"method": "GET", "path": "/health", "status": 200, "request_id": "r3", "timestamp": "2026-06-25T12:00:00Z"})
}

func TestStructuredFilters_Ring(t *testing.T) {
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	seedFilterRows(GetTransport())
	h := NewReader()

	body, _ := getJSON(t, h, "/sys?event=db.timeout")
	if rows, _ := body["rows"].([]any); len(rows) != 1 || rows[0].(map[string]any)["event"] != "db.timeout" {
		t.Errorf("sys event filter: got %v", body["rows"])
	}
	body, _ = getJSON(t, h, "/api?status=502")
	if rows, _ := body["rows"].([]any); len(rows) != 1 || rows[0].(map[string]any)["path"] != "/checkout" {
		t.Errorf("api status filter: got %v", body["rows"])
	}
	body, _ = getJSON(t, h, "/api?since=2026-06-25T11:00:00Z")
	if rows, _ := body["rows"].([]any); len(rows) != 1 || rows[0].(map[string]any)["path"] != "/health" {
		t.Errorf("api since window: got %v", body["rows"])
	}
	body, _ = getJSON(t, h, "/sys?until=2026-06-25T11:00:00Z")
	if rows, _ := body["rows"].([]any); len(rows) != 1 || rows[0].(map[string]any)["event"] != "db.timeout" {
		t.Errorf("sys until window: got %v", body["rows"])
	}
}

func TestStructuredFilters_StoreAgreesWithRing(t *testing.T) {
	resetGlobals(t)
	adb, _ := sql.Open("sqlite", ":memory:")
	sdb, _ := sql.Open("sqlite", ":memory:")
	t.Cleanup(func() { adb.Close(); sdb.Close() })
	apiStore, _ := NewStreamStore(adb, "api_log")
	sysStore, _ := NewStreamStore(sdb, "syslog")
	if err := Init(Config{ServiceID: "svc", NodeID: "node", APIStore: apiStore, SyslogStore: sysStore}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	seedFilterRows(GetTransport())
	h := NewReader()

	body, comp := getCompleteness(t, h, "/sys?event=cache.miss")
	if comp["sys"] != "store" {
		t.Errorf("expected store completeness, got %v", comp)
	}
	if rows, _ := body["rows"].([]any); len(rows) != 1 || rows[0].(map[string]any)["event"] != "cache.miss" {
		t.Errorf("persisted sys event filter: got %v", body["rows"])
	}
	body, _ = getJSON(t, h, "/api?status=502")
	if rows, _ := body["rows"].([]any); len(rows) != 1 || rows[0].(map[string]any)["status"] != float64(502) {
		t.Errorf("persisted api status filter: got %v", body["rows"])
	}
	body, _ = getJSON(t, h, "/api?since=2026-06-25T11:00:00Z")
	if rows, _ := body["rows"].([]any); len(rows) != 1 || rows[0].(map[string]any)["path"] != "/health" {
		t.Errorf("persisted api since window: got %v", body["rows"])
	}
}
