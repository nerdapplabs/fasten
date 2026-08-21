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

// TestRingStatusNumericCompare_ParityWithStore (PR #59 finding 5): the ring
// used fmt.Sprint(row["status"]) != q.Status — string equality that returns
// zero rows for ?status=0502 against integer 502. Both stores compare
// numerically (SQLite affinity, Postgres strconv.Atoi), so enabling
// persistence silently changed query results. Pin the numeric compare.
func TestRingStatusNumericCompare_ParityWithStore(t *testing.T) {
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	seedFilterRows(GetTransport())
	h := NewReader()

	// The seed pushes status=502 (int). Query with leading-zero equivalent,
	// exact numeric string, and plain int-form — all three must match the
	// same row, and none should return zero.
	for _, q := range []string{"?status=502", "?status=0502", "?status=00502"} {
		body, _ := getJSON(t, h, "/api"+q)
		rows, _ := body["rows"].([]any)
		if len(rows) != 1 || rows[0].(map[string]any)["path"] != "/checkout" {
			t.Errorf("ring /api%s got %v (want the status=502 row)", q, body["rows"])
		}
	}
	// Genuine mismatch still returns zero.
	body, _ := getJSON(t, h, "/api?status=418")
	if rows, _ := body["rows"].([]any); len(rows) != 0 {
		t.Errorf("status=418 should not match: %v", body["rows"])
	}
	// Non-numeric status query stays defensible (no crash, no bogus match).
	body, _ = getJSON(t, h, "/api?status=abc")
	if rows, _ := body["rows"].([]any); len(rows) != 0 {
		t.Errorf("status=abc should not match numeric rows: %v", body["rows"])
	}
}

// TestStructuredFilters_RingAndStoreAgree (PR #59 test-coverage gap):
// run the same query on ring-only and persisted, assert the row set matches.
// The earlier suite tested each in isolation, so the ring/store status
// divergence shipped.
func TestStructuredFilters_RingAndStoreAgree(t *testing.T) {
	// Ring-only pass.
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatalf("Init(ring): %v", err)
	}
	seedFilterRows(GetTransport())
	ringBody, _ := getJSON(t, NewReader(), "/api?status=0502")
	ringRows, _ := ringBody["rows"].([]any)

	// Persisted pass.
	resetGlobals(t)
	adb, _ := sql.Open("sqlite", ":memory:")
	t.Cleanup(func() { adb.Close() })
	apiStore, _ := NewStreamStore(adb, "api_log")
	if err := Init(Config{ServiceID: "svc", NodeID: "node", APIStore: apiStore}); err != nil {
		t.Fatalf("Init(store): %v", err)
	}
	seedFilterRows(GetTransport())
	storeBody, _ := getJSON(t, NewReader(), "/api?status=0502")
	storeRows, _ := storeBody["rows"].([]any)

	if len(ringRows) != len(storeRows) {
		t.Fatalf("ring/store row count diverges for ?status=0502: ring=%d store=%d",
			len(ringRows), len(storeRows))
	}
	if len(ringRows) == 0 {
		t.Fatal("both returned zero rows — the seed row status=502 should match ?status=0502 on both paths")
	}
}
