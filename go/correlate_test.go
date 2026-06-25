package fasten

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "modernc.org/sqlite"
)

// FR2 — unified correlation read: GET /correlate?request_id=X fans out to the
// audit store + sys/api rings-or-stores and assembles
// {request_id, audit, api, sys, counts, completeness} in one call.

func getJSON(t *testing.T, h http.Handler, path string) (map[string]any, int) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	var body map[string]any
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: decode: %v", path, err)
		}
	}
	return body, rec.Code
}

func TestCorrelate_AssemblesAllThreeStreams(t *testing.T) {
	resetGlobals(t)
	registerTestCodes(t)
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := NewSQLiteStore(db, "audit_corr")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	if err := Init(Config{ServiceID: "svc", NodeID: "node", AuditStore: store, AuditStoreFailureStrategy: "raise"}); err != nil {
		t.Fatalf("Init: %v", err)
	}

	rid := "req-corr-1"
	ctx := WithRequestID(context.Background(), rid)
	if _, err := Emit(ctx, "USER_CREATED", Target("u-1"), Actor("alice", "user")); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	tr := GetTransport()
	tr.PushAPI(APIRow{"method": "POST", "path": "/v1/checkout", "status": 502, "request_id": rid})
	tr.PushSyslog(SyslogRow{"level": "error", "event": "db.timeout", "request_id": rid})
	tr.PushAPI(APIRow{"method": "GET", "path": "/health", "status": 200, "request_id": "other"})

	body, code := getJSON(t, NewReader(), "/correlate?request_id="+rid)
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if body["request_id"] != rid {
		t.Errorf("request_id: got %v", body["request_id"])
	}
	counts, _ := body["counts"].(map[string]any)
	if counts["audit"] != float64(1) || counts["api"] != float64(1) || counts["sys"] != float64(1) {
		t.Errorf("counts: got %v, want all 1", counts)
	}
	comp, _ := body["completeness"].(map[string]any)
	if comp["audit"] != "store" || comp["api"] != "ring" || comp["sys"] != "ring" {
		t.Errorf("completeness: got %v", comp)
	}
	api, _ := body["api"].([]any)
	if len(api) != 1 || api[0].(map[string]any)["path"] != "/v1/checkout" {
		t.Errorf("api stream: got %v", body["api"])
	}
}

func TestCorrelate_EmptyForUnknownRequestID(t *testing.T) {
	resetGlobals(t)
	db, _ := sql.Open("sqlite", ":memory:")
	t.Cleanup(func() { db.Close() })
	store, _ := NewSQLiteStore(db, "audit_corr2")
	if err := Init(Config{ServiceID: "svc", NodeID: "node", AuditStore: store}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	body, code := getJSON(t, NewReader(), "/correlate?request_id=nope")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	counts, _ := body["counts"].(map[string]any)
	if counts["audit"] != float64(0) || counts["api"] != float64(0) || counts["sys"] != float64(0) {
		t.Errorf("counts: got %v, want all 0", counts)
	}
}

func TestCorrelate_RequiresRequestID(t *testing.T) {
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	_, code := getJSON(t, NewReader(), "/correlate")
	if code != http.StatusBadRequest {
		t.Fatalf("missing request_id: got status %d, want 400", code)
	}
}

func TestCorrelate_ReportsStoreWhenPersisted(t *testing.T) {
	resetGlobals(t)
	adb, _ := sql.Open("sqlite", ":memory:")
	sdb, _ := sql.Open("sqlite", ":memory:")
	t.Cleanup(func() { adb.Close(); sdb.Close() })
	audit, _ := NewSQLiteStore(adb, "audit_corr3")
	apiStore, _ := NewStreamStore(sdb, "api_log")
	if err := Init(Config{ServiceID: "svc", NodeID: "node", AuditStore: audit, APIStore: apiStore}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	rid := "req-old"
	tr := GetTransport()
	tr.PushAPI(APIRow{"method": "GET", "path": "/x", "request_id": rid})
	for i := 0; i < 2500; i++ { // bury past ring capacity
		tr.PushAPI(APIRow{"method": "GET", "path": "/n", "request_id": "n"})
	}
	body, _ := getJSON(t, NewReader(), "/correlate?request_id="+rid)
	comp, _ := body["completeness"].(map[string]any)
	if comp["api"] != "store" {
		t.Errorf("api completeness: got %v, want store", comp["api"])
	}
	counts, _ := body["counts"].(map[string]any)
	if counts["api"] != float64(1) {
		t.Errorf("recovered past ring churn: got %v api rows, want 1", counts["api"])
	}
}
