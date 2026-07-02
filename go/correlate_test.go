package fasten

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
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

func TestCorrelate_TotalsExposeTruncationRingOnly(t *testing.T) {
	// counts reflects the capped response; totals reflects what the backing
	// source holds — counts < totals is the truncation signal (100-of-100 vs
	// 100-of-5000 was previously indistinguishable).
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	rid := "req-hot"
	tr := GetTransport()
	for i := 0; i < 7; i++ {
		tr.PushSyslog(SyslogRow{"level": "info", "event": fmt.Sprintf("step.%d", i), "request_id": rid})
	}

	body, _ := getJSON(t, NewReader(), "/correlate?request_id="+rid+"&limit=3")
	counts, _ := body["counts"].(map[string]any)
	totals, _ := body["totals"].(map[string]any)
	if counts["sys"] != float64(3) {
		t.Errorf("counts.sys: got %v, want 3", counts["sys"])
	}
	if totals["sys"] != float64(7) {
		t.Errorf("totals.sys: got %v, want 7 (truncated: 3 returned of 7)", totals["sys"])
	}

	// untruncated read: counts == totals
	body, _ = getJSON(t, NewReader(), "/correlate?request_id="+rid+"&limit=100")
	counts, _ = body["counts"].(map[string]any)
	totals, _ = body["totals"].(map[string]any)
	if counts["sys"] != float64(7) || totals["sys"] != float64(7) {
		t.Errorf("untruncated: counts.sys=%v totals.sys=%v, want both 7", counts["sys"], totals["sys"])
	}
}

func TestCorrelate_TotalsCountStoreHistoryAndAudit(t *testing.T) {
	// With persistence on, totals counts durable history for the streams AND
	// the audit store (via CountFiltered) — every stream reports total vs
	// returned.
	resetGlobals(t)
	registerTestCodes(t)
	adb, _ := sql.Open("sqlite", ":memory:")
	t.Cleanup(func() { adb.Close() })
	audit, _ := NewSQLiteStore(adb, "audit_corr4")
	apiStore := newStreamStore(t, "api_log")
	if err := Init(Config{ServiceID: "svc", NodeID: "node", AuditStore: audit, APIStore: apiStore, AuditStoreFailureStrategy: "raise"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	rid := "req-deep"
	tr := GetTransport()
	for i := 0; i < 5; i++ {
		tr.PushAPI(APIRow{"method": "GET", "path": "/x", "request_id": rid})
	}
	ctx := WithRequestID(context.Background(), rid)
	if _, err := Emit(ctx, "USER_CREATED", Target("u-1"), Actor("alice", "user")); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if _, err := Emit(ctx, "USER_CREATED", Target("u-2"), Actor("alice", "user")); err != nil {
		t.Fatalf("Emit: %v", err)
	}

	body, _ := getJSON(t, NewReader(), "/correlate?request_id="+rid+"&limit=2")
	counts, _ := body["counts"].(map[string]any)
	totals, _ := body["totals"].(map[string]any)
	if counts["audit"] != float64(2) || counts["api"] != float64(2) || counts["sys"] != float64(0) {
		t.Errorf("counts: got %v, want audit=2 api=2 sys=0", counts)
	}
	if totals["api"] != float64(5) {
		t.Errorf("totals.api: got %v, want 5", totals["api"])
	}
	if totals["audit"] != float64(2) {
		t.Errorf("totals.audit: got %v, want 2", totals["audit"])
	}
	if totals["sys"] != float64(0) {
		t.Errorf("totals.sys: got %v, want 0", totals["sys"])
	}
}
