package fasten

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "modernc.org/sqlite"
)

// Every /logs read reports, per stream, whether that stream is backed by the
// durable store or a bounded ring. With persistence still off (the default),
// audit is classified as store-backed and api/sys as ring-backed.

// getCompleteness drives one reader route and returns its completeness map.
func getCompleteness(t *testing.T, h http.Handler, path string) (map[string]any, map[string]string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: status %d, body %s", path, rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("%s: decode body: %v", path, err)
	}
	raw, ok := body["completeness"].(map[string]any)
	if !ok {
		t.Fatalf("%s: response missing completeness map, got %v", path, body)
	}
	comp := make(map[string]string, len(raw))
	for k, v := range raw {
		comp[k], _ = v.(string)
	}
	return body, comp
}

func TestCompleteness_DefaultStoreVsRing(t *testing.T) {
	resetGlobals(t)
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := NewSQLiteStore(db, "audit_completeness_test")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	if err := Init(Config{ServiceID: "svc", NodeID: "node", AuditStore: store}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	h := NewReader()

	cases := []struct {
		path, stream, want string
	}{
		{"/sys", "sys", "ring"},
		{"/api", "api", "ring"},
		{"/audit", "audit", "store"},
	}
	for _, c := range cases {
		body, comp := getCompleteness(t, h, c.path)
		if comp[c.stream] != c.want {
			t.Errorf("%s: completeness[%q] = %q, want %q", c.path, c.stream, comp[c.stream], c.want)
		}
		// Additive only: pre-existing keys must survive.
		if _, ok := body["rows"]; !ok {
			t.Errorf("%s: response lost 'rows' key: %v", c.path, body)
		}
	}
	// Audit's pagination cursor key must still be present alongside completeness.
	if body, _ := getCompleteness(t, h, "/audit"); !mapHasKey(body, "next_after") {
		t.Errorf("/audit: response lost 'next_after' key")
	}
}

// TestCompleteness_FollowsPersistedStreams pins the resolver seam Phase 1
// flips: once a stream is marked persisted, its reads report "store".
func TestCompleteness_FollowsPersistedStreams(t *testing.T) {
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if got := Default.streamSource("api"); got != "ring" {
		t.Fatalf("api before persist: got %q, want ring", got)
	}
	Default.persistedStreams["api"] = true
	if got := Default.streamSource("api"); got != "store" {
		t.Fatalf("api after persist: got %q, want store", got)
	}
}

// TestCompleteness_StdoutOnlyAuditIsRing mirrors Python's
// test_stdout_only_audit_reports_ring: Init'd without an audit store
// (stdout-only mode), audit is not durable, so its completeness is "ring". The
// reader must not advertise a store that was never configured.
func TestCompleteness_StdoutOnlyAuditIsRing(t *testing.T) {
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil { // no AuditStore
		t.Fatalf("Init: %v", err)
	}
	if got := Default.streamSource("audit"); got != "ring" {
		t.Errorf("stdout-only audit: got %q, want ring", got)
	}
	_, comp := getCompleteness(t, NewReader(), "/audit")
	if comp["audit"] != "ring" {
		t.Errorf("stdout-only /audit completeness: got %q, want ring", comp["audit"])
	}
}

// TestCompleteness_ErrorPathsCarryFlag is the parity for Python's
// test_completeness_present_on_uninitialised_reads: a never-Init'd engine
// still emits the flag (plus an error) on every endpoint, so consumers parse
// one uniform shape. With no audit store configured, audit is honestly "ring" —
// it must not claim a durable "store" while erroring that nothing is stored.
// This also exercises the nil-map path through the HTTP layer — a fresh engine
// has persistedStreams == nil.
func TestCompleteness_ErrorPathsCarryFlag(t *testing.T) {
	h := (&Engine{}).NewReader() // never Init'd: xport, auditStore, persistedStreams all nil

	cases := []struct {
		path, stream, want string
	}{
		{"/sys", "sys", "ring"},
		{"/api", "api", "ring"},
		{"/audit", "audit", "ring"},
	}
	for _, c := range cases {
		body, comp := getCompleteness(t, h, c.path)
		if comp[c.stream] != c.want {
			t.Errorf("%s (uninitialised): completeness[%q] = %q, want %q", c.path, c.stream, comp[c.stream], c.want)
		}
		if _, ok := body["error"]; !ok {
			t.Errorf("%s (uninitialised): expected an 'error' key alongside completeness, got %v", c.path, body)
		}
	}
}

// TestCompleteness_NilMap pins the streamSource path that fires when the engine
// was never Init'd (persistedStreams == nil): with no store configured, every
// stream — audit included — resolves to "ring". Indexing a nil map yields false,
// so no stream is claimed durable.
func TestCompleteness_NilMap(t *testing.T) {
	e := &Engine{} // persistedStreams == nil
	if got := e.streamSource("audit"); got != "ring" {
		t.Errorf("nil-map audit: got %q, want ring", got)
	}
	if got := e.streamSource("api"); got != "ring" {
		t.Errorf("nil-map api: got %q, want ring", got)
	}
}

// TestCompleteness_RequestIDFilterCoexists proves the added completeness field
// did not shadow the pre-existing request_id query param: filtering the api
// ring still narrows rows, and the flag is still present on the filtered read.
func TestCompleteness_RequestIDFilterCoexists(t *testing.T) {
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	tr := Default.GetTransport()
	tr.PushAPI(APIRow{"method": "GET", "path": "/a", "request_id": "req-A"})
	tr.PushAPI(APIRow{"method": "GET", "path": "/b", "request_id": "req-B"})

	body, comp := getCompleteness(t, NewReader(), "/api?request_id=req-A")
	rows, _ := body["rows"].([]any)
	if len(rows) != 1 {
		t.Fatalf("request_id filter: got %d rows, want 1 (%v)", len(rows), body["rows"])
	}
	if row, _ := rows[0].(map[string]any); row["request_id"] != "req-A" {
		t.Errorf("request_id filter: row = %v, want request_id req-A", rows[0])
	}
	if comp["api"] != "ring" {
		t.Errorf("filtered read lost completeness: got %v", comp)
	}
}

func mapHasKey(m map[string]any, key string) bool {
	_, ok := m[key]
	return ok
}
