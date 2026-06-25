package fasten

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "modernc.org/sqlite"
)

// FR4 (Phase 0): every /logs read reports, per stream, whether its rows came
// from the durable store or a bounded ring. With persistence still off (the
// default), audit is served from the store and api/sys from rings.

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
// (FR1) flips: once a stream is marked persisted, its reads report "store".
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

func mapHasKey(m map[string]any, key string) bool {
	_, ok := m[key]
	return ok
}
