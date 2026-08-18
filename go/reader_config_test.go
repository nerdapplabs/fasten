package fasten

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A reader bound to a separately-configured *Engine has its own search/persist
// policy and stores — the Go equivalent of Python's router(search_enabled=,
// persist_streams=, store=, transport=) overrides (A3 parity).
func TestPerEngineReaderConfig(t *testing.T) {
	registerTestCodes(t)
	// Default engine: search disabled.
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatal(err)
	}
	def := httptest.NewRecorder()
	NewReader().ServeHTTP(def, httptest.NewRequest(http.MethodGet, "/search?q=x&since=2020-01-01T00:00:00Z", nil))
	if body := def.Body.String(); !contains(body, "search disabled") {
		t.Fatalf("Default reader: expected search disabled, got %s", body)
	}

	// A second engine: search enabled + its own syslog store — independent reader.
	db, _ := sql.Open("sqlite", ":memory:")
	sysStore, err := NewStreamStore(db, "syslog")
	if err != nil {
		t.Fatal(err)
	}
	e2 := &Engine{}
	if err := e2.Init(Config{ServiceID: "svc2", NodeID: "node2", SearchEnabled: true, SyslogStore: sysStore}); err != nil {
		t.Fatal(err)
	}
	e2.GetTransport().PushSyslog(SyslogRow{"event": "db.timeout", "timestamp": "2026-08-01T00:00:00Z", "request_id": "r-1"})

	rec := httptest.NewRecorder()
	e2.NewReader().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/search?q=timeout&since=2020-01-01T00:00:00Z", nil))
	body := rec.Body.String()
	if contains(body, "search disabled") {
		t.Fatalf("e2 reader should have search enabled: %s", body)
	}
	if !contains(body, "r-1") {
		t.Fatalf("e2 reader search should find the persisted row: %s", body)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
