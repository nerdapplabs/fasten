package fasten

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"

	_ "modernc.org/sqlite"
)

// FR1 — opt-in persistence for the api/sys streams. When a StreamStore is
// attached the ring stays the hot write path and the store is a write-through
// sink; reads come from the store (durable history) and the completeness flag
// flips ring -> store. With no store, behaviour is unchanged (ring-only).

func newStreamStore(t *testing.T, table string) *StreamStore {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s, err := NewStreamStore(db, table)
	if err != nil {
		t.Fatalf("NewStreamStore: %v", err)
	}
	return s
}

func TestStreamStore_RoundtripAndFilter(t *testing.T) {
	s := newStreamStore(t, "api_log")
	must(t, s.Insert(map[string]any{"method": "POST", "path": "/v1/checkout", "status": 502, "request_id": "r-A"}))
	must(t, s.Insert(map[string]any{"method": "GET", "path": "/v1/health", "status": 200, "request_id": "r-B"}))

	all, err := s.Query(100, nil)
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	// newest-first
	if got := []string{all[0]["request_id"].(string), all[1]["request_id"].(string)}; got[0] != "r-B" || got[1] != "r-A" {
		t.Fatalf("order: got %v, want [r-B r-A]", got)
	}
	// request_id filter
	one, _ := s.Query(100, map[string]string{"request_id": "r-A"})
	if len(one) != 1 || one[0]["path"] != "/v1/checkout" {
		t.Fatalf("request_id filter: got %v", one)
	}
}

func TestStreamStore_SurvivesBeyondRingCapacity(t *testing.T) {
	s := newStreamStore(t, "syslog")
	for i := 0; i < 5000; i++ {
		must(t, s.Insert(map[string]any{"level": "info", "event": fmt.Sprintf("e%d", i), "request_id": fmt.Sprintf("r-%d", i)}))
	}
	if n, _ := s.Count(); n != 5000 {
		t.Fatalf("count: got %d, want 5000", n)
	}
	// a request_id from long before a 2000-row ring would still hold
	old, _ := s.Query(100, map[string]string{"request_id": "r-0"})
	if len(old) != 1 {
		t.Fatalf("old request_id: got %d rows, want 1", len(old))
	}
}

func TestStreamStore_APIPersistedReportsStoreAndServesFromStore(t *testing.T) {
	resetGlobals(t)
	store := newStreamStore(t, "api_log")
	if err := Init(Config{ServiceID: "svc", NodeID: "node", APIStore: store}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if got := Default.streamSource("api"); got != "store" {
		t.Fatalf("api source: got %q, want store", got)
	}
	GetTransport().PushAPI(APIRow{"method": "POST", "path": "/v1/checkout", "status": 502, "request_id": "r-1"})

	body, comp := getCompleteness(t, NewReader(), "/api?request_id=r-1")
	if comp["api"] != "store" {
		t.Errorf("completeness flipped? got %v", comp)
	}
	rows, _ := body["rows"].([]any)
	if len(rows) != 1 {
		t.Fatalf("served from store: got %d rows, want 1", len(rows))
	}
}

func TestStreamStore_SysPersistedDepthBeyondRing(t *testing.T) {
	resetGlobals(t)
	store := newStreamStore(t, "syslog")
	if err := Init(Config{ServiceID: "svc", NodeID: "node", SyslogStore: store}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	tr := GetTransport()
	for i := 0; i < 3000; i++ { // > default ring maxlen (2000)
		tr.PushSyslog(SyslogRow{"level": "error", "event": "db.timeout", "request_id": fmt.Sprintf("r-%d", i)})
	}
	body, comp := getCompleteness(t, NewReader(), "/sys?request_id=r-0")
	if comp["sys"] != "store" {
		t.Errorf("sys source: got %v, want store", comp)
	}
	if rows, _ := body["rows"].([]any); len(rows) != 1 {
		t.Fatalf("survived ring churn: got %d rows, want 1", len(rows))
	}
}

func TestStreamStore_UnpersistedStaysRing(t *testing.T) {
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil { // audit only
		t.Fatalf("Init: %v", err)
	}
	GetTransport().PushAPI(APIRow{"method": "GET", "path": "/x", "request_id": "r-9"})
	body, comp := getCompleteness(t, NewReader(), "/api")
	if comp["api"] != "ring" {
		t.Errorf("unpersisted api: got %v, want ring", comp)
	}
	if rows, _ := body["rows"].([]any); len(rows) != 1 {
		t.Fatalf("served from ring: got %d rows, want 1", len(rows))
	}
}

func TestStreamStore_WriteThroughKeepsRingAndStoreInSync(t *testing.T) {
	resetGlobals(t)
	store := newStreamStore(t, "api_log")
	if err := Init(Config{ServiceID: "svc", NodeID: "node", APIStore: store}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	tr := GetTransport()
	tr.PushAPI(APIRow{"method": "GET", "path": "/y", "request_id": "r-7"})

	if n, _ := store.Count(); n != 1 {
		t.Errorf("store write-through: got %d, want 1", n)
	}
	if tr.API.Len() != 1 {
		t.Errorf("ring hot-path: got %d, want 1", tr.API.Len())
	}
}

// roundtrip sanity for the JSON shape returned by the reader
func TestStreamStore_StoredRowMatchesPushed(t *testing.T) {
	s := newStreamStore(t, "api_log")
	in := map[string]any{"method": "PUT", "path": "/v1/x", "status": 204, "request_id": "r-z", "extra": "kept"}
	must(t, s.Insert(in))
	out, _ := s.Query(1, nil)
	b1, _ := json.Marshal(in)
	b2, _ := json.Marshal(out[0])
	// status round-trips through JSON as float64; compare via re-marshal of normalised maps
	var m1, m2 map[string]any
	_ = json.Unmarshal(b1, &m1)
	_ = json.Unmarshal(b2, &m2)
	if fmt.Sprint(m1) != fmt.Sprint(m2) {
		t.Fatalf("row not byte-stable: in=%v out=%v", m1, m2)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
