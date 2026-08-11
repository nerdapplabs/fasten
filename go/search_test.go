package fasten

import (
	"database/sql"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// FR3 — constrained free-text search over persisted sys history. sys-only,
// opt-in (SearchEnabled), since= mandatory, hard-capped, no ranking. A match
// carries request_id so a consumer can hand it to /correlate. Parity with the
// Python test_search.py contract.

const searchSince = "2026-01-01T00:00:00Z"

func initSearch(t *testing.T, enabled, withStore bool) {
	t.Helper()
	resetGlobals(t)
	cfg := Config{ServiceID: "svc", NodeID: "node", SearchEnabled: enabled}
	if withStore {
		db, err := sql.Open("sqlite", ":memory:")
		if err != nil {
			t.Fatalf("sql.Open: %v", err)
		}
		t.Cleanup(func() { db.Close() })
		ss, err := NewStreamStore(db, "syslog")
		if err != nil {
			t.Fatalf("NewStreamStore: %v", err)
		}
		cfg.SyslogStore = ss
	}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init: %v", err)
	}
}

func seedSearch() {
	tr := GetTransport()
	tr.PushSyslog(SyslogRow{"level": "error", "event": "db.timeout",
		"message": "connection reset by peer", "timestamp": "2026-08-01T00:00:00Z", "request_id": "r-1"})
	tr.PushSyslog(SyslogRow{"level": "info", "event": "ok",
		"timestamp": "2026-08-01T00:00:01Z", "request_id": "r-2"})
}

func errStr(body map[string]any) string {
	s, _ := body["error"].(string)
	return s
}

func TestSearch_DisabledByDefault(t *testing.T) {
	initSearch(t, false, true)
	seedSearch()
	body, _ := getJSON(t, NewReader(), "/search?q=reset&since="+searchSince)
	if !strings.Contains(errStr(body), "disabled") {
		t.Fatalf("want disabled error, got %v", body)
	}
}

func TestSearch_FindsRequestID(t *testing.T) {
	initSearch(t, true, true)
	seedSearch()
	body, _ := getJSON(t, NewReader(), "/search?q=reset+by+peer&since="+searchSince)
	counts, _ := body["counts"].(map[string]any)
	if counts["sys"] != float64(1) {
		t.Fatalf("counts=%v, want sys=1 (%v)", counts, body)
	}
	m := body["matches"].([]any)[0].(map[string]any)
	if m["stream"] != "sys" || m["request_id"] != "r-1" || m["summary"] != "db.timeout" {
		t.Errorf("match=%v, want sys/r-1/db.timeout", m)
	}
}

func TestSearch_CaseInsensitive(t *testing.T) {
	initSearch(t, true, true)
	seedSearch()
	body, _ := getJSON(t, NewReader(), "/search?q=RESET&since="+searchSince)
	if body["counts"].(map[string]any)["sys"] != float64(1) {
		t.Errorf("case-insensitive match failed: %v", body["counts"])
	}
}

func TestSearch_SinceMandatory(t *testing.T) {
	initSearch(t, true, true)
	seedSearch()
	body, _ := getJSON(t, NewReader(), "/search?q=reset")
	if !strings.Contains(errStr(body), "since") {
		t.Fatalf("want since-required error, got %v", body)
	}
}

func TestSearch_RequiresPersistence(t *testing.T) {
	initSearch(t, true, false) // ring-only sys — no durable history
	seedSearch()
	body, _ := getJSON(t, NewReader(), "/search?q=reset&since="+searchSince)
	if !strings.Contains(errStr(body), "persistence") {
		t.Fatalf("want persistence error, got %v", body)
	}
}

func TestSearch_ResultCap(t *testing.T) {
	initSearch(t, true, true)
	tr := GetTransport()
	for i := 0; i < 10; i++ {
		tr.PushSyslog(SyslogRow{"event": "boom",
			"timestamp": "2026-08-01T00:00:0" + string(rune('0'+i)) + "Z",
			"request_id": "r"})
	}
	body, _ := getJSON(t, NewReader(), "/search?q=boom&since="+searchSince+"&limit=3")
	if body["counts"].(map[string]any)["sys"] != float64(3) {
		t.Errorf("want capped to 3, got %v", body["counts"])
	}
}

func TestSearch_WildcardEscaped(t *testing.T) {
	initSearch(t, true, true)
	tr := GetTransport()
	tr.PushSyslog(SyslogRow{"event": "100%done", "timestamp": "2026-08-01T00:00:00Z", "request_id": "r-w"})
	tr.PushSyslog(SyslogRow{"event": "100XYZdone", "timestamp": "2026-08-01T00:00:02Z", "request_id": "r-x"})
	body, _ := getJSON(t, NewReader(), "/search?q=100%25done&since="+searchSince)
	if body["counts"].(map[string]any)["sys"] != float64(1) {
		t.Fatalf("literal %% should match only r-w, got %v", body["counts"])
	}
	if body["matches"].([]any)[0].(map[string]any)["request_id"] != "r-w" {
		t.Errorf("wrong match: %v", body["matches"])
	}
}

func TestSysQParamGatedAndBounded(t *testing.T) {
	initSearch(t, true, true)
	seedSearch()
	body, _ := getJSON(t, NewReader(), "/sys?q=timeout&since="+searchSince)
	rows, _ := body["rows"].([]any)
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d (%v)", len(rows), body)
	}
	noSince, _ := getJSON(t, NewReader(), "/sys?q=timeout")
	if !strings.Contains(errStr(noSince), "since") {
		t.Errorf("want since error on /sys?q= without since, got %v", noSince)
	}
}
