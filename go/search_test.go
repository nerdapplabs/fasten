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
	// Per-stream error since #16 restoration — a global "error" key is only
	// for policy failures (search-disabled, since-missing); ring-only stream
	// reports errors.sys.
	perStream, _ := body["errors"].(map[string]any)
	msg, _ := perStream["sys"].(string)
	if !strings.Contains(msg, "persistence") {
		t.Fatalf("want per-stream persistence error, got %v", body)
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

func TestSearch_WildcardEscapedUnderscore(t *testing.T) {
	// `_` is the single-char LIKE wildcard; it must be escaped to match literally.
	initSearch(t, true, true)
	tr := GetTransport()
	tr.PushSyslog(SyslogRow{"event": "ab_cd", "timestamp": "2026-08-01T00:00:00Z", "request_id": "r-u"})
	tr.PushSyslog(SyslogRow{"event": "abXcd", "timestamp": "2026-08-01T00:00:02Z", "request_id": "r-x"})
	body, _ := getJSON(t, NewReader(), "/search?q=ab_cd&since="+searchSince)
	if body["counts"].(map[string]any)["sys"] != float64(1) {
		t.Fatalf("literal _ should match only r-u (not abXcd), got %v", body["counts"])
	}
	if body["matches"].([]any)[0].(map[string]any)["request_id"] != "r-u" {
		t.Errorf("wrong match: %v", body["matches"])
	}
}

func TestSearch_BackslashEscaped(t *testing.T) {
	// `\` is the ESCAPE char; it must be escaped so it is matched as data. The
	// event c\d (one backslash) is stored as c\\d in the JSON payload, so the
	// query carries two backslashes (%5C%5C).
	initSearch(t, true, true)
	tr := GetTransport()
	tr.PushSyslog(SyslogRow{"event": "c\\d", "timestamp": "2026-08-01T00:00:00Z", "request_id": "r-bs"})
	tr.PushSyslog(SyslogRow{"event": "cXd", "timestamp": "2026-08-01T00:00:02Z", "request_id": "r-dec"})
	body, _ := getJSON(t, NewReader(), "/search?q=c%5C%5Cd&since="+searchSince)
	if body["counts"].(map[string]any)["sys"] != float64(1) {
		t.Fatalf("backslashes matched literally should give only r-bs, got %v", body["counts"])
	}
	if body["matches"].([]any)[0].(map[string]any)["request_id"] != "r-bs" {
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

// TestSysQParamRejectsStructuredFilterCombination (PR #59 finding 6):
// /sys?q=... combined with a structured filter (level/request_id/service_id/
// event) must 400, not silently discard the filter. Matches /api?q= policy.
func TestSysQParamRejectsStructuredFilterCombination(t *testing.T) {
	initSearch(t, true, true)
	seedSearch()
	for _, param := range []string{"level=error", "request_id=r-1", "service_id=svc", "event=db.timeout"} {
		url := "/sys?q=timeout&since=" + searchSince + "&" + param
		body, code := getJSON(t, NewReader(), url)
		if code != 400 {
			t.Errorf("%s: want 400, got %d (%v)", url, code, body)
		}
	}
}
