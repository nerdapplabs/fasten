package fasten

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// PR #59 finding 16 (phase0 restoration): /search accepts ?streams=
// comma-separated over {audit, api, sys} and fans out to each.

func initSearchFull(t *testing.T, withStores bool) {
	t.Helper()
	resetGlobals(t)
	registerTestCodes(t)
	cfg := Config{ServiceID: "svc", NodeID: "node", SearchEnabled: true}
	if withStores {
		adb, _ := sql.Open("sqlite", ":memory:")
		t.Cleanup(func() { adb.Close() })
		audit, err := NewSQLiteStore(adb, "audit_srch")
		if err != nil {
			t.Fatalf("NewSQLiteStore: %v", err)
		}
		cfg.AuditStore = audit
		cfg.AuditStoreFailureStrategy = "raise"

		sdb, _ := sql.Open("sqlite", ":memory:")
		t.Cleanup(func() { sdb.Close() })
		sys, err := NewStreamStore(sdb, "sys_srch")
		if err != nil {
			t.Fatalf("NewStreamStore(sys): %v", err)
		}
		cfg.SyslogStore = sys

		apdb, _ := sql.Open("sqlite", ":memory:")
		t.Cleanup(func() { apdb.Close() })
		api, err := NewStreamStore(apdb, "api_srch")
		if err != nil {
			t.Fatalf("NewStreamStore(api): %v", err)
		}
		cfg.APIStore = api
	}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init: %v", err)
	}
}

func TestSearchStreams_RejectsUnknown(t *testing.T) {
	initSearchFull(t, true)
	code := status(t, NewReader(), "/search?q=x&since="+searchSince+"&streams=sys,foo")
	if code != 400 {
		t.Fatalf("unknown stream must 400, got %d", code)
	}
}

func TestSearchStreams_ApiStream(t *testing.T) {
	initSearchFull(t, true)
	tr := GetTransport()
	tr.PushAPI(APIRow{"method": "POST", "path": "/checkout", "status": 502,
		"message": "gateway timeout on payment provider",
		"timestamp": "2026-08-01T00:00:00Z", "request_id": "r-api"})
	body, _ := getJSON(t, NewReader(),
		"/search?q=gateway&since="+searchSince+"&streams=api")
	counts, _ := body["counts"].(map[string]any)
	if counts["api"] != float64(1) {
		t.Fatalf("counts.api=%v, want 1 — matches=%v", counts["api"], body["matches"])
	}
	matches, _ := body["matches"].([]any)
	m := matches[0].(map[string]any)
	if m["stream"] != "api" || m["request_id"] != "r-api" {
		t.Errorf("wrong match: %v", m)
	}
	if !strings.Contains(m["summary"].(string), "POST /checkout") {
		t.Errorf("summary should include method+path: %q", m["summary"])
	}
}

func TestSearchStreams_AuditStream(t *testing.T) {
	initSearchFull(t, true)
	if _, err := Emit(context.Background(), "USER_CREATED",
		Target("u-99"), Actor("a", "user"),
		WithDetail(map[string]any{"message": "onboarding hit gateway timeout on retry"})); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	body, _ := getJSON(t, NewReader(),
		"/search?q=gateway&since="+searchSince+"&streams=audit")
	counts, _ := body["counts"].(map[string]any)
	if counts["audit"] != float64(1) {
		t.Fatalf("counts.audit=%v, want 1 (matches=%v)", counts["audit"], body["matches"])
	}
	matches, _ := body["matches"].([]any)
	m := matches[0].(map[string]any)
	if m["stream"] != "audit" || m["summary"] != "USER_CREATED" {
		t.Errorf("wrong audit match: %v", m)
	}
}

func TestSearchStreams_AllThreeFanOut(t *testing.T) {
	initSearchFull(t, true)
	tr := GetTransport()
	tr.PushSyslog(SyslogRow{"event": "cache.miss", "message": "cache miss on key foo",
		"timestamp": "2026-08-01T00:00:00Z", "request_id": "r-sys"})
	tr.PushAPI(APIRow{"method": "GET", "path": "/foo", "status": 200,
		"message": "hit for foo",
		"timestamp": "2026-08-01T00:00:01Z", "request_id": "r-api"})
	if _, err := Emit(context.Background(), "USER_CREATED",
		Target("u"), WithDetail(map[string]any{"note": "foo did it"})); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	body, _ := getJSON(t, NewReader(),
		"/search?q=foo&since="+searchSince+"&streams=audit,api,sys")
	counts, _ := body["counts"].(map[string]any)
	if counts["sys"] != float64(1) || counts["api"] != float64(1) || counts["audit"] != float64(1) {
		t.Fatalf("counts=%v, want {sys:1, api:1, audit:1}", counts)
	}
	// Stable stream order in matches: sys → api → audit (mirrors /correlate).
	matches, _ := body["matches"].([]any)
	got := []string{}
	for _, m := range matches {
		got = append(got, m.(map[string]any)["stream"].(string))
	}
	want := []string{"sys", "api", "audit"}
	for i, s := range want {
		if got[i] != s {
			t.Errorf("stream order mismatch at %d: got %v, want %v", i, got, want)
			break
		}
	}
}

func TestSearchStreams_MissingStorePerStreamError(t *testing.T) {
	// syslog store attached, api store not — ?streams=api reports errors.api
	// rather than a silent counts.api=0.
	resetGlobals(t)
	registerTestCodes(t)
	sdb, _ := sql.Open("sqlite", ":memory:")
	t.Cleanup(func() { sdb.Close() })
	sys, _ := NewStreamStore(sdb, "sys_partial")
	if err := Init(Config{ServiceID: "svc", NodeID: "node",
		SearchEnabled: true, SyslogStore: sys}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	body, _ := getJSON(t, NewReader(),
		"/search?q=x&since="+searchSince+"&streams=sys,api")
	counts, _ := body["counts"].(map[string]any)
	if counts["api"] != float64(0) {
		t.Errorf("counts.api=%v, want 0", counts["api"])
	}
	errs, _ := body["errors"].(map[string]any)
	msg, _ := errs["api"].(string)
	if !strings.Contains(msg, "persistence") {
		t.Errorf("errors.api should mention persistence; got %q", msg)
	}
}
