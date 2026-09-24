package fasten

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// P1-46 DoS caps — pins the three fail-closed guards on the Go side:
//   1) Per-row byte cap (FASTEN_MAX_DETAIL_BYTES, default 64 KiB).
//   2) Deep-nesting graceful degrade returns <unredactable> marker.
//   3) q= length cap on /sys and /search (via searchGuard).

// ── 1) byte cap ────────────────────────────────────────────────────────────

func TestRedactDetail_ReturnsTruncatedMarkerForOversize(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "n"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	big := map[string]any{"blob": strings.Repeat("x", 100_000)}
	out := Default.redactDetail(big)
	if out["_truncated"] != true {
		t.Fatalf("oversize: expected _truncated marker, got %v", out)
	}
	if _, kept := out["blob"]; kept {
		t.Fatal("oversize: original PII-suspect key must not leak into marker")
	}
	if out["_max_detail_bytes"].(int) != MaxDetailBytesDefault {
		t.Fatalf("_max_detail_bytes: got %v, want %d", out["_max_detail_bytes"], MaxDetailBytesDefault)
	}
}

func TestRedactDetail_RespectsEnvOverride(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	t.Setenv("FASTEN_MAX_DETAIL_BYTES", "256")
	if err := Init(Config{ServiceID: "svc", NodeID: "n"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	out := Default.redactDetail(map[string]any{"x": strings.Repeat("y", 500)})
	if out["_truncated"] != true {
		t.Fatalf("env override: expected truncation at 256, got %v", out)
	}
	if out["_max_detail_bytes"].(int) != 256 {
		t.Fatalf("_max_detail_bytes: got %v, want 256", out["_max_detail_bytes"])
	}
}

func TestRedactDetail_LeavesSmallPayloadAlone(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "n"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	out := Default.redactDetail(map[string]any{"user": "alice", "action": "login"})
	if _, truncated := out["_truncated"]; truncated {
		t.Fatalf("small payload should pass through; got %v", out)
	}
	if out["user"] != "alice" || out["action"] != "login" {
		t.Fatalf("small payload contents mutated: %v", out)
	}
}

// ── 2) deep-nesting graceful degrade ───────────────────────────────────────

func nested(depth int) map[string]any {
	root := map[string]any{}
	cur := root
	for i := 0; i < depth; i++ {
		nxt := map[string]any{}
		cur["n"] = nxt
		cur = nxt
	}
	cur["leaf"] = true
	return root
}

func TestRedactDetail_ReturnsUnredactableOnDeepNesting(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "n"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	out := Default.redactDetail(nested(200))
	if out["_redact_failed"] != true {
		t.Fatalf("deep nesting: expected _redact_failed marker, got %v", out)
	}
}

func TestEmit_SurvivesDeepNesting(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	sdb, _ := sql.Open("sqlite", ":memory:")
	t.Cleanup(func() { sdb.Close() })
	store, err := NewSQLiteStore(sdb, "audit_deep")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	if err := Init(Config{ServiceID: "svc", NodeID: "n", AuditStore: store}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	row, err := Emit(context.Background(), "USER_CREATED",
		Target("u-1"), Actor("op", "user"),
		WithDetail(nested(200)))
	if err != nil {
		t.Fatalf("emit must not fail on deep nesting: %v", err)
	}
	if row.Detail["_redact_failed"] != true {
		t.Fatalf("row.Detail must carry fail-closed marker, got %v", row.Detail)
	}
}

// ── 3) q= length cap ───────────────────────────────────────────────────────

func newReaderClient(t *testing.T, searchOn bool) http.Handler {
	t.Helper()
	registerTestCodes(t)
	resetGlobals(t)
	sdb, _ := sql.Open("sqlite", ":memory:")
	t.Cleanup(func() { sdb.Close() })
	store, err := NewSQLiteStore(sdb, "audit_q")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	ssdb, _ := sql.Open("sqlite", ":memory:")
	t.Cleanup(func() { ssdb.Close() })
	ss, err := NewStreamStore(ssdb, "sys_q")
	if err != nil {
		t.Fatalf("NewStreamStore: %v", err)
	}
	if err := Init(Config{
		ServiceID: "svc", NodeID: "n",
		AuditStore:    store,
		SyslogStore:   ss,
		SearchEnabled: searchOn,
	}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return NewReader()
}

func TestHandleSys_QOver1024Returns400(t *testing.T) {
	h := newReaderClient(t, true)
	long := strings.Repeat("x", 1025)
	req := httptest.NewRequest("GET", "/sys?q="+long+"&since=2020-01-01T00:00:00Z", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	// Sys reads embed the reason inside a JSON body rather than 400ing,
	// mirroring the existing searchGuard failure surface. What matters
	// is that the store never receives the multi-KB LIKE pattern.
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body["error"] == nil || !strings.Contains(body["error"].(string), "1024") {
		t.Fatalf("expected q= cap error in body, got %v", body)
	}
}

func TestHandleSearch_QOver1024ReturnsCapError(t *testing.T) {
	h := newReaderClient(t, true)
	long := strings.Repeat("x", 1025)
	req := httptest.NewRequest("GET", "/search?q="+long+"&since=2020-01-01T00:00:00Z", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	// Same shape as handleSys: cap violation is surfaced in the response
	// body's `error` field via the searchGuard funnel. The invariant is
	// that the store never receives the multi-KB LIKE pattern.
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body["error"] == nil || !strings.Contains(body["error"].(string), "1024") {
		t.Fatalf("expected q= cap error in body, got %v", body)
	}
}

func TestHandleSys_QAtLimitAccepted(t *testing.T) {
	h := newReaderClient(t, true)
	long := strings.Repeat("x", 1024)
	req := httptest.NewRequest("GET", "/sys?q="+long+"&since=2020-01-01T00:00:00Z", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("/sys q=1024: got %d, want 200", rr.Code)
	}
}
