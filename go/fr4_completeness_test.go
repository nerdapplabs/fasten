package fasten

import (
	"context"
	"database/sql"
	"testing"
)

// TestStoreDegradedStickyThroughSuccessfulWrite covers FR4-2: a store that has
// gone store-degraded must STAY degraded after a later successful write — the
// hole in durable history does not heal. The existing degrade test closes the
// sink and asserts once; it never drives a successful write afterwards, so a
// regression that reset the flag on a healthy insert would pass unnoticed.
func TestStoreDegradedStickyThroughSuccessfulWrite(t *testing.T) {
	registerTestCodes(t)
	apiDB, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open(api): %v", err)
	}
	t.Cleanup(func() { apiDB.Close() })
	apiStore, err := NewStreamStore(apiDB, "api_sticky")
	if err != nil {
		t.Fatalf("NewStreamStore: %v", err)
	}
	auditDB, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open(audit): %v", err)
	}
	t.Cleanup(func() { auditDB.Close() })
	auditStore, err := NewSQLiteStore(auditDB, "audit_sticky")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	if err := Init(Config{ServiceID: "svc", NodeID: "node", AuditStore: auditStore, APIStore: apiStore}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	tr := GetTransport()

	if got := Default.streamSource("api"); got != "store" {
		t.Fatalf("healthy api=%q, want store", got)
	}
	// A swallowed persist failure degrades the stream.
	apiStore.NoteWriteFailure()
	if got := Default.streamSource("api"); got != "store-degraded" {
		t.Fatalf("after failure api=%q, want store-degraded", got)
	}
	// Sink recovers: a subsequent SUCCESSFUL write must NOT clear the flag.
	tr.PushAPI(APIRow{"method": "GET", "path": "/kept", "request_id": "r2"})
	if n := apiStore.WriteFailures(); n != 1 {
		t.Fatalf("a successful write must not add a failure; WriteFailures=%d, want 1", n)
	}
	if !apiStore.Degraded() {
		t.Fatal("degraded must stay true after a successful write (sticky)")
	}
	if got := Default.streamSource("api"); got != "store-degraded" {
		t.Fatalf("after recovery api=%q, want store-degraded (sticky)", got)
	}
	// The recovered row is present — history keeps growing, the earlier hole stays.
	body, _ := getJSON(t, NewReader(), "/api")
	if rows, _ := body["rows"].([]any); len(rows) != 1 {
		t.Fatalf("want 1 persisted row after recovery, got %d", len(rows))
	}
}

// TestCorrelateMixedDurabilityClasses covers FR4-3: /correlate must report each
// stream's own durability class when they differ. Every other test uses a
// uniform class; nothing pinned the mixed composition.
func TestCorrelateMixedDurabilityClasses(t *testing.T) {
	registerTestCodes(t)
	auditDB, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open(audit): %v", err)
	}
	t.Cleanup(func() { auditDB.Close() })
	auditStore, err := NewSQLiteStore(auditDB, "audit_mix")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	apiDB, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open(api): %v", err)
	}
	t.Cleanup(func() { apiDB.Close() })
	apiStore, err := NewStreamStore(apiDB, "api_mix")
	if err != nil {
		t.Fatalf("NewStreamStore: %v", err)
	}
	// audit -> store, api -> store-degraded, sys -> ring (no sys store).
	if err := Init(Config{ServiceID: "svc", NodeID: "node", AuditStore: auditStore, APIStore: apiStore}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	apiStore.NoteWriteFailure()

	body, _ := getJSON(t, NewReader(), "/correlate?request_id=r1")
	comp, _ := body["completeness"].(map[string]any)
	if comp["audit"] != "store" || comp["api"] != "store-degraded" || comp["sys"] != "ring" {
		t.Fatalf("mixed completeness = %v, want audit=store api=store-degraded sys=ring", comp)
	}
}

// TestCorrelateTruncatedFlag covers FR4-4: /correlate exposes a per-stream
// truncated boolean (counts < totals) so callers don't re-derive it.
func TestCorrelateTruncatedFlag(t *testing.T) {
	registerTestCodes(t)
	auditDB, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { auditDB.Close() })
	auditStore, err := NewSQLiteStore(auditDB, "audit_trunc")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	if err := Init(Config{ServiceID: "svc", NodeID: "node", AuditStore: auditStore, AuditStoreFailureStrategy: "raise"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	ctx := WithRequestID(context.Background(), "rq")
	for i := 0; i < 3; i++ {
		if _, err := Emit(ctx, "USER_CREATED", Target("u"), Actor("a", "user")); err != nil {
			t.Fatalf("Emit: %v", err)
		}
	}
	// limit 2 of 3 matching -> truncated.audit true.
	body, _ := getJSON(t, NewReader(), "/correlate?request_id=rq&limit=2")
	if tr, _ := body["truncated"].(map[string]any); tr["audit"] != true {
		t.Fatalf("limit=2: truncated.audit=%v, want true (counts 2 < totals 3)", body["truncated"])
	}
	// limit 10 -> not truncated.
	body2, _ := getJSON(t, NewReader(), "/correlate?request_id=rq&limit=10")
	if tr, _ := body2["truncated"].(map[string]any); tr["audit"] != false {
		t.Fatalf("limit=10: truncated.audit=%v, want false", body2["truncated"])
	}
}
