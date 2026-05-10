package fasten

import (
	"context"
	"strings"
	"testing"
)

// resetGlobals restores Default engine state after each test.
func resetGlobals(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		Default.ResetForTests()
	})
}

// registerTestCodes registers USER_CREATED and USER_DELETED once per test.
func registerTestCodes(t *testing.T) {
	t.Helper()
	clearBothRegistries()
	t.Cleanup(clearBothRegistries)
	MustRegister("user", map[Code]Meta{
		"USER_CREATED": {
			Domain:         "user",
			Category:       "account",
			Action:         "create",
			Severity:       SevInfo,
			Description:    "test",
			Emitter:        "test",
			RetentionClass: RetShort,
		},
		"USER_DELETED": {
			Domain:         "user",
			Category:       "account",
			Action:         "delete",
			Severity:       SevWarn,
			Description:    "test",
			Emitter:        "test",
			RetentionClass: RetLong,
		},
	})
}

// ── Init ──────────────────────────────────────────────────────────────────

func TestInit_RequiresServiceID(t *testing.T) {
	resetGlobals(t)
	if err := Init(Config{NodeID: "node-1"}); err == nil {
		t.Fatal("expected error when ServiceID is empty")
	}
}

func TestInit_RequiresNodeID(t *testing.T) {
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc-1"}); err == nil {
		t.Fatal("expected error when NodeID is empty")
	}
}

func TestInit_Success(t *testing.T) {
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc-1", NodeID: "node-1"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if GetTransport() == nil {
		t.Fatal("transport should be non-nil after Init")
	}
}

// ── Register ─────────────────────────────────────────────────────────────

func TestRegister_Duplicate(t *testing.T) {
	registerTestCodes(t)
	err := Register("user", map[Code]Meta{
		"USER_CREATED": {Domain: "user", Category: "account", Action: "create", Severity: SevInfo},
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate error, got %v", err)
	}
}

func TestRegister_DomainMismatch(t *testing.T) {
	clearBothRegistries()
	t.Cleanup(clearBothRegistries)

	err := Register("user", map[Code]Meta{
		"MY_CODE": {Domain: "other", Category: "test", Action: "do", Severity: SevInfo},
	})
	if err == nil || !strings.Contains(err.Error(), "domain") {
		t.Fatalf("expected domain mismatch error, got %v", err)
	}
}

// P1-10: ID is filled from the map key when omitted.
func TestRegister_FillsIDFromKey(t *testing.T) {
	clearBothRegistries()
	t.Cleanup(clearBothRegistries)

	if err := Register("svc", map[Code]Meta{
		"P1_10_FILLED": {Domain: "svc", Category: "x", Action: "x", Severity: SevInfo},
	}); err != nil {
		t.Fatalf("register failed: %v", err)
	}
	m, ok := metaOf("P1_10_FILLED")
	if !ok || m.ID != "P1_10_FILLED" {
		t.Fatalf("Meta.ID not filled from key: ok=%v id=%q", ok, m.ID)
	}
}

// P1-10: explicit ID that disagrees with map key raises.
func TestRegister_IDMismatchRaises(t *testing.T) {
	clearBothRegistries()
	t.Cleanup(clearBothRegistries)

	err := Register("svc", map[Code]Meta{
		"P1_10_MISMATCH": {ID: "WRONG_ID", Domain: "svc", Severity: SevInfo},
	})
	if err == nil || !strings.Contains(err.Error(), "disagrees") {
		t.Fatalf("expected ID-mismatch error, got %v", err)
	}
}

// P1-10: lowercase / invalid key is rejected.
func TestRegister_InvalidKeyShape(t *testing.T) {
	clearBothRegistries()

	err := Register("svc", map[Code]Meta{
		"lowercase_bad": {Domain: "svc", Severity: SevInfo},
	})
	if err == nil || !strings.Contains(err.Error(), "UPPER_SNAKE_CASE") {
		t.Fatalf("expected key-shape error, got %v", err)
	}
}

// ── Emit ──────────────────────────────────────────────────────────────────

func TestEmit_RequiresInit(t *testing.T) {
	resetGlobals(t)
	registerTestCodes(t)
	_, err := Emit(context.Background(), "USER_CREATED", Target("u-1"))
	if err == nil || !strings.Contains(err.Error(), "Init") {
		t.Fatalf("expected init error, got %v", err)
	}
}

func TestEmit_UnknownCode(t *testing.T) {
	resetGlobals(t)
	registerTestCodes(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatal(err)
	}
	_, err := Emit(context.Background(), "UNKNOWN_CODE", Target("u-1"))
	if err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("expected unknown code error, got %v", err)
	}
}

func TestEmit_Roundtrip(t *testing.T) {
	resetGlobals(t)
	registerTestCodes(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node-1"}); err != nil {
		t.Fatal(err)
	}
	row, err := Emit(context.Background(), "USER_CREATED", Target("u-42"), Actor("alice", "user"))
	if err != nil {
		t.Fatalf("emit failed: %v", err)
	}
	if row.Code != "USER_CREATED" {
		t.Errorf("code = %q, want USER_CREATED", row.Code)
	}
	if row.Action != "create" {
		t.Errorf("action = %q, want create", row.Action)
	}
	if row.Severity != SevInfo {
		t.Errorf("severity = %q, want info", row.Severity)
	}
	if row.Target != "u-42" {
		t.Errorf("target = %q, want u-42", row.Target)
	}
	if row.Actor != "alice" {
		t.Errorf("actor = %q, want alice", row.Actor)
	}
	if row.ServiceID != "svc" {
		t.Errorf("service_id = %q, want svc", row.ServiceID)
	}
	if !strings.HasPrefix(row.ID, "evt-") || len(row.ID) != 24 {
		t.Errorf("id format wrong: %q", row.ID)
	}
	if len(row.RequestID) != 12 {
		t.Errorf("request_id length = %d, want 12", len(row.RequestID))
	}
	if row.MonotonicSeq < 1 {
		t.Errorf("monotonic_seq = %d, want >= 1", row.MonotonicSeq)
	}
}

func TestEmit_MonotonicSeqIncreases(t *testing.T) {
	resetGlobals(t)
	registerTestCodes(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatal(err)
	}
	r1, _ := Emit(context.Background(), "USER_CREATED", Target("u-1"))
	r2, _ := Emit(context.Background(), "USER_DELETED", Target("u-1"))
	if r2.MonotonicSeq <= r1.MonotonicSeq {
		t.Errorf("seq did not increase: %d <= %d", r2.MonotonicSeq, r1.MonotonicSeq)
	}
}

// ── Correlation context ───────────────────────────────────────────────────

func TestWithRequestID_Roundtrip(t *testing.T) {
	ctx := WithRequestID(context.Background(), "aabbccddeeff")
	if got := RequestIDFromContext(ctx); got != "aabbccddeeff" {
		t.Errorf("got %q, want aabbccddeeff", got)
	}
}

func TestRequestIDFromContext_Empty(t *testing.T) {
	if got := RequestIDFromContext(context.Background()); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestEmit_UsesContextRequestID(t *testing.T) {
	resetGlobals(t)
	registerTestCodes(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatal(err)
	}
	ctx := WithRequestID(context.Background(), "deadbeef1234")
	row, err := Emit(ctx, "USER_CREATED", Target("u-1"))
	if err != nil {
		t.Fatal(err)
	}
	if row.RequestID != "deadbeef1234" {
		t.Errorf("request_id = %q, want deadbeef1234", row.RequestID)
	}
}

// ── RedactDetail ──────────────────────────────────────────────────────────

func TestRedactDetail_APIKey(t *testing.T) {
	out := RedactDetail(map[string]any{"api_key": "secret"})
	if out["api_key"] != RedactReplacement {
		t.Errorf("api_key not redacted: %v", out["api_key"])
	}
}

func TestRedactDetail_Password(t *testing.T) {
	out := RedactDetail(map[string]any{"password": "hunter2"})
	if out["password"] != RedactReplacement {
		t.Errorf("password not redacted: %v", out["password"])
	}
}

func TestRedactDetail_SafeKeyPreserved(t *testing.T) {
	out := RedactDetail(map[string]any{"user_id": "u-42"})
	if out["user_id"] != "u-42" {
		t.Errorf("safe key altered: %v", out["user_id"])
	}
}

func TestRedactDetail_NestedMap(t *testing.T) {
	out := RedactDetail(map[string]any{
		"outer": map[string]any{"token": "xyz", "safe": "ok"},
	})
	outer := out["outer"].(map[string]any)
	if outer["token"] != RedactReplacement {
		t.Errorf("nested token not redacted")
	}
	if outer["safe"] != "ok" {
		t.Errorf("nested safe key altered")
	}
}

func TestRedactDetail_Nil(t *testing.T) {
	if out := RedactDetail(nil); out != nil {
		t.Errorf("expected nil for nil input, got %v", out)
	}
}

func TestRedactDetail_CaseInsensitive(t *testing.T) {
	out := RedactDetail(map[string]any{"API_KEY": "x", "Password": "y"})
	if out["API_KEY"] != RedactReplacement {
		t.Errorf("API_KEY not redacted")
	}
	if out["Password"] != RedactReplacement {
		t.Errorf("Password not redacted")
	}
}

// ── RingBuffer ────────────────────────────────────────────────────────────

func TestRingBuffer_Eviction(t *testing.T) {
	rb := newRingBuffer[int](3)
	for i := 0; i < 5; i++ {
		rb.Push(i)
	}
	if rb.Len() != 3 {
		t.Errorf("len = %d, want 3", rb.Len())
	}
	all := rb.All()
	if all[0] != 4 {
		t.Errorf("newest-first: all[0] = %d, want 4", all[0])
	}
}

func TestRingBuffer_EmptyAll(t *testing.T) {
	rb := newRingBuffer[int](10)
	if all := rb.All(); len(all) != 0 {
		t.Errorf("expected empty slice, got %v", all)
	}
}
