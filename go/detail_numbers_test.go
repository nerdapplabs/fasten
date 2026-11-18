package fasten

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// A Python-sealed row with a whole-number float still verifies after a
// store round trip: the read keeps the "75.0" token.
func TestStore_ReadKeepsDetailNumberTokens(t *testing.T) {
	store, done := newMemStore(t, "audit_numbers_read")
	defer done()
	ctx := context.Background()

	var row Row
	if err := json.Unmarshal([]byte(pyFloatVectorJSON), &row); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	if err := store.Insert(ctx, row); err != nil {
		t.Fatalf("insert: %v", err)
	}
	rows, err := store.Query(ctx, Filter{Limit: 10})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if got := rows[0].Detail["setpoint"]; got != json.Number("75.0") {
		t.Errorf("setpoint = %#v, want json.Number(\"75.0\")", got)
	}
	if res := VerifyChain(rows); !res.OK {
		t.Fatalf("row read from the store fails VerifyChain: %s", res.Reason)
	}
}

// Emit stores and seals an integer above 2^53 with every digit.
func TestEmit_KeepsLargeIntegersInDetail(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	store, done := newMemStore(t, "audit_numbers_emit")
	t.Cleanup(done)
	if err := Init(Config{ServiceID: "svc-1", NodeID: "node-1", AuditStore: store,
		AuditStoreFailureStrategy: "raise"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	const big = int64(1234567890123456789)
	row, err := Emit(context.Background(), "USER_CREATED", Target("u-1"),
		WithDetail(map[string]any{"big": big, "ratio": 0.5}))
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if got := row.Detail["big"]; got != json.Number("1234567890123456789") {
		t.Errorf("emitted big = %#v, want json.Number(\"1234567890123456789\")", got)
	}

	rows, err := store.Query(context.Background(), Filter{Limit: 10})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	b, _ := json.Marshal(rows[0].Detail)
	if !strings.Contains(string(b), `"big":1234567890123456789`) {
		t.Errorf("stored detail = %s, want big unchanged", b)
	}
	if res := VerifyChain(rows); !res.OK {
		t.Fatalf("VerifyChain: %s", res.Reason)
	}
}

func TestDecodeDetail_RejectsTrailingData(t *testing.T) {
	if _, err := decodeDetail([]byte(`{"a":1} {"b":2}`)); err == nil {
		t.Fatal("want an error for data after the object")
	}
	if d, err := decodeDetail([]byte(`null`)); err != nil || d != nil {
		t.Fatalf("null: got %v, %v; want nil, nil", d, err)
	}
}
