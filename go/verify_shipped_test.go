package fasten

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

// #123: shipped_at is set after sealing, so marking rows shipped must not
// change their hashes.
func TestMarkShippedKeepsTheChainVerifying(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := NewSQLiteStore(db, "fasten_audit")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range makeRemoteChain(3, "svc", "node-1") {
		r.OriginID = r.ID
		if _, err := store.AllocateAndInsertOriginated(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	unshipped, err := store.ListUnshipped(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, len(unshipped))
	for i, r := range unshipped {
		ids[i] = r.ID
	}
	if err := store.MarkShipped(ctx, ids); err != nil {
		t.Fatal(err)
	}
	rows, err := store.Query(ctx, Filter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.ShippedAt == nil {
			t.Fatalf("row %s not marked shipped", r.ID)
		}
	}
	if res := VerifyChain(rows); !res.OK || len(rows) != 3 {
		t.Fatalf("after MarkShipped: %+v (%d rows)", res, len(rows))
	}
}

// Rows sealed with shipped_at ALREADY set, hashed by the release before §1.1
// nulled it. The same literals are in Python's test_canonical_form_2.py.
const sealedShippedRows = `[
 {"canonical_form_id":"1","id":"evt-form1-sealed-shipped","origin_id":"evt-form1-sealed-shipped",
  "hash":"5c3cf746ca5745e07baff24c66cb84b596cf6d2db94d985ff26bfbf2b97f6af2"},
 {"canonical_form_id":"1","id":"evt-form1_legacy_Z-sealed-shipped","origin_id":"evt-form1_legacy_Z-sealed-shipped",
  "hash":"11f6ce9b648ed4b54ade9720076951405320bed68170db4b6fda5602cd7cb15e"},
 {"canonical_form_id":"2","id":"evt-form2-sealed-shipped","origin_id":"evt-form2-sealed-shipped",
  "detail_salt":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "detail_commitment":"f539a999e9d125e1097ffaf48dc5034d46eda02f8ee2620ee0b896ebf9cd3dfd",
  "hash":"67acd6ab0fcd7c6c14a314a6cb4bad414aa08f1fd1edc4e2946488682491f920"}
]`

const sealedShippedBase = `{"action":"create","actor":"alice","actor_kind":"user","category":"order",
 "code":"ORDER_PLACED","detail":{"qty":3,"sku":"WIDGET"},"domain":"sales","method":"http",
 "monotonic_seq":1,"prev_hash":"genesis","request_id":"req-xyz","service_id":"gateway",
 "severity":"info","shipped_at":"2026-06-16T08:00:00.250000Z","source_node_id":"node-1",
 "target":"order/42","timestamp":"2026-06-15T10:30:45.123456Z","wire_version":"1"}`

func sealedShipped(t *testing.T) []Row {
	t.Helper()
	var extras []json.RawMessage
	if err := json.Unmarshal([]byte(sealedShippedRows), &extras); err != nil {
		t.Fatal(err)
	}
	rows := make([]Row, len(extras))
	for i, extra := range extras {
		if err := json.Unmarshal([]byte(sealedShippedBase), &rows[i]); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(extra, &rows[i]); err != nil {
			t.Fatal(err)
		}
	}
	return rows
}

func TestRowSealedWithShippedAtSetStillVerifies(t *testing.T) {
	for _, row := range sealedShipped(t) {
		if res := VerifyChain([]Row{row}); !res.OK {
			t.Errorf("%s: %s", row.ID, res.Reason)
		}
	}
}

// The fallback accepts only the stored value the row was sealed over.
func TestRowSealedWithShippedAtSetBindsThatValue(t *testing.T) {
	for _, row := range sealedShipped(t) {
		moved := row
		later := time.Date(2026, 6, 17, 0, 0, 0, 0, time.UTC)
		moved.ShippedAt = &later
		cleared := row
		cleared.ShippedAt = nil
		edited := row
		edited.Actor = "bob"
		for name, r := range map[string]Row{"moved": moved, "cleared": cleared, "edited": edited} {
			if VerifyChain([]Row{r}).OK {
				t.Errorf("%s: %s row verified", row.ID, name)
			}
		}
	}
}
