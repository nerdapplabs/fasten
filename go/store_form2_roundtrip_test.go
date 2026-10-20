package fasten

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	_ "modernc.org/sqlite"
)

// Form-"2" rows must survive the store.
//
// TestCrossLanguage_Form2 verified the HASH against the shared vector but never
// wrote a row, and nothing else exercised detail_salt / detail_commitment
// through a store. Both columns were missing from the Go DDL, the INSERT column
// list and the scan, so every write silently dropped them: a Python-sealed
// form-"2" row replicated into Go came back with an empty salt and then failed
// VerifyChain's commitment check. Go could not hold a row Python had sealed.

func form2Vector(t *testing.T) Row {
	t.Helper()
	raw, err := os.ReadFile("xlang_form2.json")
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var cases []struct {
		Label string          `json:"label"`
		Row   json.RawMessage `json:"row"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("vector file is empty")
	}
	var row Row
	if err := json.Unmarshal(cases[0].Row, &row); err != nil {
		t.Fatalf("parse row: %v", err)
	}
	if row.DetailSalt == "" || row.DetailCommitment == "" {
		t.Fatalf("vector carries no salt/commitment — wrong fixture")
	}
	return row
}

func TestForm2_StoreRoundTripPreservesCommitment(t *testing.T) {
	store, done := newMemStore(t, "audit_form2_rt")
	defer done()
	ctx := context.Background()

	want := form2Vector(t)
	if err := store.Insert(ctx, want); err != nil {
		t.Fatalf("insert: %v", err)
	}

	rows, err := store.Query(ctx, Filter{Limit: 10})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d want 1", len(rows))
	}
	got := rows[0]

	if got.DetailSalt != want.DetailSalt {
		t.Errorf("detail_salt not persisted: got %q want %q",
			got.DetailSalt, want.DetailSalt)
	}
	if got.DetailCommitment != want.DetailCommitment {
		t.Errorf("detail_commitment not persisted: got %q want %q",
			got.DetailCommitment, want.DetailCommitment)
	}
	if got.CanonicalFormID != "2" {
		t.Errorf("canonical_form_id = %q want 2", got.CanonicalFormID)
	}
	if got.Hash != want.Hash {
		t.Errorf("hash changed in the store: got %q want %q", got.Hash, want.Hash)
	}

	// The point of all of it: the row Python sealed still verifies in Go after
	// a store round trip.
	if res := VerifyChain(rows); !res.OK {
		t.Fatalf("round-tripped form-2 row fails VerifyChain: %s", res.Reason)
	}
}

// A redacted form-"2" row (detail destroyed, salt cleared, hash untouched) must
// still verify — that is the whole reason the commitment replaces detail in the
// hash. If the store dropped the commitment, this could not be checked at all.
func TestForm2_RedactedRowStillVerifies(t *testing.T) {
	store, done := newMemStore(t, "audit_form2_redact")
	defer done()
	ctx := context.Background()

	row := form2Vector(t)
	if err := store.Insert(ctx, row); err != nil {
		t.Fatalf("insert: %v", err)
	}
	// Redact in place, exactly as spec §7.1 prescribes: detail and salt go,
	// hash / prev_hash / monotonic_seq stay.
	if _, err := store.db.ExecContext(ctx,
		"UPDATE audit_form2_redact SET detail = 'null', detail_salt = '' WHERE id = ?",
		row.ID); err != nil {
		t.Fatalf("redact: %v", err)
	}

	rows, err := store.Query(ctx, Filter{Limit: 10})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if rows[0].DetailCommitment != row.DetailCommitment {
		t.Fatalf("commitment lost on redaction — the row can no longer be proved")
	}
	if res := VerifyChain(rows); !res.OK {
		t.Fatalf("redacted form-2 row fails VerifyChain: %s", res.Reason)
	}
}
