package fasten

import (
	"context"
	"errors"
	"testing"

	_ "modernc.org/sqlite"
)

// tamperChain seals an n-row remote chain, then tampers the row at index
// breakIdx (0-based) so its self-hash no longer verifies, returning the rows in
// monotonic_seq order with the break in place. The returned seq is the
// monotonic_seq of the broken row (breakIdx + 1).
func tamperChain(n, breakIdx int, serviceID, sourceNodeID string) ([]Row, int64) {
	rows := makeRemoteChain(n, serviceID, sourceNodeID)
	rows[breakIdx].Target = "evil-" + rows[breakIdx].Target // hash no longer matches
	return rows, rows[breakIdx].MonotonicSeq
}

// ── Fix #4: poison-pill / verified-prefix (store-backed) ─────────────────────

func TestIngestReplicated_PoisonPillInsertsVerifiedPrefix(t *testing.T) {
	store, done := newMemStore(t, "fasten_audit")
	defer done()
	ctx := context.Background()

	// 5-row batch, row 3 (index 2) tampered.
	rows, breakSeq := tamperChain(5, 2, "svc-a", "node-a")

	res, err := store.IngestReplicated(ctx, rows)
	if err != nil {
		t.Fatalf("poison-pill batch must NOT error, got: %v", err)
	}
	if res.Inserted != 2 {
		t.Fatalf("Inserted = %d, want 2 (verified prefix rows 1-2)", res.Inserted)
	}
	if res.RejectedFromSeq != breakSeq {
		t.Fatalf("RejectedFromSeq = %d, want %d (row 3's seq)", res.RejectedFromSeq, breakSeq)
	}
	if res.Reason == "" {
		t.Fatalf("expected a non-empty reason naming the break")
	}

	n, err := store.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != 2 {
		t.Fatalf("stored rows = %d, want 2 (rows 3-5 rejected)", n)
	}

	// Rows 1-2 are queryable; rows 3-5 are not.
	got, err := store.Query(ctx, Filter{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	storedIDs := map[string]bool{}
	for _, r := range got {
		storedIDs[r.ID] = true
	}
	if !storedIDs[rows[0].ID] || !storedIDs[rows[1].ID] {
		t.Fatalf("rows 1-2 must be queryable, stored=%v", storedIDs)
	}
	for i := 2; i < 5; i++ {
		if storedIDs[rows[i].ID] {
			t.Fatalf("row %d (seq %d) must NOT be stored", i+1, rows[i].MonotonicSeq)
		}
	}
}

func TestIngestReplicated_HappyPathNoRejection(t *testing.T) {
	store, done := newMemStore(t, "fasten_audit")
	defer done()
	ctx := context.Background()

	rows := makeRemoteChain(4, "svc-b", "node-b")
	res, err := store.IngestReplicated(ctx, rows)
	if err != nil {
		t.Fatalf("clean batch ingest failed: %v", err)
	}
	if res.Inserted != 4 {
		t.Fatalf("Inserted = %d, want 4", res.Inserted)
	}
	if res.RejectedFromSeq != 0 || res.Reason != "" {
		t.Fatalf("clean batch must not reject: RejectedFromSeq=%d Reason=%q", res.RejectedFromSeq, res.Reason)
	}
	n, _ := store.Count(ctx)
	if n != 4 {
		t.Fatalf("stored = %d, want 4", n)
	}
}

// ── Fix #3: single-transaction atomicity ─────────────────────────────────────

// TestIngestReplicatedTx_RollsBackOnInsertError injects a failure on the 3rd
// insert and proves the whole transaction rolls back — nothing is committed.
// It drives ingestReplicatedTx directly so the failure can be injected at the
// insert boundary (the same seam the store methods use).
func TestIngestReplicatedTx_RollsBackOnInsertError(t *testing.T) {
	store, done := newMemStore(t, "fasten_audit")
	defer done()
	ctx := context.Background()

	rows := makeRemoteChain(4, "svc-c", "node-c") // clean chain -> full prefix
	injected := errors.New("injected insert failure")
	calls := 0

	insertTx := func(ctx context.Context, exec execContext, row Row) error {
		calls++
		if calls == 3 { // fail mid-batch, after two successful inserts on the tx
			return injected
		}
		return store.insertReplicatedTx(ctx, exec, row)
	}

	_, err := ingestReplicatedTx(ctx, store.db, rows, insertTx)
	if !errors.Is(err, injected) {
		t.Fatalf("expected injected insert error, got: %v", err)
	}

	// Real atomicity: the two inserts that ran before the failure are rolled
	// back, so the batch committed nothing.
	n, err := store.Count(ctx)
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if n != 0 {
		t.Fatalf("rollback failed: %d rows committed, want 0", n)
	}
}

// TestIngestReplicatedTx_CleanBatchCommitsAtomically is the positive control
// for the transaction path: a clean prefix commits as one unit.
func TestIngestReplicatedTx_CleanBatchCommitsAtomically(t *testing.T) {
	store, done := newMemStore(t, "fasten_audit")
	defer done()
	ctx := context.Background()

	rows := makeRemoteChain(3, "svc-d", "node-d")
	res, err := ingestReplicatedTx(ctx, store.db, rows, store.insertReplicatedTx)
	if err != nil {
		t.Fatalf("clean tx batch failed: %v", err)
	}
	if res.Inserted != 3 {
		t.Fatalf("Inserted = %d, want 3", res.Inserted)
	}
	n, _ := store.Count(ctx)
	if n != 3 {
		t.Fatalf("stored = %d, want 3", n)
	}
}
