//go:build integration

package fasten

import (
	"context"
	"sync"
	"testing"
)

// Go + Postgres allocation against a REAL server.
//
// AllocateAndInsertOriginated, the node advisory lock and the
// UNIQUE(source_node_id, monotonic_seq) index were written and reviewed, then
// shipped, without ever executing against Postgres. That is exactly the gap
// that produced the previous Postgres-only defect: Go writing every row
// unsealed while VerifyChain reported "verified", which passed every SQLite
// test there was.
//
// Requires FASTEN_TEST_POSTGRES_DSN (the name CI and scripts/ci-local.sh set).

func pgAllocStore(t *testing.T, table string) *PostgresStore {
	t.Helper()
	db := pgDB(t) // skips when the DSN is unset
	store, err := NewPostgresStore(db, table)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	if _, err := db.Exec("DELETE FROM " + table); err != nil {
		t.Fatalf("clean: %v", err)
	}
	return store
}

func allocRow(id, svc string) Row {
	r := pgRow(id, "req-"+id)
	r.OriginID = r.ID
	r.ServiceID = svc
	r.SourceNodeID = "node-1"
	r.MonotonicSeq = 0
	r.PrevHash = ""
	r.Hash = ""
	return r
}

func TestPGAlloc_SealsAndSequences(t *testing.T) {
	store := pgAllocStore(t, "fasten_audit_alloc1")
	ctx := context.Background()

	a, err := store.AllocateAndInsertOriginated(ctx, allocRow("pa1", "svc-a"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := store.AllocateAndInsertOriginated(ctx, allocRow("pa2", "svc-b"))
	if err != nil {
		t.Fatal(err)
	}
	if a.MonotonicSeq != 1 || b.MonotonicSeq != 2 {
		t.Fatalf("seq = %d,%d want 1,2 — a second service restarted the counter",
			a.MonotonicSeq, b.MonotonicSeq)
	}
	if b.PrevHash != a.Hash {
		t.Fatalf("second row did not chain to the first: prev=%q want %q", b.PrevHash, a.Hash)
	}
	rows, err := store.Query(ctx, Filter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if res := VerifyChain(rows); !res.OK {
		t.Fatalf("chain broken: %s", res.Reason)
	}
}

// The advisory lock must serialise concurrent writers. SELECT ... FOR UPDATE
// would not: on an empty table there is no tip row to lock, so every writer
// would pass through and allocate seq 1.
func TestPGAlloc_AdvisoryLockSerialisesWriters(t *testing.T) {
	store := pgAllocStore(t, "fasten_audit_alloc2")
	ctx := context.Background()

	const n = 12
	var wg sync.WaitGroup
	var mu sync.Mutex
	errs := []error{}
	start := make(chan struct{})

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // release together, so the lock is genuinely contended
			_, err := store.AllocateAndInsertOriginated(ctx,
				allocRow(idFor(i), svcFor(i)))
			if err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if len(errs) > 0 {
		t.Fatalf("contention surfaced as errors (rows lost): %v", errs[0])
	}
	rows, err := store.Query(ctx, Filter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != n {
		t.Fatalf("rows = %d want %d", len(rows), n)
	}
	seen := map[int64]bool{}
	for _, r := range rows {
		if seen[r.MonotonicSeq] {
			t.Fatalf("duplicate monotonic_seq %d — the lock did not serialise", r.MonotonicSeq)
		}
		seen[r.MonotonicSeq] = true
	}
	for i := int64(1); i <= n; i++ {
		if !seen[i] {
			t.Fatalf("sequence is gapped: %d missing", i)
		}
	}
	if res := VerifyChain(rows); !res.OK {
		t.Fatalf("chain broken under contention: %s", res.Reason)
	}
}

// seq must span EVERY row on the node, sealed or not. Filtering unsealed rows
// out of MAX(seq) restarts the counter and collides with them — the defect the
// SQLite backend had.
func TestPGAlloc_UnsealedRowsOccupyTheirSequence(t *testing.T) {
	store := pgAllocStore(t, "fasten_audit_alloc3")
	ctx := context.Background()

	unsealed := allocRow("pa-unsealed", "svc-a")
	unsealed.MonotonicSeq = 42 // no hash: never sealed
	// Insert() is the originated path and does not require a hash, so this
	// lands a row that occupies seq 42 while never having been sealed.
	if err := store.Insert(ctx, unsealed); err != nil {
		t.Fatalf("insert unsealed row: %v", err)
	}
	next, err := store.AllocateAndInsertOriginated(ctx, allocRow("pa-next", "svc-a"))
	if err != nil {
		t.Fatal(err)
	}
	if next.MonotonicSeq != 43 {
		t.Fatalf("allocated seq %d against an existing unsealed row at 42 — the counter restarted",
			next.MonotonicSeq)
	}
}

// A retry after a lost ack must return the PERSISTED row, not a freshly sealed
// one with a burned sequence number.
func TestPGAlloc_RetryIsIdempotent(t *testing.T) {
	store := pgAllocStore(t, "fasten_audit_alloc4")
	ctx := context.Background()

	first, err := store.AllocateAndInsertOriginated(ctx, allocRow("pa-idem", "svc-a"))
	if err != nil {
		t.Fatal(err)
	}
	again, err := store.AllocateAndInsertOriginated(ctx, allocRow("pa-idem", "svc-a"))
	if err != nil {
		t.Fatal(err)
	}
	if again.MonotonicSeq != first.MonotonicSeq || again.Hash != first.Hash {
		t.Fatalf("retry returned a different row: seq %d/%d hash %s/%s",
			first.MonotonicSeq, again.MonotonicSeq, first.Hash[:8], again.Hash[:8])
	}
	rows, err := store.Query(ctx, Filter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("retry duplicated the row: %d rows", len(rows))
	}
}

func idFor(i int) string  { return "pa-c" + string(rune('a'+i%26)) + string(rune('0'+i/26)) }
func svcFor(i int) string { return "svc-" + string(rune('a'+i%3)) }
