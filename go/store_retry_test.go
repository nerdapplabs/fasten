package fasten

import (
	"context"
	"testing"
)

// A retry after a commit whose result was lost inserts an id that is already
// stored. INSERT OR IGNORE drops it, so the store must return the stored row,
// not a freshly sealed one at the next seq that was never written.
func TestAllocateRetryReturnsTheStoredRow(t *testing.T) {
	store, done := newMemStore(t, "audit_retry")
	defer done()
	ctx := context.Background()

	r := makeRemoteChain(1, "svc", "node-1")[0]
	r.MonotonicSeq, r.PrevHash, r.Hash, r.CanonicalFormID = 0, "", "", ""
	r.DetailSalt, r.DetailCommitment = "", ""
	r.Detail = map[string]any{"k": "v"}

	first, err := store.AllocateAndInsertOriginated(ctx, r)
	if err != nil {
		t.Fatalf("first insert: %v", err)
	}
	retry, err := store.AllocateAndInsertOriginated(ctx, r)
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if retry.MonotonicSeq != first.MonotonicSeq || retry.Hash != first.Hash {
		t.Fatalf("retry returned seq %d hash %s, stored seq %d hash %s",
			retry.MonotonicSeq, retry.Hash, first.MonotonicSeq, first.Hash)
	}
	if res := VerifyChain([]Row{retry}); !res.OK {
		t.Fatalf("returned row does not verify: %s", res.Reason)
	}
	n, err := store.Count(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("stored %d rows, want 1", n)
	}
}
