package fasten

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
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
