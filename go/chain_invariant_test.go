package fasten

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// The tamper chain is per (service_id, source_node_id) and monotonic_seq is a
// per-node counter (see README + python/fasten/attrs.py). Replication must
// preserve each origin's sub-chain. These tests pin the three invariants a
// reviewer found broken:
//
//   - Fix 1: MaxMonotonicSeq scoped to the engine's own identity, so a restart
//     after ingesting a foreign origin's rows does not seed seq from that
//     foreign sub-chain.
//   - Fix 2: ListUnshippedOriginated returns only rows this node ORIGINATED.
//   - Fix 3: a Go-Emit-sealed row is accepted by Go VerifyChain (the seal and
//     the verifier agree on one canonical hash form).

func newMemStore(t *testing.T, table string) (*SQLiteStore, func()) {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sqlite open: %v", err)
	}
	store, err := NewSQLiteStore(db, table)
	if err != nil {
		db.Close()
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	return store, func() { db.Close() }
}

// makeRemoteChain builds a valid n-row tamper chain as if emitted by a remote
// origin, sealed with the same canonical hash the verifier uses.
func makeRemoteChain(n int, serviceID, sourceNodeID string) []Row {
	rows := make([]Row, 0, n)
	prev := "genesis"
	for i := 0; i < n; i++ {
		r := Row{
			WireVersion:  "1",
			ID:           "evt-remote-" + serviceID + "-" + itoa(i),
			OriginID:     "evt-remote-" + serviceID + "-" + itoa(i),
			MonotonicSeq: int64(i + 1),
			Timestamp:    time.Date(2026, 6, 18, 10, 0, i, 0, time.UTC),
			Code:         "USER_CREATED", Action: "create", Severity: SevInfo,
			ServiceID: serviceID, SourceNodeID: sourceNodeID,
			Actor: "system", ActorKind: "service",
			Target: "u-" + itoa(i), Category: "account", Domain: "user",
			Method: "sdk", RequestID: "req-remote-" + itoa(i),
			Detail:   map[string]any{},
			PrevHash: prev,
		}
		r.Hash = rowHashPyCompat(r)
		rows = append(rows, r)
		prev = r.Hash
	}
	return rows
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}

// ── Fix 3: Go-Emit-sealed row round-trips through Go VerifyChain ──────────────

func TestFix3_GoEmitSealedRowVerifies(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc-1", NodeID: "node-1"}); err != nil {
		t.Fatalf("Init: %v", err)
	}

	r1, err := Emit(context.Background(), "USER_CREATED", Target("u-1"))
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	r2, err := Emit(context.Background(), "USER_CREATED", Target("u-2"))
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}

	// A Go-Emit-sealed row must self-verify: recomputing its canonical hash
	// must reproduce the stored Hash. Before Fix 3 the seal used a different
	// JSON form than the verifier, so this failed.
	if got := rowHashPyCompat(r1); got != r1.Hash {
		t.Fatalf("Go-sealed row hash not reproducible by verifier:\n  sealed = %s\n  verify = %s", r1.Hash, got)
	}

	res := VerifyChain([]Row{r1, r2})
	if !res.OK {
		t.Fatalf("Go-Emit-sealed 2-row chain must verify, got: %+v", res)
	}
}

// TestFix3_CrossLanguageVectorStillPasses guards that the canonical form used
// by Emit (now rowHashPyCompat) still matches the frozen Python vector.
func TestFix3_CrossLanguageVectorStillPasses(t *testing.T) {
	if got := rowHashPyCompat(pyVectorRow()); got != pyVectorHash {
		t.Fatalf("cross-language vector regressed:\n  go     = %s\n  python = %s", got, pyVectorHash)
	}
}

// ── Fix 1: restart seeds seq scoped to the engine's own identity ──────────────

func TestFix1_RestartSeedsSeqScopedToOwnIdentity(t *testing.T) {
	store, cleanup := newMemStore(t, "audit_fix1")
	defer cleanup()
	ctx := context.Background()
	const hubSvc, hubNode = "hub-svc", "hub-node"
	const aSvc, aNode = "node-a-svc", "node-a-node"

	registerTestCodes(t)
	resetGlobals(t)

	// Session 1: hub emits one originated row.
	hub := &Engine{}
	if err := hub.Init(Config{
		ServiceID: hubSvc, NodeID: hubNode,
		AuditStore: store, AuditStoreFailureStrategy: "raise",
	}); err != nil {
		t.Fatalf("hub.Init: %v", err)
	}
	r1, err := hub.Emit(ctx, "USER_CREATED", Target("hub-1"))
	if err != nil {
		t.Fatalf("hub.Emit: %v", err)
	}
	if r1.MonotonicSeq != 1 {
		t.Fatalf("first hub row seq = %d, want 1", r1.MonotonicSeq)
	}

	// Hub ingests 100 rows from node A (seq 1..100 on A's sub-chain).
	if _, err := store.IngestReplicated(ctx, makeRemoteChain(100, aSvc, aNode)); err != nil {
		t.Fatalf("IngestReplicated: %v", err)
	}

	// Global MAX is now 100, but the hub's own sub-chain max is still 1.
	if mx, _ := store.MaxMonotonicSeq(ctx, "", ""); mx != 100 {
		t.Fatalf("global MaxMonotonicSeq = %d, want 100", mx)
	}
	if mx, _ := store.MaxMonotonicSeq(ctx, hubSvc, hubNode); mx != 1 {
		t.Fatalf("hub-scoped MaxMonotonicSeq = %d, want 1", mx)
	}

	// Session 2: restart — fresh Engine re-seeds seq from the store.
	hub2 := &Engine{}
	if err := hub2.Init(Config{
		ServiceID: hubSvc, NodeID: hubNode,
		AuditStore: store, AuditStoreFailureStrategy: "raise",
	}); err != nil {
		t.Fatalf("hub2.Init: %v", err)
	}
	r2, err := hub2.Emit(ctx, "USER_CREATED", Target("hub-2"))
	if err != nil {
		t.Fatalf("hub2.Emit: %v", err)
	}

	// Load-bearing: hub's next row is seq=2, not seq=101. This is the Fix 1
	// invariant — seq seeds from the hub's OWN sub-chain max (1), not the
	// global max (100, dominated by node A's ingested rows).
	if r2.MonotonicSeq != 2 {
		t.Fatalf("hub seq after restart = %d, want 2 (unscoped seed leaked node A's sub-chain)", r2.MonotonicSeq)
	}
	_ = r1 // r1 is the session-1 row; its hash continuity across restart is a
	// separate concern: the Go engine does not yet reseed prevHash from the
	// store on Init (no HashSeeder), so r2.PrevHash is "genesis" after restart.
	// That gap is out of scope for Fix 1, which is purely about seq scoping.

	// Each stored hub row self-verifies (its recomputed hash matches the seal).
	hubRows, err := store.Query(ctx, Filter{SourceNodeID: hubNode, Limit: 1000})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(hubRows) != 2 {
		t.Fatalf("expected 2 hub rows, got %d", len(hubRows))
	}
	for _, row := range hubRows {
		if got := rowHashPyCompat(row); got != row.Hash {
			t.Fatalf("hub row seq=%d hash not reproducible: sealed=%s verify=%s", row.MonotonicSeq, row.Hash, got)
		}
	}
}

// ── Fix 2: ListUnshippedOriginated returns only originated rows ───────────────

func TestFix2_ListUnshippedOriginatedExcludesReplicated(t *testing.T) {
	store, cleanup := newMemStore(t, "audit_fix2")
	defer cleanup()
	ctx := context.Background()
	const hubSvc, hubNode = "hub-svc", "hub-node"
	const aSvc, aNode = "node-a-svc", "node-a-node"

	registerTestCodes(t)
	resetGlobals(t)

	hub := &Engine{}
	if err := hub.Init(Config{
		ServiceID: hubSvc, NodeID: hubNode,
		AuditStore: store, AuditStoreFailureStrategy: "raise",
	}); err != nil {
		t.Fatalf("hub.Init: %v", err)
	}
	own1, _ := hub.Emit(ctx, "USER_CREATED", Target("hub-1"))
	own2, _ := hub.Emit(ctx, "USER_CREATED", Target("hub-2"))

	if _, err := store.IngestReplicated(ctx, makeRemoteChain(3, aSvc, aNode)); err != nil {
		t.Fatalf("IngestReplicated: %v", err)
	}

	// Plain ListUnshipped bleeds all 5 rows (legacy behaviour).
	all, err := store.ListUnshipped(ctx, 100)
	if err != nil {
		t.Fatalf("ListUnshipped: %v", err)
	}
	if len(all) != 5 {
		t.Fatalf("plain ListUnshipped should see all 5 unshipped rows, got %d", len(all))
	}

	// Originated-only returns just the hub's 2 rows.
	got, err := store.ListUnshippedOriginated(ctx, hubSvc, hubNode, 100)
	if err != nil {
		t.Fatalf("ListUnshippedOriginated: %v", err)
	}
	gotIDs := map[string]bool{}
	for _, r := range got {
		gotIDs[r.ID] = true
		if r.OriginID != r.ID {
			t.Fatalf("originated row must have origin_id == id, got %s / %s", r.OriginID, r.ID)
		}
		if r.SourceNodeID != hubNode {
			t.Fatalf("originated row must belong to the hub, got node %s", r.SourceNodeID)
		}
	}
	if len(gotIDs) != 2 || !gotIDs[own1.ID] || !gotIDs[own2.ID] {
		t.Fatalf("ListUnshippedOriginated must return only the hub's 2 rows, got %d: %v", len(gotIDs), gotIDs)
	}
}
