package fasten

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Ingest checks a batch against what the store already holds (spec §4): a row
// that disagrees with a stored row is rejected and reported, not ignored.

func ingestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "agg.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	db.SetMaxOpenConns(1)
	s, err := NewSQLiteStore(db, "fasten_audit")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func resealFrom(prev string, rows []Row) []Row {
	out := make([]Row, len(rows))
	for i, r := range rows {
		out[i] = Seal(prev, r)
		prev = out[i].Hash
	}
	return out
}

func ingestOK(t *testing.T, s *SQLiteStore, rows []Row) IngestResult {
	t.Helper()
	res, err := s.IngestReplicated(context.Background(), rows)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func storedCount(t *testing.T, s *SQLiteStore) int {
	t.Helper()
	rows, err := s.Query(context.Background(), Filter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

func TestIngestRedeliveringAStoredBatchIsANoOp(t *testing.T) {
	s, rows := ingestStore(t), makeRemoteChain(3, "svc", "node-1")
	ingestOK(t, s, rows)
	if res := ingestOK(t, s, rows); res.RejectedFromSeq != 0 || storedCount(t, s) != 3 {
		t.Fatalf("re-delivery: %+v, %d rows", res, storedCount(t, s))
	}
}

func TestIngestAContinuingBatchIsStored(t *testing.T) {
	s, rows := ingestStore(t), makeRemoteChain(5, "svc", "node-1")
	ingestOK(t, s, rows[:3])
	if res := ingestOK(t, s, rows[3:]); res.RejectedFromSeq != 0 || storedCount(t, s) != 5 {
		t.Fatalf("continuation: %+v, %d rows", res, storedCount(t, s))
	}
}

func TestIngestARowThatDiffersFromTheStoredRowWithItsIDIsRejected(t *testing.T) {
	s, rows := ingestStore(t), makeRemoteChain(3, "svc", "node-1")
	other := make([]Row, len(rows))
	copy(other, rows)
	for i := range other {
		other[i].Target = "u-other"
	}
	ingestOK(t, s, resealFrom("genesis", other))
	res := ingestOK(t, s, rows)
	if res.RejectedFromSeq != 1 || res.Inserted != 0 || !strings.Contains(res.Reason, "stored row") {
		t.Fatalf("want rejection at 1, got %+v", res)
	}
}

func TestIngestANewRowAtAStoredSeqIsRejected(t *testing.T) {
	s, rows := ingestStore(t), makeRemoteChain(2, "svc", "node-1")
	ingestOK(t, s, rows)
	x := rows[0]
	x.ID, x.OriginID = "evt-x1", "evt-x1"
	if res := ingestOK(t, s, resealFrom("genesis", []Row{x})); res.RejectedFromSeq != 1 || storedCount(t, s) != 2 {
		t.Fatalf("want rejection at 1, got %+v", res)
	}
}

func TestIngestANewRowMustLinkToTheStoredRowBeforeIt(t *testing.T) {
	s, rows := ingestStore(t), makeRemoteChain(4, "svc", "node-1")
	ingestOK(t, s, rows[:2])
	detached := resealFrom(strings.Repeat("0", 64), rows[2:])
	if res := ingestOK(t, s, detached); res.RejectedFromSeq != 3 || storedCount(t, s) != 2 {
		t.Fatalf("want rejection at 3, got %+v", res)
	}
}

func TestIngestTheStoredRowAfterANewOneMustLinkToIt(t *testing.T) {
	s, rows := ingestStore(t), makeRemoteChain(3, "svc", "node-1")
	ingestOK(t, s, rows[:1])
	ingestOK(t, s, rows[2:]) // seq 2 still missing
	filler := rows[1]
	filler.Target = "u-other"
	if res := ingestOK(t, s, resealFrom(rows[0].Hash, []Row{filler})); res.RejectedFromSeq != 2 {
		t.Fatalf("want rejection at 2, got %+v", res)
	}
	if res := ingestOK(t, s, rows[1:2]); res.RejectedFromSeq != 0 {
		t.Fatalf("the real row must fit, got %+v", res)
	}
}

func TestIngestAKeptRowIsCheckedAgainstTheStoredRowAfterIt(t *testing.T) {
	// Stored 1-4 and 6; the batch's 6 conflicts, so only its 5 can be kept,
	// and that 5 must still link to the stored 6.
	s, rows := ingestStore(t), makeRemoteChain(6, "svc", "node-1")
	ingestOK(t, s, rows[:4])
	ingestOK(t, s, rows[5:])
	other := []Row{rows[4], rows[5]}
	other[0].Target = "u-other"
	other[1].Target, other[1].ID, other[1].OriginID = "u-other", "evt-x6", "evt-x6"
	other = resealFrom(rows[3].Hash, other)
	if res := ingestOK(t, s, other); res.RejectedFromSeq != 5 || res.Inserted != 0 {
		t.Fatalf("want rejection at 5, got %+v", res)
	}
	if res := ingestOK(t, s, rows[4:5]); res.RejectedFromSeq != 0 {
		t.Fatalf("the real row must fit, got %+v", res)
	}
}

func TestIngestAndEmitOnSeveralConnectionsDoNotFailBusy(t *testing.T) {
	// A pooled *sql.DB: ingests and allocations on separate connections must
	// wait for the write lock, not fail with SQLITE_BUSY.
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "agg.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	db.SetMaxOpenConns(8)
	s, err := NewSQLiteStore(db, "fasten_audit")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for n := 0; n < 4; n++ {
		chain := makeRemoteChain(20, "svc"+itoa(n), "node-"+itoa(n))
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < len(chain); i += 5 {
				res, err := s.IngestReplicated(ctx, chain[i:i+5])
				if err == nil && res.RejectedFromSeq != 0 {
					err = errors.New(res.Reason)
				}
				if err != nil {
					errs <- err
				}
			}
		}()
	}
	for n := 0; n < 4; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				row := makeRemoteChain(1, "svc", "local")[0]
				row.ID = "evt-local-" + itoa(n) + "-" + itoa(i)
				row.OriginID = row.ID
				if _, err := s.AllocateAndInsertOriginated(ctx, row); err != nil {
					errs <- err
				}
			}
		}(n)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent write failed: %v", err)
	}
	if got := storedCount(t, s); got != 100 {
		t.Fatalf("stored %d rows, want 100", got)
	}
}

func TestBeginImmediateRaisesBusyTimeoutOnlyForTheTransaction(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct{ set, during int }{
		{0, sqliteBusyTimeoutMs}, {100, sqliteBusyTimeoutMs}, {30000, 30000},
	} {
		db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "t.db"))
		if err != nil {
			t.Fatal(err)
		}
		conn, err := db.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		busy := func() int {
			var v int
			if err := conn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&v); err != nil {
				t.Fatal(err)
			}
			return v
		}
		if _, err := conn.ExecContext(ctx, "PRAGMA busy_timeout = "+itoa(tc.set)); err != nil {
			t.Fatal(err)
		}
		restore, err := beginImmediate(ctx, conn)
		if err != nil {
			t.Fatal(err)
		}
		during := busy()
		_, _ = conn.ExecContext(ctx, "ROLLBACK")
		restore()
		after := busy()
		conn.Close()
		db.Close()
		if during != tc.during || after != tc.set {
			t.Fatalf("busy_timeout %d: %d during, %d after; want %d, %d", tc.set, during, after, tc.during, tc.set)
		}
	}
}

func TestAllocationLeavesThePoolsBusyTimeoutAsSet(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "t.db")+"?_pragma=busy_timeout(100)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	s, err := NewSQLiteStore(db, "fasten_audit")
	if err != nil {
		t.Fatal(err)
	}
	row := makeRemoteChain(1, "svc", "node-1")[0]
	row.Hash, row.PrevHash = "", ""
	if _, err := s.AllocateAndInsertOriginated(ctx, row); err != nil {
		t.Fatal(err)
	}
	var v int
	if err := db.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != 100 {
		t.Fatalf("busy_timeout = %d after allocation, want the pool's 100", v)
	}
}

func TestIngestOneIDOnTwoNodesInABatchIsRejected(t *testing.T) {
	// id is unique across nodes, so the store could keep only one of them.
	s := ingestStore(t)
	a := makeRemoteChain(1, "svc", "node-a")[0]
	b := a
	b.SourceNodeID = "node-b"
	b = Seal("genesis", b)
	res, err := ingestPrefix(context.Background(), s.db, []Row{a, b}, 0, "", s.insertReplicatedTx, s.lookup())
	if err != nil {
		t.Fatal(err)
	}
	if res.RejectedFromSeq != 1 || res.Inserted != 0 || !strings.Contains(res.Reason, "also in this batch") {
		t.Fatalf("want a rejection at 1, got %+v", res)
	}
	if storedCount(t, s) != 0 {
		t.Fatal("a row was stored")
	}
}

func TestIngestOneIDTwiceOnOneNodeInABatchIsRejected(t *testing.T) {
	s, rows := ingestStore(t), makeRemoteChain(3, "svc", "node-1")
	for i := range rows {
		rows[i].ID, rows[i].OriginID = "evt-x", "evt-x"
	}
	res := ingestOK(t, s, resealFrom("genesis", rows))
	if res.RejectedFromSeq != 2 || res.Inserted != 1 || !strings.Contains(res.Reason, "also in this batch") {
		t.Fatalf("want a rejection at 2, got %+v", res)
	}
	if storedCount(t, s) != 1 {
		t.Fatal("want only seq 1 stored")
	}
}

func TestIngestARowAfterAStoredUnsealedRowLinksToGenesis(t *testing.T) {
	s, rows := ingestStore(t), makeRemoteChain(2, "svc", "node-1")
	unsealed := rows[0]
	unsealed.Hash, unsealed.PrevHash = "", ""
	if err := s.InsertOriginated(context.Background(), unsealed); err != nil {
		t.Fatal(err)
	}
	if res := ingestOK(t, s, resealFrom(strings.Repeat("0", 64), rows[1:])); res.RejectedFromSeq != 2 {
		t.Fatalf("want a rejection at 2, got %+v", res)
	}
	if res := ingestOK(t, s, resealFrom("genesis", rows[1:])); res.RejectedFromSeq != 0 || res.Inserted != 1 {
		t.Fatalf("want row 2 stored, got %+v", res)
	}
}

func TestIngestASkippedInsertIsCheckedAgain(t *testing.T) {
	// An insert skipped for a row stored meanwhile must not count as stored:
	// the ingest checks the stored rows again.
	s, rows := ingestStore(t), makeRemoteChain(2, "svc", "node-1")
	calls := 0
	insertTx := func(ctx context.Context, exec execContext, row Row) (int64, error) {
		calls++
		if calls == 1 {
			return 0, nil
		}
		return s.insertReplicatedTx(ctx, exec, row)
	}
	res, err := ingestReplicatedTx(context.Background(), s.db, rows, insertTx, s.lookup())
	if err != nil {
		t.Fatal(err)
	}
	if res.Inserted != 2 || calls != 3 || storedCount(t, s) != 2 {
		t.Fatalf("got %+v after %d inserts", res, calls)
	}
}
