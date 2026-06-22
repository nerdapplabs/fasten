package fasten

import (
	"context"
	"database/sql"
	"sort"
)

// IngestResult reports the outcome of an IngestReplicated call.
//
// IngestReplicated inserts the longest VERIFIED prefix of the batch (from the
// chain start up to, but not including, the first break) in a single
// transaction and never returns a chain-break error. Inserted counts the rows
// committed. When the chain breaks partway, RejectedFromSeq carries the
// MonotonicSeq of the first broken row (rows at/after it are NOT inserted) and
// Reason explains where it diverged, so the sender resyncs from that point
// instead of re-shipping a poison-pilled batch forever. On a fully-verified
// batch RejectedFromSeq is 0 and Reason is "".
type IngestResult struct {
	Inserted        int    `json:"inserted"`
	RejectedFromSeq int64  `json:"rejected_from_seq"`
	Reason          string `json:"reason"`
}

// execContext is the subset of *sql.DB / *sql.Tx that the insert helpers need.
// Both satisfy it, so the same SQL runs autocommit (on the DB) or inside a
// transaction (on a Tx).
type execContext interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// verifiedPrefix returns the longest VERIFIED run of rows from the chain start.
//
// Rows are sorted by MonotonicSeq, then the hash chain is verified:
//   - intact -> (allSorted, rejectedFromSeq=0, reason="")
//   - broken -> (rows with MonotonicSeq < firstBreakAt, firstBreakAt, reason)
//
// No I/O — the caller inserts the prefix and reports firstBreakAt as
// RejectedFromSeq. This is the Go counterpart of the Python verified_prefix.
func verifiedPrefix(rows []Row) (prefix []Row, rejectedFromSeq int64, reason string) {
	sorted := make([]Row, len(rows))
	copy(sorted, rows)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].MonotonicSeq < sorted[j].MonotonicSeq
	})

	res := VerifyChain(sorted)
	if res.OK {
		return sorted, 0, ""
	}
	for _, row := range sorted {
		if row.MonotonicSeq < res.FirstBreakAt {
			prefix = append(prefix, row)
		}
	}
	return prefix, res.FirstBreakAt, res.Reason
}

// ingestReplicatedTx verifies the chain, then inserts the verified prefix using
// a single *sql.Tx: BeginTx -> insert each prefix row on the tx -> Commit, with
// Rollback on any insert error. This gives real atomicity (a failure mid-batch
// commits nothing), unlike per-row autocommit inserts.
//
// It is the shared core behind SQLiteStore.IngestReplicated and
// PostgresStore.IngestReplicated. A chain break is NOT an error: only the
// verified prefix is inserted and RejectedFromSeq names the first broken
// sequence so the sender resyncs. Inserts are idempotent (INSERT OR IGNORE /
// ON CONFLICT DO NOTHING on the id PK), so re-delivery after a commit is a
// no-op and a retry after a rolled-back failure re-inserts cleanly.
func ingestReplicatedTx(
	ctx context.Context,
	db *sql.DB,
	rows []Row,
	insertTx func(context.Context, execContext, Row) error,
) (IngestResult, error) {
	prefix, rejectedFromSeq, reason := verifiedPrefix(rows)
	if len(prefix) == 0 {
		return IngestResult{Inserted: 0, RejectedFromSeq: rejectedFromSeq, Reason: reason}, nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return IngestResult{}, err
	}
	inserted := 0
	for _, row := range prefix {
		if err := insertTx(ctx, tx, row); err != nil {
			_ = tx.Rollback()
			return IngestResult{}, err
		}
		inserted++
	}
	if err := tx.Commit(); err != nil {
		_ = tx.Rollback()
		return IngestResult{}, err
	}
	return IngestResult{
		Inserted:        inserted,
		RejectedFromSeq: rejectedFromSeq,
		Reason:          reason,
	}, nil
}

// IngestReplicated verifies and stores a batch of rows replicated from another
// origin (node -> upstream aggregator reverse sync). The verified prefix is
// inserted in a single transaction; a chain break inserts only the prefix and
// reports RejectedFromSeq (no error). See ingestReplicatedTx.
//
// Decoupled from the Engine: this is store-scoped (a method on the store), so a
// replication sink calls it with only a store — no fasten.Init, no service
// identity, no drainer required:
//
//	store, _ := fasten.NewSQLiteStore(db, "audit")
//	res, _ := store.IngestReplicated(ctx, rows) // no fasten.Init needed
func (s *SQLiteStore) IngestReplicated(ctx context.Context, rows []Row) (IngestResult, error) {
	return ingestReplicatedTx(ctx, s.db, rows, s.insertReplicatedTx)
}

// IngestReplicated verifies and stores a batch of rows replicated from another
// origin. The verified prefix is inserted in a single transaction; a chain
// break inserts only the prefix and reports RejectedFromSeq (no error). See
// ingestReplicatedTx.
func (s *PostgresStore) IngestReplicated(ctx context.Context, rows []Row) (IngestResult, error) {
	return ingestReplicatedTx(ctx, s.db, rows, s.insertReplicatedTx)
}
