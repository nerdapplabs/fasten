package fasten

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
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

// txConn is what the ingest transaction runs on: a *sql.Tx, or a dedicated
// *sql.Conn driven by hand (SQLite BEGIN IMMEDIATE).
type txConn interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// storedLookup reads, on the ingest transaction, what a store already holds,
// so a batch can be checked against it (spec §4).
type storedLookup struct {
	table string
	ph    func(n int) string // placeholder for the n-th argument ("?" or "$n")
	// lock serialises ingest with allocation on a node; nil for SQLite, where
	// immediate takes the write lock before the first read instead.
	lock      func(ctx context.Context, tx txConn, node string) error
	immediate bool
}

type storedRow struct{ id, hash, prevHash string }

func (l storedLookup) byID(ctx context.Context, tx txConn, id string) (string, bool, error) {
	var hash string
	err := tx.QueryRowContext(ctx, "SELECT hash FROM "+l.table+" WHERE id = "+l.ph(1), id).Scan(&hash)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	return hash, err == nil, err
}

func (l storedLookup) atSeq(ctx context.Context, tx txConn, node string, seq int64) (storedRow, bool, error) {
	var r storedRow
	err := tx.QueryRowContext(ctx,
		"SELECT id, hash, prev_hash FROM "+l.table+" WHERE source_node_id = "+l.ph(1)+
			" AND monotonic_seq = "+l.ph(2)+" LIMIT 1", node, seq).Scan(&r.id, &r.hash, &r.prevHash)
	if err == sql.ErrNoRows {
		return storedRow{}, false, nil
	}
	return r, err == nil, err
}

// storedConflict returns the first row of a verified prefix that disagrees with
// what the store already holds (spec §4): its seq and why, or 0. A row already
// stored with the same hash is a re-delivery, not a conflict.
func storedConflict(ctx context.Context, tx txConn, l storedLookup, prefix []Row) (int64, string, error) {
	// The stored neighbours are checked even when the batch holds one too: the
	// batch neighbour may be cut by a later break, and if both are kept they
	// must agree anyway.
	ordered := append([]Row(nil), prefix...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].MonotonicSeq != ordered[j].MonotonicSeq {
			return ordered[i].MonotonicSeq < ordered[j].MonotonicSeq
		}
		return ordered[i].SourceNodeID < ordered[j].SourceNodeID
	})
	nodeOf := map[string]string{}
	for _, row := range ordered {
		node, seq := row.SourceNodeID, row.MonotonicSeq
		// id is unique across nodes, so only one of these could be stored.
		if other, seen := nodeOf[row.ID]; seen && other != node {
			return seq, fmt.Sprintf("row %s: also in this batch on node '%s'", row.ID, other), nil
		}
		nodeOf[row.ID] = node
		held, ok, err := l.byID(ctx, tx, row.ID)
		if err != nil {
			return 0, "", err
		}
		if ok {
			if held != row.Hash {
				return seq, fmt.Sprintf("row %s: differs from the stored row with that id", row.ID), nil
			}
			continue
		}
		if other, ok, err := l.atSeq(ctx, tx, node, seq); err != nil {
			return 0, "", err
		} else if ok {
			return seq, fmt.Sprintf("row %s: seq %d on node %q is stored as row %s", row.ID, seq, node, other.id), nil
		}
		// After an unsealed row the store links to "genesis" (spec §2).
		if before, ok, err := l.atSeq(ctx, tx, node, seq-1); err != nil {
			return 0, "", err
		} else if ok && row.PrevHash != cmp.Or(before.hash, "genesis") {
			return seq, fmt.Sprintf("row %s: prev_hash does not match stored row %s", row.ID, before.id), nil
		}
		if after, ok, err := l.atSeq(ctx, tx, node, seq+1); err != nil {
			return 0, "", err
		} else if ok && after.prevHash != row.Hash {
			return seq, fmt.Sprintf("row %s: stored row %s does not link to it", row.ID, after.id), nil
		}
	}
	return 0, "", nil
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
	insertTx func(context.Context, execContext, Row) (int64, error),
	look storedLookup,
) (IngestResult, error) {
	prefix, rejectedFromSeq, reason := verifiedPrefix(rows)
	if len(prefix) == 0 {
		return IngestResult{Inserted: 0, RejectedFromSeq: rejectedFromSeq, Reason: reason}, nil
	}
	// The node locks don't cover ids, which are unique across nodes; if an
	// ingest for another node stored one of these ids meanwhile, check again.
	for range 3 {
		res, err := ingestPrefix(ctx, db, prefix, rejectedFromSeq, reason, insertTx, look)
		if !errors.Is(err, errStoredMeanwhile) {
			return res, err
		}
	}
	return IngestResult{}, errors.New("fasten IngestReplicated: rows kept being stored by another writer")
}

// errStoredMeanwhile means another writer stored a row with this id after the
// stored-row checks ran, so the insert was skipped.
var errStoredMeanwhile = errors.New("row stored meanwhile")

// ingestPrefix checks a verified prefix against the stored rows and inserts
// what agrees, in one transaction.
func ingestPrefix(
	ctx context.Context,
	db *sql.DB,
	prefix []Row,
	rejectedFromSeq int64,
	reason string,
	insertTx func(context.Context, execContext, Row) (int64, error),
	look storedLookup,
) (IngestResult, error) {
	tx, commit, rollback, err := beginIngest(ctx, db, look.immediate)
	if err != nil {
		return IngestResult{}, err
	}
	// Check against what is already stored, in the same transaction (spec
	// §4): a conflicting row is reported, never ignored.
	if look.lock != nil {
		nodes := map[string]bool{}
		for _, r := range prefix {
			nodes[r.SourceNodeID] = true
		}
		sortedNodes := make([]string, 0, len(nodes))
		for n := range nodes {
			sortedNodes = append(sortedNodes, n)
		}
		sort.Strings(sortedNodes)
		for _, n := range sortedNodes {
			if err := look.lock(ctx, tx, n); err != nil {
				rollback()
				return IngestResult{}, err
			}
		}
	}
	conflictSeq, why, err := storedConflict(ctx, tx, look, prefix)
	if err != nil {
		rollback()
		return IngestResult{}, err
	}
	if conflictSeq != 0 {
		kept := prefix[:0:0]
		for _, r := range prefix {
			if r.MonotonicSeq < conflictSeq {
				kept = append(kept, r)
			}
		}
		prefix, rejectedFromSeq, reason = kept, conflictSeq, why
	}
	inserted := 0
	for _, row := range prefix {
		n, err := insertTx(ctx, tx, row)
		if err == nil && n == 0 {
			// Skipped: fine for a re-delivery, not for any other row.
			if held, _, herr := look.byID(ctx, tx, row.ID); herr != nil {
				err = herr
			} else if held != row.Hash {
				err = errStoredMeanwhile
			}
		}
		if err != nil {
			rollback()
			return IngestResult{}, err
		}
		inserted++
	}
	if err := commit(); err != nil {
		rollback()
		return IngestResult{}, err
	}
	return IngestResult{
		Inserted:        inserted,
		RejectedFromSeq: rejectedFromSeq,
		Reason:          reason,
	}, nil
}

// beginIngest starts the ingest transaction. With immediate (SQLite) the write
// lock must be held before the stored-row reads, or a commit by another
// connection in between makes the first insert fail with SQLITE_BUSY.
// database/sql cannot ask for BEGIN IMMEDIATE, so, as in
// SQLiteStore.AllocateAndInsertOriginated, a dedicated connection is driven by
// hand.
func beginIngest(ctx context.Context, db *sql.DB, immediate bool) (txConn, func() error, func(), error) {
	if !immediate {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return nil, nil, nil, err
		}
		return tx, tx.Commit, func() { _ = tx.Rollback() }, nil
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	restore, err := beginImmediate(ctx, conn)
	if err != nil {
		_ = conn.Close()
		return nil, nil, nil, err
	}
	done := false
	commit := func() error {
		if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
			return err
		}
		done = true
		restore()
		return conn.Close()
	}
	rollback := func() {
		if !done {
			// Not ctx: a cancelled ctx would skip the ROLLBACK and return the
			// connection to the pool still holding the write lock.
			_, _ = conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK")
			done = true
		}
		restore()
		_ = conn.Close()
	}
	return conn, commit, rollback, nil
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
	return ingestReplicatedTx(ctx, s.db, rows, s.insertReplicatedTx, s.lookup())
}

func (s *SQLiteStore) lookup() storedLookup {
	return storedLookup{table: s.table, ph: func(int) string { return "?" }, immediate: true}
}

// IngestReplicated verifies and stores a batch of rows replicated from another
// origin. The verified prefix is inserted in a single transaction; a chain
// break inserts only the prefix and reports RejectedFromSeq (no error). See
// ingestReplicatedTx.
func (s *PostgresStore) IngestReplicated(ctx context.Context, rows []Row) (IngestResult, error) {
	return ingestReplicatedTx(ctx, s.db, rows, s.insertReplicatedTx, s.lookup())
}

// lookup takes the same node lock as AllocateAndInsertOriginated.
func (s *PostgresStore) lookup() storedLookup {
	return storedLookup{
		table: s.table,
		ph:    func(n int) string { return fmt.Sprintf("$%d", n) },
		lock: func(ctx context.Context, tx txConn, node string) error {
			_, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", node)
			return err
		},
	}
}
