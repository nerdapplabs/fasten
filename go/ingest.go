package fasten

import (
	"context"
	"fmt"
)

// IngestResult reports the outcome of an IngestReplicated call.
type IngestResult struct {
	Inserted int `json:"inserted"`
}

// ingestReplicated verifies the chain of incoming rows and, only if it is
// intact, inserts every row via the supplied idempotent insert function.
//
// This is the shared core behind SQLiteStore.IngestReplicated and
// PostgresStore.IngestReplicated. A replication sink (an upstream aggregator
// receiving rows reverse-synced from a node) MUST refuse a broken chain wholesale:
// if VerifyChain reports a break the function inserts NOTHING and returns an
// error naming the first broken sequence. Inserts are idempotent (INSERT OR
// IGNORE / ON CONFLICT DO NOTHING on the id PK), so re-delivering an already
// stored batch is a no-op and the rows' fields are preserved as-is.
func ingestReplicated(
	ctx context.Context,
	rows []Row,
	insert func(context.Context, Row) error,
) (IngestResult, error) {
	res := VerifyChain(rows)
	if !res.OK {
		return IngestResult{}, fmt.Errorf(
			"fasten ingest_replicated: chain verification failed at monotonic_seq %d: %s",
			res.FirstBreakAt, res.Reason,
		)
	}
	inserted := 0
	for _, row := range rows {
		if err := insert(ctx, row); err != nil {
			return IngestResult{Inserted: inserted}, fmt.Errorf(
				"fasten ingest_replicated: insert of row %s failed: %w", row.ID, err)
		}
		inserted++
	}
	return IngestResult{Inserted: inserted}, nil
}

// IngestReplicated verifies and stores a batch of rows replicated from another
// origin (node -> upstream aggregator reverse sync). The chain is verified
// first; a break rejects the whole batch and inserts nothing. See ingestReplicated.
func (s *SQLiteStore) IngestReplicated(ctx context.Context, rows []Row) (IngestResult, error) {
	return ingestReplicated(ctx, rows, s.InsertReplicated)
}

// IngestReplicated verifies and stores a batch of rows replicated from another
// origin. The chain is verified first; a break rejects the whole batch and
// inserts nothing. See ingestReplicated.
func (s *PostgresStore) IngestReplicated(ctx context.Context, rows []Row) (IngestResult, error) {
	return ingestReplicated(ctx, rows, s.InsertReplicated)
}
