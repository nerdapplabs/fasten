//go:build integration

package fasten

import (
	"context"
	"testing"
)

func TestIngestForRefusesRowsContinuingTheLocalChainPostgres(t *testing.T) {
	db := pgDB(t)
	table := uniqueTable("ingest_local")
	t.Cleanup(func() { dropTable(t, db, table) })
	s, err := NewPostgresStore(db, table)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	own := makeRemoteChain(3, "svc-agg", "agg")
	if _, err := s.IngestReplicated(ctx, own[:2]); err != nil {
		t.Fatal(err)
	}
	res, err := s.IngestReplicatedFor(ctx, "agg", own[2:])
	if err != nil || res.RejectedFromSeq != 3 || res.Inserted != 0 {
		t.Fatalf("got %+v, %v", res, err)
	}
	stored, err := s.Query(ctx, Filter{Limit: 10})
	if err != nil || len(stored) != 2 {
		t.Fatalf("stored %d rows, %v", len(stored), err)
	}
}

func TestIngestRepeatedAndUnsealedRowsPostgres(t *testing.T) {
	db := pgDB(t)
	table := uniqueTable("ingest_repeat")
	t.Cleanup(func() { dropTable(t, db, table) })
	s, err := NewPostgresStore(db, table)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	rows := unsealedHead()
	res, err := s.IngestReplicated(ctx, append(rows, rows[2]))
	if err != nil || res.RejectedFromSeq != 0 || res.Inserted != 2 {
		t.Fatalf("got %+v, %v", res, err)
	}
	stored, err := s.Query(ctx, Filter{Limit: 10})
	if err != nil || len(stored) != 2 {
		t.Fatalf("stored %d rows, %v", len(stored), err)
	}
}
