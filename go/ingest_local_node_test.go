package fasten

import (
	"context"
	"strings"
	"testing"
)

// Ingest refuses rows whose source_node_id is the receiving node: a node's own
// rows come from its emit path, never from replication.

func TestIngestForRefusesRowsContinuingTheLocalChain(t *testing.T) {
	s, own := ingestStore(t), makeRemoteChain(4, "svc-agg", "agg")
	ingestOK(t, s, own[:2])
	res, err := s.IngestReplicatedFor(context.Background(), "agg", own[2:])
	if err != nil {
		t.Fatal(err)
	}
	if res.RejectedFromSeq != 3 || res.Inserted != 0 || !strings.Contains(res.Reason, "is this node") {
		t.Fatalf("got %+v", res)
	}
	if n := storedCount(t, s); n != 2 {
		t.Fatalf("stored %d rows, want 2", n)
	}
}

func TestIngestForCutsAMixedBatchAtTheFirstLocalRow(t *testing.T) {
	s := ingestStore(t)
	rows := append(makeRemoteChain(3, "svc-1", "node-1"), makeRemoteChain(2, "svc-agg", "agg")[1])
	res, err := s.IngestReplicatedFor(context.Background(), "agg", rows)
	if err != nil {
		t.Fatal(err)
	}
	if res.RejectedFromSeq != 2 || res.Inserted != 1 || storedCount(t, s) != 1 {
		t.Fatalf("got %+v, %d rows", res, storedCount(t, s))
	}
}

func TestIngestForKeepsAnEarlierBreak(t *testing.T) {
	s := ingestStore(t)
	rows := makeRemoteChain(2, "svc-1", "node-1")
	rows[1].Target = "u-edited"
	rows = append(rows, makeRemoteChain(3, "svc-agg", "agg")[2])
	res, err := s.IngestReplicatedFor(context.Background(), "agg", rows)
	if err != nil {
		t.Fatal(err)
	}
	plain := ingestOK(t, ingestStore(t), rows[:2])
	if res.RejectedFromSeq != 2 || res.Inserted != 1 || res.Reason != plain.Reason {
		t.Fatalf("got %+v, want the chain break %+v", res, plain)
	}
}

func TestIngestForLeavesOtherNodesAlone(t *testing.T) {
	s := ingestStore(t)
	res, err := s.IngestReplicatedFor(context.Background(), "agg", makeRemoteChain(2, "svc-1", "node-1"))
	if err != nil || res.RejectedFromSeq != 0 || res.Inserted != 2 {
		t.Fatalf("got %+v, %v", res, err)
	}
}

func TestEngineIngestReplicatedRefusesItsOwnNode(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	s := ingestStore(t)
	e := &Engine{}
	if err := e.Init(Config{ServiceID: "svc-agg", NodeID: "agg", AuditStore: s, AuditStoreFailureStrategy: "raise"}); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	res, err := e.IngestReplicated(ctx, makeRemoteChain(1, "svc-agg", "agg"))
	if err != nil || res.RejectedFromSeq != 1 || res.Inserted != 0 {
		t.Fatalf("own node: %+v, %v", res, err)
	}
	res, err = e.IngestReplicated(ctx, makeRemoteChain(2, "svc-1", "node-1"))
	if err != nil || res.RejectedFromSeq != 0 || res.Inserted != 2 {
		t.Fatalf("other node: %+v, %v", res, err)
	}
}

func TestIngestForResentLocalRowsAreStillABreak(t *testing.T) {
	// Already stored, but still not something replication may deliver.
	s, own := ingestStore(t), makeRemoteChain(2, "svc-agg", "agg")
	ingestOK(t, s, own)
	res, err := s.IngestReplicatedFor(context.Background(), "agg", own)
	if err != nil || res.RejectedFromSeq != 1 || res.Inserted != 0 {
		t.Fatalf("got %+v, %v", res, err)
	}
}

func TestIngestForCutsAtTheLowestLocalSeqNotTheFirstInTheBatch(t *testing.T) {
	s, own := ingestStore(t), makeRemoteChain(3, "svc-agg", "agg")
	rows := append(makeRemoteChain(3, "svc-1", "node-1"), own[2], own[1])
	res, err := s.IngestReplicatedFor(context.Background(), "agg", rows)
	if err != nil || res.RejectedFromSeq != 2 || res.Inserted != 1 || !strings.Contains(res.Reason, own[1].ID) {
		t.Fatalf("got %+v, %v", res, err)
	}
}

func TestIngestForALocalRowAtTheSameSeqCutsOtherNodesToo(t *testing.T) {
	s := ingestStore(t)
	rows := append(makeRemoteChain(1, "svc-1", "node-1"), makeRemoteChain(1, "svc-agg", "agg")...)
	res, err := s.IngestReplicatedFor(context.Background(), "agg", rows)
	if err != nil || res.RejectedFromSeq != 1 || res.Inserted != 0 {
		t.Fatalf("got %+v, %v", res, err)
	}
}

func TestIngestForAnEmptyLocalNodeSkipsTheCheck(t *testing.T) {
	s := ingestStore(t)
	res, err := s.IngestReplicatedFor(context.Background(), "", makeRemoteChain(2, "svc-agg", "agg"))
	if err != nil || res.RejectedFromSeq != 0 || res.Inserted != 2 {
		t.Fatalf("got %+v, %v", res, err)
	}
}

func TestIngestForALocalRowAtSeqZeroIsAnError(t *testing.T) {
	s := ingestStore(t)
	row := makeRemoteChain(1, "svc-agg", "agg")[0]
	row.MonotonicSeq = 0
	rows := append(makeRemoteChain(2, "svc-1", "node-1"), row)
	if _, err := s.IngestReplicatedFor(context.Background(), "agg", rows); err == nil {
		t.Fatal("want an error: RejectedFromSeq 0 would read as no break")
	}
	if n := storedCount(t, s); n != 0 {
		t.Fatalf("stored %d rows, want 0", n)
	}
}

// plainIngestStore has IngestReplicated but not IngestReplicatedFor.
type plainIngestStore struct {
	AuditRepository
	s *SQLiteStore
}

func (p plainIngestStore) IngestReplicated(ctx context.Context, rows []Row) (IngestResult, error) {
	return p.s.IngestReplicated(ctx, rows)
}

func TestEngineIngestReplicatedChecksAStoreWithoutIngestReplicatedFor(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	s := ingestStore(t)
	e := &Engine{}
	if err := e.Init(Config{ServiceID: "svc-agg", NodeID: "agg", AuditStore: plainIngestStore{s, s}, AuditStoreFailureStrategy: "raise"}); err != nil {
		t.Fatal(err)
	}
	res, err := e.IngestReplicated(context.Background(), makeRemoteChain(1, "svc-agg", "agg"))
	if err != nil || res.RejectedFromSeq != 1 || storedCount(t, s) != 0 {
		t.Fatalf("got %+v, %v", res, err)
	}
}

func TestPackageIngestReplicatedRefusesTheDefaultEnginesNode(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	s := ingestStore(t)
	if err := Init(Config{ServiceID: "svc-agg", NodeID: "agg", AuditStore: s, AuditStoreFailureStrategy: "raise"}); err != nil {
		t.Fatal(err)
	}
	res, err := IngestReplicated(context.Background(), makeRemoteChain(1, "svc-agg", "agg"))
	if err != nil || res.RejectedFromSeq != 1 || storedCount(t, s) != 0 {
		t.Fatalf("got %+v, %v", res, err)
	}
}

func TestEngineIngestReplicatedNeedsAnAuditStore(t *testing.T) {
	_, err := (&Engine{}).IngestReplicated(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "requires an audit store") {
		t.Fatalf("got %v", err)
	}
}
