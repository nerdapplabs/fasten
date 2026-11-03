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
	if res.RejectedFromSeq != 2 || res.Inserted != 1 || strings.Contains(res.Reason, "is this node") {
		t.Fatalf("got %+v", res)
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

func TestEngineIngestReplicatedNeedsALocalIngester(t *testing.T) {
	if _, err := (&Engine{}).IngestReplicated(context.Background(), nil); err == nil {
		t.Fatal("want an error without an audit store")
	}
}
