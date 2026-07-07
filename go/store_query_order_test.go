package fasten

// Query ordering across sub-chains (#68).
//
// MonotonicSeq is a per-(service_id, source_node_id) counter — comparing it
// across sub-chains is meaningless. A global Query must order by wall-clock
// first, so a chatty old chain's high counters cannot bury a quieter chain's
// newer rows below the page limit. Seq stays the same-timestamp tie-breaker
// within one chain.

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func orderRow(seq int64, ts time.Time, serviceID, nodeID string) Row {
	id := fmt.Sprintf("evt-%s-%d", nodeID, seq)
	return Row{
		ID:           id,
		OriginID:     id,
		MonotonicSeq: seq,
		Timestamp:    ts,
		Code:         "USER_CREATED",
		Action:       "create",
		Severity:     SevInfo,
		ServiceID:    serviceID,
		SourceNodeID: nodeID,
		Actor:        "system",
		ActorKind:    "service",
		Target:       "u-1",
		Category:     "account",
		Domain:       "user",
		Method:       "sdk",
		RequestID:    "req-" + id,
	}
}

func TestQuery_OrdersByTimeAcrossSubChains(t *testing.T) {
	store, closeFn := newMemStore(t, "order_chains")
	defer closeFn()
	ctx := context.Background()
	now := time.Now().UTC()

	// Chain A: an older, chattier writer — high seq, day-old timestamps.
	for i := 0; i < 5; i++ {
		row := orderRow(int64(100+i), now.Add(-24*time.Hour).Add(time.Duration(i)*time.Minute), "svc-a", "node-a")
		if err := store.InsertOriginated(ctx, row); err != nil {
			t.Fatalf("insert chain A: %v", err)
		}
	}
	// Chain B: a fresh writer — counter restarted at 1, current timestamps.
	for i := 0; i < 3; i++ {
		row := orderRow(int64(1+i), now.Add(time.Duration(i-3)*time.Minute), "svc-b", "node-b")
		if err := store.InsertOriginated(ctx, row); err != nil {
			t.Fatalf("insert chain B: %v", err)
		}
	}

	page, err := store.Query(ctx, Filter{Limit: 4})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(page) != 4 {
		t.Fatalf("expected 4 rows, got %d", len(page))
	}
	// Newest wall-clock rows come first: all of chain B precedes any of chain A.
	for i := 0; i < 3; i++ {
		if page[i].SourceNodeID != "node-b" {
			t.Fatalf("row %d: expected node-b (newer chain) first, got %s (seq %d)",
				i, page[i].SourceNodeID, page[i].MonotonicSeq)
		}
	}
	for i := 1; i < len(page); i++ {
		if page[i].Timestamp.After(page[i-1].Timestamp) {
			t.Fatalf("rows not in descending time order at index %d", i)
		}
	}
}

func TestQuery_SameTimestampTiesBreakBySeq(t *testing.T) {
	store, closeFn := newMemStore(t, "order_ties")
	defer closeFn()
	ctx := context.Background()
	ts := time.Now().UTC()

	for _, seq := range []int64{1, 2} {
		if err := store.InsertOriginated(ctx, orderRow(seq, ts, "svc", "node-1")); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	page, err := store.Query(ctx, Filter{Limit: 2})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if page[0].MonotonicSeq != 2 || page[1].MonotonicSeq != 1 {
		t.Fatalf("same-timestamp ties must break by seq DESC, got [%d, %d]",
			page[0].MonotonicSeq, page[1].MonotonicSeq)
	}
}
