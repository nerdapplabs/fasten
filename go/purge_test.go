package fasten

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"
)

// An age purge deletes only a seq prefix of each node's rows (spec §2.3).

type purgeStore interface {
	IngestReplicated(ctx context.Context, rows []Row) (IngestResult, error)
	MarkShipped(ctx context.Context, ids []string) error
	Purge(ctx context.Context, before time.Time, respectUnshipped bool) (int, error)
	Query(ctx context.Context, f Filter) ([]Row, error)
}

// purgeChain seals rows seq 1.. on node, stamped minutesAgo before now.
func purgeChain(node string, minutesAgo []int, now time.Time) []Row {
	var rows []Row
	prev := "genesis"
	for i, mins := range minutesAgo {
		r := cpRow(i+1, node, "u1")
		r.ID = fmt.Sprintf("evt-%s-%d", node, i+1)
		r.OriginID = r.ID
		r.Timestamp = now.Add(-time.Duration(mins) * time.Minute)
		r = Seal(prev, r)
		rows = append(rows, r)
		prev = r.Hash
	}
	return rows
}

func runPurgeCases(t *testing.T, open func(t *testing.T) purgeStore) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	ingest := func(t *testing.T, s purgeStore, rows []Row) {
		t.Helper()
		if res, err := s.IngestReplicated(ctx, rows); err != nil || res.Inserted != len(rows) {
			t.Fatalf("ingest: %+v %v", res, err)
		}
	}
	check := func(t *testing.T, s purgeStore, want map[string][]int64) {
		t.Helper()
		rows, err := s.Query(ctx, Filter{Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		got := map[string][]int64{}
		for _, r := range rows {
			got[r.SourceNodeID] = append(got[r.SourceNodeID], r.MonotonicSeq)
		}
		for node, seqs := range want {
			slices.Sort(got[node])
			if !slices.Equal(got[node], seqs) {
				t.Fatalf("node %s: seqs %v, want %v", node, got[node], seqs)
			}
		}
		if res := VerifyChain(rows); !res.OK {
			t.Fatalf("verify after purge: %+v", res)
		}
	}

	t.Run("deletes only a seq prefix", func(t *testing.T) {
		// Seq 3 is newer than the cutoff and seq 4 older: a timestamp-only
		// delete takes 4 and keeps 3 and 5, and the chain breaks at 5.
		s := open(t)
		ingest(t, s, purgeChain("node-a", []int{100, 90, 79, 80, 70, 60}, now))
		ingest(t, s, purgeChain("node-b", []int{100, 90}, now)) // all old
		n, err := s.Purge(ctx, now.Add(-79*time.Minute-30*time.Second), false)
		if err != nil || n != 4 {
			t.Fatalf("purged %d, %v; want 4", n, err)
		}
		check(t, s, map[string][]int64{"node-a": {3, 4, 5, 6}, "node-b": nil})
	})

	t.Run("keeps rows above an unshipped row", func(t *testing.T) {
		s := open(t)
		ingest(t, s, purgeChain("node-a", []int{100, 90, 80, 10}, now))
		if err := s.MarkShipped(ctx, []string{"evt-node-a-1", "evt-node-a-3"}); err != nil {
			t.Fatal(err)
		}
		n, err := s.Purge(ctx, now.Add(-30*time.Minute), true)
		if err != nil || n != 1 {
			t.Fatalf("purged %d, %v; want 1", n, err)
		}
		check(t, s, map[string][]int64{"node-a": {2, 3, 4}})
	})
}

func TestPurgeSQLite(t *testing.T) {
	runPurgeCases(t, func(t *testing.T) purgeStore { return ingestStore(t) })
}
