package fasten

import (
	"strings"
	"testing"
)

// Unsealed rows in a chain (spec §2): allowed only before a node's first
// sealed row, which then links to "genesis".

func unsealed(r Row) Row {
	r.Hash = ""
	return r
}

func TestVerifyUnsealedRowsBeforeTheChainStartsAreSkipped(t *testing.T) {
	legacy := makeRemoteChain(2, "svc", "node-1")
	for i := range legacy {
		legacy[i] = unsealed(legacy[i])
		legacy[i].PrevHash = ""
	}
	chain := makeRemoteChain(2, "svc", "node-1")
	for i := range chain {
		chain[i].MonotonicSeq += 2
		chain[i].ID += "-sealed"
	}
	prev := "genesis"
	for i := range chain {
		chain[i] = Seal(prev, chain[i])
		prev = chain[i].Hash
	}
	if res := VerifyChain(append(legacy, chain...)); !res.OK {
		t.Fatalf("want ok, got %+v", res)
	}
}

func TestVerifyAnAllUnsealedStreamVerifies(t *testing.T) {
	rows := makeRemoteChain(2, "svc", "node-1")
	if res := VerifyChain([]Row{unsealed(rows[0]), unsealed(rows[1])}); !res.OK {
		t.Fatalf("want ok, got %+v", res)
	}
}

func TestVerifyClearedHashBreaksTheChain(t *testing.T) {
	for _, tc := range []struct {
		name    string
		clear   []int
		breakAt int64
	}{
		{"middle row", []int{1}, 2},
		{"last row", []int{2}, 3},
		{"leading rows", []int{0, 1}, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rows := makeRemoteChain(3, "svc", "node-1")
			for _, i := range tc.clear {
				rows[i].Target = "edited"
				rows[i] = unsealed(rows[i])
			}
			res := VerifyChain(rows)
			if res.OK || res.FirstBreakAt != tc.breakAt {
				t.Fatalf("want a break at %d, got %+v", tc.breakAt, res)
			}
		})
	}
}

func TestVerifyAWindowThatStartsMidChainVerifies(t *testing.T) {
	if res := VerifyChain(makeRemoteChain(4, "svc", "node-1")[2:]); !res.OK {
		t.Fatalf("want ok, got %+v", res)
	}
}

func TestVerifyNodesAreSeparateChains(t *testing.T) {
	a := makeRemoteChain(3, "svc", "node-a")
	b := makeRemoteChain(3, "svc", "node-b")
	rows := append(append([]Row{}, a...), b...)
	rows = append(rows, unsealed(makeRemoteChain(4, "svc", "node-c")[3]))
	if res := VerifyChain(rows); !res.OK {
		t.Fatalf("interleaved nodes must verify, got %+v", res)
	}
}

func TestVerifyPurgedHeadWithUnsealedRowsKeptVerifies(t *testing.T) {
	// Retention removed sealed seqs 3-4; unsealed 1-2 survive below the chain.
	legacy := makeRemoteChain(2, "svc", "node-1")
	for i := range legacy {
		legacy[i] = unsealed(legacy[i])
		legacy[i].PrevHash = ""
	}
	chain := makeRemoteChain(6, "svc", "node-1")[4:] // seqs 5-6
	if res := VerifyChain(append(legacy, chain...)); !res.OK {
		t.Fatalf("want ok, got %+v", res)
	}
}

func TestVerifyUnsealedRowTiedWithFirstSealedSeqBreaksInAnyOrder(t *testing.T) {
	sealed := makeRemoteChain(2, "svc", "node-1")
	tie := unsealed(sealed[0])
	tie.ID = "evt-tie"
	for _, rows := range [][]Row{
		append([]Row{tie}, sealed...),
		append(append([]Row{}, sealed...), tie),
	} {
		if res := VerifyChain(rows); res.OK || res.FirstBreakAt != 1 {
			t.Fatalf("want a break at 1, got %+v", res)
		}
	}
}

func TestVerifyFirstBreakIsTheLowestSeqAcrossNodes(t *testing.T) {
	a := makeRemoteChain(4, "svc", "node-a")
	b := makeRemoteChain(3, "svc", "node-b")
	a[2] = unsealed(a[2]) // node-a breaks at 3
	b[1] = unsealed(b[1]) // node-b breaks at 2
	if res := VerifyChain(append(a, b...)); res.OK || res.FirstBreakAt != 2 {
		t.Fatalf("want a break at 2, got %+v", res)
	}
}

func TestIngestKeepsTheRowsBeforeAnUnsealedOne(t *testing.T) {
	rows := makeRemoteChain(3, "svc", "node-1")
	rows[1] = unsealed(rows[1])
	prefix, rejectedFrom, _ := verifiedPrefix(rows)
	if len(prefix) != 1 || prefix[0].MonotonicSeq != 1 || rejectedFrom != 2 {
		t.Fatalf("prefix %d rows, rejected from %d; want [1] and 2", len(prefix), rejectedFrom)
	}
}

func TestVerifyAnEditBelowADuplicateSeqIsTheFirstBreak(t *testing.T) {
	rows := makeRemoteChain(4, "svc", "node-1")
	rows[1].Target = "edited" // hash mismatch at 2
	dup := makeRemoteChain(4, "svc", "node-1")[3]
	dup.ID = "evt-dup"
	dup = Seal(rows[3].Hash, dup)
	if res := VerifyChain(append(rows, dup)); res.OK || res.FirstBreakAt != 2 {
		t.Fatalf("want a break at 2, got %+v", res)
	}
}

func TestVerifyADuplicateSeqBreaksAndARedeliveredRowDoesNot(t *testing.T) {
	rows := makeRemoteChain(3, "svc", "node-1")
	if res := VerifyChain(append(append([]Row{}, rows...), rows[1])); !res.OK {
		t.Fatalf("a re-delivered row must verify, got %+v", res)
	}
	dup := rows[1]
	dup.ID = "evt-dup"
	dup = Seal(rows[0].Hash, dup)
	res := VerifyChain(append(append([]Row{}, rows...), dup))
	// Same reason as Python, which quotes the node with !r.
	if res.OK || res.FirstBreakAt != 2 || !strings.Contains(res.Reason, "duplicate monotonic_seq 2 on node 'node-1'") {
		t.Fatalf("want a duplicate break at 2, got %+v", res)
	}
}

func TestVerifyChecksEverySealedCopyOfARow(t *testing.T) {
	rows := makeRemoteChain(3, "svc", "node-1")
	stale := unsealed(rows[1])
	stale.MonotonicSeq = 0
	if res := VerifyChain(append(append([]Row{}, rows...), stale)); !res.OK {
		t.Fatalf("an unsealed copy must be ignored, got %+v", res)
	}
	edited := rows[1]
	edited.Target = "edited" // hash left as it was
	resealed := Seal(rows[0].Hash, edited)
	for _, extra := range []Row{edited, resealed} {
		for _, in := range [][]Row{
			append(append([]Row{}, rows...), extra),
			append([]Row{extra}, rows...),
		} {
			if res := VerifyChain(in); res.OK || res.FirstBreakAt != 2 {
				t.Fatalf("want a break at 2, got %+v", res)
			}
		}
	}
}

func TestVerifyACaptureWithBothStdoutLinesChecksTheSealedRows(t *testing.T) {
	// Spec §8: each row's unsealed phase-1 line comes before its sealed one.
	rows := makeRemoteChain(3, "svc", "node-1")
	var phase1 []Row
	for _, r := range rows {
		r = unsealed(r)
		r.MonotonicSeq, r.PrevHash = 0, ""
		phase1 = append(phase1, r)
	}
	if res := VerifyChain(append(append([]Row{}, phase1...), rows...)); !res.OK {
		t.Fatalf("want ok, got %+v", res)
	}
	edited := append([]Row{}, rows...)
	edited[2].Target = "edited"
	if res := VerifyChain(append(append([]Row{}, phase1...), edited...)); res.OK || res.FirstBreakAt != 3 {
		t.Fatalf("want a break at 3, got %+v", res)
	}
}
