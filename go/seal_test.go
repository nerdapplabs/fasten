package fasten

import (
	"strings"
	"testing"
	"time"
)

// bareRow is an unsealed row used by the seal/form-id tests.
func bareRow(seq int64, id string) Row {
	return Row{
		WireVersion:  "1",
		ID:           id,
		OriginID:     id,
		MonotonicSeq: seq,
		Timestamp:    time.Date(2026, 6, 15, 10, 30, 45, 0, time.UTC),
		Code:         "USER_CREATED",
		Action:       "create",
		Severity:     "info",
		ServiceID:    "svc",
		SourceNodeID: "node",
		Actor:        "a",
		ActorKind:    "user",
		Target:       "u/1",
		Category:     "account",
		Domain:       "user",
		Method:       "sdk",
		RequestID:    "req-1",
		Detail:       map[string]any{"k": "v"},
	}
}

// TestSeal_RoundTrip proves a Seal-sealed row verifies under VerifyChain.
func TestSeal_RoundTrip(t *testing.T) {
	row := Seal("genesis", bareRow(1, "evt-1"))
	if row.Hash == "" {
		t.Fatal("Seal must compute a hash")
	}
	if row.PrevHash != "genesis" {
		t.Fatalf("PrevHash = %q, want genesis", row.PrevHash)
	}
	if row.CanonicalFormID != "1" {
		t.Fatalf("CanonicalFormID = %q, want 1", row.CanonicalFormID)
	}
	if res := VerifyChain([]Row{row}); !res.OK {
		t.Fatalf("Seal-sealed row must verify, got: %+v", res)
	}
}

// TestSeal_TwoRowChain proves a chain sealed entirely with Seal verifies.
func TestSeal_TwoRowChain(t *testing.T) {
	r1 := Seal("genesis", bareRow(1, "evt-1"))
	r2 := Seal(r1.Hash, bareRow(2, "evt-2"))
	if res := VerifyChain([]Row{r1, r2}); !res.OK {
		t.Fatalf("two-row Seal chain must verify, got: %+v", res)
	}
}

// TestVerifyChain_UnknownCanonicalFormID proves a row carrying an unknown
// canonical_form_id is REJECTED, with the reason naming the offending id.
func TestVerifyChain_UnknownCanonicalFormID(t *testing.T) {
	row := Seal("genesis", bareRow(1, "evt-1"))
	// Forge an unknown form id WITHOUT recomputing the hash — the rejection must
	// be on the unknown id, ahead of any hash recompute.
	row.CanonicalFormID = "99"
	res := VerifyChain([]Row{row})
	if res.OK {
		t.Fatalf("unknown canonical_form_id must reject, got OK: %+v", res)
	}
	if res.FirstBreakAt != row.MonotonicSeq {
		t.Fatalf("FirstBreakAt = %d, want %d", res.FirstBreakAt, row.MonotonicSeq)
	}
	if !strings.Contains(res.Reason, `"99"`) ||
		!strings.Contains(res.Reason, "unknown canonical_form_id") {
		t.Fatalf("reason must name the unknown id, got: %q", res.Reason)
	}
}
