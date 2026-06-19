package fasten

import (
	"testing"
	"time"
)

// pyVectorRow is the exact AuditRow the Python generator below produced. Its
// expected hash was computed by Python fasten.engine._row_hash. The Go row hash
// MUST equal pyVectorHash byte-for-byte, proving cross-language chain
// compatibility (a Go upstream aggregator verifying a Python-node-sealed chain).
//
// To regenerate, run (from the fasten submodule root):
//
//	docker run --rm -v "$PWD/python:/app" -w /app python:3.12 python3 - <<'PY'
//	import sys; sys.path.insert(0, '.')
//	from datetime import datetime, timezone
//	from fasten.attrs import AuditRow
//	from fasten.chain import _row_hash
//	row = AuditRow(
//	    id='evt-abc123', origin_id='evt-abc123', monotonic_seq=1,
//	    timestamp=datetime(2026,6,15,10,30,45,123456, tzinfo=timezone.utc),
//	    code='ORDER_PLACED', action='create', severity='info',
//	    service_id='gateway', source_node_id='node-1', tenant_id='tenant-x',
//	    actor='alice', actor_kind='user', target='order/42',
//	    category='order', domain='sales', method='http', request_id='req-xyz',
//	    detail={'qty': 3, 'sku': 'WIDGET'}, prev_hash='genesis')
//	print(_row_hash(row.to_dict()))
//	PY
//
// The form includes canonical_form_id="1" (item 6 — the canonical form is itself
// versioned and tamper-evident), so this hash differs from the pre-item-6 value.
const pyVectorHash = "cbf5a1ee4bb7baeb0b433bedfa60434bdea42627b9671183895970bbff02f9ac"

func pyVectorRow() Row {
	tid := "tenant-x"
	return Row{
		WireVersion:  "1",
		ID:           "evt-abc123",
		OriginID:     "evt-abc123",
		MonotonicSeq: 1,
		Timestamp:    time.Date(2026, 6, 15, 10, 30, 45, 123456000, time.UTC),
		Code:         "ORDER_PLACED",
		Action:       "create",
		Severity:     "info",
		ServiceID:    "gateway",
		SourceNodeID: "node-1",
		TenantID:     &tid,
		Actor:        "alice",
		ActorKind:    "user",
		Target:       "order/42",
		Category:     "order",
		Domain:       "sales",
		Method:       "http",
		RequestID:    "req-xyz",
		Detail:       map[string]any{"qty": 3, "sku": "WIDGET"},
		PrevHash:     "genesis",
		Hash:         pyVectorHash,
	}
}

// TestRowHash_CrossLanguageVector is the load-bearing cross-language test:
// Go's row hash of a Python-sealed row must equal the hash Python computed.
func TestRowHash_CrossLanguageVector(t *testing.T) {
	got := rowHashPyCompat(pyVectorRow())
	if got != pyVectorHash {
		t.Fatalf("cross-language hash mismatch:\n  go     = %s\n  python = %s", got, pyVectorHash)
	}
}

// TestVerifyChain_OK_PythonVector proves VerifyChain accepts a single
// Python-sealed row (genesis prev_hash, correct self-hash).
func TestVerifyChain_OK_PythonVector(t *testing.T) {
	res := VerifyChain([]Row{pyVectorRow()})
	if !res.OK {
		t.Fatalf("expected OK, got: %+v", res)
	}
	if res.TotalRows != 1 {
		t.Fatalf("TotalRows = %d, want 1", res.TotalRows)
	}
}

// TestVerifyChain_Tampered_FieldChange proves a mutated field (without
// recomputing the hash) is detected as a break at that row's seq.
func TestVerifyChain_Tampered_FieldChange(t *testing.T) {
	r := pyVectorRow()
	r.Target = "order/9999" // tamper after the hash was sealed
	res := VerifyChain([]Row{r})
	if res.OK {
		t.Fatalf("expected break, got OK: %+v", res)
	}
	if res.FirstBreakAt != 1 {
		t.Fatalf("FirstBreakAt = %d, want 1", res.FirstBreakAt)
	}
}

// TestVerifyChain_Empty returns OK for an empty slice (matches Python).
func TestVerifyChain_Empty(t *testing.T) {
	res := VerifyChain(nil)
	if !res.OK || res.TotalRows != 0 {
		t.Fatalf("empty chain: %+v", res)
	}
}

// TestVerifyChain_PrevHashLink builds a genuine two-row chain with Go's own
// seal function and confirms a broken prev_hash link is detected.
func TestVerifyChain_PrevHashLink(t *testing.T) {
	r1 := pyVectorRow()
	r2 := Row{
		WireVersion: "1", ID: "evt-def456", OriginID: "evt-def456",
		MonotonicSeq: 2,
		Timestamp:    time.Date(2026, 6, 15, 10, 30, 46, 0, time.UTC),
		Code:         "ORDER_PLACED", Action: "create", Severity: "info",
		ServiceID: "gateway", SourceNodeID: "node-1",
		Actor: "system", ActorKind: "service",
		Category: "order", Domain: "sales", Method: "sdk", RequestID: "req-2",
		Detail:   map[string]any{},
		PrevHash: r1.Hash, // correct link
	}
	r2.Hash = rowHashPyCompat(r2)

	if res := VerifyChain([]Row{r1, r2}); !res.OK {
		t.Fatalf("intact 2-row chain should verify, got: %+v", res)
	}

	r2.PrevHash = "wronghash"
	r2.Hash = rowHashPyCompat(r2) // self-hash valid, but link is broken
	if res := VerifyChain([]Row{r1, r2}); res.OK || res.FirstBreakAt != 2 {
		t.Fatalf("broken prev_hash link should break at seq 2, got: %+v", res)
	}
}

// TestVerifiedPrefix_RejectsFirstRowBreak proves a chain broken at the first
// row yields an empty verified prefix and names the break (Fix #4 — no longer a
// reject-all raise; the caller inserts the empty prefix and resyncs).
func TestVerifiedPrefix_RejectsFirstRowBreak(t *testing.T) {
	r := pyVectorRow()
	r.Target = "tampered" // breaks the self-hash at seq 1
	prefix, rejectedFromSeq, reason := verifiedPrefix([]Row{r})
	if len(prefix) != 0 {
		t.Fatalf("first-row break must yield empty prefix, got %d rows", len(prefix))
	}
	if rejectedFromSeq != r.MonotonicSeq {
		t.Fatalf("rejectedFromSeq = %d, want %d", rejectedFromSeq, r.MonotonicSeq)
	}
	if reason == "" {
		t.Fatalf("expected a non-empty reason for the break")
	}
}

// TestVerifiedPrefix_IntactChain proves an intact chain is fully verified.
func TestVerifiedPrefix_IntactChain(t *testing.T) {
	prefix, rejectedFromSeq, reason := verifiedPrefix([]Row{pyVectorRow()})
	if len(prefix) != 1 {
		t.Fatalf("intact chain prefix = %d rows, want 1", len(prefix))
	}
	if rejectedFromSeq != 0 || reason != "" {
		t.Fatalf("intact chain must not reject: rejectedFromSeq=%d reason=%q", rejectedFromSeq, reason)
	}
}
