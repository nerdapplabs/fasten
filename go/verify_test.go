package fasten

import (
	"context"
	"testing"
	"time"
)

// pyVectorRow is the exact AuditRow the Python generator below produced. Its
// expected hash was computed by Python fasten.engine._row_hash. The Go row hash
// MUST equal pyVectorHash byte-for-byte, proving cross-language chain
// compatibility (edge-manager Go verifying a gateway-Python-sealed chain).
//
// To regenerate, run (from the fasten submodule root):
//
//	docker run --rm -v "$PWD/python:/app" -w /app python:3.12 python3 - <<'PY'
//	import sys; sys.path.insert(0, '.')
//	from datetime import datetime, timezone
//	from fasten.attrs import AuditRow
//	from fasten.engine import _row_hash
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
const pyVectorHash = "561b6028cac9d69c9ae0b7f814bf99dadbe6eef558ec68481ed71e32bcfb08e2"

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

// TestIngestReplicated_RejectsBrokenChain proves a broken chain inserts nothing.
func TestIngestReplicated_RejectsBrokenChain(t *testing.T) {
	r := pyVectorRow()
	r.Target = "tampered"
	inserted := 0
	_, err := ingestReplicated(context.Background(), []Row{r},
		func(context.Context, Row) error { inserted++; return nil })
	if err == nil {
		t.Fatalf("expected error on broken chain")
	}
	if inserted != 0 {
		t.Fatalf("broken chain must insert nothing, inserted %d", inserted)
	}
}

// TestIngestReplicated_InsertsValidChain proves a good chain inserts every row.
func TestIngestReplicated_InsertsValidChain(t *testing.T) {
	inserted := 0
	res, err := ingestReplicated(context.Background(), []Row{pyVectorRow()},
		func(context.Context, Row) error { inserted++; return nil })
	if err != nil {
		t.Fatalf("valid chain ingest failed: %v", err)
	}
	if res.Inserted != 1 || inserted != 1 {
		t.Fatalf("Inserted = %d (callback %d), want 1", res.Inserted, inserted)
	}
}
