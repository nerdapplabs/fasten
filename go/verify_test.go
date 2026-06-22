package fasten

import (
	"encoding/json"
	"testing"
	"time"
)

// pyFloatVectorJSON is a Python-sealed row exactly as Python fasten emits it,
// with a WHOLE-NUMBER float (setpoint: 75.0), a fractional float (12.5) and an
// int (7) in detail. Python json.dumps renders 75.0 as "75.0"; a Go row decoded
// with a plain unmarshal would render the resulting float64 as "75" and fail
// verification. pyFloatVectorHash is the hash Python computed over this row.
//
// Regenerate from the fasten submodule root with the same generator as
// pyVectorHash but detail={'setpoint':75.0,'tolerance':12.5,'retries':7}.
const pyFloatVectorHash = "512021c690ddfd2077192cb6d75921ea36d35b3270a12fdf91888d5ffabcf54b"

const pyFloatVectorJSON = `{"id": "evt-float-vec", "origin_id": "evt-float-vec", "monotonic_seq": 1, "timestamp": "2026-06-15T10:30:45+00:00", "code": "SETPOINT_WRITE", "action": "write", "severity": "info", "service_id": "event-engine", "source_node_id": "node-1", "tenant_id": "acme", "actor": "event-engine", "actor_kind": "service", "target": "connector-opcua-01/ns=2;s=Valve", "category": "actuation", "domain": "control", "method": "sdk", "request_id": "req-float-1", "detail": {"setpoint": 75.0, "tolerance": 12.5, "retries": 7}, "wire_version": "1", "shipped_at": null, "canonical_form_id": "1", "prev_hash": "genesis", "hash": "512021c690ddfd2077192cb6d75921ea36d35b3270a12fdf91888d5ffabcf54b"}`

// TestVerifyChain_WholeNumberFloatVector proves a Python-sealed row carrying a
// whole-number float in detail verifies on the Go side. It is the regression
// guard for the float-normalization cross-language break: Row.UnmarshalJSON
// preserves the "75.0" token (via UseNumber) so Go reproduces Python's rendering.
func TestVerifyChain_WholeNumberFloatVector(t *testing.T) {
	var row Row
	if err := json.Unmarshal([]byte(pyFloatVectorJSON), &row); err != nil {
		t.Fatalf("unmarshal python float vector: %v", err)
	}
	if got := rowHashPyCompat(row); got != pyFloatVectorHash {
		t.Fatalf("whole-number-float hash mismatch (Go must render 75.0 not 75):\n  go     = %s\n  python = %s", got, pyFloatVectorHash)
	}
	if res := VerifyChain([]Row{row}); !res.OK {
		t.Fatalf("Go rejected a Python-sealed whole-number-float row: %+v", res)
	}
}

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
