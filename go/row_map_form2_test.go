package fasten

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// rowFromMap goes through JSON the way a reader of stdout or the HTTP
// endpoints does.
func rowFromMap(t *testing.T, m map[string]any) Row {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var row Row
	if err := json.Unmarshal(b, &row); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return row
}

func TestRowToMap_Form2RowVerifiesAfterJSON(t *testing.T) {
	sealed := Seal("genesis", bareRow(1, "evt-1"))
	m := rowToMap(sealed)
	if m["detail_salt"] != sealed.DetailSalt || m["detail_commitment"] != sealed.DetailCommitment {
		t.Fatalf("rowToMap dropped salt/commitment: %v / %v", m["detail_salt"], m["detail_commitment"])
	}
	if res := VerifyChain([]Row{rowFromMap(t, m)}); !res.OK {
		t.Fatalf("form-2 row read back from rowToMap does not verify: %s", res.Reason)
	}
}

func TestRowToMap_OmitsEmptySaltAndCommitment(t *testing.T) {
	m := rowToMap(bareRow(1, "evt-1"))
	if _, ok := m["detail_salt"]; ok {
		t.Error("unsealed row should have no detail_salt key")
	}
	if _, ok := m["detail_commitment"]; ok {
		t.Error("unsealed row should have no detail_commitment key")
	}
}

func TestEmit_SealedStdoutLineVerifies(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	store, cleanup := newMemStore(t, "fasten_audit")
	t.Cleanup(cleanup)
	if err := Init(Config{ServiceID: "svc-1", NodeID: "node-1", AuditStore: store,
		AuditStoreFailureStrategy: "raise"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	out := captureStdout(t, func() {
		if _, err := Emit(context.Background(), "USER_CREATED", Target("u-1"),
			WithDetail(map[string]any{"k": "v"})); err != nil {
			t.Fatalf("Emit: %v", err)
		}
	})
	var sealedLine string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.Contains(line, `"shape":"audit"`) && strings.Contains(line, `"hash"`) {
			sealedLine = line
		}
	}
	if sealedLine == "" {
		t.Fatalf("no sealed audit line on stdout:\n%s", out)
	}
	var row Row
	if err := json.Unmarshal([]byte(sealedLine), &row); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res := VerifyChain([]Row{row}); !res.OK {
		t.Fatalf("sealed stdout line does not verify: %s\n%s", res.Reason, sealedLine)
	}
}

func TestRowToMap_RedactedForm2RowVerifiesAfterJSON(t *testing.T) {
	sealed := Seal("genesis", bareRow(1, "evt-1"))
	sealed.Detail = nil
	sealed.DetailSalt = ""
	m := rowToMap(sealed)
	if _, ok := m["detail_salt"]; ok {
		t.Error("redacted row should have no detail_salt key")
	}
	if res := VerifyChain([]Row{rowFromMap(t, m)}); !res.OK {
		t.Fatalf("redacted form-2 row read back from rowToMap does not verify: %s", res.Reason)
	}
}

// delRow holds DEL (0x7f) in target and in detail.
func delRow() Row {
	return Row{
		WireVersion:  "1",
		ID:           "evt-del",
		OriginID:     "evt-del",
		MonotonicSeq: 1,
		Timestamp:    time.Date(2026, 6, 15, 10, 30, 45, 123456000, time.UTC),
		Code:         "ORDER_PLACED",
		Action:       "create",
		Severity:     "info",
		ServiceID:    "gateway",
		SourceNodeID: "node-1",
		Actor:        "alice",
		ActorKind:    "user",
		Target:       "order/\x7f42",
		Category:     "order",
		Domain:       "sales",
		Method:       "http",
		RequestID:    "req-xyz",
		Detail:       map[string]any{"note": "a\x7fb"},
		DetailSalt:   strings.Repeat("b", 64),
	}
}

// Python's json.dumps(ensure_ascii=True) writes DEL (0x7f) as \u007f. The
// hashes below come from python/fasten/chain.py for this row.
func TestCanonicalJSON_EscapesDELLikePython(t *testing.T) {
	row := delRow()
	if got := string(canonicalJSON(map[string]any{"s": "\x7f"})); got != `{"s":"\u007f"}` {
		t.Errorf("canonicalJSON = %s, want {\"s\":\"\\u007f\"}", got)
	}

	sealed := Seal("genesis", row)
	const pyCommitment = "9a837ae6d78f634f2731b76037f50cf3dbc1ac5f13bde1f0f26a1745f4853251"
	const pyForm2Hash = "55404a784f6fe52f181b7e880e4bb25667e7800fc17890bf6c13b67073a00f13"
	if sealed.DetailCommitment != pyCommitment {
		t.Errorf("detail_commitment = %s, want %s", sealed.DetailCommitment, pyCommitment)
	}
	if sealed.Hash != pyForm2Hash {
		t.Errorf("form 2 hash = %s, want %s", sealed.Hash, pyForm2Hash)
	}

	row.CanonicalFormID = "1"
	row.PrevHash = "genesis"
	const pyForm1Hash = "a7816f9fec4ca3c7f56a28493bc522601cda73848304d3e6b3f1c0b1c8312807"
	if got := rowHashPyCompat(row); got != pyForm1Hash {
		t.Errorf("form 1 hash = %s, want %s", got, pyForm1Hash)
	}
}

// Hashes Go sealed delRow with before it escaped DEL, from the Go SDK at
// origin/main (DEL left raw in the canonical JSON).
const (
	rawDELCommitment = "9f56c9d55c78a68e3438acd78c9184602d48f7f5c7c8102c008c57dcc2aed54f"
	rawDELForm2Hash  = "a81613148862cd4447110c6da9e8ad7c12465a159dd9ee83261d550c92f42e95"
	rawDELForm1Hash  = "0223c0d666cea08f2b0ebdac0ceda0ed41ac88aaec2e8ef2f0148df39d2f14c9"
)

func rawDELRows() (form1, form2 Row) {
	form2 = delRow()
	form2.CanonicalFormID = "2"
	form2.PrevHash = "genesis"
	form2.DetailCommitment = rawDELCommitment
	form2.Hash = rawDELForm2Hash
	form1 = delRow()
	form1.CanonicalFormID = "1"
	form1.PrevHash = "genesis"
	form1.DetailSalt = ""
	form1.Hash = rawDELForm1Hash
	return form1, form2
}

func TestVerifyChain_AcceptsRowsSealedWithRawDEL(t *testing.T) {
	form1, form2 := rawDELRows()
	for _, row := range []Row{form1, form2} {
		if res := VerifyChain([]Row{row}); !res.OK {
			t.Errorf("form %s row sealed with raw DEL: %s", row.CanonicalFormID, res.Reason)
		}
		if res := VerifyChain([]Row{rowFromMap(t, rowToMap(row))}); !res.OK {
			t.Errorf("form %s row sealed with raw DEL, after JSON: %s", row.CanonicalFormID, res.Reason)
		}
	}
	if res := VerifyChain([]Row{Seal("genesis", delRow())}); !res.OK {
		t.Errorf("row sealed with DEL escaped: %s", res.Reason)
	}
}

func TestVerifyChain_RawDELFallbackStillCatchesTampering(t *testing.T) {
	form1, form2 := rawDELRows()
	cases := []struct {
		name   string
		row    Row
		edit   func(*Row)
		reason string
	}{
		{"form 2 target", form2, func(r *Row) { r.Target = "order/\x7f43" }, "hash mismatch"},
		{"form 2 target spelled as an escape", form2, func(r *Row) { r.Target = `order/\u007f42` }, "hash mismatch"},
		{"form 2 target without DEL", form2, func(r *Row) { r.Target = "order/42" }, "hash mismatch"},
		{"form 2 detail", form2, func(r *Row) { r.Detail = map[string]any{"note": "a\x7fc"} }, "detail does not match its commitment"},
		{"form 1 target", form1, func(r *Row) { r.Target = "order/\x7f43" }, "hash mismatch"},
		{"form 1 detail", form1, func(r *Row) { r.Detail = map[string]any{"note": "a\x7fc"} }, "hash mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			row := tc.row
			tc.edit(&row)
			res := VerifyChain([]Row{row})
			if res.OK || !strings.Contains(res.Reason, tc.reason) {
				t.Fatalf("got OK=%v reason %q, want %q", res.OK, res.Reason, tc.reason)
			}
		})
	}
}
