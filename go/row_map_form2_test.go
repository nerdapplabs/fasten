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

// Python's json.dumps(ensure_ascii=True) writes DEL (0x7f) as \u007f. The
// hashes below come from python/fasten/chain.py for this row.
func TestCanonicalJSON_EscapesDELLikePython(t *testing.T) {
	row := Row{
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
