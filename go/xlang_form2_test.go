package fasten

import (
	"encoding/json"
	"os"
	"testing"
)

// Form "2" sealed by Python's PUBLIC path, verified by Go's PUBLIC VerifyChain.
// This is the check that was impossible before Go carried form "2": every row
// Python wrote was unreadable by Go verification, replication ingest and the
// doctor endpoint.
func TestCrossLanguage_Form2(t *testing.T) {
	raw, err := os.ReadFile("xlang_form2.json")
	if err != nil {
		t.Skipf("vectors not generated: %v", err)
	}
	var cases []struct {
		Label string          `json:"label"`
		Row   json.RawMessage `json:"row"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("bad vector file: %v", err)
	}
	for _, c := range cases {
		t.Run(c.Label, func(t *testing.T) {
			var row Row
			if err := json.Unmarshal(c.Row, &row); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if row.CanonicalFormID != "2" {
				t.Fatalf("expected form 2, got %q", row.CanonicalFormID)
			}
			if got := rowHashForm2(row); got != row.Hash {
				t.Fatalf("hash mismatch\n  python = %s\n  go     = %s", row.Hash, got)
			}
			if res := VerifyChain([]Row{row}); !res.OK {
				t.Fatalf("VerifyChain rejected a Python-sealed form-2 row: %s", res.Reason)
			}
		})
	}
}

// The commitment must be re-checked on read, or rewriting detail while leaving
// the commitment intact would verify clean — making form "2" weaker than "1".
func TestForm2_DetailTamperingDetected(t *testing.T) {
	raw, err := os.ReadFile("xlang_form2.json")
	if err != nil {
		t.Skip("vectors not generated")
	}
	var cases []struct {
		Label string          `json:"label"`
		Row   json.RawMessage `json:"row"`
	}
	_ = json.Unmarshal(raw, &cases)
	for _, c := range cases {
		var row Row
		_ = json.Unmarshal(c.Row, &row)
		if row.Detail == nil {
			continue // redacted row: nothing left to tamper with
		}
		t.Run(c.Label+"/tampered", func(t *testing.T) {
			row.Detail = map[string]any{"qty": 999, "sku": "STOLEN"}
			if res := VerifyChain([]Row{row}); res.OK {
				t.Fatal("rewritten detail verified clean — commitment not re-checked")
			}
		})
		t.Run(c.Label+"/salt_cleared", func(t *testing.T) {
			row.DetailSalt = ""
			if res := VerifyChain([]Row{row}); res.OK {
				t.Fatal("clearing the salt disabled the commitment check")
			}
		})
	}
}

// spec/go-sealed-form2.json is the Go->Python direction: Python's
// test_canonical_form_2.py verifies this exact chain. Pinned here so a change
// to Seal that alters the bytes fails in Go rather than surfacing as an
// unexplained Python failure.
func TestCrossLanguage_GoSealedVectorIsStable(t *testing.T) {
	raw, err := os.ReadFile("../spec/go-sealed-form2.json")
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var rows []Row
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d want 2", len(rows))
	}
	for _, r := range rows {
		if r.CanonicalFormID != "2" {
			t.Errorf("%s: form = %q want 2", r.ID, r.CanonicalFormID)
		}
		if got := detailCommitment(r.DetailSalt, r.Detail); got != r.DetailCommitment {
			t.Errorf("%s: commitment drifted:\n got %s\nwant %s", r.ID, got, r.DetailCommitment)
		}
		if got := hashFnByForm[r.CanonicalFormID](r); got != r.Hash {
			t.Errorf("%s: hash drifted — regenerate the vector and update Python:\n got %s\nwant %s",
				r.ID, got, r.Hash)
		}
	}
	if res := VerifyChain(rows); !res.OK {
		t.Fatalf("Go cannot verify its own committed vector: %s", res.Reason)
	}
}

// spec/python-sealed-forms.json is produced by the Python SDK's own sealing
// path across both canonical forms and both timestamp shapes. Go must accept
// every case, including the legacy always-"Z" form-"1" hashes that
// pre-conformance Python wrote — those rows exist in deployments, verify in
// Python via its own fallback, and read as tampering here without ours.
func TestCrossLanguage_GoAcceptsEveryPythonSealedForm(t *testing.T) {
	raw, err := os.ReadFile("../spec/python-sealed-forms.json")
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var f struct {
		CurrentForm string `json:"current_form"`
		Cases       []struct {
			Label string          `json:"label"`
			Row   json.RawMessage `json:"row"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	if f.CurrentForm != currentCanonicalFormID {
		t.Errorf("SDKs seal different forms: python %q, go %q — cross-SDK rows will not verify",
			f.CurrentForm, currentCanonicalFormID)
	}
	if len(f.Cases) == 0 {
		t.Fatal("empty vector")
	}
	for _, c := range f.Cases {
		t.Run(c.Label, func(t *testing.T) {
			var row Row
			if err := json.Unmarshal(c.Row, &row); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if res := VerifyChain([]Row{row}); !res.OK {
				t.Fatalf("Go rejects a Python-sealed row: %s", res.Reason)
			}
		})
	}
}
