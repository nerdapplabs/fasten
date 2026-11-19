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
		if got := hashFnByForm[r.CanonicalFormID](r, canonicalJSON); got != r.Hash {
			t.Errorf("%s: hash drifted — regenerate the vector and update Python:\n got %s\nwant %s",
				r.ID, got, r.Hash)
		}
	}
	if res := VerifyChain(rows); !res.OK {
		t.Fatalf("Go cannot verify its own committed vector: %s", res.Reason)
	}
}

// spec/rust-sealed-form2.json and spec/js-sealed-form2.json are the Rust->Go
// and JS->Go directions: four rows each SDK sealed through its own store,
// with float, large-integer, non-ASCII, DEL and nested detail, and one row
// redacted after sealing.
func TestCrossLanguage_GoVerifiesARustSealedChain(t *testing.T) {
	verifySealedVector(t, "../spec/rust-sealed-form2.json", "Rust", "76.0")
}

func TestCrossLanguage_GoVerifiesAJSSealedChain(t *testing.T) {
	verifySealedVector(t, "../spec/js-sealed-form2.json", "JS", "76.5")
}

// verifySealedVector checks each row's commitment and hash, the chain, and
// that a changed detail on the first row is caught.
func verifySealedVector(t *testing.T, path, sdk, tampered string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var rows []Row
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	if len(rows) != 4 {
		t.Fatalf("rows = %d want 4", len(rows))
	}
	redacted := 0
	for _, r := range rows {
		if r.CanonicalFormID != "2" || r.Hash == "" {
			t.Errorf("%s: form = %q hash = %q, want a sealed form-2 row", r.ID, r.CanonicalFormID, r.Hash)
		}
		if r.Detail == nil {
			redacted++
			if r.DetailSalt != "" || r.DetailCommitment == "" {
				t.Errorf("%s: a redacted row keeps its commitment and loses its salt", r.ID)
			}
			continue
		}
		if got := detailCommitment(r.DetailSalt, r.Detail); got != r.DetailCommitment {
			t.Errorf("%s: commitment disagrees with %s:\n got %s\nwant %s", r.ID, sdk, got, r.DetailCommitment)
		}
		if got := hashFnByForm[r.CanonicalFormID](r, canonicalJSON); got != r.Hash {
			t.Errorf("%s: hash disagrees with %s:\n got %s\nwant %s", r.ID, sdk, got, r.Hash)
		}
	}
	if redacted != 1 {
		t.Errorf("redacted rows = %d want 1", redacted)
	}
	if res := VerifyChain(rows); !res.OK {
		t.Fatalf("Go rejects a %s-sealed chain: %s", sdk, res.Reason)
	}

	rows[0].Detail = map[string]any{"setpoint": json.Number(tampered)}
	if res := VerifyChain(rows); res.OK {
		t.Fatalf("Go accepted a tampered detail on a %s-sealed row", sdk)
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
			// The commitment with the current encoding alone: VerifyChain
			// also tries Go's older encodings, so the check above can pass
			// through a fallback. Numbers here are json.Number and keep
			// Python's text, so pyNumbers itself is checked by
			// TestCrossLanguage_GoSealedNumbersVector and pynumber_test.go.
			if row.CanonicalFormID == "2" && row.Detail != nil {
				if got := detailCommitment(row.DetailSalt, row.Detail); got != row.DetailCommitment {
					t.Errorf("detail commitment %s, want %s", got, row.DetailCommitment)
				}
			}
		})
	}
}
