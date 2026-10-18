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
