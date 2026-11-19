package fasten

import (
	"encoding/json"
	"os"
	"strings"
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

// spec/js-sealed-form2.json and spec/js-sealed-stdout.jsonl are the JS->Go
// direction, written by scripts/gen_js_vectors.mjs from the JS engine and
// Postgres store: the rows as stored (one redacted after sealing) and every
// audit line the engine wrote. node-js-u16 holds a row with unpaired
// surrogates in its detail. encoding/json reads those as U+FFFD, so its
// commitment cannot match here; Python and JS verify that node.
const jsSurrogateNode = "node-js-u16"

func jsRowsByNode(t *testing.T, rows []Row) (main, u16 []Row) {
	t.Helper()
	for _, r := range rows {
		if r.SourceNodeID == jsSurrogateNode {
			u16 = append(u16, r)
		} else {
			main = append(main, r)
		}
	}
	if len(u16) == 0 {
		t.Fatalf("no %s rows", jsSurrogateNode)
	}
	return main, u16
}

func TestCrossLanguage_GoVerifiesAJSSealedChain(t *testing.T) {
	raw, err := os.ReadFile("../spec/js-sealed-form2.json")
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var all []Row
	if err := json.Unmarshal(raw, &all); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	if len(all) != 6 {
		t.Fatalf("rows = %d want 6", len(all))
	}
	rows, _ := jsRowsByNode(t, all)
	redacted := 0
	for _, r := range rows {
		if r.CanonicalFormID != "2" || len(r.Hash) != 64 {
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
			t.Errorf("%s: commitment disagrees with JS:\n got %s\nwant %s", r.ID, got, r.DetailCommitment)
		}
		if got := hashFnByForm[r.CanonicalFormID](r, canonicalJSON); got != r.Hash {
			t.Errorf("%s: hash disagrees with JS:\n got %s\nwant %s", r.ID, got, r.Hash)
		}
	}
	if redacted != 1 {
		t.Errorf("redacted rows = %d want 1", redacted)
	}
	if rows[1].Actor != "op\u00e9\x7f\U0001f600" || rows[1].Target != "sensor/op\u00e9\x7f\U0001f600" {
		t.Errorf("actor %q target %q", rows[1].Actor, rows[1].Target)
	}
	if res := VerifyChain(rows); !res.OK {
		t.Fatalf("Go rejects a JS-sealed chain: %s", res.Reason)
	}

	// A changed detail on a JS-sealed row is caught.
	rows[0].Detail = map[string]any{"half": json.Number("76.5")}
	if res := VerifyChain(rows); res.OK {
		t.Fatal("Go accepted a tampered detail on a JS-sealed row")
	}
}

// The stdout lines as an ingester reads them: two per row, unsealed then
// sealed, each with a "shape" key.
func TestCrossLanguage_GoVerifiesTheJSStdoutLines(t *testing.T) {
	raw, err := os.ReadFile("../spec/js-sealed-stdout.jsonl")
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var rows []Row
	seen := map[string][]bool{}
	var order []string
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		var shape struct {
			Shape string `json:"shape"`
		}
		if err := json.Unmarshal([]byte(line), &shape); err != nil || shape.Shape != "audit" {
			t.Fatalf("not an audit line (%v): %s", err, line)
		}
		var r Row
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("parse line: %v", err)
		}
		if seen[r.ID] == nil {
			order = append(order, r.ID)
		}
		seen[r.ID] = append(seen[r.ID], r.Hash != "")
		rows = append(rows, r)
	}
	if len(order) != 6 {
		t.Fatalf("rows = %d want 6", len(order))
	}
	for _, id := range order {
		if got := seen[id]; len(got) != 2 || got[0] || !got[1] {
			t.Errorf("%s: lines sealed = %v, want [false true]", id, got)
		}
	}
	main, _ := jsRowsByNode(t, rows)
	if res := VerifyChain(main); !res.OK {
		t.Fatalf("Go rejects the JS stdout lines: %s", res.Reason)
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
