package fasten

import (
	"encoding/json"
	"os"
	"testing"
)

// TestCrossLanguage_PythonSealedRowsVerifyInGo seals through Python's PUBLIC
// path (chain.seal) and verifies through Go's PUBLIC path (VerifyChain).
//
// The previous vector was a hand-pinned constant compared against Go's own
// output — it could never detect the two SDKs disagreeing. This can.
//
// whole_second / one_micro exist because spec §1.2 renders microseconds "only
// when nonzero": micros==0 takes a different branch in both implementations,
// and a hash test that only uses .123456 never exercises it.
func TestCrossLanguage_PythonSealedRowsVerifyInGo(t *testing.T) {
	raw, err := os.ReadFile("xlang_vectors.json")
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
	if len(cases) == 0 {
		t.Fatal("no vectors")
	}
	for _, c := range cases {
		t.Run(c.Label, func(t *testing.T) {
			var row Row
			if err := json.Unmarshal(c.Row, &row); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			got := rowHashPyCompat(row)
			if got != row.Hash {
				t.Fatalf("cross-language hash mismatch\n  python sealed = %s\n  go recomputed = %s\n  timestamp     = %s",
					row.Hash, got, row.Timestamp.Format("2006-01-02T15:04:05.000000Z07:00"))
			}
			if res := VerifyChain([]Row{row}); !res.OK {
				t.Fatalf("VerifyChain rejected a Python-sealed row: %s", res.Reason)
			}
		})
	}
}
