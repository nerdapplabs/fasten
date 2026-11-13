package fasten

import (
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
	"time"
)

// Expected values are CPython's repr() of the same floats.
func TestPyFloatRepr_MatchesCPython(t *testing.T) {
	cases := []struct {
		f    float64
		want string
	}{
		{5e-05, "5e-05"},
		{1e-07, "1e-07"},
		{1e-06, "1e-06"},
		{1e-05, "1e-05"},
		{0.0001, "0.0001"},
		{0.001, "0.001"},
		{0.1, "0.1"},
		{0.5, "0.5"},
		{1.5, "1.5"},
		{12.5, "12.5"},
		{75.0, "75.0"},
		{100.0, "100.0"},
		{123.456, "123.456"},
		{1000000000000000.0, "1000000000000000.0"},
		{1234567890123456.0, "1234567890123456.0"},
		{1e+16, "1e+16"},
		{1.2345678901234566e+17, "1.2345678901234566e+17"},
		{1e+20, "1e+20"},
		{1e+21, "1e+21"},
		{1.5e+300, "1.5e+300"},
		{5e-324, "5e-324"},
		{1.7976931348623157e+308, "1.7976931348623157e+308"},
		{0.30000000000000004, "0.30000000000000004"},
		{2.5e-10, "2.5e-10"},
		{math.Copysign(0, -1), "-0.0"},
		{-5e-05, "-5e-05"},
		{-1e+16, "-1e+16"},
		{-12.5, "-12.5"},
		{0.0, "0.0"},
	}
	for _, c := range cases {
		if got := pyFloatRepr(c.f); got != c.want {
			t.Errorf("pyFloatRepr(%v) = %q, want %q", c.f, got, c.want)
		}
	}
}

// Python's json.dumps(json.loads(in)) for each input, strings untouched.
func TestPyNumbers_RewritesTokensOnly(t *testing.T) {
	in := `{"a":0.00005,"b":"0.00005","c":-0,"d":[1e-7,7,{"e":1.0E+2}],"f":"x\"0.1","g":-12.50,"h":12345678901234567890}`
	want := `{"a":5e-05,"b":"0.00005","c":0,"d":[1e-07,7,{"e":100.0}],"f":"x\"0.1","g":-12.5,"h":12345678901234567890}`
	if got := string(pyNumbers([]byte(in))); got != want {
		t.Errorf("pyNumbers:\n got %s\nwant %s", got, want)
	}
	same := `{"qty":3,"price":75.0,"rate":5e-05}`
	if got := string(pyNumbers([]byte(same))); got != same {
		t.Errorf("CPython-form tokens changed: %s", got)
	}
}

func numbersRow() Row {
	return Row{
		WireVersion:  "1",
		ID:           "evt-go-numbers",
		OriginID:     "evt-go-numbers",
		MonotonicSeq: 1,
		Timestamp:    time.Date(2026, 6, 15, 10, 30, 45, 123456000, time.UTC),
		Code:         "SENSOR_READ",
		Action:       "read",
		Severity:     "info",
		ServiceID:    "gateway",
		SourceNodeID: "node-1",
		Actor:        "plc-7",
		ActorKind:    "device",
		Target:       "sensor/42",
		Category:     "telemetry",
		Domain:       "plant",
		Method:       "mqtt",
		RequestID:    "req-num",
		Detail: map[string]any{
			"tiny":     0.00005,
			"tinier":   1e-7,
			"neg_zero": math.Copysign(0, -1),
			"big":      1e16,
			"huge":     1e21,
			"frac":     12.5,
			"whole":    75.0,
			"count":    7,
			"max_int":  int64(math.MaxInt64),
			"text":     "café ✓",
			"empty":    "",
			"nested":   map[string]any{"list": []any{1, 2.5, map[string]any{"x": 0.0001}}},
		},
		DetailSalt: strings.Repeat("c", 64),
	}
}

// A row older Go releases sealed, with numbers as encoding/json writes them,
// still verifies.
func TestVerify_AcceptsRowsSealedWithGoNumbers(t *testing.T) {
	row := numbersRow()
	row.CanonicalFormID = currentCanonicalFormID
	row.PrevHash = "genesis"
	row.DetailCommitment = detailCommitmentWith(row.DetailSalt, row.Detail, canonicalJSONGoNumbers)
	row.Hash = hashFnByForm[currentCanonicalFormID](row, canonicalJSONGoNumbers)
	if string(canonicalJSON(row.Detail)) == string(canonicalJSONGoNumbers(row.Detail)) {
		t.Fatal("the row has no number the two renderings disagree on")
	}
	if res := VerifyChain([]Row{row}); !res.OK {
		t.Fatalf("a row sealed with Go's old number rendering no longer verifies: %s", res.Reason)
	}
}

// spec/go-sealed-numbers.json is a Go-sealed row whose detail has the numbers
// Go and CPython used to render differently. Python verifies it in
// test_canonical_form_2.py. FASTEN_WRITE_GO_VECTORS=1 rewrites it.
func TestCrossLanguage_GoSealedNumbersVector(t *testing.T) {
	const path = "../spec/go-sealed-numbers.json"
	sealed := Seal("genesis", numbersRow())
	if os.Getenv("FASTEN_WRITE_GO_VECTORS") == "1" {
		out, err := json.MarshalIndent([]Row{sealed}, "", " ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var rows []Row
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d want 1", len(rows))
	}
	if rows[0].Hash != sealed.Hash || rows[0].DetailCommitment != sealed.DetailCommitment {
		t.Fatalf("the vector drifted from Seal; regenerate it with FASTEN_WRITE_GO_VECTORS=1 and check Python")
	}
	if res := VerifyChain(rows); !res.OK {
		t.Fatalf("Go cannot verify its own vector: %s", res.Reason)
	}
}
