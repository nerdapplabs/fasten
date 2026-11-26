package fasten

// Redact conformance: loads spec/redact-conformance.json and runs every case.
//
// The spec is the single source of truth; fasten-core/src/redact.rs is canonical.
// All SDKs must pass every case; failures indicate a divergence from the Rust impl.
//
// The Stripe live-key case is not in the JSON spec (GitHub push protection
// false-positive). It is tested below via a runtime-constructed value.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

type _ConformanceCase struct {
	Name         string         `json:"name"`
	Group        string         `json:"group"`
	CheckNumbers bool           `json:"check_numbers"`
	Input        map[string]any `json:"input"`
	Expected     map[string]any `json:"expected"`
}

func _loadConformanceCases(t *testing.T) []_ConformanceCase {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	specPath := filepath.Join(filepath.Dir(file), "..", "spec", "redact-conformance.json")
	data, err := os.ReadFile(specPath)
	if err != nil {
		t.Fatalf("cannot read redact-conformance.json: %v", err)
	}
	var spec struct {
		Cases []_ConformanceCase `json:"cases"`
	}
	// json.Number keeps each number as written in the spec.
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&spec); err != nil {
		t.Fatalf("cannot parse redact-conformance.json: %v", err)
	}
	return spec.Cases
}

func TestRedactConformance(t *testing.T) {
	cases := _loadConformanceCases(t)
	for _, c := range cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			// The audit detail path returns numbers as json.Number, so
			// both sides compare by the digits as written.
			e := &Engine{}
			e.configureRedaction(nil, "", &c.CheckNumbers)
			got := e.redactAuditDetail(c.Input)
			gotJSON, _ := json.Marshal(got)
			wantJSON, _ := json.Marshal(c.Expected)
			gotV, wantV := _decodeNumbers(t, gotJSON), _decodeNumbers(t, wantJSON)
			if !reflect.DeepEqual(gotV, wantV) {
				t.Errorf("got  %s\nwant %s", gotJSON, wantJSON)
			}
		})
	}

	t.Run("typed_numbers", func(t *testing.T) {
		detail := map[string]any{
			"i64": int64(4111111111111111),
			"u64": uint64(9704000000000000008),
			"n":   42,
		}
		on := true
		e := &Engine{}
		e.configureRedaction(nil, "", &on)
		got := e.redactDetail(detail)
		if got["i64"] != "***CC***" || got["u64"] != "***CC***" || got["n"] != float64(42) {
			t.Errorf("typed numbers: got %v", got)
		}
		off := false
		e.configureRedaction(nil, "", &off)
		if got := e.redactDetail(detail); got["i64"] != float64(4111111111111111) {
			t.Errorf("typed numbers with the option off: got %v", got)
		}
	})

	// Stripe live key, constructed at runtime so the literal sk_live_<24+ chars>
	// never appears in source (GitHub push-protection false-positive).
	t.Run("value_stripe_live", func(t *testing.T) {
		key := "sk" + "_live_" + strings.Repeat("A", 24)
		got := RedactDetail(map[string]any{"note": key})
		if got["note"] != "***STRIPE_KEY***" {
			t.Errorf("stripe: got %v, want ***STRIPE_KEY***", got["note"])
		}
	})
}

func _decodeNumbers(t *testing.T, data []byte) any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("decode %s: %v", data, err)
	}
	return v
}
