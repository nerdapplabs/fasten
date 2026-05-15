package fasten

// Redact conformance — loads spec/redact-conformance.json, runs every case.
//
// The spec is the single source of truth; fasten-core/src/redact.rs is canonical.
// All SDKs must pass every case; failures indicate a divergence from the Rust impl.
//
// NOTE: The Stripe live-key case is not in the JSON spec (GitHub push protection
// false-positive). It is tested below via a runtime-constructed value.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

type _ConformanceCase struct {
	Name     string         `json:"name"`
	Group    string         `json:"group"`
	Input    map[string]any `json:"input"`
	Expected map[string]any `json:"expected"`
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
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatalf("cannot parse redact-conformance.json: %v", err)
	}
	return spec.Cases
}

func TestRedactConformance(t *testing.T) {
	cases := _loadConformanceCases(t)
	for _, c := range cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			got := RedactDetail(c.Input)
			// Marshal both sides to normalise float64 vs int differences from JSON decode.
			gotJSON, _ := json.Marshal(got)
			wantJSON, _ := json.Marshal(c.Expected)
			var gotV, wantV any
			json.Unmarshal(gotJSON, &gotV)
			json.Unmarshal(wantJSON, &wantV)
			if !reflect.DeepEqual(gotV, wantV) {
				t.Errorf("got  %s\nwant %s", gotJSON, wantJSON)
			}
		})
	}

	// Stripe live key — constructed at runtime so the literal sk_live_<24+ chars>
	// never appears in source (GitHub push-protection false-positive).
	t.Run("value_stripe_live", func(t *testing.T) {
		key := "sk" + "_live_" + strings.Repeat("A", 24)
		got := RedactDetail(map[string]any{"note": key})
		if got["note"] != "***STRIPE_KEY***" {
			t.Errorf("stripe: got %v, want ***STRIPE_KEY***", got["note"])
		}
	})
}
