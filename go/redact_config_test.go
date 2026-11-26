package fasten

import "testing"

// ExtraRedactKeys + RedactReplacement via Config (parity with the Python SDK).
// Extra keys must AUGMENT the built-in patterns, not replace them.
func TestRedactExtraKeysAndReplacement_Config(t *testing.T) {
	registerTestCodes(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node",
		ExtraRedactKeys: []string{"employee_ref"}, RedactReplacement: "[X]"}); err != nil {
		t.Fatal(err)
	}
	out := RedactDetail(map[string]any{"employee_ref": "e-1", "password": "p", "name": "ok"})
	if out["employee_ref"] != "[X]" {
		t.Fatalf("custom key should be redacted with [X]: %v", out)
	}
	if out["password"] != "[X]" {
		t.Fatalf("built-in key must still redact (with the custom token): %v", out)
	}
	if out["name"] != "ok" {
		t.Fatalf("non-PII field changed: %v", out)
	}
}

// Same, driven by env vars (FASTEN_REDACT_KEYS comma-separated / _REPLACEMENT).
func TestRedactExtraKeysAndReplacement_Env(t *testing.T) {
	registerTestCodes(t)
	t.Setenv("FASTEN_REDACT_KEYS", "employee_ref, badge_no")
	t.Setenv("FASTEN_REDACT_REPLACEMENT", "###")
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatal(err)
	}
	out := RedactDetail(map[string]any{"badge_no": "b", "secret": "s", "ok": "v"})
	if out["badge_no"] != "###" || out["secret"] != "###" {
		t.Fatalf("env redact keys/replacement: %v", out)
	}
	if out["ok"] != "v" {
		t.Fatalf("non-PII field changed: %v", out)
	}
}

// With no customization, redaction is unchanged: built-ins + the "***" token.
func TestRedactDefaults_Unchanged(t *testing.T) {
	registerTestCodes(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatal(err)
	}
	out := RedactDetail(map[string]any{"password": "p", "ok": "v"})
	if out["password"] != "***" {
		t.Fatalf("default replacement should be ***: %v", out)
	}
	if out["ok"] != "v" {
		t.Fatalf("non-PII field changed: %v", out)
	}
}

// TestRedactEnginesAreIsolated (PR #59 finding 2): multi-tenant callers
// create separate *Engine instances. Configuring engine B must not silently
// un-redact engine A's PII keys. Before the fix, redactExtraKeysJSON /
// redactReplacement were package-level, and B.Init reset A's config to "".
func TestRedactEnginesAreIsolated(t *testing.T) {
	registerTestCodes(t)

	a := &Engine{}
	if err := a.Init(Config{ServiceID: "svc-a", NodeID: "n",
		ExtraRedactKeys: []string{"ssn"}, RedactReplacement: "[A]"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.ResetForTests() })

	b := &Engine{}
	if err := b.Init(Config{ServiceID: "svc-b", NodeID: "n"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.ResetForTests() })

	got := a.redactDetail(map[string]any{"ssn": "123-45-6789", "ok": "v"})
	if got["ssn"] != "[A]" {
		t.Fatalf("engine A must still redact ssn with [A] after engine B Init; got %v", got)
	}

	// Engine b uses core defaults — "ssn" is not a built-in and stays through.
	got2 := b.redactDetail(map[string]any{"ssn": "999", "password": "p"})
	if got2["password"] != "***" {
		t.Fatalf("engine B default token should be ***: %v", got2)
	}
}

// A replacement that isn't UTF-8 is treated as unset: matching keys get the
// default "***", as in the other SDKs.
func TestRedactReplacementNotUTF8(t *testing.T) {
	registerTestCodes(t)

	e := &Engine{}
	if err := e.Init(Config{ServiceID: "svc", NodeID: "n", RedactReplacement: "[\xff]"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.ResetForTests() })

	got := e.redactDetail(map[string]any{"password": "p", "ok": "v"})
	if got["password"] != "***" || got["ok"] != "v" {
		t.Fatalf("want password redacted and ok kept; got %v", got)
	}
}

// A number card gets the card token, not the configured replacement.
func TestRedactNumberCardWithCustomReplacement(t *testing.T) {
	registerTestCodes(t)

	on := true
	e := &Engine{}
	if err := e.Init(Config{ServiceID: "svc", NodeID: "n", RedactReplacement: "[gone]", RedactNumbers: &on}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { e.ResetForTests() })

	got := e.redactDetail(map[string]any{"card": 4111111111111111, "token": "x"})
	if got["card"] != "***CC***" || got["token"] != "[gone]" {
		t.Fatalf("want card ***CC*** and token [gone]; got %v", got)
	}
}

// FASTEN_REDACT_NUMBERS turns the number check on; Config.RedactNumbers wins.
func TestRedactNumbersEnv(t *testing.T) {
	registerTestCodes(t)
	detail := map[string]any{"card": 4111111111111111}

	e := &Engine{}
	t.Cleanup(func() { e.ResetForTests() })
	if err := e.Init(Config{ServiceID: "svc", NodeID: "n"}); err != nil {
		t.Fatal(err)
	}
	if got := e.redactDetail(detail); got["card"] != float64(4111111111111111) {
		t.Fatalf("off by default; got %v", got)
	}

	t.Setenv("FASTEN_REDACT_NUMBERS", "1")
	if err := e.Init(Config{ServiceID: "svc", NodeID: "n"}); err != nil {
		t.Fatal(err)
	}
	if got := e.redactDetail(detail); got["card"] != "***CC***" {
		t.Fatalf("env on; got %v", got)
	}

	off := false
	if err := e.Init(Config{ServiceID: "svc", NodeID: "n", RedactNumbers: &off}); err != nil {
		t.Fatal(err)
	}
	if got := e.redactDetail(detail); got["card"] != float64(4111111111111111) {
		t.Fatalf("config off over env on; got %v", got)
	}
}
