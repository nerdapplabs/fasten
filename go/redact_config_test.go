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
