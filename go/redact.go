package fasten

import "encoding/json"

// Redaction customization (parity with the Python SDK's FASTEN_REDACT_KEYS /
// FASTEN_REDACT_REPLACEMENT and init params). Set once by Init/configureRedaction.
// Empty = use the core defaults (built-in patterns + "***"). Extra keys augment
// the built-ins; they never replace them.
var (
	redactExtraKeysJSON string // JSON array of extra key patterns, "" = none
	redactReplacement   string // replacement token, "" = core default "***"
)

// RedactDetail returns a deep-redacted copy of detail via the Rust core.
// All redaction logic (key-pattern + value-shape) lives in fasten-core.
func RedactDetail(d map[string]any) map[string]any {
	if d == nil {
		return nil
	}
	b, err := json.Marshal(d)
	if err != nil {
		return d
	}
	var out string
	if redactExtraKeysJSON != "" || redactReplacement != "" {
		out, err = coreRedactJSONFull(string(b), redactExtraKeysJSON, redactReplacement)
	} else {
		out, err = coreRedactJSON(string(b))
	}
	if err != nil {
		return d
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		return d
	}
	return result
}
