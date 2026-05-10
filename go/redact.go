package fasten

import "encoding/json"

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
	out, err := coreRedactJSON(string(b))
	if err != nil {
		return d
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		return d
	}
	return result
}
