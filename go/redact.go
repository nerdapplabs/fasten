package fasten

import "encoding/json"

// redactDetail returns a deep-redacted copy of detail via the Rust core,
// using this Engine's extra keys + replacement token. All redaction logic
// (key-pattern + value-shape) lives in fasten-core.
//
// Engine-scoped so multi-tenant callers running more than one Engine keep
// isolated redact config. redactMu is a RWMutex read here — concurrent
// Emits (readers) don't contend, while Init (writer) blocks new reads to
// swap in the new config atomically.
func (e *Engine) redactDetail(d map[string]any) map[string]any {
	if d == nil {
		return nil
	}
	b, err := json.Marshal(d)
	if err != nil {
		return d
	}
	e.redactMu.RLock()
	extra := e.redactExtraKeysJSON
	repl := e.redactReplacement
	e.redactMu.RUnlock()

	var out string
	if extra != "" || repl != "" {
		out, err = coreRedactJSONFull(string(b), extra, repl)
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

// RedactDetail is the package-level shim that redacts via the Default engine.
// New code should reach for Engine.redactDetail through a specific Engine
// instance (multi-tenant callers keep isolated redact config that way).
func RedactDetail(d map[string]any) map[string]any {
	return Default.redactDetail(d)
}
