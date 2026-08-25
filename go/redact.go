package fasten

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

// MaxDetailBytesDefault is the fasten-owned per-row byte ceiling used when
// FASTEN_MAX_DETAIL_BYTES is unset. 64 KiB is enough for the largest
// legitimate structured audit rows and small enough that 2000 ring slots
// stay under 128 MiB even at the ceiling.
const MaxDetailBytesDefault = 64 * 1024

// maxDetailBytes reads FASTEN_MAX_DETAIL_BYTES (positive integer) or
// returns the default. Malformed / non-positive env falls back silently
// to the default — the guarantee is "there is always a cap".
func maxDetailBytes() int {
	if s := os.Getenv("FASTEN_MAX_DETAIL_BYTES"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return n
		}
	}
	return MaxDetailBytesDefault
}

// redactDetail returns a deep-redacted copy of detail via the Rust core,
// using this Engine's extra keys + replacement token. All redaction logic
// (key-pattern + value-shape) lives in fasten-core.
//
// Engine-scoped so multi-tenant callers running more than one Engine keep
// isolated redact config. redactMu is a RWMutex read here — concurrent
// Emits (readers) don't contend, while Init (writer) blocks new reads to
// swap in the new config atomically.
//
// P1-46: guarded by a byte cap (FASTEN_MAX_DETAIL_BYTES, default 64 KiB) —
// oversize inputs get a truncation marker BEFORE the core call so an
// attacker-controlled multi-MB blob can't fill the ring, and core failures
// (e.g. serde_json's 128-depth recursion limit) turn into an unredactable
// marker rather than falling back to the ORIGINAL (potentially PII-laden)
// map. Fail-closed on both paths.
func (e *Engine) redactDetail(d map[string]any) map[string]any {
	if d == nil {
		return nil
	}
	b, err := json.Marshal(d)
	if err != nil {
		return unredactableMarker()
	}
	cap := maxDetailBytes()
	if len(b) > cap {
		return truncatedMarker(len(b), cap)
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
		return unredactableMarker()
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		return unredactableMarker()
	}
	return result
}

// truncatedMarker is the fail-closed replacement for an oversize payload.
// Never returns the original bytes — the whole point is that we don't
// trust attacker-controlled input to be safe to store.
func truncatedMarker(size, cap int) map[string]any {
	return map[string]any{
		"_truncated":        true,
		"_truncated_bytes":  size,
		"_max_detail_bytes": cap,
		"_summary":          fmt.Sprintf("<truncated %d bytes; cap %d>", size, cap),
	}
}

// unredactableMarker is the fail-closed replacement for a core redact
// failure (deep nesting, invalid utf, marshal collapse). Same rule as
// truncation: never return the original bytes.
func unredactableMarker() map[string]any {
	return map[string]any{
		"_redact_failed": true,
		"_summary":       "<unredactable>",
	}
}

// RedactDetail is the package-level shim that redacts via the Default engine.
// New code should reach for Engine.redactDetail through a specific Engine
// instance (multi-tenant callers keep isolated redact config that way).
func RedactDetail(d map[string]any) map[string]any {
	return Default.redactDetail(d)
}
