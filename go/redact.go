package fasten

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
)

// MaxDetailBytesDefault is the per-row detail size cap when
// FASTEN_MAX_DETAIL_BYTES is unset. At 64 KiB, 2000 ring slots stay under
// 128 MiB.
const MaxDetailBytesDefault = 64 * 1024

// maxDetailBytes reads FASTEN_MAX_DETAIL_BYTES. A missing, malformed or
// non-positive value gives the default, so there is always a cap.
func maxDetailBytes() int {
	if s := os.Getenv("FASTEN_MAX_DETAIL_BYTES"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return n
		}
	}
	return MaxDetailBytesDefault
}

// redactDetail returns a redacted copy of d using fasten-core and this
// Engine's extra keys and replacement.
//
// Input over the byte cap (FASTEN_MAX_DETAIL_BYTES) is replaced with a
// truncation marker before the core call, and a core failure (e.g.
// serde_json's 128-depth limit) gives an unredactable marker. Neither path
// returns the original map.
func (e *Engine) redactDetail(d map[string]any) map[string]any {
	if d == nil {
		return nil
	}
	b, err := json.Marshal(d)
	if err != nil {
		return unredactableMarker()
	}
	maxBytes := maxDetailBytes()
	if len(b) > maxBytes {
		return truncatedMarker(len(b), maxBytes)
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

// truncatedMarker replaces an oversize payload. It never includes the
// original bytes.
func truncatedMarker(size, maxBytes int) map[string]any {
	return map[string]any{
		"_truncated":        true,
		"_truncated_bytes":  size,
		"_max_detail_bytes": maxBytes,
		"_summary":          fmt.Sprintf("<truncated %d bytes; cap %d>", size, maxBytes),
	}
}

// unredactableMarker replaces a payload that couldn't be redacted (deep
// nesting, invalid UTF-8, marshal failure). It never includes the original.
func unredactableMarker() map[string]any {
	return map[string]any{
		"_redact_failed": true,
		"_summary":       "<unredactable>",
	}
}

// RedactDetail redacts d with the Default engine's settings.
func RedactDetail(d map[string]any) map[string]any {
	return Default.redactDetail(d)
}
