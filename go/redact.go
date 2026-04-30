package fasten

import "strings"

// Deep redaction: detail values whose keys match a pattern from
// spec/row-schema.json get replaced with REDACT_REPLACEMENT. Patterns
// are simple keywords (e.g. `api[_-]?key`); we lowercase + strip _/-
// from both key and pattern, then substring-match — equivalent to
// case-insensitive search of the original regex for all current
// patterns. No external regex dep.

var redactWords = func() []string {
	out := make([]string, 0, len(REDACT_PATTERNS))
	for _, p := range REDACT_PATTERNS {
		s := strings.ReplaceAll(p, "[_-]?", "")
		s = strings.ReplaceAll(s, "_", "")
		s = strings.ReplaceAll(s, "-", "")
		out = append(out, strings.ToLower(s))
	}
	return out
}()

func normKey(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '_' || c == '-' {
			continue
		}
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b = append(b, c)
	}
	return string(b)
}

func keyIsSecret(key string) bool {
	k := normKey(key)
	for _, p := range redactWords {
		if strings.Contains(k, p) {
			return true
		}
	}
	return false
}

// RedactDetail returns a deep-redacted copy of detail. Used by Emit;
// exported so transport / store implementations can apply the same rules.
func RedactDetail(d map[string]any) map[string]any {
	if d == nil {
		return nil
	}
	out := make(map[string]any, len(d))
	for k, v := range d {
		if keyIsSecret(k) {
			out[k] = REDACT_REPLACEMENT
		} else {
			out[k] = redactValue(v)
		}
	}
	return out
}

func redactValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		return RedactDetail(t)
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = redactValue(x)
		}
		return out
	default:
		return v
	}
}
