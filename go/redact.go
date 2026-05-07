package fasten

import (
	"regexp"
	"strings"
)

// Deep redaction: two passes before emit.
//   - Pass 1 — key-pattern: keys matching RedactPatterns → RedactReplacement.
//   - Pass 2 — value-shape: string scalars matching known secret shapes (JWT,
//     CC/Luhn, AWS/GH tokens, Stripe, OpenAI) → type-hinting token.

var redactWords = func() []string {
	out := make([]string, 0, len(RedactPatterns))
	for _, p := range RedactPatterns {
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

// ── Value-shape patterns ──────────────────────────────────────────────────

type valuePattern struct {
	re   *regexp.Regexp
	repl string
}

var (
	_ccDigitRE = regexp.MustCompile(`\b\d[\d\s\-]{11,17}\d\b`)
	_valuePatterns = []valuePattern{
		{regexp.MustCompile(`eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+`), "***JWT***"},
		{regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----`), "***PRIVATE_KEY***"},
		{regexp.MustCompile(`(?:AKIA|ASIA)[A-Z0-9]{16}`), "***AWS_KEY***"},
		{regexp.MustCompile(`(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}`), "***GH_TOKEN***"},
		{regexp.MustCompile(`sk_live_[A-Za-z0-9]{24,}`), "***STRIPE_KEY***"},
		{regexp.MustCompile(`sk-(?:proj-)?[A-Za-z0-9_\-]{32,}`), "***OPENAI_KEY***"},
	}
)

func luhnValid(digits string) bool {
	total := 0
	for i, ch := range []byte(digits) {
		n := int(ch - '0')
		if (len(digits)-1-i)%2 == 1 {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		total += n
	}
	return total%10 == 0
}

func checkValueShape(s string) string {
	if m := _ccDigitRE.FindString(s); m != "" {
		digits := strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' {
				return r
			}
			return -1
		}, m)
		if len(digits) >= 13 && len(digits) <= 19 && luhnValid(digits) {
			return "***CC***"
		}
	}
	for _, p := range _valuePatterns {
		if p.re.MatchString(s) {
			return p.repl
		}
	}
	return ""
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
			out[k] = RedactReplacement
		} else {
			out[k] = redactValue(v)
		}
	}
	return out
}

func redactValue(v any) any {
	switch t := v.(type) {
	case string:
		if r := checkValueShape(t); r != "" {
			return r
		}
		return t
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
