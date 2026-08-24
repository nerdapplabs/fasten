package fasten

import (
	"regexp"
	"strings"
)

// Query translation — NL / smart-box input to structured chips (§3.7, §6.3).
//
// Discovery input is translated into the same primitives the reader already
// exposes — structured field filters, a correlation request_id, and the bounded
// free-text q= — so the translator is an interpreter above the reader, not a
// fourth query surface, and it never invents a filter the store doesn't support
// (an unknown field:value becomes search text). Mirrors the Python fasten.query.

// knownQueryFields are the structured filter fields the reader supports. A
// field:value chip is only produced for one of these.
var knownQueryFields = map[string]bool{
	"request_id": true, "code": true, "domain": true, "source_node_id": true,
	"tenant_id": true, "actor": true, "target": true, "method": true, "path": true,
	"status": true, "service_id": true, "event": true, "level": true,
	"since": true, "until": true,
}

var (
	// A bare token that looks like a correlation id → pivot to /correlate.
	// mint id is 12 hex chars; require >= 8 to avoid matching short words.
	hexIDRe  = regexp.MustCompile(`^[0-9a-f]{8,}$`)
	quotedRe = regexp.MustCompile(`"([^"]*)"`)
)

// Chips is the translated query: the three reader primitives side by side.
// RequestID is the exclusive correlation pivot (when set, correlate rather than
// filter). Filters are structured exact-match chips composed with AND. Q is the
// bounded free-text fallback.
type Chips struct {
	RequestID string
	Filters   map[string]string
	Q         string
}

// Translator turns query text into Chips. The rule-based OSS translator and a
// cloud NL model are interchangeable behind it.
type Translator interface {
	Translate(text string) Chips
}

// RuleTranslator is the deterministic reference translator — the §6.3 smart-box
// rules. Prose like "yesterday 2pm" is left to a cloud NL model; this parser
// does not guess time ranges it cannot ground.
type RuleTranslator struct{}

func (RuleTranslator) Translate(text string) Chips {
	text = strings.TrimSpace(text)
	if len(text) >= 4 && strings.EqualFold(text[:4], "ask:") {
		text = strings.TrimSpace(text[4:])
	}
	chips := Chips{Filters: map[string]string{}}
	var qParts []string

	// Quoted spans are free-text, verbatim.
	remainder := quotedRe.ReplaceAllStringFunc(text, func(m string) string {
		qParts = append(qParts, m[1:len(m)-1]) // strip the surrounding quotes
		return " "
	})

	for _, tok := range strings.Fields(remainder) {
		if field, value, ok := strings.Cut(tok, ":"); ok && value != "" && knownQueryFields[strings.ToLower(field)] {
			if strings.ToLower(field) == "request_id" {
				chips.RequestID = value
			} else {
				chips.Filters[strings.ToLower(field)] = value
			}
			continue
		}
		if looksLikeRequestID(tok) {
			chips.RequestID = tok
			continue
		}
		qParts = append(qParts, tok)
	}
	if len(qParts) > 0 {
		chips.Q = strings.Join(qParts, " ")
	}
	return chips
}

func looksLikeRequestID(tok string) bool {
	return hexIDRe.MatchString(tok) || IsSentinel(tok)
}

// TranslateQuery translates query text with the default rule translator.
func TranslateQuery(text string) Chips { return RuleTranslator{}.Translate(text) }
