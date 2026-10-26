package fasten

import (
	"regexp"
	"strings"
)

// Query translation turns search-box text into the reader's own parameters
// (field filters, a request_id, and free-text q), spec §3.7 and §6.3. An
// unknown field:value becomes search text rather than a new filter.

// knownQueryFields are the structured filter fields the reader supports. A
// field:value chip is only produced for one of these.
var knownQueryFields = map[string]bool{
	"request_id": true, "code": true, "domain": true, "source_node_id": true,
	"tenant_id": true, "actor": true, "target": true, "method": true, "path": true,
	"status": true, "service_id": true, "event": true, "level": true,
	"since": true, "until": true,
}

var (
	// A bare token that looks like a request id switches to /correlate.
	// Minted ids are 12 hex chars; >= 8 avoids matching short words.
	hexIDRe  = regexp.MustCompile(`^[0-9a-f]{8,}$`)
	quotedRe = regexp.MustCompile(`"([^"]*)"`)
)

// Chips is a translated query. When RequestID is set the caller should
// correlate instead of filtering. Filters are exact-match and ANDed; Q is
// free text.
type Chips struct {
	RequestID string
	Filters   map[string]string
	Q         string
}

// Translator turns query text into Chips.
type Translator interface {
	Translate(text string) Chips
}

// RuleTranslator applies the §6.3 rules. It doesn't try to parse prose like
// "yesterday 2pm".
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
		qParts = append(qParts, m[1:len(m)-1])
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
