package fasten

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// PII retention horizon (P1-55), the Go half of P1-47.
//
// PiiInDetail=true forced RetShort at register-time and force-redacted Detail
// on Emit, but nothing expired anything: startRetention only ever covered the
// api and sys streams, and no Go store could destroy a stored payload. An
// operator could not express "personal data gone at 30 days, operational
// history kept a year" at all.

// RedactionCandidate is a row that a PII horizon would redact. MonotonicSeq
// travels with the id because spec §7.2 records redacted_seq, which is not
// derivable from the id.
type RedactionCandidate struct {
	ID           string
	MonotonicSeq int64
}

// RedactionRepository is the spec §7.1 capability. Split in two halves so a
// caller can write its §7.2 records BEFORE anything is destroyed: the reverse
// order has a window where the rows are gone and the record fails, leaving no
// trace and nothing a retry can find.
type RedactionRepository interface {
	ListRedactionCandidates(ctx context.Context, before time.Time, codes []Code) ([]RedactionCandidate, error)
	RedactRows(ctx context.Context, ids []string) ([]string, error)
}

// piiCodes returns the codes whose rows may carry personal data in Detail.
//
// Includes a code if it declares PiiInDetail OR is classified RetShort — the
// register-time forcing makes the first imply the second, and an adopter who
// sets RetShort directly has said the same thing about retention.
func piiCodes() []Code {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]Code, 0, len(_registry))
	for code, meta := range _registry {
		if meta.PiiInDetail || meta.RetentionClass == RetShort {
			out = append(out, code)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// CodeAuditRowRedacted is fasten's own code for the spec §7.2 redaction event.
// Registered lazily on first use so adopters who never redact don't carry it.
const CodeAuditRowRedacted Code = "AUDIT_ROW_REDACTED"

const redactionDomain Domain = "fasten"

func ensureRedactionCode() error {
	if _, ok := metaOf(CodeAuditRowRedacted); ok {
		return nil
	}
	return Register(redactionDomain, map[Code]Meta{
		CodeAuditRowRedacted: {
			ID:             CodeAuditRowRedacted,
			Domain:         redactionDomain,
			Category:       "retention",
			Action:         "redact",
			Severity:       SevWarn,
			Description:    "Audit row detail destroyed under a retention policy",
			Emitter:        "fasten",
			RetentionClass: RetLong,
		},
	})
}

// RedactExpired destroys Detail on expired PII rows AND records that it
// happened (spec §7.1 + §7.2). Returns the ids redacted.
//
// Records before destroying: an emit failure then destroys nothing and the
// retry is clean, and a destroy failure leaves the data intact under a record
// the next tick converges on.
func (e *Engine) RedactExpired(ctx context.Context, before time.Time, reason string) ([]string, error) {
	store, ok := e.auditStore.(RedactionRepository)
	if !ok {
		return nil, fmt.Errorf(
			"fasten.RedactExpired: audit store %T does not implement "+
				"RedactionRepository (spec §7.1)", e.auditStore)
	}
	codes := piiCodes()
	if len(codes) == 0 {
		return nil, nil
	}
	if err := ensureRedactionCode(); err != nil {
		return nil, err
	}
	candidates, err := store.ListRedactionCandidates(ctx, before, codes)
	if err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	if reason == "" {
		reason = "retention"
	}
	ids := make([]string, 0, len(candidates))
	for _, c := range candidates {
		if _, err := e.Emit(ctx, CodeAuditRowRedacted,
			Target(c.ID),
			// spec §7.2 shape; redacted_id too, since seq is only unique per
			// source node.
			WithDetail(map[string]any{
				"redacted_seq": c.MonotonicSeq,
				"reason":       reason,
				"redacted_id":  c.ID,
			}),
		); err != nil {
			return nil, fmt.Errorf("fasten.RedactExpired: recording the §7.2 event for %s failed, nothing destroyed: %w", c.ID, err)
		}
		ids = append(ids, c.ID)
	}
	return store.RedactRows(ctx, ids)
}
