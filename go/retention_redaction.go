package fasten

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// The PII retention horizon: expiring a stored audit payload without breaking
// the chain it belongs to (spec §7.1/§7.2).
//
// Two horizons, because one cannot express the policy: operational history is
// kept by age, while personal data in Detail goes sooner. A single age purge
// forces a choice between destroying the history too or keeping the personal
// data as long as the history.
//
// Redaction, never deletion — removing a row from a hash-chained stream is
// what VerifyChain reports as tampering. Under form "2" the hash covers
// DetailCommitment rather than Detail, so the payload can be destroyed while
// the hash, PrevHash and MonotonicSeq stay put (P1-55).

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
	// The int is the number of form-"1" rows past the horizon that were NOT
	// returned because their detail is inside the hash. Reported by the
	// caller, which has the sys stream; a store writing to stderr puts a
	// privacy-relevant miss somewhere nothing is monitoring.
	ListRedactionCandidates(ctx context.Context, before time.Time, codes []Code) ([]RedactionCandidate, int, error)
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
	candidates, skippedForm1, err := store.ListRedactionCandidates(ctx, before, codes)
	if err != nil {
		return nil, err
	}
	if skippedForm1 > 0 {
		e.drainerSysLog("warn", "pii_redaction_skipped_legacy_form", map[string]any{
			"rows": skippedForm1,
			"reason": "canonical_form_id != 2; detail is inside the hash, " +
				"so redacting would break the chain. The personal data in " +
				"these rows still exists.",
		})
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	if reason == "" {
		reason = "retention"
	}
	// One row at a time, record then destroy. Emitting the whole batch and
	// then destroying it in one call meant a failed destroy left every row
	// still a candidate, so the next tick re-emitted a record for all of them
	// — duplicate events scaling with the batch. Per row, only the row that
	// failed between its own record and its destroy can repeat.
	redacted := make([]string, 0, len(candidates))
	for _, c := range candidates {
		// emitRow(durable=true): queue mode (the default) swallows store
		// failures and returns normally, so a plain Emit let the destroy
		// proceed for rows whose record had never persisted.
		if _, err := e.emitRow(ctx, CodeAuditRowRedacted, true,
			Target(c.ID),
			// spec §7.2 shape; redacted_id too, since seq is only unique per
			// source node.
			WithDetail(map[string]any{
				"redacted_seq": c.MonotonicSeq,
				"reason":       reason,
				"redacted_id":  c.ID,
			}),
		); err != nil {
			return redacted, fmt.Errorf("fasten.RedactExpired: recording the §7.2 event for %s failed, nothing destroyed for it: %w", c.ID, err)
		}
		done, err := store.RedactRows(ctx, []string{c.ID})
		if err != nil {
			return redacted, err
		}
		redacted = append(redacted, done...)
	}
	return redacted, nil
}
