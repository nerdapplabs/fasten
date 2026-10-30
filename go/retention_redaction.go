package fasten

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// PII retention (spec §7.1, §7.2): Detail on PII rows is destroyed sooner
// than the rows themselves, which are kept by age.
//
// Rows are redacted, not deleted, because deleting from a hash chain shows up
// as tampering in VerifyChain. Under form "2" the hash covers
// DetailCommitment rather than Detail, so Detail can go while the hash,
// PrevHash and MonotonicSeq stay.

// RedactionCandidate is a row that a PII horizon would redact. MonotonicSeq
// travels with the id because spec §7.2 records redacted_seq, which is not
// derivable from the id.
type RedactionCandidate struct {
	ID           string
	MonotonicSeq int64
}

// RedactionRepository is the spec §7.1 capability. Listing and redacting are
// separate so the caller can write the §7.2 record before anything is
// destroyed; the other order can lose rows with no record and nothing to retry.
type RedactionRepository interface {
	// The int is the number of form-"1" rows past the horizon that were NOT
	// returned because their detail is inside the hash. Reported by the
	// caller, which has the sys stream; a store writing to stderr puts a
	// privacy-relevant miss somewhere nothing is monitoring.
	ListRedactionCandidates(ctx context.Context, before time.Time, codes []Code) ([]RedactionCandidate, int, error)
	RedactRows(ctx context.Context, ids []string) ([]string, error)
}

// piiCodes returns the codes whose rows may carry personal data in Detail:
// those with PiiInDetail or RetShort. Register forces PiiInDetail codes to
// RetShort, and setting RetShort directly means the same for retention.
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

// RedactExpired destroys Detail on expired PII rows and records each one
// (spec §7.1, §7.2). It returns the ids redacted.
//
// The record is written first. If that fails nothing is destroyed; if the
// destroy fails the data is intact and the next run picks it up again.
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
	// One row at a time, so a failed destroy can only duplicate the record
	// for that one row on the next run, not for the whole batch.
	redacted := make([]string, 0, len(candidates))
	for _, c := range candidates {
		// durable=true: in queue mode a plain Emit returns before the row is
		// stored, and the destroy must not run unless the record persisted.
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
