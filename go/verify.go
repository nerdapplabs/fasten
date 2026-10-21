package fasten

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// currentCanonicalFormID is stamped on every row sealed by this SDK version.
//
// Canonical forms
// ---------------
// The hashed canonical form is versioned via Row.CanonicalFormID so the choice
// of bytes is tamper-evident and future forms are additive.
//
// Form "1": SHA-256 of the canonical JSON of the row map built by
// pyCanonicalRowMap (the "hash" key excluded, canonical_form_id INCLUDED),
// matching Python json.dumps(sort_keys=True, separators=(',',':'),
// default=str) over AuditRow.to_dict() byte-for-byte.
//
// Form "2" (spec §1.4, what we seal now): detail_commitment replaces detail in
// the hashed set, so detail can be destroyed for retention without moving the
// hash. Form "1" rows still verify under form "1" — old rows are never
// re-sealed, which would destroy the evidence.
//
// This MUST match Python's CURRENT_CANONICAL_FORM_ID. While Go sealed "1" and
// Python sealed "2", the two SDKs produced different forms for the same row,
// and the PII horizon (Config.RetentionPII) could never fire on a Go-sealed
// row: form "1" hashes detail directly, so redacting one breaks the chain.
// VerifyChain dispatches per row and REJECTS an unknown id.
const currentCanonicalFormID = "2"

// legacyCanonicalFormID is the form a row carries when canonical_form_id is
// absent — i.e. it was written before the field existed, which means form "1".
const legacyCanonicalFormID = "1"

// hashFnByForm maps a canonical_form_id to the function that hashes a row under
// that form. Adding v2 is purely additive: register a new id here, stamp it in
// Seal, and VerifyChain dispatches automatically.
var hashFnByForm = map[string]func(Row) string{
	"1": rowHashPyCompat,
	"2": rowHashForm2,
}

// Seal returns a copy of row sealed into the chain: it stamps the current
// CanonicalFormID, sets PrevHash, mints the form-"2" salt/commitment, and
// computes the self Hash. This is the ONE canonical way to seal a row — Emit
// goes through it, so Go Emit, Go VerifyChain and Python seal agree on a
// single field set.
func Seal(prevHash string, row Row) Row {
	row.CanonicalFormID = currentCanonicalFormID
	row.PrevHash = prevHash
	// Mirrors Python chain.seal: reuse a caller-supplied salt (a replicated
	// row arrives with its own) and mint one otherwise.
	if row.DetailSalt == "" {
		row.DetailSalt = newDetailSalt()
	}
	row.DetailCommitment = detailCommitment(row.DetailSalt, row.Detail)
	row.Hash = hashFnByForm[currentCanonicalFormID](row)
	return row
}

// newDetailSalt mints a 32-byte salt, hex-encoded — the same shape as Python's
// secrets.token_hex(32), so a commitment is reproducible across SDKs.
func newDetailSalt() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is not recoverable: a predictable salt makes the
		// commitment guessable, which is the one thing it exists to prevent.
		panic("fasten: crypto/rand unavailable, cannot mint a detail salt: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// VerifyResult is the outcome of VerifyChain.
//
// OK is true when every hash-bearing row's recomputed hash matches its stored
// hash AND each row's PrevHash matches the preceding row's Hash. FirstBreakAt
// is the MonotonicSeq of the first row that fails either check (0 when OK).
type VerifyResult struct {
	OK           bool   `json:"ok"`
	TotalRows    int    `json:"total_rows"`
	FirstBreakAt int64  `json:"first_break_at"`
	Reason       string `json:"reason"`
}

// VerifyChain walks the per-row tamper-evidence hash chain and reports whether
// it is intact. It is the Go counterpart of the Python fasten.verify_chain and
// produces byte-for-byte identical row hashes, so a Go upstream aggregator can
// verify chains that were sealed by a Python node.
//
// The canonical hashed form, the cross-language rendering rules (including the
// whole-number-float hazard in §1.3), the canonical_form_id registry, and the
// replication contract are normative in ../spec/chain-replication.md.
//
// Semantics mirror Python engine.py verify_chain exactly:
//
//   - Rows are sorted by MonotonicSeq before walking.
//   - Rows with an empty Hash (written before hash-chain support) are skipped.
//   - For each hash-bearing row the canonical row hash is recomputed and
//     compared to the stored Hash.
//   - Each row's PrevHash is compared to the preceding row's Hash.
//   - On the first mismatch the walk stops and returns OK=false with
//     FirstBreakAt set to that row's MonotonicSeq.
//
// It does NOT detect tail truncation — that needs an external tip anchor.
func VerifyChain(rows []Row) VerifyResult {
	total := len(rows)
	if total == 0 {
		return VerifyResult{OK: true, TotalRows: 0}
	}

	sorted := make([]Row, total)
	copy(sorted, rows)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].MonotonicSeq < sorted[j].MonotonicSeq
	})

	for i, row := range sorted {
		if row.Hash == "" {
			continue // pre-upgrade row; skip
		}
		formID := row.CanonicalFormID
		if formID == "" {
			// "1", NOT currentCanonicalFormID: a row written before the field
			// existed IS form "1". Defaulting to "current" silently
			// re-interpreted every legacy row the moment the SDK started
			// sealing "2", and they then failed the commitment check.
			formID = legacyCanonicalFormID
		}
		hashFn, ok := hashFnByForm[formID]
		if !ok {
			return VerifyResult{
				OK:           false,
				TotalRows:    total,
				FirstBreakAt: row.MonotonicSeq,
				Reason:       fmt.Sprintf("row %s: unknown canonical_form_id %q", row.ID, formID),
			}
		}
		// Form "2" hashes detail_commitment, NOT detail. The hash therefore
		// does not protect detail on its own: an attacker could rewrite detail
		// and leave the commitment intact. Whenever detail is present the
		// commitment MUST be recomputable and must match — and a missing salt
		// is a break, not a skip, or clearing it would disable the check.
		// Redaction clears detail AND salt together (spec §7.1), so a
		// legitimately redacted row never reaches here.
		if formID == "2" && row.Detail != nil {
			if row.DetailSalt == "" {
				return VerifyResult{
					OK:           false,
					TotalRows:    total,
					FirstBreakAt: row.MonotonicSeq,
					Reason: fmt.Sprintf(
						"row %s: detail present but detail_salt is missing — commitment cannot be verified",
						row.ID),
				}
			}
			if detailCommitment(row.DetailSalt, row.Detail) != row.DetailCommitment {
				return VerifyResult{
					OK:           false,
					TotalRows:    total,
					FirstBreakAt: row.MonotonicSeq,
					Reason:       fmt.Sprintf("row %s: detail does not match its commitment", row.ID),
				}
			}
		}

		expected := hashFn(row)
		if expected != row.Hash {
			return VerifyResult{
				OK:           false,
				TotalRows:    total,
				FirstBreakAt: row.MonotonicSeq,
				Reason:       fmt.Sprintf("row %s: hash mismatch", row.ID),
			}
		}
		if i > 0 {
			prev := sorted[i-1]
			if prev.Hash != "" && row.PrevHash != prev.Hash {
				return VerifyResult{
					OK:           false,
					TotalRows:    total,
					FirstBreakAt: row.MonotonicSeq,
					Reason: fmt.Sprintf(
						"row %s: prev_hash does not match preceding row %s", row.ID, prev.ID),
				}
			}
		}
	}
	return VerifyResult{OK: true, TotalRows: total}
}

// rowHashPyCompat reproduces Python fasten.engine._row_hash byte-for-byte:
// SHA-256 of the canonical JSON of the row dict with the "hash" field excluded.
//
// The canonical form matches Python's
//
//	json.dumps(d, sort_keys=True, separators=(',',':'), default=str)
//
// over AuditRow.to_dict(), which means:
//   - the exact Python field set (NOTE: no pii_in_detail, which the Go wire
//     Row carries but the Python AuditRow does not),
//   - sorted keys (top level and nested), compact separators,
//   - None -> null for tenant_id / shipped_at,
//   - timestamp / shipped_at as Python datetime.isoformat() strings,
//   - non-ASCII escaped as \uXXXX (Python json.dumps ensure_ascii=True),
//   - <, >, & left literal (Python does not HTML-escape).
func rowHashPyCompat(row Row) string {
	d := pyCanonicalRowMap(row)
	b := canonicalJSON(d)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// detailCommitment is the salted commitment to detail (spec §1.4):
// sha256(salt || canonical_json(detail)). Must match
// python/fasten/chain.py::detail_commitment byte for byte.
//
// The salt is what makes the commitment hiding. An unsalted digest of a
// low-entropy value is a dictionary attack away from the original, so
// redaction drops the salt along with the payload.
func detailCommitment(salt string, detail map[string]any) string {
	if detail == nil {
		detail = map[string]any{}
	}
	sum := sha256.Sum256(append([]byte(salt), canonicalJSON(detail)...))
	return hex.EncodeToString(sum[:])
}

// rowHashForm2 hashes form "2" (spec §1.4): form "1"'s field set with detail
// and detail_salt removed and detail_commitment added, and the timestamp taken
// VERBATIM from the wire form rather than re-rendered.
//
// Form "1" hashed "+00:00" while the row carried always-"Z" on the wire, so
// every SDK needed a second private timestamp renderer used only in the hash
// path — which is how Go and Python drifted apart inside it (P1-48). Form "2"
// has one timestamp form, the one already written to the wire.
func rowHashForm2(row Row) string {
	d := pyCanonicalRowMap(row)
	delete(d, "detail")
	d["detail_commitment"] = row.DetailCommitment
	d["timestamp"] = canonicalTS(row.Timestamp)
	if row.ShippedAt != nil {
		d["shipped_at"] = canonicalTS(*row.ShippedAt)
	}
	sum := sha256.Sum256(canonicalJSON(d))
	return hex.EncodeToString(sum[:])
}

// pyCanonicalRowMap builds the map whose key set and value encodings match
// Python AuditRow.to_dict() minus the "hash" key. pii_in_detail is
// deliberately omitted because the Python row dict never contains it.
func pyCanonicalRowMap(row Row) map[string]any {
	var tenant any
	if row.TenantID != nil {
		tenant = *row.TenantID
	}
	var shipped any
	if row.ShippedAt != nil {
		shipped = pyISOFormat(*row.ShippedAt)
	}
	wire := row.WireVersion
	if wire == "" {
		wire = "1"
	}
	detail := row.Detail
	if detail == nil {
		detail = map[string]any{}
	}
	formID := row.CanonicalFormID
	if formID == "" {
		formID = legacyCanonicalFormID // see VerifyChain
	}
	return map[string]any{
		"canonical_form_id": formID,
		"id":                row.ID,
		"origin_id":         row.OriginID,
		"monotonic_seq":     row.MonotonicSeq,
		"timestamp":         pyISOFormat(row.Timestamp),
		"code":              string(row.Code),
		"action":            row.Action,
		"severity":          string(row.Severity),
		"service_id":        row.ServiceID,
		"source_node_id":    row.SourceNodeID,
		"tenant_id":         tenant,
		"actor":             row.Actor,
		"actor_kind":        row.ActorKind,
		"target":            row.Target,
		"category":          row.Category,
		"domain":            string(row.Domain),
		"method":            row.Method,
		"request_id":        row.RequestID,
		"detail":            detail,
		"wire_version":      wire,
		"shipped_at":        shipped,
		"prev_hash":         row.PrevHash,
	}
}

// pyISOFormat formats t exactly as Python datetime.isoformat() does for a
// UTC-aware datetime: the timestamps fasten emits are always tz-aware UTC, so
//   - the offset is rendered as "+00:00" (not "Z"),
//   - the fractional part is omitted entirely when microseconds == 0,
//   - otherwise it is exactly six digits (microseconds, trailing zeros kept),
//   - nanosecond precision is truncated to microseconds (Python has none).
func pyISOFormat(t time.Time) string {
	u := t.UTC()
	base := u.Format("2006-01-02T15:04:05")
	micros := u.Nanosecond() / 1000
	if micros != 0 {
		base += "." + fmt.Sprintf("%06d", micros)
	}
	return base + "+00:00"
}

// canonicalJSON renders v the way Python's
// json.dumps(v, sort_keys=True, separators=(',',':'), default=str, ensure_ascii=True)
// would: sorted keys, compact separators, HTML left literal, non-ASCII escaped.
//
// Go's encoding/json already sorts map keys and uses compact separators, so we
// only have to (a) disable Go's default HTML escaping and (b) escape non-ASCII
// runes to \uXXXX. Because every structural JSON byte is ASCII, escaping any
// byte >= 0x80 is safe and only touches string contents.
func canonicalJSON(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	// Encode panics-free for the map shapes we build; an error here would be a
	// programming bug, not runtime data, so we surface the encoder's own bytes.
	_ = enc.Encode(v)
	// Encoder appends a trailing newline; strip it.
	out := bytes.TrimRight(buf.Bytes(), "\n")
	return asciiEscape(out)
}

// asciiEscape replaces every non-ASCII rune in the JSON bytes with its \uXXXX
// (or surrogate-pair) escape, matching Python json.dumps ensure_ascii=True.
func asciiEscape(b []byte) []byte {
	// Fast path: pure ASCII needs no rewrite.
	if isASCII(b) {
		return b
	}
	var sb strings.Builder
	for i := 0; i < len(b); {
		c := b[i]
		if c < utf8.RuneSelf {
			sb.WriteByte(c)
			i++
			continue
		}
		r, size := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && size == 1 {
			// Invalid byte — emit as-is to avoid corrupting length.
			sb.WriteByte(c)
			i++
			continue
		}
		if r > 0xFFFF {
			// Encode as a UTF-16 surrogate pair, matching Python.
			r -= 0x10000
			hi := 0xD800 + (r >> 10)
			lo := 0xDC00 + (r & 0x3FF)
			sb.WriteString(`\u` + strconv.FormatInt(int64(hi), 16))
			sb.WriteString(`\u` + strconv.FormatInt(int64(lo), 16))
		} else {
			sb.WriteString(`\u` + padHex(r))
		}
		i += size
	}
	return []byte(sb.String())
}

func isASCII(b []byte) bool {
	for _, c := range b {
		if c >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// padHex returns the lowercase 4-digit hex of r, matching Python's \uXXXX form.
func padHex(r rune) string {
	h := strconv.FormatInt(int64(r), 16)
	for len(h) < 4 {
		h = "0" + h
	}
	return h
}
