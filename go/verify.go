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

// currentCanonicalFormID is stamped on every row this SDK seals. It must
// match Python's CURRENT_CANONICAL_FORM_ID.
//
// Form "1": SHA-256 of the canonical JSON of pyCanonicalRowMap (without
// "hash", with canonical_form_id), matching Python's form "1" hash:
// AuditRow.to_dict() with timestamps in isoformat (+00:00) form, through
// json.dumps(sort_keys=True, separators=(',',':'), default=str).
//
// Form "2" (spec §1.4): detail_commitment replaces detail in the hashed set,
// so detail can be removed for retention without changing the hash. Old
// rows keep verifying under form "1" and are never re-sealed. VerifyChain
// picks the form per row and rejects an unknown id.
const currentCanonicalFormID = "2"

// legacyCanonicalFormID is the form of a row without canonical_form_id: it
// predates the field, so it is form "1".
const legacyCanonicalFormID = "1"

// hashFnByForm maps a canonical_form_id to its row hash function. A new form
// is added here and stamped in Seal; VerifyChain picks it up from this map.
var hashFnByForm = map[string]func(Row) string{
	"1": rowHashPyCompat,
	"2": rowHashForm2,
}

// Seal returns a copy of row sealed into the chain: it stamps the current
// CanonicalFormID, sets PrevHash, sets the detail salt and commitment, and
// computes Hash. Emit seals through this.
func Seal(prevHash string, row Row) Row {
	row.CanonicalFormID = currentCanonicalFormID
	row.PrevHash = prevHash
	// A replicated row arrives with its own salt; keep it.
	if row.DetailSalt == "" {
		row.DetailSalt = newDetailSalt()
	}
	row.DetailCommitment = detailCommitment(row.DetailSalt, row.Detail)
	row.Hash = hashFnByForm[currentCanonicalFormID](row)
	return row
}

// newDetailSalt returns 32 random bytes, hex-encoded, like Python's
// secrets.token_hex(32).
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

// VerifyChain checks the hash chain over rows and reports whether it is
// intact. Row hashes match Python's, so chains sealed by either SDK verify
// here. The hashed form and rendering rules are specified in
// ../spec/chain-replication.md.
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
			// A row without the field predates it, so it is form "1".
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
		if expected != row.Hash && formID == "1" {
			// Pre-conformance Python hashed the wire timestamp verbatim
			// (always-"Z") while the spec and Go use "+00:00" — the
			// divergence in #91. Those rows exist in deployments and are not
			// tampered; without this they verify in Python (which has the
			// same fallback) and fail here, which reads as tampering.
			// Delete with form "1".
			expected = rowHashForm1LegacyZ(row)
		}
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
//   - the exact Python field set (no pii_in_detail, which the Go Row
//     carries but the Python AuditRow does not),
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

// rowHashForm1LegacyZ is form "1" as pre-conformance Python actually sealed
// it: the always-"Z" wire timestamp hashed verbatim, instead of the spec §1.2
// "+00:00" variable-width rendering. Mirrors Python's
// _row_hash_form_1_legacy_z. Verification fallback only — never used to seal.
func rowHashForm1LegacyZ(row Row) string {
	d := pyCanonicalRowMap(row)
	delete(d, "hash")
	d["timestamp"] = canonicalTS(row.Timestamp)
	if row.ShippedAt != nil {
		d["shipped_at"] = canonicalTS(*row.ShippedAt)
	}
	sum := sha256.Sum256(canonicalJSON(d))
	return hex.EncodeToString(sum[:])
}

// rowHashForm2 hashes form "2" (spec §1.4): form "1"'s fields with detail
// replaced by detail_commitment, and timestamps in the same canonical form
// as on the wire (form "1" used a separate "+00:00" rendering).
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

// pyCanonicalRowMap builds the map with the same keys and value encodings as
// Python's AuditRow.to_dict(), without "hash" (and without pii_in_detail,
// which Python's dict doesn't have).
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

// pyISOFormat formats t as Python's datetime.isoformat() does for a UTC
// datetime:
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
// encoding/json already sorts map keys and is compact, so this only turns off
// HTML escaping and escapes non-ASCII runes as \uXXXX. Bytes >= 0x80 only
// appear inside strings, so that is safe.
func canonicalJSON(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	// The maps built here always encode, so the error is ignored.
	_ = enc.Encode(v)
	out := bytes.TrimRight(buf.Bytes(), "\n")
	return asciiEscape(out)
}

// asciiEscape replaces every non-ASCII rune in the JSON bytes with its \uXXXX
// (or surrogate-pair) escape, matching Python json.dumps ensure_ascii=True.
func asciiEscape(b []byte) []byte {
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
			// Invalid UTF-8: copy the byte as is.
			sb.WriteByte(c)
			i++
			continue
		}
		if r > 0xFFFF {
			// UTF-16 surrogate pair, as Python writes it.
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
