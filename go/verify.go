package fasten

import (
	"bytes"
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
		expected := rowHashPyCompat(row)
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
	return map[string]any{
		"id":             row.ID,
		"origin_id":      row.OriginID,
		"monotonic_seq":  row.MonotonicSeq,
		"timestamp":      pyISOFormat(row.Timestamp),
		"code":           string(row.Code),
		"action":         row.Action,
		"severity":       string(row.Severity),
		"service_id":     row.ServiceID,
		"source_node_id": row.SourceNodeID,
		"tenant_id":      tenant,
		"actor":          row.Actor,
		"actor_kind":     row.ActorKind,
		"target":         row.Target,
		"category":       row.Category,
		"domain":         string(row.Domain),
		"method":         row.Method,
		"request_id":     row.RequestID,
		"detail":         detail,
		"wire_version":   wire,
		"shipped_at":     shipped,
		"prev_hash":      row.PrevHash,
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
