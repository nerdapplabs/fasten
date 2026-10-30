package fasten

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"sync"
)

// RingBuffer is a thread-safe, fixed-capacity circular buffer. The oldest
// entry is overwritten when full. Queries return newest-first.
type RingBuffer[T any] struct {
	buf   []T
	mu    sync.RWMutex
	cap   int
	head  int // index of next-write slot in buf
	count int // entries currently stored (<= cap)
}

func newRingBuffer[T any](capacity int) *RingBuffer[T] {
	return &RingBuffer[T]{cap: capacity, buf: make([]T, capacity)}
}

func (rb *RingBuffer[T]) Push(item T) {
	if rb.cap == 0 {
		// Capacity 0 keeps nothing, like Python's deque(maxlen=0). cap never
		// changes, so no lock is needed here.
		return
	}
	rb.mu.Lock()
	defer rb.mu.Unlock()
	rb.buf[rb.head] = item
	rb.head = (rb.head + 1) % rb.cap
	if rb.count < rb.cap {
		rb.count++
	}
}

// All returns a snapshot newest-first.
func (rb *RingBuffer[T]) All() []T {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	out := make([]T, rb.count)
	for i := 0; i < rb.count; i++ {
		idx := (rb.head - 1 - i + rb.cap) % rb.cap
		out[i] = rb.buf[idx]
	}
	return out
}

func (rb *RingBuffer[T]) Len() int {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.count
}

// SyslogRow is a structured syslog entry.
type SyslogRow map[string]any

// APIRow is a structured API request log entry.
type APIRow map[string]any

// Transport owns the ring buffers and stdout writes. Sys and api rows go to
// the rings only (the caller owns stdout); audit rows are also printed to
// stdout.
//
// If a stream has a store attached, rows are written to both the ring and
// the store, and reads for that stream come from the store.
type Transport struct {
	Syslog      *RingBuffer[SyslogRow]
	API         *RingBuffer[APIRow]
	SyslogStore StreamRepository
	APIStore    StreamRepository

	// Sentinel invariant: rows written before the first real request belong to
	// one stable boot window; context-less rows after that are orphans.
	serviceID     string
	bootRequestID string
	bootMu        sync.Mutex
	bootOver      bool

	// redact is set by Init to the Engine's redactDetail and applied to sys
	// and api rows before they are stored anywhere. Nil before Init.
	redact func(map[string]any) map[string]any
}

func NewTransport(maxlen int) *Transport {
	return &Transport{
		Syslog: newRingBuffer[SyslogRow](maxlen),
		API:    newRingBuffer[APIRow](maxlen),
	}
}

// stampRequestID guarantees a non-empty request_id on every stream row (the
// sentinel invariant). A real id ends the boot window; a missing id is filled
// with the shared boot sentinel during startup, else a unique orphan id.
func (t *Transport) stampRequestID(row map[string]any) {
	if rid, _ := row["request_id"].(string); rid != "" {
		if !IsSentinel(rid) {
			t.bootMu.Lock()
			t.bootOver = true
			t.bootMu.Unlock()
		}
		return
	}
	t.bootMu.Lock()
	useBoot := t.bootRequestID != "" && !t.bootOver
	t.bootMu.Unlock()
	if useBoot {
		row["request_id"] = t.bootRequestID
	} else {
		row["request_id"] = MintSentinel("orphan", t.serviceID)
	}
}

// PushSyslog adds a syslog row to the ring and, if attached, the store. It
// doesn't write to stdout; the slog handler does that.
//
// A store failure is reported on stderr and not returned, so logging never
// fails. It is also counted on the store, which marks the stream
// "store-degraded"; reads come from the store, so they would otherwise
// miss the row without saying so.
func (t *Transport) PushSyslog(row SyslogRow) {
	t.stampRequestID(row)
	row = SyslogRow(t.redactRow(row))
	t.Syslog.Push(row)
	if t.SyslogStore != nil {
		if err := t.SyslogStore.Insert(row); err != nil {
			t.SyslogStore.NoteWriteFailure()
			// Type-only stderr: a Postgres INSERT error message can carry
			// the offending row value (NotNullViolation cites the column),
			// and stderr is not redacted.
			fmt.Fprintf(os.Stderr, "fasten: syslog persist failed: %T\n", err)
		}
	}
}

// PushAPI adds an API request row to the ring and, if attached, the store.
// Store failures are handled as in PushSyslog.
func (t *Transport) PushAPI(row APIRow) {
	t.stampRequestID(row)
	row = APIRow(t.redactRow(row))
	t.API.Push(row)
	if t.APIStore != nil {
		if err := t.APIStore.Insert(row); err != nil {
			t.APIStore.NoteWriteFailure()
			// Type-only stderr; see PushSyslog for why.
			fmt.Fprintf(os.Stderr, "fasten: api persist failed: %T\n", err)
		}
	}
}

// redactRow applies the redact hook, if set.
func (t *Transport) redactRow(row map[string]any) map[string]any {
	if t.redact == nil {
		return row
	}
	return t.redact(row)
}

// SyslogDepth returns the current number of syslog rows in the ring buffer.
func (t *Transport) SyslogDepth() int { return t.Syslog.Len() }

// APIDepth returns the current number of API-log rows in the ring buffer.
func (t *Transport) APIDepth() int { return t.API.Len() }

// WriteAudit writes an audit row to stdout as {"shape":"audit",...} JSON.
func (t *Transport) WriteAudit(row map[string]any) {
	row["shape"] = "audit"
	b, err := json.Marshal(row)
	if err != nil {
		return
	}
	fmt.Println(string(b))
}

// StreamQuery holds the optional filters for a sys/api stream read. Empty
// fields are ignored. Ring and store reads apply them the same way.
//
// Since and Until are compared as strings, which only works for timestamps
// in the canonical form (see canonical_ts.go, spec §4.3).
type StreamQuery struct {
	Level     string // sys
	ServiceID string // sys
	Event     string // sys
	Method    string // api
	Path      string // api
	Status    string // api ("" = no filter; matched against the row's value)
	RequestID string // common
	Since     string // common: timestamp >= Since
	Until     string // common: timestamp <= Until
}

func tsOf(r map[string]any) string { s, _ := r["timestamp"].(string); return s }

func inWindow(ts, since, until string) bool {
	if since != "" && ts < since {
		return false
	}
	if until != "" && ts > until {
		return false
	}
	return true
}

// syslogMatches applies q's sys filters to a ring row.
func syslogMatches(r SyslogRow, q StreamQuery) bool {
	if q.Level != "" && r["level"] != q.Level {
		return false
	}
	if q.RequestID != "" && r["request_id"] != q.RequestID {
		return false
	}
	if q.ServiceID != "" && r["service_id"] != q.ServiceID {
		return false
	}
	if q.Event != "" && r["event"] != q.Event {
		return false
	}
	return inWindow(tsOf(r), q.Since, q.Until)
}

// apiMatches applies q's api filters to a ring row.
func apiMatches(r APIRow, q StreamQuery) bool {
	if q.Method != "" && r["method"] != q.Method {
		return false
	}
	if q.Path != "" {
		if p, _ := r["path"].(string); q.Path != p {
			return false
		}
	}
	if q.RequestID != "" && r["request_id"] != q.RequestID {
		return false
	}
	if q.Status != "" && !statusEquals(r["status"], q.Status) {
		return false
	}
	return inWindow(tsOf(r), q.Since, q.Until)
}

// QuerySyslog returns up to limit syslog rows, newest-first, from the store
// if one is attached, otherwise from the ring.
func (t *Transport) QuerySyslog(limit int, q StreamQuery) ([]SyslogRow, error) {
	if t.SyslogStore != nil {
		rows, err := t.SyslogStore.Query(limit, map[string]string{
			"level": q.Level, "request_id": q.RequestID,
			"service_id": q.ServiceID, "event": q.Event,
		}, q.Since, q.Until)
		if err != nil {
			return nil, err
		}
		out := make([]SyslogRow, len(rows))
		for i, r := range rows {
			out[i] = SyslogRow(r)
		}
		return out, nil
	}
	var out []SyslogRow
	for _, r := range t.Syslog.All() {
		if !syslogMatches(r, q) {
			continue
		}
		out = append(out, r)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

// CountSyslog counts all syslog rows matching q, so a capped QuerySyslog can
// report truncation.
func (t *Transport) CountSyslog(q StreamQuery) (int, error) {
	if t.SyslogStore != nil {
		return t.SyslogStore.CountMatching(map[string]string{
			"level": q.Level, "request_id": q.RequestID,
			"service_id": q.ServiceID, "event": q.Event,
		}, q.Since, q.Until)
	}
	n := 0
	for _, r := range t.Syslog.All() {
		if syslogMatches(r, q) {
			n++
		}
	}
	return n, nil
}

// SearchSyslog runs a free-text search over stored sys rows. Search only
// covers stored history, so with no store it returns (nil, false, nil); the
// bool tells "no store" apart from "no matches".
func (t *Transport) SearchSyslog(q, since, until string, limit int) ([]SyslogRow, bool, error) {
	if t.SyslogStore == nil {
		return nil, false, nil
	}
	rows, err := t.SyslogStore.Search(q, since, until, limit)
	if err != nil {
		return nil, true, err
	}
	out := make([]SyslogRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, SyslogRow(r))
	}
	return out, true, nil
}

// SearchAPI is SearchSyslog for the api stream.
func (t *Transport) SearchAPI(q, since, until string, limit int) ([]APIRow, bool, error) {
	if t.APIStore == nil {
		return nil, false, nil
	}
	rows, err := t.APIStore.Search(q, since, until, limit)
	if err != nil {
		return nil, true, err
	}
	out := make([]APIRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, APIRow(r))
	}
	return out, true, nil
}

// QueryAPI returns up to limit API rows, newest-first, from the store if one
// is attached, otherwise from the ring.
func (t *Transport) QueryAPI(limit int, q StreamQuery) ([]APIRow, error) {
	if t.APIStore != nil {
		rows, err := t.APIStore.Query(limit, map[string]string{
			"method": q.Method, "path": q.Path,
			"request_id": q.RequestID, "status": q.Status,
		}, q.Since, q.Until)
		if err != nil {
			return nil, err
		}
		out := make([]APIRow, len(rows))
		for i, r := range rows {
			out[i] = APIRow(r)
		}
		return out, nil
	}
	var out []APIRow
	for _, r := range t.API.All() {
		if !apiMatches(r, q) {
			continue
		}
		out = append(out, r)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

// CountAPI counts all API rows matching q, so a capped QueryAPI can report
// truncation.
func (t *Transport) CountAPI(q StreamQuery) (int, error) {
	if t.APIStore != nil {
		return t.APIStore.CountMatching(map[string]string{
			"method": q.Method, "path": q.Path,
			"request_id": q.RequestID, "status": q.Status,
		}, q.Since, q.Until)
	}
	n := 0
	for _, r := range t.API.All() {
		if apiMatches(r, q) {
			n++
		}
	}
	return n, nil
}

// statusEquals compares a ring row's status to a query string numerically,
// so "0502", 502 and "502" are equal as they are in the stores (spec §4).
// If either side isn't an integer it falls back to string equality.
func statusEquals(rowStatus any, queryStatus string) bool {
	qi, qerr := strconv.Atoi(queryStatus)
	switch v := rowStatus.(type) {
	case int:
		return qerr == nil && v == qi
	case int64:
		return qerr == nil && v == int64(qi)
	case float64:
		return qerr == nil && int(v) == qi
	case string:
		if qerr == nil {
			if ri, err := strconv.Atoi(v); err == nil {
				return ri == qi
			}
		}
		return v == queryStatus
	default:
		return fmt.Sprint(rowStatus) == queryStatus
	}
}
