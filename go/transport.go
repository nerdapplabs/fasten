package fasten

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// RingBuffer is a thread-safe, fixed-capacity buffer. Oldest entries drop
// when full. Queries return newest-first.
//
// Implemented as a true circular buffer over a fixed-capacity slice. The
// earlier `rb.buf = rb.buf[1:]` pop strategy retained the original
// backing array and only advanced the slice header, so the underlying
// memory grew by one element per push past capacity until GC eventually
// reclaimed it — effectively unbounded heap growth on a hot syslog
// path. Circular index keeps the backing array exactly `cap` entries.
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
	// Walk backwards from the most recently written slot.
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

// Transport owns the ring buffers and stdout writes.
// Syslog and API use push-only (no stdout duplication — caller owns stdout).
// Audit writes to stdout for belt-and-braces capture.
//
// When a stream store is attached (FR1, opt-in persistence) the ring stays
// the hot write path and the store is a write-through sink; reads for that
// stream are served from the store so they reach durable history instead of
// a bounded window. Without a store the stream is ring-only (default).
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

// PushSyslog buffers a syslog row (+ persists if a store is attached).
// No stdout write — caller (slog handler) owns that.
//
// A persist failure must never break the hot logging path (the ring already
// holds the row), so it is logged to stderr and swallowed — but it is also
// recorded on the store, which degrades the stream's completeness flag to
// "store-degraded". Without that, reads (served from the store, never the
// ring, once a store is attached) would silently miss the row while the flag
// asserted durability.
func (t *Transport) PushSyslog(row SyslogRow) {
	t.stampRequestID(row)
	t.Syslog.Push(row)
	if t.SyslogStore != nil {
		if err := t.SyslogStore.Insert(row); err != nil {
			t.SyslogStore.NoteWriteFailure()
			fmt.Fprintf(os.Stderr, "fasten: syslog persist failed: %v\n", err)
		}
	}
}

// PushAPI buffers an API request row (+ persists if a store is attached).
// No stdout write — middleware owns logging. Persist-failure handling is the
// same as PushSyslog: swallow, but degrade the completeness flag.
func (t *Transport) PushAPI(row APIRow) {
	t.stampRequestID(row)
	t.API.Push(row)
	if t.APIStore != nil {
		if err := t.APIStore.Insert(row); err != nil {
			t.APIStore.NoteWriteFailure()
			fmt.Fprintf(os.Stderr, "fasten: api persist failed: %v\n", err)
		}
	}
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
// fields are ignored. The indexed structured fields (event, status, time
// window) are honoured identically whether the read is served from the ring
// or the durable store.
//
// The Since/Until window compares timestamps as strings (lexicographic, both
// in the ring scan and in SQL). That is correct for the canonical
// UTC RFC3339Nano timestamps fasten's own writers stamp, but mixed formats —
// "…+00:00" vs "…Z", differing fractional-second precision — do not order
// lexicographically. If you push rows with your own timestamps, keep them in
// one canonical UTC format or the window will mis-compare.
type StreamQuery struct {
	Level     string // sys
	ServiceID string // sys
	Event     string // sys
	Method    string // api
	Path      string // api
	Status    string // api ("" = no filter; matched against the row's value)
	RequestID string // common
	Since     string // common — timestamp >= Since (ISO-8601)
	Until     string // common — timestamp <= Until (ISO-8601)
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

// QuerySyslog returns up to limit syslog rows, newest-first. Served from the
// durable store when one is attached, otherwise from the in-memory ring.
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
		if q.Level != "" && r["level"] != q.Level {
			continue
		}
		if q.RequestID != "" && r["request_id"] != q.RequestID {
			continue
		}
		if q.ServiceID != "" && r["service_id"] != q.ServiceID {
			continue
		}
		if q.Event != "" && r["event"] != q.Event {
			continue
		}
		if !inWindow(tsOf(r), q.Since, q.Until) {
			continue
		}
		out = append(out, r)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

// CountSyslog returns the total number of syslog rows matching q in the
// backing source (durable store, or the ring's current window) — the
// uncapped counterpart of QuerySyslog, so capped reads can report truncation.
func (t *Transport) CountSyslog(q StreamQuery) (int, error) {
	if t.SyslogStore != nil {
		return t.SyslogStore.CountMatching(map[string]string{
			"level": q.Level, "request_id": q.RequestID,
			"service_id": q.ServiceID, "event": q.Event,
		}, q.Since, q.Until)
	}
	n := 0
	for _, r := range t.Syslog.All() {
		if q.Level != "" && r["level"] != q.Level {
			continue
		}
		if q.RequestID != "" && r["request_id"] != q.RequestID {
			continue
		}
		if q.ServiceID != "" && r["service_id"] != q.ServiceID {
			continue
		}
		if q.Event != "" && r["event"] != q.Event {
			continue
		}
		if !inWindow(tsOf(r), q.Since, q.Until) {
			continue
		}
		n++
	}
	return n, nil
}

// SearchSyslog runs the FR3 free-text search over persisted sys history.
// Returns (nil, nil) when the sys stream is ring-only — search is defined over
// durable history, not a bounded window, so without a store there is nothing
// honest to search (the reader surfaces this as "search requires sys
// persistence"). The bool return distinguishes "no store" from "no matches".
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

// QueryAPI returns up to limit API rows, newest-first. Served from the
// durable store when one is attached, otherwise from the in-memory ring.
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
		if q.Method != "" && r["method"] != q.Method {
			continue
		}
		if q.Path != "" {
			if p, _ := r["path"].(string); q.Path != p {
				continue
			}
		}
		if q.RequestID != "" && r["request_id"] != q.RequestID {
			continue
		}
		if q.Status != "" && fmt.Sprint(r["status"]) != q.Status {
			continue
		}
		if !inWindow(tsOf(r), q.Since, q.Until) {
			continue
		}
		out = append(out, r)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

// CountAPI returns the total number of API rows matching q in the backing
// source (durable store, or the ring's current window) — the uncapped
// counterpart of QueryAPI, so capped reads can report truncation.
func (t *Transport) CountAPI(q StreamQuery) (int, error) {
	if t.APIStore != nil {
		return t.APIStore.CountMatching(map[string]string{
			"method": q.Method, "path": q.Path,
			"request_id": q.RequestID, "status": q.Status,
		}, q.Since, q.Until)
	}
	n := 0
	for _, r := range t.API.All() {
		if q.Method != "" && r["method"] != q.Method {
			continue
		}
		if q.Path != "" {
			if p, _ := r["path"].(string); q.Path != p {
				continue
			}
		}
		if q.RequestID != "" && r["request_id"] != q.RequestID {
			continue
		}
		if q.Status != "" && fmt.Sprint(r["status"]) != q.Status {
			continue
		}
		if !inWindow(tsOf(r), q.Since, q.Until) {
			continue
		}
		n++
	}
	return n, nil
}
