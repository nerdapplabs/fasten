package fasten

import (
	"encoding/json"
	"fmt"
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
	head  int  // index of next-write slot in buf
	count int  // entries currently stored (<= cap)
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
type Transport struct {
	Syslog *RingBuffer[SyslogRow]
	API    *RingBuffer[APIRow]
}

func NewTransport(maxlen int) *Transport {
	return &Transport{
		Syslog: newRingBuffer[SyslogRow](maxlen),
		API:    newRingBuffer[APIRow](maxlen),
	}
}

// PushSyslog buffers a syslog row. No stdout write — caller (slog handler) owns that.
func (t *Transport) PushSyslog(row SyslogRow) { t.Syslog.Push(row) }

// PushAPI buffers an API request row. No stdout write — middleware owns logging.
func (t *Transport) PushAPI(row APIRow) { t.API.Push(row) }

// WriteAudit writes an audit row to stdout as {"shape":"audit",...} JSON.
func (t *Transport) WriteAudit(row map[string]any) {
	row["shape"] = "audit"
	b, err := json.Marshal(row)
	if err != nil {
		return
	}
	fmt.Println(string(b))
}

// QuerySyslog returns up to limit syslog rows, newest-first.
// Optionally filter by level, requestID, serviceID.
func (t *Transport) QuerySyslog(limit int, level, requestID, serviceID string) []SyslogRow {
	all := t.Syslog.All()
	var out []SyslogRow
	for _, r := range all {
		if level != "" && r["level"] != level {
			continue
		}
		if requestID != "" && r["request_id"] != requestID {
			continue
		}
		if serviceID != "" && r["service_id"] != serviceID {
			continue
		}
		out = append(out, r)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// QueryAPI returns up to limit API rows, newest-first.
func (t *Transport) QueryAPI(limit int, method, path, requestID string) []APIRow {
	all := t.API.All()
	var out []APIRow
	for _, r := range all {
		if method != "" && r["method"] != method {
			continue
		}
		if path != "" {
			p, _ := r["path"].(string)
			if path != p {
				continue
			}
		}
		if requestID != "" && r["request_id"] != requestID {
			continue
		}
		out = append(out, r)
		if len(out) >= limit {
			break
		}
	}
	return out
}
