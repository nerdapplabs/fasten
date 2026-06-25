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
	SyslogStore *StreamStore
	APIStore    *StreamStore
}

func NewTransport(maxlen int) *Transport {
	return &Transport{
		Syslog: newRingBuffer[SyslogRow](maxlen),
		API:    newRingBuffer[APIRow](maxlen),
	}
}

// PushSyslog buffers a syslog row (+ persists if a store is attached).
// No stdout write — caller (slog handler) owns that.
func (t *Transport) PushSyslog(row SyslogRow) {
	t.Syslog.Push(row)
	if t.SyslogStore != nil {
		if err := t.SyslogStore.Insert(row); err != nil {
			fmt.Fprintf(os.Stderr, "fasten: syslog persist failed: %v\n", err)
		}
	}
}

// PushAPI buffers an API request row (+ persists if a store is attached).
// No stdout write — middleware owns logging.
func (t *Transport) PushAPI(row APIRow) {
	t.API.Push(row)
	if t.APIStore != nil {
		if err := t.APIStore.Insert(row); err != nil {
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

// QuerySyslog returns up to limit syslog rows, newest-first.
// Optionally filter by level, requestID, serviceID. Served from the durable
// store when one is attached, otherwise from the in-memory ring.
func (t *Transport) QuerySyslog(limit int, level, requestID, serviceID string) ([]SyslogRow, error) {
	if t.SyslogStore != nil {
		rows, err := t.SyslogStore.Query(limit, map[string]string{
			"level": level, "request_id": requestID, "service_id": serviceID,
		})
		if err != nil {
			return nil, err
		}
		out := make([]SyslogRow, len(rows))
		for i, r := range rows {
			out[i] = SyslogRow(r)
		}
		return out, nil
	}
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
	return out, nil
}

// QueryAPI returns up to limit API rows, newest-first. Served from the
// durable store when one is attached, otherwise from the in-memory ring.
func (t *Transport) QueryAPI(limit int, method, path, requestID string) ([]APIRow, error) {
	if t.APIStore != nil {
		rows, err := t.APIStore.Query(limit, map[string]string{
			"method": method, "path": path, "request_id": requestID,
		})
		if err != nil {
			return nil, err
		}
		out := make([]APIRow, len(rows))
		for i, r := range rows {
			out[i] = APIRow(r)
		}
		return out, nil
	}
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
	return out, nil
}
