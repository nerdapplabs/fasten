package rivet

import (
	"context"
	"log/slog"
	"time"
)

// SlogHandler wraps an underlying slog.Handler and pushes each log record
// into rivet's syslog ring buffer. The underlying handler still writes to
// its own destination (e.g. stdout JSON) — no double-write occurs.
//
// Usage:
//
//	base := slog.NewJSONHandler(os.Stdout, nil)
//	logger := slog.New(rivet.NewSlogHandler(base))
//	slog.SetDefault(logger)
type SlogHandler struct {
	next      slog.Handler
	transport *Transport
	preAttrs  []slog.Attr
	group     string
}

// NewSlogHandler wraps next and pushes to the global rivet transport.
// If rivet is not yet initialised, the handler degrades to next-only.
func NewSlogHandler(next slog.Handler) *SlogHandler {
	return &SlogHandler{next: next, transport: _transport}
}

func (h *SlogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *SlogHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.transport != nil {
		row := SyslogRow{
			"level":      r.Level.String(),
			"event":      r.Message,
			"timestamp":  r.Time.UTC().Format(time.RFC3339Nano),
			"request_id": RequestIDFromContext(ctx),
			"service_id": _serviceID,
		}
		// pre-attached attrs (WithAttrs)
		for _, a := range h.preAttrs {
			row[a.Key] = a.Value.Any()
		}
		// record-level attrs
		r.Attrs(func(a slog.Attr) bool {
			row[a.Key] = a.Value.Any()
			return true
		})
		h.transport.PushSyslog(row)
	}
	return h.next.Handle(ctx, r)
}

func (h *SlogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &SlogHandler{
		next:      h.next.WithAttrs(attrs),
		transport: h.transport,
		preAttrs:  append(h.preAttrs, attrs...),
		group:     h.group,
	}
}

func (h *SlogHandler) WithGroup(name string) slog.Handler {
	return &SlogHandler{
		next:      h.next.WithGroup(name),
		transport: h.transport,
		preAttrs:  h.preAttrs,
		group:     name,
	}
}
