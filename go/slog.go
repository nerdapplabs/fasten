package fasten

import (
	"context"
	"log/slog"
	"strings"
)

// SlogHandler copies each slog record into fasten's syslog buffer and then
// passes it on to the wrapped handler.
//
// Usage:
//
//	base := slog.NewJSONHandler(os.Stdout, nil)
//	logger := slog.New(fasten.NewSlogHandler(base))
//	slog.SetDefault(logger)
type SlogHandler struct {
	next      slog.Handler
	transport *Transport
	preAttrs  []slog.Attr
	group     string
}

// NewSlogHandler wraps next. If fasten isn't initialised yet, records only
// go to next.
func NewSlogHandler(next slog.Handler) *SlogHandler {
	return &SlogHandler{next: next, transport: Default.xport}
}

func (h *SlogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

func (h *SlogHandler) Handle(ctx context.Context, r slog.Record) error {
	if h.transport != nil {
		row := SyslogRow{
			// Other writers use lowercase levels and level filters are
			// exact-match, so "INFO" from slog would never match "info".
			"level":      strings.ToLower(r.Level.String()),
			"event":      r.Message,
			"timestamp":  canonicalTS(r.Time),
			"request_id": RequestIDFromContext(ctx),
			"service_id": Default.serviceID,
		}
		for _, a := range h.preAttrs {
			row[a.Key] = a.Value.Any()
		}
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
