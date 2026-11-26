package fasten

import (
	"io"
	"log/slog"
	"testing"
)

// Two loggers made from one parent must keep their own attrs. WithAttrs
// appended into the parent's spare capacity, so the second child overwrote
// the first one's attr.
func TestWithAttrsSiblingsKeepTheirOwnAttrs(t *testing.T) {
	pre := make([]slog.Attr, 1, 4)
	pre[0] = slog.String("svc", "api")
	parent := &SlogHandler{next: slog.NewTextHandler(io.Discard, nil), preAttrs: pre}

	a := parent.WithAttrs([]slog.Attr{slog.String("user", "alice")}).(*SlogHandler)
	b := parent.WithAttrs([]slog.Attr{slog.String("user", "bob")}).(*SlogHandler)

	if got := a.preAttrs[1].Value.String(); got != "alice" {
		t.Fatalf("first logger's user attr is %q after a sibling was made, want alice", got)
	}
	if got := b.preAttrs[1].Value.String(); got != "bob" {
		t.Fatalf("second logger's user attr is %q, want bob", got)
	}
}
