package fastenctx

import (
	"context"
	"testing"
)

func TestWithRequestID_RoundTrip(t *testing.T) {
	ctx := WithRequestID(context.Background(), "req-abc123")
	if got := RequestIDFromContext(ctx); got != "req-abc123" {
		t.Fatalf("round-trip: got %q, want %q", got, "req-abc123")
	}
}

func TestRequestIDFromContext_Missing(t *testing.T) {
	if got := RequestIDFromContext(context.Background()); got != "" {
		t.Fatalf("missing: got %q, want empty string", got)
	}
}

func TestWithRequestID_Overwrite(t *testing.T) {
	ctx := WithRequestID(context.Background(), "first")
	ctx = WithRequestID(ctx, "second")
	if got := RequestIDFromContext(ctx); got != "second" {
		t.Fatalf("overwrite: got %q, want %q", got, "second")
	}
}

func TestHeaderRequestID(t *testing.T) {
	if HeaderRequestID != "X-Request-ID" {
		t.Fatalf("header constant: got %q, want %q", HeaderRequestID, "X-Request-ID")
	}
}

// Sentinel/id helpers must be usable from fastenctx alone (cgo-free consumers).
func TestMintID(t *testing.T) {
	id := MintID()
	if len(id) != 12 {
		t.Fatalf("MintID len = %d, want 12 (%q)", len(id), id)
	}
	if MintID() == id {
		t.Fatal("MintID should not repeat")
	}
	if IsSentinel(id) {
		t.Fatalf("a real id %q must not classify as a sentinel", id)
	}
	if k := RequestIDKind(id); k != "request" {
		t.Fatalf("RequestIDKind(real) = %q, want request", k)
	}
}

func TestMintSentinel(t *testing.T) {
	for _, kind := range SentinelKinds {
		s := MintSentinel(kind, "svc")
		if !IsSentinel(s) {
			t.Fatalf("MintSentinel(%q) = %q, not classified as sentinel", kind, s)
		}
		if got := RequestIDKind(s); got != kind {
			t.Fatalf("RequestIDKind(%q) = %q, want %q", s, got, kind)
		}
	}
}

func TestMintSentinel_UnknownKindPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("MintSentinel with an unknown kind must panic")
		}
	}()
	MintSentinel("nope", "svc")
}
