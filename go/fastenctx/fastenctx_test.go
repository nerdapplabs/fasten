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
