// Package fastenctx carries the fasten correlation request-id through a
// context.Context.
//
// It is a deliberately minimal, zero-dependency subpackage (imports only the
// standard library "context"). Adopters who need to read or set the ambient
// request-id — middleware, transport shims, background workers — can import
// fastenctx alone without pulling in the cgo/FFI machinery of the top-level
// fasten package.
//
// The context key here is the SAME key the top-level fasten package uses:
// fasten.WithRequestID / fasten.RequestIDFromContext delegate to these
// functions, and the fasten HTTP RequestID middleware sets the value via
// fasten.WithRequestID. So a value set anywhere (middleware, fasten.Emit,
// or a direct fastenctx.WithRequestID call) is visible everywhere.
package fastenctx

import "context"

// HeaderRequestID is the canonical HTTP header carrying the correlation id.
const HeaderRequestID = "X-Request-ID"

// ctxKey is an unexported context key type so values stored here cannot
// collide with keys defined in other packages.
type ctxKey int

const requestIDKey ctxKey = 1

// WithRequestID returns a copy of ctx that carries id as the ambient
// correlation request-id.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestIDFromContext returns the ambient correlation request-id, or ""
// if none has been set on ctx.
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}
