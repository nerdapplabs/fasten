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

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// HeaderRequestID is the canonical HTTP header carrying the correlation id.
const HeaderRequestID = "X-Request-ID"

// MintID returns a new 12-character hex request id. Pure stdlib — usable from a
// zero-cgo consumer that imports only fastenctx.
func MintID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// SentinelKinds are the namespaces for rows written outside a real request
// context. Stamping one (instead of leaving request_id empty) keeps every
// stream row correlatable and self-describing — see the sentinel invariant.
//
// Only boot and orphan are ever auto-stamped (by the transport); sched, bg,
// and lib exist for callers that mint sentinels explicitly via MintSentinel
// for their own scheduled/background/library-context writes.
var SentinelKinds = []string{"boot", "sched", "bg", "lib", "orphan"}

// MintSentinel mints a namespaced sentinel request_id (e.g.
// "orphan-svc-ab12cd34ef56"). boot is minted once per process and shared; the
// others are per-task/per-write.
//
// Panics on an unknown kind — a programming error, never runtime input, so a
// panic is the idiomatic Go signal. The Python SDK (fasten.mint_sentinel)
// raises ValueError on the same condition, likewise idiomatic there. The
// behaviour differs by language idiom on purpose; the contract (reject an
// unknown kind loudly) is identical.
func MintSentinel(kind, serviceID string) string {
	if !isSentinelKind(kind) {
		panic(fmt.Sprintf("fasten: unknown sentinel kind %q; expected one of %v", kind, SentinelKinds))
	}
	if serviceID == "" {
		serviceID = "svc"
	}
	return fmt.Sprintf("%s-%s-%s", kind, serviceID, MintID())
}

// RequestIDKind classifies a request_id by its namespace: a sentinel kind, or
// "request" for a real correlation id. Lets a UI pivot/filter by origin.
//
// Classification is by prefix, so a REAL id that happens to start with
// "boot-"/"sched-"/"bg-"/"lib-"/"orphan-" is misclassified as a sentinel.
func RequestIDKind(requestID string) string {
	for _, k := range SentinelKinds {
		if strings.HasPrefix(requestID, k+"-") {
			return k
		}
	}
	return "request"
}

// IsSentinel reports whether requestID is a minted sentinel, not a real id.
func IsSentinel(requestID string) bool { return RequestIDKind(requestID) != "request" }

func isSentinelKind(kind string) bool {
	for _, k := range SentinelKinds {
		if k == kind {
			return true
		}
	}
	return false
}

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
