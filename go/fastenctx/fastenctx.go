// Package fastenctx carries the fasten correlation request-id through a
// context.Context.
//
// It uses only the standard library, so middleware and workers can read or
// set the request id without pulling in the cgo parts of package fasten.
//
// fasten.WithRequestID and fasten.RequestIDFromContext call these functions,
// so both packages see the same value.
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

// MintID returns a new 12-character hex request id.
func MintID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// SentinelKinds are the request_id prefixes for rows written outside a
// request, so request_id is never empty. The transport stamps boot and
// orphan itself; sched, bg and lib are for callers using MintSentinel.
var SentinelKinds = []string{"boot", "sched", "bg", "lib", "orphan"}

// MintSentinel returns a sentinel request_id such as
// "orphan-svc-ab12cd34ef56". It panics on an unknown kind, which is a
// programming error rather than bad input.
func MintSentinel(kind, serviceID string) string {
	if !isSentinelKind(kind) {
		panic(fmt.Sprintf("fasten: unknown sentinel kind %q; expected one of %v", kind, SentinelKinds))
	}
	if serviceID == "" {
		serviceID = "svc"
	}
	return fmt.Sprintf("%s-%s-%s", kind, serviceID, MintID())
}

// RequestIDKind returns the sentinel kind of requestID, or "request" for a
// real id. It goes by prefix, so a real id starting with e.g. "boot-" is
// reported as a sentinel.
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

type ctxKey int

const requestIDKey ctxKey = 1

// WithRequestID returns a copy of ctx carrying id as the request id.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestIDFromContext returns the request id in ctx, or "".
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}
