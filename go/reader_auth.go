package fasten

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// RequireBearer returns middleware that enforces `Authorization: Bearer <token>`
// on every request. The expected token is read from the environment
// variable named by tokenEnv (empty => panics loudly at wire time). A
// missing/malformed header or a mismatched token replies 401 with a
// deliberately generic body — no leak of "header present but wrong" vs
// "no header at all". Constant-time compare (crypto/subtle).
//
// Usage:
//
//	mux := http.NewServeMux()
//	mux.Handle("/api/v1/logs/", http.StripPrefix(
//	    "/api/v1/logs",
//	    fasten.RequireBearer("FASTEN_READER_TOKEN")(fasten.NewReader()),
//	))
//
// This is the opinionated default so callers who don't yet have an auth
// stack can hand the reader a real gate. Anything shared/public-facing
// belongs behind your own auth layer instead (P1-45).
func RequireBearer(tokenEnv string) func(http.Handler) http.Handler {
	if tokenEnv == "" {
		tokenEnv = "FASTEN_READER_TOKEN"
	}
	expected := os.Getenv(tokenEnv)
	if expected == "" {
		panic(fmt.Sprintf(
			"fasten.RequireBearer: $%s is unset or empty. "+
				"Set it to the shared bearer token, or wire your own "+
				"middleware (this helper is opinionated — env-var only).",
			tokenEnv))
	}
	expBytes := []byte(expected)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hdr := r.Header.Get("Authorization")
			const prefix = "Bearer "
			if !strings.HasPrefix(hdr, prefix) {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
			presented := []byte(hdr[len(prefix):])
			if subtle.ConstantTimeCompare(presented, expBytes) != 1 {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
