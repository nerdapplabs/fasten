package fasten

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// RequireBearer returns middleware that requires `Authorization: Bearer <token>`.
// The token is read from the env var named by tokenEnv (FASTEN_READER_TOKEN
// if empty); it panics if that variable is unset. Any failure gets the same
// 401 body, and the token is compared in constant time.
//
// Usage:
//
//	mux := http.NewServeMux()
//	mux.Handle("/api/v1/logs/", http.StripPrefix(
//	    "/api/v1/logs",
//	    fasten.RequireBearer("FASTEN_READER_TOKEN")(fasten.NewReader()),
//	))
//
// It's meant for callers without an auth stack yet. Put anything shared or
// public-facing behind your own auth layer.
func RequireBearer(tokenEnv string) func(http.Handler) http.Handler {
	if tokenEnv == "" {
		tokenEnv = "FASTEN_READER_TOKEN"
	}
	expected := os.Getenv(tokenEnv)
	if expected == "" {
		panic(fmt.Sprintf(
			"fasten.RequireBearer: $%s is unset or empty. "+
				"Set it to the shared bearer token, or wire your own "+
				"middleware (this helper is opinionated: env-var only).",
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
