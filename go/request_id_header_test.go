package fasten

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A client's X-Request-ID is used when it is 1 to 128 characters of letters,
// digits, ".", "_" and "-"; anything else gets a new id.
func TestRequestIDHeaderValidation(t *testing.T) {
	var seen string
	h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = RequestIDFromContext(r.Context())
	}))
	call := func(id string) string {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if id != "" {
			req.Header.Set("X-Request-ID", id)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if got := rec.Header().Get("X-Request-ID"); got != seen {
			t.Fatalf("response header %q != context id %q", got, seen)
		}
		return seen
	}

	for _, id := range []string{"req-A1.b2_c3", "550e8400-e29b-41d4-a716-446655440000", strings.Repeat("x", 128)} {
		if got := call(id); got != id {
			t.Errorf("valid id %q was replaced by %q", id, got)
		}
	}
	for _, id := range []string{strings.Repeat("x", 129), strings.Repeat("x", 2700), "has space", "semi;colon", "caf\u00e9", "bad\xffbyte"} {
		got := call(id)
		if got == id || !validRequestID(got) {
			t.Errorf("unusable id %q gave %q, want a new id", id, got)
		}
	}
	if got := call(""); !validRequestID(got) {
		t.Errorf("missing header gave %q, want a new id", got)
	}
}
