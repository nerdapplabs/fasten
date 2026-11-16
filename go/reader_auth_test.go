package fasten

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// RequireBearer contract, pinned so a future refactor can't
// silently regress the "unset env => panic" or "wrong token => 401"
// invariants that make this a real footgun-reduction default.

func TestRequireBearer_UnsetEnvPanics(t *testing.T) {
	t.Setenv("FASTEN_READER_TOKEN", "")
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("RequireBearer with empty env must panic at wire time")
		}
	}()
	_ = RequireBearer("FASTEN_READER_TOKEN")
}

func TestRequireBearer_MissingHeaderReturns401(t *testing.T) {
	t.Setenv("FASTEN_READER_TOKEN", "s3cret")
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := RequireBearer("FASTEN_READER_TOKEN")(inner)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/anything", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no auth header: got %d, want 401", rr.Code)
	}
}

func TestRequireBearer_WrongSchemeReturns401(t *testing.T) {
	t.Setenv("FASTEN_READER_TOKEN", "s3cret")
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := RequireBearer("FASTEN_READER_TOKEN")(inner)
	req := httptest.NewRequest("GET", "/anything", nil)
	req.Header.Set("Authorization", "Basic s3cret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("Basic scheme: got %d, want 401", rr.Code)
	}
}

func TestRequireBearer_WrongTokenReturns401(t *testing.T) {
	t.Setenv("FASTEN_READER_TOKEN", "s3cret")
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := RequireBearer("FASTEN_READER_TOKEN")(inner)
	req := httptest.NewRequest("GET", "/anything", nil)
	req.Header.Set("Authorization", "Bearer nope")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: got %d, want 401", rr.Code)
	}
}

func TestRequireBearer_MatchingTokenPassesThrough(t *testing.T) {
	t.Setenv("FASTEN_READER_TOKEN", "s3cret")
	reached := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	h := RequireBearer("FASTEN_READER_TOKEN")(inner)
	req := httptest.NewRequest("GET", "/anything", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if !reached {
		t.Fatal("valid token: inner handler was not invoked")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("valid token: got %d, want 200", rr.Code)
	}
}

func TestRequireBearer_EmptyArgUsesDefaultEnvName(t *testing.T) {
	t.Setenv("FASTEN_READER_TOKEN", "s3cret")
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := RequireBearer("")(inner) // empty => defaults to FASTEN_READER_TOKEN
	req := httptest.NewRequest("GET", "/anything", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("default env name: got %d, want 200", rr.Code)
	}
}

// NewReader needs WithAuth or WithoutAuth.
func TestNewReader_PanicsWithoutAnAuthChoice(t *testing.T) {
	mustPanic := func(name string, fn func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Errorf("%s: expected a panic", name)
			}
		}()
		fn()
	}
	pass := func(next http.Handler) http.Handler { return next }
	mustPanic("no option", func() { NewReader() })
	mustPanic("tenant scope only", func() {
		NewReader(WithTenantScope(func(*http.Request) (string, bool) { return "t", true }))
	})
	mustPanic("both", func() { NewReader(WithAuth(pass), WithoutAuth()) })
	mustPanic("nil middleware", func() { WithAuth(nil) })
}

// WithAuth puts every reader route behind the middleware.
func TestNewReader_WithAuthGuardsEveryRoute(t *testing.T) {
	t.Setenv("FASTEN_READER_TOKEN", "s3cret")
	e := &Engine{}
	h := e.NewReader(WithAuth(RequireBearer("")))
	for _, path := range []string{"/sys", "/api", "/search?q=x", "/correlate", "/topology", "/audit/doctor", "/audit"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without a token: status %d, want 401", path, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/topology", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusUnauthorized {
		t.Errorf("/topology with the token: status 401")
	}
}
