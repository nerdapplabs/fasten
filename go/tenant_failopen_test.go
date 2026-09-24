package fasten

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A resolved-but-BLANK tenant must 401, not read every tenant. Every
// downstream branch tests `tenant != ""` and treats blank as "no filter", so
// letting "" through turned isolation into a full cross-tenant read.
func TestResolveTenant_EmptyScopeIs401(t *testing.T) {
	e := &Engine{
		enforceTenantIsolation: true,
		tenantScope:            func(*http.Request) (string, bool) { return "", true },
	}
	w := httptest.NewRecorder()
	if _, ok := e.resolveTenant(w, httptest.NewRequest("GET", "/x", nil)); ok {
		t.Fatal("empty tenant accepted — isolation fails open")
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestResolveTenant_NoHookStaysSingleTenant(t *testing.T) {
	e := &Engine{}
	w := httptest.NewRecorder()
	if _, ok := e.resolveTenant(w, httptest.NewRequest("GET", "/x", nil)); !ok {
		t.Fatal("no-hook single-tenant mode must pass through")
	}
}

// Ring-backed streams return a nil slice on no-match; it must marshal as []
// not null, or clients iterating the array break.
func TestScopeAPIRows_NeverMarshalsNull(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rows  []APIRow
		scope string
	}{
		{"nil unscoped", nil, ""},
		{"nil scoped", nil, "tenant-a"},
		{"no match scoped", []APIRow{{"tenant_id": "other"}}, "tenant-a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(scopeAPIRows(tc.rows, tc.scope))
			if err != nil {
				t.Fatal(err)
			}
			if string(b) == "null" {
				t.Fatalf("marshalled as null, want []")
			}
		})
	}
}
