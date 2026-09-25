package fasten

import (
	"context"
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

// Same invariant as TestScopeAPIRows_NeverMarshalsNull. Written as a table over
// BOTH helpers so a future scope*Rows can be added here rather than fixed one
// at a time — scopeSyslogRows was missed precisely because the first test only
// covered the half that had been fixed.
func TestScopeRows_NeverMarshalsNull(t *testing.T) {
	for _, scope := range []string{"", "tenant-a"} {
		t.Run("syslog/nil/scope="+scope, func(t *testing.T) {
			b, err := json.Marshal(scopeSyslogRows(nil, scope))
			if err != nil {
				t.Fatal(err)
			}
			if string(b) == "null" {
				t.Fatal("scopeSyslogRows marshalled as null, want []")
			}
		})
		t.Run("api/nil/scope="+scope, func(t *testing.T) {
			b, err := json.Marshal(scopeAPIRows(nil, scope))
			if err != nil {
				t.Fatal(err)
			}
			if string(b) == "null" {
				t.Fatal("scopeAPIRows marshalled as null, want []")
			}
		})
	}
	t.Run("syslog/no-match-scoped", func(t *testing.T) {
		b, _ := json.Marshal(scopeSyslogRows([]SyslogRow{{"tenant_id": "other"}}, "tenant-a"))
		if string(b) == "null" {
			t.Fatal("scoped no-match marshalled as null, want []")
		}
	})
}

// Reader options must NOT mutate the shared Engine. fasten.NewReader() targets
// the package-level Default, so applying options to the engine meant a second
// reader silently re-scoped the first and two policies on one engine were
// impossible.
func TestNewReader_OptionsDoNotMutateTheEngine(t *testing.T) {
	e := &Engine{}
	_ = e.NewReader(WithTenantScope(
		func(*http.Request) (string, bool) { return "tenant-a", true }))

	if e.tenantScope != nil {
		t.Fatal("NewReader mutated the engine's tenantScope")
	}
	if e.enforceTenantIsolation {
		t.Fatal("NewReader mutated enforceTenantIsolation")
	}
}

func TestNewReader_TwoReadersKeepSeparateScopes(t *testing.T) {
	e := &Engine{}

	// Reader A resolves a real tenant. Reader B resolves BLANK, which must 401
	// under enforcement. If options still mutated the shared engine, whichever
	// reader was constructed last would decide for both.
	a := e.NewReader(
		EnforceTenantIsolation(),
		WithTenantScope(func(*http.Request) (string, bool) { return "tenant-a", true }))
	b := e.NewReader(
		EnforceTenantIsolation(),
		WithTenantScope(func(*http.Request) (string, bool) { return "", true }))

	status := func(h http.Handler) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/topology", nil))
		return rec.Code
	}

	if got := status(b); got != http.StatusUnauthorized {
		t.Fatalf("reader B (blank scope) = %d, want 401", got)
	}
	if got := status(a); got == http.StatusUnauthorized {
		t.Fatal("reader A was 401'd — reader B's scope leaked onto it")
	}
}

// spec §2.1 / §8.1 — the engine holds no chain state. The store allocates
// inside the insert transaction, so two engines on one node share one chain;
// with no store at all, rows go out unsealed rather than carrying a fabricated
// in-memory sequence that cannot survive a restart or a second process.
func TestEngine_StoreAllocatesSequence(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	store, cleanup := newMemStore(t, "alloc_shared")
	defer cleanup()
	ctx := context.Background()

	a, b := &Engine{}, &Engine{}
	for _, tc := range []struct {
		e   *Engine
		svc string
	}{{a, "svc-a"}, {b, "svc-b"}} {
		if err := tc.e.Init(Config{
			ServiceID: tc.svc, NodeID: "node-1",
			AuditStore: store, AuditStoreFailureStrategy: "raise",
		}); err != nil {
			t.Fatalf("Init %s: %v", tc.svc, err)
		}
	}

	r1, err := a.Emit(ctx, "USER_CREATED", Target("u-1"))
	if err != nil {
		t.Fatal(err)
	}
	r2, err := b.Emit(ctx, "USER_CREATED", Target("u-2"))
	if err != nil {
		t.Fatal(err)
	}
	if r1.MonotonicSeq == r2.MonotonicSeq {
		t.Fatalf("two engines minted the same seq %d — the P0-9 defect", r1.MonotonicSeq)
	}
	if r2.PrevHash != r1.Hash {
		t.Fatalf("second engine did not chain to the first: prev=%q want %q",
			r2.PrevHash, r1.Hash)
	}
	rows, err := store.Query(ctx, Filter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if res := VerifyChain(rows); !res.OK {
		t.Fatalf("chain broken across two engines: %s", res.Reason)
	}
}

func TestEngine_NoStoreEmitsUnsealed(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node-1"}); err != nil {
		t.Fatal(err)
	}
	row, err := Emit(context.Background(), "USER_CREATED", Target("u-1"))
	if err != nil {
		t.Fatal(err)
	}
	if row.Hash != "" {
		t.Fatalf("storeless emit sealed the row (hash=%q); spec §8.1 forbids "+
			"fabricating a sequence with nothing to allocate against", row.Hash)
	}
	if res := VerifyChain([]Row{row}); !res.OK {
		t.Fatal("VerifyChain must skip hashless rows, not reject them")
	}
}
