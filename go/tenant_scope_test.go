package fasten

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// P1-44 — cross-tenant isolation on reader endpoints (Go).
//
// Pins the enforcement contract: when NewReader(WithTenantScope(fn)) is
// wired, every reader endpoint (/audit, /correlate, /search, /sys, /api,
// /topology) IGNORES any caller-supplied ?tenant_id= and scopes the
// result to the resolved tenant. Tenant B cannot see tenant A's rows via
// any known attack vector.

func initSharedStore(t *testing.T) *SQLiteStore {
	t.Helper()
	resetGlobals(t)
	registerTestCodes(t)
	// Two tenants writing to the same physical store — mirror a hosted
	// multi-tenant deployment where each tenant's process has its own
	// Engine.tenantID but all write into a shared audit table.
	db, _ := sql.Open("sqlite", ":memory:")
	t.Cleanup(func() { db.Close() })
	audit, err := NewSQLiteStore(db, "audit_shared")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	sysDB, _ := sql.Open("sqlite", ":memory:")
	t.Cleanup(func() { sysDB.Close() })
	sysStore, _ := NewStreamStore(sysDB, "sys_shared")
	apiDB, _ := sql.Open("sqlite", ":memory:")
	t.Cleanup(func() { apiDB.Close() })
	apiStore, _ := NewStreamStore(apiDB, "api_shared")

	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		rid := "req-" + tenant
		if err := Init(Config{ServiceID: "svc", NodeID: "node",
			TenantID: tenant, AuditStore: audit,
			APIStore: apiStore, SyslogStore: sysStore,
			AuditStoreFailureStrategy: "raise", SearchEnabled: true,
		}); err != nil {
			t.Fatalf("Init(%s): %v", tenant, err)
		}
		ctx := WithRequestID(context.Background(), rid)
		if _, err := Emit(ctx, "USER_CREATED",
			Target("u-"+tenant), Actor("op", "user"),
			WithDetail(map[string]any{"marker": "marker-" + tenant})); err != nil {
			t.Fatalf("Emit(%s): %v", tenant, err)
		}
		tr := GetTransport()
		tr.PushSyslog(SyslogRow{"event": "auth", "message": "marker-" + tenant,
			"tenant_id": tenant, "request_id": rid,
			"timestamp": "2026-08-22T10:00:00.000000Z"})
		tr.PushAPI(APIRow{"method": "GET", "path": "/" + tenant, "status": 200,
			"tenant_id": tenant, "request_id": rid,
			"timestamp": "2026-08-22T10:00:00.000000Z"})
	}
	// Final Init with no tenant so /audit/doctor + helpers that read the
	// Engine's own tenant don't stick on tenant-b.
	Init(Config{ServiceID: "svc", NodeID: "node", AuditStore: audit,
		APIStore: apiStore, SyslogStore: sysStore,
		AuditStoreFailureStrategy: "raise", SearchEnabled: true})
	return audit
}

// ── baseline: no scope hook, behaviour unchanged ─────────────────────────

func TestTenantScope_NoHookKeepsCurrentBehaviour(t *testing.T) {
	initSharedStore(t)
	body, _ := getJSON(t, NewReader(), "/audit?limit=10")
	rows, _ := body["rows"].([]any)
	seen := map[string]bool{}
	for _, r := range rows {
		tid, _ := r.(map[string]any)["tenant_id"].(string)
		seen[tid] = true
	}
	if !seen["tenant-a"] || !seen["tenant-b"] {
		t.Fatalf("no-hook baseline must see both tenants; got %v", seen)
	}
}

// ── EnforceTenantIsolation requires WithTenantScope ──────────────────────

func TestTenantScope_EnforceWithoutHookPanics(t *testing.T) {
	resetGlobals(t)
	registerTestCodes(t)
	Init(Config{ServiceID: "svc", NodeID: "node"})
	defer func() {
		if recover() == nil {
			t.Fatal("EnforceTenantIsolation() with no WithTenantScope must panic")
		}
	}()
	NewReader(EnforceTenantIsolation())
}

// ── with scope: audit endpoint filters ───────────────────────────────────

func TestTenantScope_AuditScopesToResolvedTenant(t *testing.T) {
	initSharedStore(t)
	h := NewReader(WithTenantScope(func(*http.Request) (string, bool) { return "tenant-a", true }))
	body, _ := getJSON(t, h, "/audit?limit=10")
	rows, _ := body["rows"].([]any)
	if len(rows) == 0 {
		t.Fatal("scoped read must return tenant-a's rows")
	}
	for _, r := range rows {
		if r.(map[string]any)["tenant_id"] != "tenant-a" {
			t.Errorf("row tenant_id != tenant-a: %v", r)
		}
	}
}

func TestTenantScope_AuditIgnoresCallerTenantIDOverride(t *testing.T) {
	// Attack: A caller passes ?tenant_id=tenant-b hoping to read B's rows.
	initSharedStore(t)
	h := NewReader(WithTenantScope(func(*http.Request) (string, bool) { return "tenant-a", true }))
	body, _ := getJSON(t, h, "/audit?tenant_id=tenant-b&limit=10")
	rows, _ := body["rows"].([]any)
	for _, r := range rows {
		if r.(map[string]any)["tenant_id"] != "tenant-a" {
			t.Errorf("?tenant_id=tenant-b must not override the resolved scope; got %v", r)
		}
	}
}

func TestTenantScope_401WhenScopeReturnsFalse(t *testing.T) {
	initSharedStore(t)
	h := NewReader(WithTenantScope(func(*http.Request) (string, bool) { return "", false }))
	code := status(t, h, "/audit?limit=10")
	if code != 401 {
		t.Errorf("scope returning ok=false must 401; got %d", code)
	}
}

// ── /correlate: X-Request-ID pivot attack blocked ────────────────────────

func TestTenantScope_CorrelateBlocksCrossTenantRequestID(t *testing.T) {
	initSharedStore(t)
	// Tenant B knows A's request_id and hits /correlate.
	h := NewReader(WithTenantScope(func(*http.Request) (string, bool) { return "tenant-b", true }))
	body, _ := getJSON(t, h, "/correlate?request_id=req-tenant-a&limit=10")
	if audit, _ := body["audit"].([]any); len(audit) != 0 {
		t.Errorf("audit must be empty when scoped to a different tenant; got %v", audit)
	}
	for _, key := range []string{"api", "sys"} {
		if rows, _ := body[key].([]any); len(rows) != 0 {
			for _, r := range rows {
				if r.(map[string]any)["tenant_id"] != "tenant-b" {
					t.Errorf("%s leaked cross-tenant row: %v", key, r)
				}
			}
		}
	}
}

// ── /search: substring-across-tenants blocked ───────────────────────────

func TestTenantScope_SearchAuditBlocksCrossTenantSubstring(t *testing.T) {
	initSharedStore(t)
	h := NewReader(WithTenantScope(func(*http.Request) (string, bool) { return "tenant-b", true }))
	body, _ := getJSON(t, h,
		"/search?q=marker-tenant-a&since=2026-01-01T00:00:00Z&streams=audit")
	counts, _ := body["counts"].(map[string]any)
	if counts["audit"] != float64(0) {
		t.Errorf("cross-tenant audit substring must return 0; got %v", counts["audit"])
	}
}

func TestTenantScope_SearchSysBlocksCrossTenantSubstring(t *testing.T) {
	initSharedStore(t)
	h := NewReader(WithTenantScope(func(*http.Request) (string, bool) { return "tenant-b", true }))
	body, _ := getJSON(t, h,
		"/search?q=marker-tenant-a&since=2026-01-01T00:00:00Z&streams=sys")
	counts, _ := body["counts"].(map[string]any)
	if counts["sys"] != float64(0) {
		t.Errorf("cross-tenant sys substring must return 0; got %v", counts["sys"])
	}
}

// ── /sys and /api: post-filter blocks cross-tenant rows ──────────────────

func TestTenantScope_SysPostFilters(t *testing.T) {
	initSharedStore(t)
	h := NewReader(WithTenantScope(func(*http.Request) (string, bool) { return "tenant-a", true }))
	body, _ := getJSON(t, h, "/sys?limit=10")
	for _, r := range body["rows"].([]any) {
		if r.(map[string]any)["tenant_id"] != "tenant-a" {
			t.Errorf("/sys leaked cross-tenant row: %v", r)
		}
	}
}

func TestTenantScope_APIPostFilters(t *testing.T) {
	initSharedStore(t)
	h := NewReader(WithTenantScope(func(*http.Request) (string, bool) { return "tenant-a", true }))
	body, _ := getJSON(t, h, "/api?limit=10")
	for _, r := range body["rows"].([]any) {
		if r.(map[string]any)["tenant_id"] != "tenant-a" {
			t.Errorf("/api leaked cross-tenant row: %v", r)
		}
	}
}

// ── /topology: fleet enumeration blocked ────────────────────────────────

func TestTenantScope_TopologyPostFilters(t *testing.T) {
	initSharedStore(t)
	h := NewReader(WithTenantScope(func(*http.Request) (string, bool) { return "tenant-a", true }))
	body, _ := getJSON(t, h, "/topology")
	for _, s := range body["sources"].([]any) {
		if s.(map[string]any)["tenant_id"] != "tenant-a" {
			t.Errorf("/topology leaked cross-tenant source: %v", s)
		}
	}
}

// Silence unused-import for strings when Go elides.
var _ = strings.ToLower
