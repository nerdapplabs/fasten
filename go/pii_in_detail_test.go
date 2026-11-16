package fasten

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// resetForPII clears state set by other tests in this package.
func resetForPII(t *testing.T) {
	t.Helper()
	clearBothRegistries()
}

// ── #1 force RetShort at registration ────────────────────────────────────

func TestPII_ForcesRetShort(t *testing.T) {
	resetForPII(t)
	if err := Register("pii", map[Code]Meta{
		"PII_FORCE_SHORT": {
			Domain: "pii", Category: "x", Action: "x",
			Severity:    SevInfo,
			Description: "x", Emitter: "t",
			RetentionClass: RetLong,
			PiiInDetail:    true,
		},
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	m, _ := metaOf("PII_FORCE_SHORT")
	if m.RetentionClass != RetShort {
		t.Fatalf("expected RetShort, got %v", m.RetentionClass)
	}
}

// ── #2 force-redact detail on emit ───────────────────────────────────────

func TestPII_ForceRedactsDetail(t *testing.T) {
	resetForPII(t)
	resetGlobals(t)
	_ = Init(Config{ServiceID: "svc", NodeID: "node"})
	if err := Register("pii", map[Code]Meta{
		"PII_FULL_REDACT": {
			Domain: "pii", Category: "c", Action: "a",
			Severity:    SevInfo,
			Description: "x", Emitter: "t",
			PiiInDetail: true,
		},
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	row, err := Emit(context.Background(), "PII_FULL_REDACT",
		Target("u-42"),
		WithDetail(map[string]any{"city": "Mumbai", "ip": "203.0.113.1"}),
	)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if _, ok := row.Detail["city"]; ok {
		t.Fatal("city must not survive PII force-redact")
	}
	if _, ok := row.Detail["ip"]; ok {
		t.Fatal("ip must not survive PII force-redact")
	}
	if row.Detail["_redacted"] != "***" {
		t.Fatalf("expected _redacted='***', got %v", row.Detail["_redacted"])
	}
	if row.Detail["_pii_in_detail"] != true {
		t.Fatal("_pii_in_detail must be true")
	}
	if !row.PiiInDetail {
		t.Fatal("Row.PiiInDetail must be true for PII codes")
	}
}

func TestPII_PassthroughKeys(t *testing.T) {
	resetForPII(t)
	resetGlobals(t)
	_ = Init(Config{ServiceID: "svc", NodeID: "node"})
	if err := Register("pii", map[Code]Meta{
		"PII_PARTIAL": {
			Domain: "pii", Category: "c", Action: "a",
			Severity:    SevInfo,
			Description: "x", Emitter: "t",
			PiiInDetail:           true,
			DetailPassthroughKeys: []string{"region"},
		},
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	row, err := Emit(context.Background(), "PII_PARTIAL",
		Target("u-42"),
		WithDetail(map[string]any{
			"city":    "Mumbai",
			"region":  "MH",
			"api_key": "sk-secret",
		}),
	)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if row.Detail["region"] != "MH" {
		t.Fatalf("expected region=MH, got %v", row.Detail["region"])
	}
	if _, ok := row.Detail["city"]; ok {
		t.Fatal("city must not survive (not in passthrough)")
	}
	// api_key not in passthrough list, so it's gone entirely
	if _, ok := row.Detail["api_key"]; ok {
		t.Fatal("api_key must not survive (not in passthrough)")
	}
}

func TestNonPII_KeepsDetail(t *testing.T) {
	resetForPII(t)
	resetGlobals(t)
	_ = Init(Config{ServiceID: "svc", NodeID: "node"})
	if err := Register("nonpii", map[Code]Meta{
		"NON_PII_BASIC": {
			Domain: "nonpii", Category: "c", Action: "a",
			Severity:    SevInfo,
			Description: "x", Emitter: "t",
		},
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	row, err := Emit(context.Background(), "NON_PII_BASIC",
		Target("u-42"),
		WithDetail(map[string]any{"city": "Mumbai", "api_key": "sk-secret"}),
	)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if row.Detail["city"] != "Mumbai" {
		t.Fatal("non-secret key must survive non-PII codes")
	}
	if row.Detail["api_key"] != "***" {
		t.Fatal("secret key must still be redacted")
	}
	if _, ok := row.Detail["_pii_in_detail"]; ok {
		t.Fatal("non-PII row must not carry _pii_in_detail marker")
	}
	if row.PiiInDetail {
		t.Fatal("Row.PiiInDetail must be false for non-PII codes")
	}
}

// ── #3 SQLite column persists pii_in_detail ──────────────────────────────

func TestPII_SQLitePersistsColumn(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sqlite open: %v", err)
	}
	defer db.Close()

	store, err := NewSQLiteStore(db, "audit_pii_test")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}

	row := Row{
		ID: "evt-pii", OriginID: "evt-pii", MonotonicSeq: 1,
		Code: "X_PII", Action: "x", Severity: SevInfo,
		ServiceID: "s", SourceNodeID: "n",
		Actor: "a", ActorKind: "user",
		Target: "t", Category: "c", Domain: "d",
		Method: "sdk", RequestID: "abc123def456",
		Detail:      map[string]any{"_redacted": "***"},
		PiiInDetail: true,
	}
	if err := store.Insert(context.Background(), row); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	got, err := store.Query(context.Background(), Filter{RequestID: "abc123def456"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 || !got[0].PiiInDetail {
		t.Fatalf("expected one row with PiiInDetail=true, got %+v", got)
	}
}

// A yaml code with pii_in_detail is handled like one from Register: short
// retention, and Emit keeps only the passthrough keys and the two markers.
func TestPII_YAMLCode(t *testing.T) {
	resetYAMLState(t)
	resetGlobals(t)
	_ = Init(Config{ServiceID: "svc", NodeID: "node"})
	path := writeYAML(t, `
domain: user
codes:
  USER_PII_SEEN:
    pii_in_detail: true
    retention_class: long
    detail_passthrough_keys: [tenant]
`)
	if err := Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	m, ok := metaOf("USER_PII_SEEN")
	if !ok || !m.PiiInDetail || m.RetentionClass != RetShort {
		t.Fatalf("meta = %+v, want PiiInDetail and RetShort", m)
	}

	row, err := Emit(context.Background(), "USER_PII_SEEN",
		Target("u-1"),
		WithDetail(map[string]any{"email": "alice@example.com", "tenant": "acme"}),
	)
	if err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if _, ok := row.Detail["email"]; ok {
		t.Fatalf("email must not be kept: %v", row.Detail)
	}
	if row.Detail["_redacted"] != "***" || row.Detail["_pii_in_detail"] != true || row.Detail["tenant"] != "acme" {
		t.Fatalf("detail = %v", row.Detail)
	}
	if !row.PiiInDetail {
		t.Fatal("Row.PiiInDetail must be true")
	}
}

// detail_passthrough_keys items that aren't strings are a load error.
func TestPII_YAMLPassthroughKeysMustBeStrings(t *testing.T) {
	resetYAMLState(t)
	for _, v := range []string{"[1, true]", "tenant", "null", "", "[tenant, 1.5]"} {
		path := writeYAML(t, "domain: x\ncodes:\n  BAD_PASS:\n    detail_passthrough_keys: "+v+"\n")
		err := Load(path)
		if err == nil || !strings.Contains(err.Error(), "BAD_PASS: detail_passthrough_keys must be a list of strings") {
			t.Fatalf("%s: want a load error naming the code, got %v", v, err)
		}
	}
}

// A list shared through an anchor is followed, as in the other loaders.
func TestPII_YAMLPassthroughKeysThroughAnAnchor(t *testing.T) {
	resetYAMLState(t)
	path := writeYAML(t, "domain: user\ncodes:\n  USER_A:\n    pii_in_detail: true\n    detail_passthrough_keys: &pt [tenant, region]\n  USER_B:\n    pii_in_detail: true\n    detail_passthrough_keys: *pt\n")
	if err := Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	m, ok := metaOf("USER_B")
	if !ok || strings.Join(m.DetailPassthroughKeys, ",") != "tenant,region" {
		t.Fatalf("USER_B passthrough = %v, want [tenant region]", m.DetailPassthroughKeys)
	}
}
