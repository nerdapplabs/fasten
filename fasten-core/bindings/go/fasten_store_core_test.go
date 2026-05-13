// Tests for the Go binding (fasten_core.go).
//
// Requires libfasten_core at link time:
//
//	cd fasten/fasten-core && cargo build --release --features all
//	cd bindings/go
//	CGO_LDFLAGS="-L../../../../target/release" go test -v ./...
//
// PostgreSQL tests are skipped when FASTEN_TEST_POSTGRES_DSN is absent.
package fastenstore_test

import (
	"encoding/json"
	"os"
	"testing"

	fastenstore "."
)

// ── helpers ───────────────────────────────────────────────────────────────────

func makeRow(id, code string) map[string]any {
	return map[string]any{
		"wire_version":    "1",
		"id":              id,
		"origin_id":       id,
		"monotonic_seq":   1,
		"timestamp":       "2026-05-07T00:00:00.000Z",
		"code":            code,
		"action":          "test",
		"severity":        "info",
		"service_id":      "test-svc",
		"source_node_id":  "node-1",
		"actor":           "tester",
		"actor_kind":      "user",
		"target":          "res-1",
		"category":        "test",
		"domain":          "test",
		"method":          "sdk",
		"request_id":      "req-001",
		"detail":          map[string]any{"key": "value"},
	}
}

func pgDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("FASTEN_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("FASTEN_TEST_POSTGRES_DSN not set")
	}
	return dsn
}

// ── Version ───────────────────────────────────────────────────────────────────

func TestVersion(t *testing.T) {
	v := fastenstore.Version()
	if v == "" {
		t.Fatal("Version() returned empty string")
	}
	t.Logf("library version: %s", v)
}

// ── SQLite ────────────────────────────────────────────────────────────────────

func TestSQLite_OpenAndPing(t *testing.T) {
	store, err := fastenstore.Open("sqlite", ":memory:", "audit_log")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	if err := store.Ping(); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestSQLite_Insert(t *testing.T) {
	store, err := fastenstore.Open("sqlite", ":memory:", "audit_log")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	if err := store.Insert(makeRow("evt-go-sqlite-001", "TEST")); err != nil {
		t.Fatalf("Insert: %v", err)
	}
}

func TestSQLite_InsertIdempotent(t *testing.T) {
	store, err := fastenstore.Open("sqlite", ":memory:", "audit_log")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	row := makeRow("evt-go-idem-001", "TEST")
	if err := store.Insert(row); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if err := store.Insert(row); err != nil {
		t.Fatalf("idempotent insert: %v", err) // INSERT OR IGNORE
	}
}

func TestSQLite_InsertJSON(t *testing.T) {
	store, err := fastenstore.Open("sqlite", ":memory:", "audit_log")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	b, _ := json.Marshal(makeRow("evt-go-json-001", "TEST"))
	if err := store.InsertJSON(string(b)); err != nil {
		t.Fatalf("InsertJSON: %v", err)
	}
}

func TestSQLite_NullableColumns(t *testing.T) {
	store, err := fastenstore.Open("sqlite", ":memory:", "audit_log")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	row := makeRow("evt-go-null-001", "TEST")
	row["tenant_id"] = "tenant-abc"
	row["shipped_at"] = "2026-05-07T01:00:00.000Z"
	if err := store.Insert(row); err != nil {
		t.Fatalf("Insert with nullable cols: %v", err)
	}
}

func TestSQLite_PiiInDetail(t *testing.T) {
	store, err := fastenstore.Open("sqlite", ":memory:", "audit_log")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	row := makeRow("evt-go-pii-001", "TEST")
	row["pii_in_detail"] = true
	if err := store.Insert(row); err != nil {
		t.Fatalf("Insert pii: %v", err)
	}
}

func TestSQLite_InvalidTableNameReturnsError(t *testing.T) {
	_, err := fastenstore.Open("sqlite", ":memory:", "bad-name!")
	if err == nil {
		t.Fatal("expected error for invalid table name, got nil")
	}
}

func TestSQLite_UnknownBackendReturnsError(t *testing.T) {
	_, err := fastenstore.Open("nope", ":memory:", "audit_log")
	if err == nil {
		t.Fatal("expected error for unknown backend, got nil")
	}
}

// ── PostgreSQL ────────────────────────────────────────────────────────────────

func TestPostgres_OpenAndPing(t *testing.T) {
	dsn := pgDSN(t)
	store, err := fastenstore.Open("postgres", dsn, "fasten_go_sc_test")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	if err := store.Ping(); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestPostgres_InsertIdempotent(t *testing.T) {
	dsn := pgDSN(t)
	store, err := fastenstore.Open("postgres", dsn, "fasten_go_sc_test")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()

	row := makeRow("evt-go-pg-001", "TEST")
	if err := store.Insert(row); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if err := store.Insert(row); err != nil {
		t.Fatalf("idempotent insert: %v", err) // ON CONFLICT DO NOTHING
	}
}

func TestPostgres_SchemaQualified(t *testing.T) {
	dsn := pgDSN(t)
	store, err := fastenstore.Open("postgres", dsn, "fasten_go_sc_schema.audit_rows")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer store.Close()
	if err := store.Insert(makeRow("evt-go-schema-001", "TEST")); err != nil {
		t.Fatalf("Insert: %v", err)
	}
}
