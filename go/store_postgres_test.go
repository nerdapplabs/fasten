//go:build integration

package fasten

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func pgDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("FASTEN_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("FASTEN_TEST_POSTGRES_DSN not set")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		t.Fatalf("db.Ping: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func uniqueTable(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
}

func dropTable(t *testing.T, db *sql.DB, table string) {
	t.Helper()
	if _, err := db.Exec(fmt.Sprintf(`DROP TABLE IF EXISTS %s`, table)); err != nil {
		t.Logf("drop table %s: %v", table, err)
	}
}

func pgRow(id, requestID string) Row {
	return Row{
		ID:           id,
		OriginID:     id,
		MonotonicSeq: 1,
		Timestamp:    time.Now().UTC(),
		Code:         "USER_CREATED",
		Action:       "create",
		Severity:     SevInfo,
		ServiceID:    "svc-pg",
		SourceNodeID: "node-1",
		Actor:        "alice",
		ActorKind:    "user",
		Target:       "u-42",
		Category:     "account",
		Domain:       "user",
		Method:       "sdk",
		RequestID:    requestID,
		Detail:       map[string]any{"env": "test"},
	}
}

func TestPostgres_NewStore_InvalidTableName(t *testing.T) {
	db := pgDB(t)
	_, err := NewPostgresStore(db, "bad-name!")
	if err == nil {
		t.Fatal("expected error for invalid table name")
	}
}

func TestPostgres_InsertAndQuery(t *testing.T) {
	db := pgDB(t)
	table := uniqueTable("pg_insert")
	defer dropTable(t, db, table)

	store, err := NewPostgresStore(db, table)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}

	row := pgRow("evt-pg-001", "reqaabbccdd11")
	if err := store.Insert(context.Background(), row); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	got, err := store.Query(context.Background(), Filter{RequestID: "reqaabbccdd11"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 row, got %d", len(got))
	}
	if got[0].ID != "evt-pg-001" {
		t.Errorf("id = %q, want evt-pg-001", got[0].ID)
	}
	if got[0].Code != "USER_CREATED" {
		t.Errorf("code = %q, want USER_CREATED", got[0].Code)
	}
	if got[0].ServiceID != "svc-pg" {
		t.Errorf("service_id = %q, want svc-pg", got[0].ServiceID)
	}
}

func TestPostgres_InsertIdempotent(t *testing.T) {
	db := pgDB(t)
	table := uniqueTable("pg_idempotent")
	defer dropTable(t, db, table)

	store, err := NewPostgresStore(db, table)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}

	row := pgRow("evt-pg-dup", "reqdup000001")
	if err := store.Insert(context.Background(), row); err != nil {
		t.Fatalf("first Insert: %v", err)
	}
	if err := store.Insert(context.Background(), row); err != nil {
		t.Fatalf("second Insert (idempotent): %v", err)
	}

	got, err := store.Query(context.Background(), Filter{RequestID: "reqdup000001"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 row after duplicate insert, got %d", len(got))
	}
}

func TestPostgres_ListUnshipped(t *testing.T) {
	db := pgDB(t)
	table := uniqueTable("pg_unshipped")
	defer dropTable(t, db, table)

	store, err := NewPostgresStore(db, table)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}

	for i := 0; i < 3; i++ {
		r := pgRow(fmt.Sprintf("evt-unshipped-%d", i), fmt.Sprintf("req%012d", i))
		r.MonotonicSeq = int64(i + 1)
		if err := store.Insert(context.Background(), r); err != nil {
			t.Fatalf("Insert %d: %v", i, err)
		}
	}

	rows, err := store.ListUnshipped(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListUnshipped: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("expected 3 unshipped rows, got %d", len(rows))
	}
	for _, r := range rows {
		if r.ShippedAt != nil {
			t.Errorf("row %s should not have shipped_at set", r.ID)
		}
	}
}

func TestPostgres_MarkShipped(t *testing.T) {
	db := pgDB(t)
	table := uniqueTable("pg_shipped")
	defer dropTable(t, db, table)

	store, err := NewPostgresStore(db, table)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}

	ids := []string{"evt-ship-1", "evt-ship-2", "evt-ship-3"}
	for i, id := range ids {
		r := pgRow(id, fmt.Sprintf("reqship%06d", i))
		r.MonotonicSeq = int64(i + 1)
		if err := store.Insert(context.Background(), r); err != nil {
			t.Fatalf("Insert %s: %v", id, err)
		}
	}

	if err := store.MarkShipped(context.Background(), ids[:2]); err != nil {
		t.Fatalf("MarkShipped: %v", err)
	}

	unshipped, err := store.ListUnshipped(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListUnshipped: %v", err)
	}
	if len(unshipped) != 1 {
		t.Fatalf("expected 1 unshipped row, got %d", len(unshipped))
	}
	if unshipped[0].ID != "evt-ship-3" {
		t.Errorf("expected evt-ship-3 unshipped, got %s", unshipped[0].ID)
	}
}

func TestPostgres_MarkShipped_Empty(t *testing.T) {
	db := pgDB(t)
	table := uniqueTable("pg_ship_empty")
	defer dropTable(t, db, table)

	store, err := NewPostgresStore(db, table)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	if err := store.MarkShipped(context.Background(), nil); err != nil {
		t.Fatalf("MarkShipped(nil): %v", err)
	}
}

func TestPostgres_Purge(t *testing.T) {
	db := pgDB(t)
	table := uniqueTable("pg_purge")
	defer dropTable(t, db, table)

	store, err := NewPostgresStore(db, table)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}

	old := pgRow("evt-old", "reqold0000001")
	old.Timestamp = time.Now().UTC().Add(-48 * time.Hour)
	old.MonotonicSeq = 1
	if err := store.Insert(context.Background(), old); err != nil {
		t.Fatalf("Insert old: %v", err)
	}

	recent := pgRow("evt-recent", "reqrecent0001")
	recent.MonotonicSeq = 2
	if err := store.Insert(context.Background(), recent); err != nil {
		t.Fatalf("Insert recent: %v", err)
	}

	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	n, err := store.Purge(context.Background(), cutoff, false)
	if err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 purged row, got %d", n)
	}

	rows, err := store.Query(context.Background(), Filter{})
	if err != nil {
		t.Fatalf("Query after purge: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != "evt-recent" {
		t.Fatalf("expected only evt-recent to remain, got %v", rows)
	}
}

func TestPostgres_Purge_RespectUnshipped(t *testing.T) {
	db := pgDB(t)
	table := uniqueTable("pg_purge_unshipped")
	defer dropTable(t, db, table)

	store, err := NewPostgresStore(db, table)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}

	shipped := pgRow("evt-shipped", "reqshipped001")
	shipped.Timestamp = time.Now().UTC().Add(-48 * time.Hour)
	shipped.MonotonicSeq = 1
	if err := store.Insert(context.Background(), shipped); err != nil {
		t.Fatalf("Insert shipped: %v", err)
	}
	if err := store.MarkShipped(context.Background(), []string{"evt-shipped"}); err != nil {
		t.Fatalf("MarkShipped: %v", err)
	}

	unshipped := pgRow("evt-unshipped", "requnsent0001")
	unshipped.Timestamp = time.Now().UTC().Add(-48 * time.Hour)
	unshipped.MonotonicSeq = 2
	if err := store.Insert(context.Background(), unshipped); err != nil {
		t.Fatalf("Insert unshipped: %v", err)
	}

	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	n, err := store.Purge(context.Background(), cutoff, true)
	if err != nil {
		t.Fatalf("Purge(respectUnshipped=true): %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 purged row, got %d", n)
	}

	rows, err := store.ListUnshipped(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListUnshipped: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != "evt-unshipped" {
		t.Fatalf("unshipped row should survive respectUnshipped purge, got %v", rows)
	}
}

func TestPostgres_QueryFilters(t *testing.T) {
	db := pgDB(t)
	table := uniqueTable("pg_filters")
	defer dropTable(t, db, table)

	store, err := NewPostgresStore(db, table)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}

	r1 := pgRow("evt-filter-1", "reqfilter00001")
	r1.MonotonicSeq = 1
	r1.Code = "USER_CREATED"
	r1.Domain = "user"

	r2 := pgRow("evt-filter-2", "reqfilter00002")
	r2.MonotonicSeq = 2
	r2.Code = "USER_DELETED"
	r2.Domain = "user"

	for _, r := range []Row{r1, r2} {
		if err := store.Insert(context.Background(), r); err != nil {
			t.Fatalf("Insert %s: %v", r.ID, err)
		}
	}

	got, err := store.Query(context.Background(), Filter{Code: "USER_CREATED"})
	if err != nil {
		t.Fatalf("Query by Code: %v", err)
	}
	if len(got) != 1 || got[0].ID != "evt-filter-1" {
		t.Fatalf("expected evt-filter-1, got %v", got)
	}

	got, err = store.Query(context.Background(), Filter{Domain: "user"})
	if err != nil {
		t.Fatalf("Query by Domain: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 rows for domain=user, got %d", len(got))
	}

	got, err = store.Query(context.Background(), Filter{SourceNodeID: "node-1"})
	if err != nil {
		t.Fatalf("Query by SourceNodeID: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 rows for source_node_id=node-1, got %d", len(got))
	}
}

func TestPostgres_SchemaQualifiedTable(t *testing.T) {
	db := pgDB(t)

	schema := fmt.Sprintf("fasten_test_%d", time.Now().UnixNano())
	table := schema + ".audit"
	defer func() {
		db.Exec(fmt.Sprintf(`DROP SCHEMA IF EXISTS %s CASCADE`, schema))
	}()

	store, err := NewPostgresStore(db, table)
	if err != nil {
		t.Fatalf("NewPostgresStore with schema: %v", err)
	}

	row := pgRow("evt-schema-1", "reqschema00001")
	if err := store.Insert(context.Background(), row); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	got, err := store.Query(context.Background(), Filter{RequestID: "reqschema00001"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 || got[0].ID != "evt-schema-1" {
		t.Fatalf("expected evt-schema-1, got %v", got)
	}
}

func TestPostgres_PiiInDetail(t *testing.T) {
	db := pgDB(t)
	table := uniqueTable("pg_pii")
	defer dropTable(t, db, table)

	store, err := NewPostgresStore(db, table)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}

	row := pgRow("evt-pii-1", "reqpii0000001")
	row.PiiInDetail = true
	row.Detail = map[string]any{"_redacted": "***", "_pii_in_detail": true}
	if err := store.Insert(context.Background(), row); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	got, err := store.Query(context.Background(), Filter{RequestID: "reqpii0000001"})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(got) != 1 || !got[0].PiiInDetail {
		t.Fatalf("expected PiiInDetail=true, got %+v", got)
	}
}
