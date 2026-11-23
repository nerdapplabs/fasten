//go:build integration

package fasten

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Rows written through stores opened from Postgres DSNs are stored, and the
// audit chain verifies.
func TestEnvDSN_PostgresRoundTrip(t *testing.T) {
	dsn := pgDSN(t)
	db := pgDB(t)
	audit, api := uniqueTable("env_audit"), uniqueTable("env_api")
	t.Cleanup(func() {
		dropTable(t, db, audit)
		dropTable(t, db, api)
	})
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	e := envEngine(t)
	t.Setenv("FASTEN_AUDIT_DSN", dsn+sep+"table="+audit)
	// The scheme is read in any case.
	upper := "POSTGRES" + dsn[strings.Index(dsn, ":"):]
	t.Setenv("FASTEN_API_DSN", upper+sep+"table="+api)
	if err := initRaise(e, Config{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, ok := e.auditStore.(*PostgresStore); !ok {
		t.Fatalf("audit store is %T, want *PostgresStore", e.auditStore)
	}
	ps, ok := e.apiStore.(*PostgresStreamStore)
	if !ok {
		t.Fatalf("api store is %T, want *PostgresStreamStore", e.apiStore)
	}
	emitAndVerify(t, e, 3, 3)
	e.GetTransport().PushAPI(APIRow{"method": "GET", "path": "/x", "request_id": "r1"})
	if n, err := ps.Count(); err != nil || n != 1 {
		t.Fatalf("api rows %d, %v; want 1", n, err)
	}

	// A re-init with the same DSNs keeps the stores and the chain.
	first := e.auditStore
	if err := initRaise(e, Config{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if e.auditStore != first {
		t.Fatal("re-init with the same DSN must keep the store")
	}
	emitAndVerify(t, e, 4, 7)

	pgAudit := e.auditStore.(*PostgresStore)
	if !e.Close(5 * time.Second) {
		t.Fatal("Close returned false")
	}
	if err := pgAudit.db.Ping(); err == nil {
		t.Fatal("the Postgres store is still open after Close")
	}
}

// FASTEN_SYSLOG_DSN takes a Postgres DSN, with the default table syslog.
func TestEnvSyslogDSN_PostgresDefaultTable(t *testing.T) {
	dsn := pgDSN(t)
	db := pgDB(t)
	dropTable(t, db, "syslog")
	t.Cleanup(func() { dropTable(t, db, "syslog") })
	e := envEngine(t)
	t.Setenv("FASTEN_SYSLOG_DSN", dsn)
	if err := initRaise(e, Config{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	ps, ok := e.syslogStore.(*PostgresStreamStore)
	if !ok {
		t.Fatalf("sys store is %T, want *PostgresStreamStore", e.syslogStore)
	}
	e.LogSys(context.Background(), "info", "pg_sys", nil)
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM syslog`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("syslog rows %d, %v; want 1", n, err)
	}
	if !e.Close(5 * time.Second) {
		t.Fatal("Close returned false")
	}
	if err := ps.db.Ping(); err == nil {
		t.Fatal("the Postgres sys store is still open after Close")
	}
}
