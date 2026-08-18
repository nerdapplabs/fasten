package fasten

import "testing"

// FASTEN_API_DSN / FASTEN_SYSLOG_DSN autoload a SQLite stream store when no
// explicit store is passed — parity with the Python SDK.
func TestEnvDSNAutoloadSQLite(t *testing.T) {
	registerTestCodes(t)
	t.Setenv("FASTEN_API_DSN", t.TempDir()+"/api.db")
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if Default.apiStore == nil {
		t.Fatal("FASTEN_API_DSN should have autoloaded an api store")
	}
	if got := Default.streamSource("api"); got != "store" {
		t.Fatalf("api streamSource=%q, want store", got)
	}
	// sys was not configured -> still ring
	if got := Default.streamSource("sys"); got != "ring" {
		t.Fatalf("sys streamSource=%q, want ring", got)
	}
}

// Go bundles no Postgres driver, so a Postgres DSN must fail with a clear error
// rather than silently open a file literally named "postgres://…".
func TestEnvDSNAutoloadRejectsPostgres(t *testing.T) {
	registerTestCodes(t)
	t.Setenv("FASTEN_SYSLOG_DSN", "postgres://u:p@localhost:5432/db")
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err == nil {
		t.Fatal("a Postgres FASTEN_SYSLOG_DSN must return a clear error")
	}
}
