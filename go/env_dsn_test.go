package fasten

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// FASTEN_API_DSN / FASTEN_SYSLOG_DSN autoload a SQLite stream store when no
// explicit store is passed — parity with the Python SDK.
func TestEnvDSNAutoloadSQLite(t *testing.T) {
	registerTestCodes(t)
	clearDSNEnv(t)
	t.Cleanup(Default.ResetForTests)
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

// OpenStreamStore accepts sqlite:/// URL DSNs and honours ?table= to
// override the default table name, as the Python SDK does.
func TestOpenStreamStore_SqliteURL(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStreamStore("sqlite:///"+dir+"/streams.db?table=my_sys", "syslog")
	if err != nil {
		t.Fatalf("sqlite:/// URL DSN with ?table= should be accepted: %v", err)
	}
	defer s.db.Close()
	if s.table != "my_sys" {
		t.Errorf("?table= override ignored: got %q, want my_sys", s.table)
	}
}

func TestOpenStreamStore_RejectsNonSqliteURL(t *testing.T) {
	// Neither is a SQLite DSN; reject rather than opening a file literally
	// named "mysql://...".
	for _, dsn := range []string{"mysql://host/db", "postgresql+psycopg://host/db", "postgres://host/db"} {
		if _, err := OpenStreamStore(dsn, "syslog"); err == nil {
			t.Fatalf("%s: want an error, not a file", dsn)
		}
	}
}

func TestParseStoreDSN_Forms(t *testing.T) {
	sqlite := func(path, table string, wal bool) storeDSN {
		return storeDSN{scheme: "sqlite", conn: path, table: table, wal: wal}
	}
	pg := func(conn, table string) storeDSN {
		return storeDSN{scheme: "postgres", conn: conn, table: table}
	}
	for _, c := range []struct {
		dsn  string
		want storeDSN
	}{
		{"sqlite:///rel.db", sqlite("rel.db", "audit_log", true)},
		{"sqlite:////abs/a.db", sqlite("/abs/a.db", "audit_log", true)},
		{"SQLite:///rel.db?wal=false", sqlite("rel.db", "audit_log", false)},
		{"/var/a.db?table=t1", sqlite("/var/a.db", "t1", true)},
		{"./a.db", sqlite("./a.db", "audit_log", true)},
		{"sqlite:///a.db?table=&wal=true", sqlite("a.db", "audit_log", true)},
		{"/var/a.db?table=t1&_pragma=busy_timeout(5000)", sqlite("/var/a.db?_pragma=busy_timeout(5000)", "t1", true)},
		{"postgres://u:p@db/app?table=audit.rows&sslmode=disable", pg("postgres://u:p@db/app?sslmode=disable", "audit.rows")},
		{"PostgreSQL://db/app?table=t", pg("postgresql://db/app", "t")},
		{"postgres://db/app", pg("postgres://db/app", "audit_log")},
	} {
		got, err := parseStoreDSN(c.dsn, "audit_log")
		if err != nil {
			t.Errorf("%s: %v", c.dsn, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: got %+v, want %+v", c.dsn, got, c.want)
		}
	}
}

func TestParseStoreDSN_ErrorsNameTheSchemeOnly(t *testing.T) {
	for _, c := range []struct{ dsn, want string }{
		{"mysql://app:hunter2@db/audit", `'mysql'`},
		{"postgresql+psycopg://app:hunter2@db/audit", `'postgresql+psycopg'`},
		{"host=db password=hunter2", "keyword form"},
		{" dbname = app password=hunter2", "keyword form"},
		{"sqlite://", "no path"},
		{"sqlite:///", "no path"},
		{"sqlite://app:hunter2@db", "no path"},
		{"file:///var/hunter2.db", "'file'"},
		{"file:/var/hunter2.db?mode=rwc", "DSN form not recognised"},
		{"C:/hunter2/a.db", "DSN form not recognised"},
		{`C:\hunter2\a.db`, "DSN form not recognised"},
	} {
		_, err := parseStoreDSN(c.dsn, "audit_log")
		if err == nil {
			t.Fatalf("%s: want an error", c.dsn)
		}
		if msg := err.Error(); !strings.Contains(msg, c.want) || strings.Contains(msg, "hunter2") {
			t.Errorf("%s: error %q", c.dsn, msg)
		}
	}
}

// clearDSNEnv unsets the DSN variables for the test.
func clearDSNEnv(t *testing.T) {
	t.Helper()
	for _, v := range dsnEnvVars {
		t.Setenv(v, "")
	}
}

// envEngine is an Engine for env DSN tests, reset at the end of the test.
func envEngine(t *testing.T) *Engine {
	t.Helper()
	registerTestCodes(t)
	clearDSNEnv(t)
	e := &Engine{}
	t.Cleanup(e.ResetForTests)
	return e
}

func initRaise(e *Engine, cfg Config) error {
	cfg.ServiceID, cfg.NodeID, cfg.AuditStoreFailureStrategy = "svc", "node", "raise"
	return e.Init(cfg)
}

// emitAndVerify emits n rows through e and checks that its audit store
// holds a verified chain of want rows.
func emitAndVerify(t *testing.T, e *Engine, n, want int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		if _, err := e.Emit(ctx, "USER_CREATED", Target("u-1")); err != nil {
			t.Fatalf("Emit: %v", err)
		}
	}
	rows, err := e.auditStore.Query(ctx, Filter{Limit: 100})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != want {
		t.Fatalf("got %d rows, want %d", len(rows), want)
	}
	if res := VerifyChain(rows); !res.OK {
		t.Fatalf("chain does not verify: %+v", res)
	}
}

func journalMode(t *testing.T, path string) string {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var mode string
	if err := db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		t.Fatal(err)
	}
	return mode
}

func TestEnvAuditDSN_SQLiteForms(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	for _, c := range []struct {
		name, dsn, file, table, journal string
	}{
		{"relative", "sqlite:///rel.db", "rel.db", "audit_log", "wal"},
		{"absolute", "sqlite:///" + dir + "/abs.db", dir + "/abs.db", "audit_log", "wal"},
		{"scheme case", "SQLITE:///" + dir + "/upper.db", dir + "/upper.db", "audit_log", "wal"},
		{"bare path", dir + "/bare.db", dir + "/bare.db", "audit_log", "wal"},
		{"table", dir + "/t.db?table=my_audit", dir + "/t.db", "my_audit", "wal"},
		{"no wal", "sqlite:///" + dir + "/nowal.db?wal=false", dir + "/nowal.db", "audit_log", "delete"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := envEngine(t)
			t.Setenv("FASTEN_AUDIT_DSN", c.dsn)
			if err := initRaise(e, Config{}); err != nil {
				t.Fatalf("Init: %v", err)
			}
			s, ok := e.auditStore.(*SQLiteStore)
			if !ok {
				t.Fatalf("audit store is %T, want *SQLiteStore", e.auditStore)
			}
			if s.table != c.table {
				t.Fatalf("table %q, want %q", s.table, c.table)
			}
			if got := e.streamSource("audit"); got != "store" {
				t.Fatalf("audit streamSource=%q, want store", got)
			}
			emitAndVerify(t, e, 3, 3)
			if _, err := os.Stat(c.file); err != nil {
				t.Fatalf("store file: %v", err)
			}
			if got := journalMode(t, c.file); got != c.journal {
				t.Fatalf("journal_mode %q, want %q", got, c.journal)
			}
		})
	}
}

func TestEnvAuditDSN_ExplicitConfigWins(t *testing.T) {
	e := envEngine(t)
	dir := t.TempDir()
	t.Setenv("FASTEN_AUDIT_DSN", dir+"/env.db")
	t.Setenv("FASTEN_API_DSN", dir+"/env-api.db")
	db, err := sql.Open("sqlite", dir+"/mine.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := NewSQLiteStore(db, "audit_log")
	if err != nil {
		t.Fatal(err)
	}
	api, err := OpenStreamStore(dir+"/mine-api.db", "api_log")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { api.db.Close() })
	if err := initRaise(e, Config{AuditStore: store, APIStore: api}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if e.auditStore != store || e.apiStore != api {
		t.Fatal("a store passed in Config must win over the environment")
	}
	for _, f := range []string{"env.db", "env-api.db"} {
		if _, err := os.Stat(filepath.Join(dir, f)); !os.IsNotExist(err) {
			t.Fatalf("%s was created: %v", f, err)
		}
	}
}

func TestEnvDSN_BadDSNFailsInitNamingTheVariableOnly(t *testing.T) {
	for _, c := range []struct{ env, dsn, want string }{
		{"FASTEN_AUDIT_DSN", "mysql://app:hunter2@db/audit", `'mysql'`},
		{"FASTEN_AUDIT_DSN", "host=db user=app password=hunter2", "keyword form"},
		{"FASTEN_AUDIT_DSN", "postgresql+psycopg://app:hunter2@db/audit", `'postgresql+psycopg'`},
		{"FASTEN_AUDIT_DSN", "sqlite://", "no path"},
		{"FASTEN_API_DSN", "mysql://app:hunter2@db/audit", `'mysql'`},
		{"FASTEN_SYSLOG_DSN", "host=db password=hunter2", "keyword form"},
	} {
		e := envEngine(t)
		t.Setenv(c.env, c.dsn)
		err := initRaise(e, Config{})
		if err == nil {
			t.Fatalf("%s=%s: want an Init error", c.env, c.dsn)
		}
		msg := err.Error()
		if !strings.Contains(msg, c.env) || !strings.Contains(msg, c.want) {
			t.Errorf("%s=%s: error %q", c.env, c.dsn, msg)
		}
		if strings.Contains(msg, "hunter2") || (len(c.dsn) > len("sqlite://") && strings.Contains(msg, c.dsn)) {
			t.Errorf("error quotes the DSN: %q", msg)
		}
		e.ResetForTests()
		t.Setenv(c.env, "")
	}
}

// Every DSN is checked before any store opens: a failed Init creates no
// file and keeps the stores it had.
func TestEnvDSN_FailedInitCreatesNoFileAndKeepsStores(t *testing.T) {
	e := envEngine(t)
	dir := t.TempDir()
	t.Setenv("FASTEN_AUDIT_DSN", dir+"/a.db")
	t.Setenv("FASTEN_API_DSN", dir+"/api.db")
	if err := initRaise(e, Config{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	audit, api := e.auditStore, e.apiStore

	for _, c := range []struct{ env, dsn, want string }{
		{"FASTEN_SYSLOG_DSN", dir + "/missing/sys.db", "cannot open the sqlite store (*fs.PathError)"},
		{"FASTEN_SYSLOG_DSN", dir + "/sys.db?table=bad-name", "not a valid SQL identifier"},
		{"FASTEN_SYSLOG_DSN", "mysql://db/x", `'mysql'`},
	} {
		t.Setenv("FASTEN_AUDIT_DSN", dir+"/b.db")
		t.Setenv(c.env, c.dsn)
		err := initRaise(e, Config{})
		if err == nil || !strings.Contains(err.Error(), c.env+": ") || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: error %v, want %q", c.dsn, err, c.want)
		}
		if strings.Contains(err.Error(), dir) {
			t.Fatalf("error quotes the path: %v", err)
		}
		entries, _ := os.ReadDir(dir)
		for _, en := range entries {
			if n := en.Name(); n != "a.db" && n != "api.db" && !strings.HasPrefix(n, "a.db-") && !strings.HasPrefix(n, "api.db-") {
				t.Fatalf("failed Init created %s", n)
			}
		}
		if e.auditStore != audit || e.apiStore != api {
			t.Fatal("failed Init replaced the stores")
		}
	}
	// The kept stores are still open.
	t.Setenv("FASTEN_AUDIT_DSN", dir+"/a.db")
	t.Setenv("FASTEN_SYSLOG_DSN", "")
	if err := initRaise(e, Config{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if e.auditStore != audit || e.apiStore != api {
		t.Fatal("Init with the same DSNs must keep the stores")
	}
	emitAndVerify(t, e, 1, 1)
	if _, err := api.Count(); err != nil {
		t.Fatalf("api store closed: %v", err)
	}
}

func TestEnvDSN_SameDSNKeepsStoreOtherDSNClosesIt(t *testing.T) {
	e := envEngine(t)
	dir := t.TempDir()
	t.Setenv("FASTEN_AUDIT_DSN", dir+"/a.db")
	t.Setenv("FASTEN_SYSLOG_DSN", dir+"/sys.db")
	if err := initRaise(e, Config{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	first := e.auditStore.(*SQLiteStore)
	sys := e.syslogStore.(*StreamStore)
	if err := initRaise(e, Config{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if e.auditStore != first || e.syslogStore != sys {
		t.Fatal("re-init with the same DSN must keep the store")
	}
	emitAndVerify(t, e, 2, 2)

	t.Setenv("FASTEN_AUDIT_DSN", dir+"/b.db")
	if err := initRaise(e, Config{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if e.auditStore == first {
		t.Fatal("a new DSN must open a new store")
	}
	if err := first.db.Ping(); err == nil {
		t.Fatal("the store for the old DSN is still open")
	}
	if err := sys.db.Ping(); err != nil {
		t.Fatalf("the unchanged sys store was closed: %v", err)
	}
	emitAndVerify(t, e, 1, 1)

	// A store passed in Config replaces the one from the environment,
	// which is closed.
	second := e.auditStore.(*SQLiteStore)
	db, err := sql.Open("sqlite", dir+"/mine.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	mine, err := NewSQLiteStore(db, "audit_log")
	if err != nil {
		t.Fatal(err)
	}
	if err := initRaise(e, Config{AuditStore: mine}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := second.db.Ping(); err == nil {
		t.Fatal("the store from the environment is still open")
	}
}

func TestEnvDSN_CloseClosesEnvStores(t *testing.T) {
	e := envEngine(t)
	dir := t.TempDir()
	t.Setenv("FASTEN_AUDIT_DSN", dir+"/a.db")
	t.Setenv("FASTEN_API_DSN", dir+"/api.db")
	t.Setenv("FASTEN_SYSLOG_DSN", dir+"/sys.db")
	if err := e.Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	dbs := []*sql.DB{
		e.auditStore.(*SQLiteStore).db,
		e.apiStore.(*StreamStore).db,
		e.syslogStore.(*StreamStore).db,
	}
	if !e.Close(5 * time.Second) {
		t.Fatal("Close returned false")
	}
	for i, db := range dbs {
		if err := db.Ping(); err == nil {
			t.Fatalf("store %d still open after Close", i)
		}
	}
	// A later Init opens them again.
	if err := initRaise(e, Config{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := e.auditStore.(*SQLiteStore).db.Ping(); err != nil {
		t.Fatalf("Init after Close: %v", err)
	}
	emitAndVerify(t, e, 1, 1)
}

func TestEnvDSN_UnreadVariableReportedOnce(t *testing.T) {
	e := envEngine(t)
	for _, v := range []string{"FASTEN_AUDIT_DNS", "FASTEN_SYSLOG_URL"} {
		warnedDSNEnv.Delete(v)
		t.Cleanup(func() { warnedDSNEnv.Delete(v) })
	}
	t.Setenv("FASTEN_AUDIT_DNS", "sqlite:///hunter2.db")
	t.Setenv("FASTEN_SYSLOG_URL", "sqlite:///hunter2.db")
	t.Setenv("FASTEN_AUDIT_DSN", t.TempDir()+"/a.db")
	reported := func() map[string]int {
		rows, err := e.GetTransport().QuerySyslog(1000, StreamQuery{})
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]int{}
		for _, r := range rows {
			if r["event"] != "env_dsn_not_read" {
				continue
			}
			for _, v := range r {
				if s, ok := v.(string); ok && strings.Contains(s, "hunter2") {
					t.Fatalf("the report quotes the value: %v", r)
				}
			}
			got[r["variable"].(string)]++
		}
		return got
	}
	if err := initRaise(e, Config{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	got := reported()
	if got["FASTEN_AUDIT_DNS"] != 1 || got["FASTEN_SYSLOG_URL"] != 1 {
		t.Fatalf("reports %v, want one for each misnamed variable", got)
	}
	if got["FASTEN_AUDIT_DSN"] != 0 {
		t.Fatal("FASTEN_AUDIT_DSN is read and must not be reported")
	}
	if err := initRaise(e, Config{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if got := reported(); got["FASTEN_AUDIT_DNS"] != 0 || got["FASTEN_SYSLOG_URL"] != 0 {
		t.Fatalf("reported again on re-init: %v", got)
	}
}
