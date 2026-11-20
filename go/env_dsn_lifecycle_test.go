package fasten

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// waitFor fails the test if cond is not true within timeout.
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// wgDone reports whether wg finishes waiting within timeout.
func wgDone(wg *sync.WaitGroup, timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// auditRows reads the audit rows in the SQLite file at path.
func auditRows(t *testing.T, path string) []Row {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, err := NewSQLiteStore(db, "audit_log")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := s.Query(context.Background(), Filter{Limit: 10000})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// streamCount counts the rows in the stream table of the SQLite file at path.
func streamCount(t *testing.T, path, table string) int {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// A failed Init leaves the stores, transport, retention and drainer as they
// were, however late the check that fails.
func TestEnvDSN_FailedInitLeavesEngineAsItWas(t *testing.T) {
	e := envEngine(t)
	dir := t.TempDir()
	t.Setenv("FASTEN_AUDIT_DSN", dir+"/a.db")
	t.Setenv("FASTEN_SYSLOG_DSN", dir+"/sys.db")
	base := Config{ServiceID: "svc", NodeID: "node", RetentionSyslog: time.Hour}
	if err := e.Init(base); err != nil {
		t.Fatalf("Init: %v", err)
	}
	audit, sys, xport := e.auditStore, e.syslogStore, e.GetTransport()
	envAudit, envSys := e.envStores["FASTEN_AUDIT_DSN"], e.envStores["FASTEN_SYSLOG_DSN"]
	drainer, wg := e.activeDrainer(), e.retentionWg
	if drainer == nil || wg == nil || e.retentionCancel == nil {
		t.Fatal("Init must install a drainer and start retention")
	}

	badStrategy := base
	badStrategy.AuditStoreFailureStrategy = "bogus"
	mismatch := base
	mismatch.PersistStreams = []string{"api"}
	badRetention := base
	badRetention.RetentionSyslog = 0
	for _, c := range []struct {
		name string
		cfg  Config
		env  map[string]string
		want string
	}{
		{"strategy", badStrategy, nil, "AuditStoreFailureStrategy"},
		{"persist streams", mismatch, nil, "PersistStreams"},
		{"retention", badRetention, map[string]string{"FASTEN_RETENTION_SYSLOG": "1.5h"}, "FASTEN_RETENTION_SYSLOG"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("FASTEN_AUDIT_DSN", dir+"/b.db")
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			err := e.Init(c.cfg)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %v, want one about %s", err, c.want)
			}
			if e.auditStore != audit || e.syslogStore != sys || e.apiStore != nil || e.GetTransport() != xport {
				t.Fatal("a failed Init replaced a store or the transport")
			}
			if e.envStores["FASTEN_AUDIT_DSN"] != envAudit || e.envStores["FASTEN_SYSLOG_DSN"] != envSys || len(e.envStores) != 2 {
				t.Fatalf("a failed Init changed the env stores: %v", e.envStores)
			}
			if e.activeDrainer() != drainer || e.retentionWg != wg || e.retentionCancel == nil {
				t.Fatal("a failed Init changed the drainer or retention")
			}
			if exists(dir + "/b.db") {
				t.Fatal("a failed Init created b.db")
			}
		})
	}

	if _, err := e.Emit(context.Background(), "USER_CREATED", Target("u-1")); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if !e.Flush(5 * time.Second) {
		t.Fatal("Flush timed out")
	}
	rows, err := audit.Query(context.Background(), Filter{Limit: 10})
	if err != nil || len(rows) != 1 {
		t.Fatalf("a.db rows %d, %v; want 1", len(rows), err)
	}
}

// DSN errors name a scheme only when the DSN has one.
func TestParseStoreDSN_ErrorsNameASchemeOnlyWhenTheDSNHasOne(t *testing.T) {
	leaks := []string{"admin", "s3cret", "db.internal", "user", "pw", "host"}
	for _, dsn := range []string{
		"admin:s3cret@db.internal:5432/app",
		"db.internal:5432/app",
		"user:pw@host/db",
	} {
		_, perr := parseStoreDSN(dsn, "audit_log")
		_, serr := OpenStreamStore(dsn, "syslog")
		e := envEngine(t)
		t.Setenv("FASTEN_AUDIT_DSN", dsn)
		ierr := initRaise(e, Config{})
		for _, err := range []error{perr, serr, ierr} {
			if err == nil {
				t.Fatalf("%s: want an error", dsn)
			}
			msg := err.Error()
			if !strings.Contains(msg, "DSN form not recognised") {
				t.Errorf("%s: error %q", dsn, msg)
			}
			for _, leak := range leaks {
				if strings.Contains(msg, leak) {
					t.Errorf("%s: error %q quotes %q", dsn, msg, leak)
				}
			}
		}
		e.ResetForTests()
	}
	// With "//" after it, the scheme is named.
	if _, err := parseStoreDSN("mysql://admin:s3cret@db/app", "t"); err == nil ||
		!strings.Contains(err.Error(), `"mysql"`) || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("error %v", err)
	}
	// As in Python, a ':' in a later path segment, or after a leading '.',
	// leaves a bare path.
	for _, dsn := range []string{"data/a:b.db", "./a:b.db"} {
		d, err := parseStoreDSN(dsn, "t")
		if err != nil || d.conn != dsn {
			t.Fatalf("%s: got %+v, %v", dsn, d, err)
		}
	}
}

// A SQLite path is used as written and a fragment is dropped, as Python's
// urlparse gives them (sqlite_dsn_path in python/fasten/store/sqlite.py).
func TestParseStoreDSN_PathsAsPythonParsesThem(t *testing.T) {
	for _, c := range []struct{ dsn, path, table string }{
		{"sqlite:///./audit%20log.db", "./audit%20log.db", "audit_log"},
		{"sqlite:///./100%.db", "./100%.db", "audit_log"},
		{"./audit.db#x", "./audit.db", "audit_log"},
		{"sqlite:///a.db#x?y", "a.db", "audit_log"},
		{"sqlite://app:pw@db/%zz", "%zz", "audit_log"},
		{"sqlite:rel.db", "rel.db", "audit_log"},
		{"/a.db?table=t#frag", "/a.db", "t"},
		{"./a.db?x#y?table=t", "./a.db?x", "audit_log"},
		{"sqlite:///a.db?table=my%5Ft", "a.db", "my_t"},
	} {
		d, err := parseStoreDSN(c.dsn, "audit_log")
		if err != nil {
			t.Errorf("%s: %v", c.dsn, err)
			continue
		}
		if d.conn != c.path || d.table != c.table {
			t.Errorf("%s: path %q table %q, want %q %q", c.dsn, d.conn, d.table, c.path, c.table)
		}
	}
	// The file is created under the name as written.
	dir := t.TempDir()
	t.Chdir(dir)
	e := envEngine(t)
	t.Setenv("FASTEN_AUDIT_DSN", "sqlite:///./audit%20log.db")
	if err := initRaise(e, Config{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	emitAndVerify(t, e, 1, 1)
	if !exists(filepath.Join(dir, "audit%20log.db")) {
		t.Fatal("audit%20log.db was not created")
	}
}

// blockingPurgeStore is a stream store whose Purge waits for release.
type blockingPurgeStore struct {
	StreamRepository
	entered chan struct{}
	release chan struct{}
}

func (s *blockingPurgeStore) Purge(before string) (int64, error) {
	close(s.entered)
	<-s.release
	return s.StreamRepository.Purge(before)
}

// Close does not wait past its timeout for a purge it cannot cancel; the
// store the purge uses is closed once the purge returns.
func TestEnvDSN_CloseDoesNotWaitOnARunningPurge(t *testing.T) {
	e := envEngine(t)
	t.Setenv("FASTEN_SYSLOG_DSN", t.TempDir()+"/sys.db")
	if err := initRaise(e, Config{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	held := e.envStores["FASTEN_SYSLOG_DSN"]
	blocking := &blockingPurgeStore{
		StreamRepository: e.syslogStore,
		entered:          make(chan struct{}),
		release:          make(chan struct{}),
	}
	held.store = blocking
	e.syslogStore = blocking
	e.startRetention(retentionWindows{sys: time.Hour})
	select {
	case <-blocking.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the purge did not start")
	}

	start := time.Now()
	if e.Close(50 * time.Millisecond) {
		t.Fatal("Close returned true with a purge still running")
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("Close took %v", took)
	}
	if err := held.db.Ping(); err != nil {
		t.Fatalf("the store was closed under the running purge: %v", err)
	}
	close(blocking.release)
	waitFor(t, 5*time.Second, "the store to close", func() bool { return held.db.Ping() != nil })
}

// A slog handler writes to the engine's current transport, so it follows
// Close, Init and a DSN change.
func TestSlogHandlerFollowsReinit(t *testing.T) {
	registerTestCodes(t)
	clearDSNEnv(t)
	t.Cleanup(Default.ResetForTests)
	dir := t.TempDir()
	logger := slog.New(NewSlogHandler(slog.NewTextHandler(io.Discard, nil)))

	t.Setenv("FASTEN_SYSLOG_DSN", dir+"/sys1.db")
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	logger.Info("first")
	Close(5 * time.Second)
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	logger.Info("second")
	for _, ev := range []string{"first", "second"} {
		if n, err := Default.syslogStore.CountMatching(map[string]string{"event": ev}, "", ""); err != nil || n != 1 {
			t.Fatalf("sys1.db %s rows %d, %v; want 1", ev, n, err)
		}
	}

	t.Setenv("FASTEN_SYSLOG_DSN", dir+"/sys2.db")
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	logger.With("k", "v").Info("third")
	if n, err := Default.syslogStore.CountMatching(map[string]string{"event": "third"}, "", ""); err != nil || n != 1 {
		t.Fatalf("sys2.db third rows %d, %v; want 1", n, err)
	}
}

// After Close, rows meant for stores opened from the environment go to
// stdout or the rings only and count as no failure; stores passed in
// Config stay open and in use.
func TestEnvDSN_AfterCloseRowsSkipEnvStores(t *testing.T) {
	e := envEngine(t)
	dir := t.TempDir()
	t.Setenv("FASTEN_AUDIT_DSN", dir+"/a.db")
	t.Setenv("FASTEN_API_DSN", dir+"/api.db")
	t.Setenv("FASTEN_SYSLOG_DSN", dir+"/sys.db")
	if err := initRaise(e, Config{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	sys := e.syslogStore
	if !e.Close(5 * time.Second) {
		t.Fatal("Close returned false")
	}
	if e.auditStore != nil || e.apiStore != nil || e.syslogStore != nil {
		t.Fatal("Close kept a store opened from the environment")
	}
	x := e.GetTransport()
	if x.APIStore != nil || x.SyslogStore != nil {
		t.Fatal("the transport still writes to a closed store")
	}
	row, err := e.Emit(context.Background(), "USER_CREATED", Target("u-1"))
	if err != nil || row.Hash != "" {
		t.Fatalf("Emit after Close: %+v, %v; want an unsealed row and no error", row, err)
	}
	e.LogSys(context.Background(), "info", "after_close", nil)
	x.PushAPI(APIRow{"method": "GET", "path": "/x"})
	for _, stream := range []string{"audit", "api", "sys"} {
		if got := e.streamSource(stream); got != "ring" {
			t.Fatalf("%s streamSource=%q, want ring", stream, got)
		}
	}
	if e.auditDegraded() || sys.Degraded() {
		t.Fatal("rows after Close counted as store failures")
	}
	if rows, _ := x.QuerySyslog(10, StreamQuery{Event: "after_close"}); len(rows) != 1 {
		t.Fatalf("ring rows %v, want the row", rows)
	}
	if got := len(auditRows(t, dir+"/a.db")); got != 0 {
		t.Fatalf("a.db rows %d, want 0", got)
	}
}

// Close stops retention and leaves stores passed in Config open; a row
// for a Config store is stored inline after Close.
func TestEnvDSN_CloseStopsRetentionKeepsConfigStores(t *testing.T) {
	e := envEngine(t)
	dir := t.TempDir()
	t.Setenv("FASTEN_API_DSN", dir+"/api.db")
	db, err := sql.Open("sqlite", dir+"/mine.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	mine, err := NewSQLiteStore(db, "audit_log")
	if err != nil {
		t.Fatal(err)
	}
	sys, err := OpenStreamStore(dir+"/mine-sys.db", "syslog")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sys.db.Close() })
	err = e.Init(Config{
		ServiceID: "svc", NodeID: "node", AuditStore: mine, SyslogStore: sys,
		RetentionSyslog: time.Hour, RetentionAPI: time.Hour,
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	wg := e.retentionWg
	if wg == nil || e.retentionCancel == nil {
		t.Fatal("Init must start retention")
	}
	if !e.Close(5 * time.Second) {
		t.Fatal("Close returned false")
	}
	if e.retentionCancel != nil || !wgDone(wg, 5*time.Second) {
		t.Fatal("Close did not stop retention")
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("Close closed the audit store passed in Config: %v", err)
	}
	if err := sys.db.Ping(); err != nil {
		t.Fatalf("Close closed the sys store passed in Config: %v", err)
	}
	if e.auditStore != mine || e.syslogStore != sys || e.GetTransport().SyslogStore != sys {
		t.Fatal("Close dropped a store passed in Config")
	}
	if _, err := e.Emit(context.Background(), "USER_CREATED", Target("u-1")); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if rows, err := mine.Query(context.Background(), Filter{Limit: 10}); err != nil || len(rows) != 1 {
		t.Fatalf("rows %d, %v; want the row stored inline", len(rows), err)
	}
}

// A store that fails to open rolls back the ones this Init opened and the
// files it created; the previous stores stay.
func TestEnvDSN_OpenFailureRollsBack(t *testing.T) {
	e := envEngine(t)
	dir := t.TempDir()
	t.Setenv("FASTEN_AUDIT_DSN", dir+"/a.db")
	if err := initRaise(e, Config{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	audit := e.auditStore
	bad := dir + "/bad.db"
	if err := os.WriteFile(bad, []byte("not a database, just text that is long enough"), 0o600); err != nil {
		t.Fatal(err)
	}
	var opened []*envStore
	testHookEnvOpened = func(es *envStore) { opened = append(opened, es) }
	t.Cleanup(func() { testHookEnvOpened = nil })

	t.Setenv("FASTEN_AUDIT_DSN", dir+"/new.db")
	t.Setenv("FASTEN_SYSLOG_DSN", bad)
	err := initRaise(e, Config{})
	if err == nil {
		t.Fatal("want an Init error")
	}
	msg := err.Error()
	prefix := "fasten.Init: FASTEN_SYSLOG_DSN: cannot open the sqlite store ("
	if !strings.HasPrefix(msg, prefix) || !strings.HasSuffix(msg, ")") || strings.Contains(msg, dir) {
		t.Fatalf("error %q", msg)
	}
	if typ := strings.TrimSuffix(strings.TrimPrefix(msg, prefix), ")"); typ != "*sqlite.Error" {
		t.Fatalf("error type %q", typ)
	}
	if len(opened) != 1 || opened[0].name != "FASTEN_AUDIT_DSN" {
		t.Fatalf("opened %v, want the new audit store", opened)
	}
	if err := opened[0].db.Ping(); err == nil {
		t.Fatal("the store this Init opened is still open")
	}
	for _, f := range []string{"new.db", "new.db-wal", "new.db-shm"} {
		if exists(filepath.Join(dir, f)) {
			t.Fatalf("the failed Init left %s", f)
		}
	}
	if !exists(bad) {
		t.Fatal("the rollback removed a file that was there before")
	}
	if e.auditStore != audit || e.envStores["FASTEN_AUDIT_DSN"].store != audit || e.syslogStore != nil {
		t.Fatal("a failed Init replaced the stores")
	}
	emitAndVerify(t, e, 2, 2)
}

// A re-init onto another DSN in queue mode stores every queued row in the
// old store before closing it.
func TestEnvDSN_ReinitQueueModeKeepsQueuedRowsInOldStore(t *testing.T) {
	e := envEngine(t)
	dir := t.TempDir()
	t.Setenv("FASTEN_AUDIT_DSN", dir+"/a.db")
	t.Setenv("FASTEN_SYSLOG_DSN", dir+"/s1.db")
	cfg := Config{ServiceID: "svc", NodeID: "node"}
	if err := e.Init(cfg); err != nil {
		t.Fatalf("Init: %v", err)
	}
	old := e.auditStore.(*SQLiteStore)
	oldSys := e.syslogStore.(*StreamStore)
	const n = 50
	for i := 0; i < n; i++ {
		if _, err := e.Emit(context.Background(), "USER_CREATED", Target("u-1")); err != nil {
			t.Fatalf("Emit: %v", err)
		}
	}
	e.GetTransport().PushSyslog(SyslogRow{"level": "info", "event": "before_switch"})

	t.Setenv("FASTEN_AUDIT_DSN", dir+"/b.db")
	t.Setenv("FASTEN_SYSLOG_DSN", dir+"/s2.db")
	if err := e.Init(cfg); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := old.db.Ping(); err == nil {
		t.Fatal("the old audit store is still open")
	}
	if err := oldSys.db.Ping(); err == nil {
		t.Fatal("the old sys store is still open")
	}
	if old.Degraded() || oldSys.Degraded() {
		t.Fatal("a write hit a closed store")
	}
	rows := auditRows(t, dir+"/a.db")
	if len(rows) != n {
		t.Fatalf("a.db rows %d, want %d", len(rows), n)
	}
	if res := VerifyChain(rows); !res.OK {
		t.Fatalf("a.db chain does not verify: %+v", res)
	}
	if got, err := e.auditStore.Query(context.Background(), Filter{Limit: 10}); err != nil || len(got) != 0 {
		t.Fatalf("b.db rows %d, %v; want 0", len(got), err)
	}
	for _, ev := range []string{"audit_drain_lost_at_stop", "audit_drain_dead_letter", "audit_sync_fallback_failed"} {
		if rows := countSysEvent(t, e, ev); rows != 0 {
			t.Fatalf("%d %s events", rows, ev)
		}
	}
	db, err := sql.Open("sqlite", dir+"/s1.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var marked int
	if err := db.QueryRow(`SELECT COUNT(*) FROM syslog WHERE event = 'before_switch'`).Scan(&marked); err != nil || marked != 1 {
		t.Fatalf("s1.db before_switch rows %d, %v; want 1", marked, err)
	}
	if got, _ := e.syslogStore.CountMatching(map[string]string{"event": "before_switch"}, "", ""); got != 0 {
		t.Fatalf("s2.db holds %d rows from before the switch", got)
	}
}

func countSysEvent(t *testing.T, e *Engine, event string) int {
	t.Helper()
	rows, err := e.GetTransport().QuerySyslog(1000, StreamQuery{Event: event})
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

// Without a driver registered as "postgres", a Postgres DSN fails Init
// before anything opens; with one, the open fails on an unreachable
// server. Neither error quotes the DSN.
func TestEnvDSN_PostgresDriverLookup(t *testing.T) {
	dsn := "postgres://app:hunter2@127.0.0.1:1/secretdb?sslmode=disable&connect_timeout=2"
	for _, c := range []struct {
		name    string
		drivers []string
		want    string
	}{
		{"no driver", nil, "needs a database/sql driver"},
		{"driver", []string{"postgres"}, "cannot open the postgres store ("},
	} {
		t.Run(c.name, func(t *testing.T) {
			drivers := c.drivers
			sqlDrivers = func() []string { return drivers }
			t.Cleanup(func() { sqlDrivers = sql.Drivers })
			e := envEngine(t)
			dir := t.TempDir()
			t.Setenv("FASTEN_AUDIT_DSN", dsn)
			t.Setenv("FASTEN_API_DSN", dir+"/api.db")
			err := initRaise(e, Config{})
			if err == nil {
				t.Fatal("want an Init error")
			}
			msg := err.Error()
			if !strings.Contains(msg, "FASTEN_AUDIT_DSN") || !strings.Contains(msg, c.want) {
				t.Fatalf("error %q, want %q", msg, c.want)
			}
			for _, leak := range []string{"hunter2", "secretdb", "app", "127.0.0.1"} {
				if strings.Contains(msg, leak) {
					t.Fatalf("error quotes %q: %q", leak, msg)
				}
			}
			if entries, _ := os.ReadDir(dir); len(entries) != 0 {
				t.Fatalf("the failed Init left %v", entries)
			}
		})
	}
}

// Stream DSNs through Init: default tables, ?table=, ?wal=false, and a
// DSN removed on re-init.
func TestEnvStreamDSN_Init(t *testing.T) {
	e := envEngine(t)
	dir := t.TempDir()
	t.Setenv("FASTEN_API_DSN", dir+"/api.db")
	t.Setenv("FASTEN_SYSLOG_DSN", "sqlite:///"+dir+"/sys.db")
	if err := initRaise(e, Config{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	api, sys := e.apiStore.(*StreamStore), e.syslogStore.(*StreamStore)
	if api.table != "api_log" || sys.table != "syslog" {
		t.Fatalf("tables %q, %q; want api_log, syslog", api.table, sys.table)
	}
	if got := journalMode(t, dir+"/sys.db"); got != "wal" {
		t.Fatalf("journal_mode %q, want wal", got)
	}

	t.Setenv("FASTEN_API_DSN", dir+"/api2.db?table=my_api&wal=false")
	t.Setenv("FASTEN_SYSLOG_DSN", "sqlite:///"+dir+"/sys2.db?table=my_sys")
	if err := initRaise(e, Config{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	api2, sys2 := e.apiStore.(*StreamStore), e.syslogStore.(*StreamStore)
	if api2.table != "my_api" || sys2.table != "my_sys" {
		t.Fatalf("tables %q, %q; want my_api, my_sys", api2.table, sys2.table)
	}
	e.GetTransport().PushAPI(APIRow{"method": "GET", "path": "/x"})
	if got := streamCount(t, dir+"/api2.db", "my_api"); got != 1 {
		t.Fatalf("api2.db rows %d, want 1", got)
	}
	if got := journalMode(t, dir+"/api2.db"); got != "delete" {
		t.Fatalf("journal_mode %q, want delete", got)
	}
	if exists(dir + "/api2.db?table=my_api&wal=false") {
		t.Fatal("the query became part of the file name")
	}

	t.Setenv("FASTEN_SYSLOG_DSN", "")
	if err := initRaise(e, Config{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := sys2.db.Ping(); err == nil {
		t.Fatal("the sys store for the removed DSN is still open")
	}
	if e.syslogStore != nil || e.GetTransport().SyslogStore != nil {
		t.Fatal("the sys stream still has a store")
	}
	if got := e.streamSource("sys"); got != "ring" {
		t.Fatalf("sys streamSource=%q, want ring", got)
	}
	if e.apiStore != api2 {
		t.Fatal("the unchanged api DSN must keep its store")
	}
}

// OpenStreamStore takes a file:///abs/path.db URI.
func TestOpenStreamStore_FileURI(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenStreamStore("file://"+dir+"/uri.db?table=my_sys", "syslog")
	if err != nil {
		t.Fatalf("OpenStreamStore: %v", err)
	}
	defer s.db.Close()
	if s.table != "my_sys" || !exists(dir+"/uri.db") {
		t.Fatalf("table %q, file created %v", s.table, exists(dir+"/uri.db"))
	}
}
