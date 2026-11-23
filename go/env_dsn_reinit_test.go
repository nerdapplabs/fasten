package fasten

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"strconv"
	"sync"
	"testing"
	"time"
)

// In queue mode, a row emitted after Init switched the audit store and
// before it installed the new drainer is stored inline in the new store.
func TestEnvDSN_EmitDuringStoreSwitchIsStoredInNewStore(t *testing.T) {
	e := envEngine(t)
	dir := t.TempDir()
	cfg := Config{ServiceID: "svc", NodeID: "node"}
	t.Setenv("FASTEN_AUDIT_DSN", dir+"/a.db")
	if err := e.Init(cfg); err != nil {
		t.Fatalf("Init: %v", err)
	}
	testHookStoreSwitched = func() {
		testHookStoreSwitched = nil
		if _, err := e.Emit(context.Background(), "USER_CREATED", Target("u-1")); err != nil {
			t.Errorf("Emit: %v", err)
		}
	}
	t.Cleanup(func() { testHookStoreSwitched = nil })
	t.Setenv("FASTEN_AUDIT_DSN", dir+"/b.db")
	if err := e.Init(cfg); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if got := auditRows(t, dir+"/a.db"); len(got) != 0 {
		t.Fatalf("a.db rows %d, want 0", len(got))
	}
	rows, err := e.auditStore.Query(context.Background(), Filter{Limit: 10})
	if err != nil || len(rows) != 1 || rows[0].Hash == "" {
		t.Fatalf("b.db rows %+v, %v; want the row, sealed", rows, err)
	}
}

// blockingStreamStore is a stream store whose first Insert waits for
// release.
type blockingStreamStore struct {
	*StreamStore
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	free    sync.Once
}

func (s *blockingStreamStore) unblock() { s.free.Do(func() { close(s.release) }) }

func (s *blockingStreamStore) Insert(row map[string]any) error {
	first := false
	s.once.Do(func() { first = true; close(s.entered) })
	if first {
		<-s.release
	}
	return s.StreamStore.Insert(row)
}

// blockSysStore makes the next sys store Init opens from the environment a
// blockingStreamStore.
func blockSysStore(t *testing.T) *blockingStreamStore {
	t.Helper()
	b := &blockingStreamStore{entered: make(chan struct{}), release: make(chan struct{})}
	testHookEnvOpened = func(es *envStore) {
		if es.name == "FASTEN_SYSLOG_DSN" && b.StreamStore == nil {
			b.StreamStore = es.store.(*StreamStore)
			es.store = b
		}
	}
	t.Cleanup(func() {
		testHookEnvOpened = nil
		b.unblock()
	})
	return b
}

// sysRows counts the rows with event in the sys table of the file at path.
func sysRows(t *testing.T, path, event string) int {
	t.Helper()
	// The store may still be checkpointing as it closes.
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM syslog WHERE event = ?`, event).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Init waits for a push running on a stream store it closes, and a push
// through the replaced transport goes to the new one.
func TestEnvDSN_ReinitWaitsForStreamPushes(t *testing.T) {
	e := envEngine(t)
	dir := t.TempDir()
	cfg := Config{ServiceID: "svc", NodeID: "node", AuditStoreFailureStrategy: "raise"}
	b := blockSysStore(t)
	t.Setenv("FASTEN_SYSLOG_DSN", dir+"/s1.db")
	if err := e.Init(cfg); err != nil {
		t.Fatalf("Init: %v", err)
	}
	old := e.GetTransport()
	go old.PushSyslog(SyslogRow{"level": "info", "event": "in_flight"})
	waitClosed(t, b.entered, "the push to start")

	t.Setenv("FASTEN_SYSLOG_DSN", dir+"/s2.db")
	inited := make(chan error, 1)
	go func() { inited <- e.Init(cfg) }()
	select {
	case err := <-inited:
		t.Fatalf("Init returned (%v) while a push to the store it closes was running", err)
	case <-time.After(200 * time.Millisecond):
	}
	b.unblock()
	select {
	case err := <-inited:
		if err != nil {
			t.Fatalf("Init: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Init did not return")
	}
	if b.Degraded() {
		t.Fatal("a push hit a closed store")
	}
	if n := sysRows(t, dir+"/s1.db", "in_flight"); n != 1 {
		t.Fatalf("s1.db in_flight rows %d, want 1", n)
	}

	old.PushSyslog(SyslogRow{"level": "info", "event": "late"})
	if n, err := e.syslogStore.CountMatching(map[string]string{"event": "late"}, "", ""); err != nil || n != 1 {
		t.Fatalf("s2.db late rows %d, %v; want 1", n, err)
	}
}

// Close does not wait past its timeout for a stream push, and closes the
// store once the push returns.
func TestEnvDSN_CloseWaitsForStreamPushesInBackground(t *testing.T) {
	e := envEngine(t)
	dir := t.TempDir()
	b := blockSysStore(t)
	t.Setenv("FASTEN_SYSLOG_DSN", dir+"/s1.db")
	if err := initRaise(e, Config{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	go e.GetTransport().PushSyslog(SyslogRow{"level": "info", "event": "in_flight"})
	waitClosed(t, b.entered, "the push to start")
	start := time.Now()
	if e.Close(200 * time.Millisecond) {
		t.Fatal("Close returned true while a push was running")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Close took %v", d)
	}
	if err := b.db.Ping(); err != nil {
		t.Fatal("Close closed the store under a running push")
	}
	b.unblock()
	waitFor(t, 5*time.Second, "the store to close", func() bool { return b.db.Ping() != nil })
	if b.Degraded() {
		t.Fatal("the push hit a closed store")
	}
	if n := sysRows(t, dir+"/s1.db", "in_flight"); n != 1 {
		t.Fatalf("s1.db in_flight rows %d, want 1", n)
	}
}

// Init can run while Emit, LogSys and a slog handler use the engine.
// Run with -race.
func TestInitRacesEmitAndSlog(t *testing.T) {
	registerTestCodes(t)
	clearDSNEnv(t)
	t.Cleanup(Default.ResetForTests)
	db, err := sql.Open("sqlite", t.TempDir()+"/a.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := NewSQLiteStore(db, "audit_log")
	if err != nil {
		t.Fatal(err)
	}
	cfg := func(i int) Config {
		return Config{
			ServiceID: "svc-" + strconv.Itoa(i), NodeID: "node", TenantID: "t" + strconv.Itoa(i),
			AuditStore: store, AuditStoreFailureStrategy: "raise", SearchEnabled: i%2 == 0,
		}
	}
	if err := Init(cfg(0)); err != nil {
		t.Fatalf("Init: %v", err)
	}
	logger := slog.New(NewSlogHandler(slog.NewTextHandler(io.Discard, nil)))
	ctx := context.Background()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for _, f := range []func(){
		func() {
			if _, err := Emit(ctx, "USER_CREATED", Target("u-1")); err != nil {
				t.Errorf("Emit: %v", err)
			}
		},
		func() { logger.Info("tick", "k", "v") },
		func() { Default.LogSys(ctx, "info", "tick", nil) },
		func() { _ = Default.SearchEnabled() },
	} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				select {
				case <-stop:
					return
				default:
					f()
				}
			}
		}()
	}
	for i := 1; i <= 20; i++ {
		if err := Init(cfg(i)); err != nil {
			t.Errorf("Init: %v", err)
		}
	}
	close(stop)
	wg.Wait()
}
