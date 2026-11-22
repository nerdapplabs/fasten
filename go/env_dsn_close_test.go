package fasten

import (
	"context"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"
)

// hungAuditStore is an audit store whose inserts wait until unblock.
type hungAuditStore struct {
	*SQLiteStore
	entered chan struct{}
	release chan struct{}
	enter   sync.Once
	free    sync.Once
}

func (s *hungAuditStore) AllocateAndInsertOriginated(ctx context.Context, row Row) (Row, error) {
	s.enter.Do(func() { close(s.entered) })
	<-s.release
	return s.SQLiteStore.AllocateAndInsertOriginated(ctx, row)
}

func (s *hungAuditStore) unblock() { s.free.Do(func() { close(s.release) }) }

// hangAuditStore makes the next audit store Init opens from the
// environment a hungAuditStore. It is unblocked at the end of the test.
func hangAuditStore(t *testing.T) *hungAuditStore {
	t.Helper()
	h := &hungAuditStore{entered: make(chan struct{}), release: make(chan struct{})}
	testHookEnvOpened = func(es *envStore) {
		if es.name == "FASTEN_AUDIT_DSN" && h.SQLiteStore == nil {
			h.SQLiteStore = es.store.(*SQLiteStore)
			es.store = h
		}
	}
	t.Cleanup(func() {
		testHookEnvOpened = nil
		h.unblock()
	})
	return h
}

func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// emitPromptly fails the test if an Emit through e does not return within
// two seconds.
func emitPromptly(t *testing.T, e *Engine) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := e.Emit(context.Background(), "USER_CREATED", Target("u-2"))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Emit: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Emit blocked")
	}
}

// Close does not wait past its timeout for an insert that hangs, inline or
// in the drainer, and emits during and after it return at once. The store
// is closed once the insert returns.
func TestEnvDSN_CloseDoesNotWaitOnAHungInsert(t *testing.T) {
	for _, strategy := range []string{"raise", "queue"} {
		t.Run(strategy, func(t *testing.T) {
			e := envEngine(t)
			t.Setenv("FASTEN_AUDIT_DSN", t.TempDir()+"/a.db")
			hung := hangAuditStore(t)
			err := e.Init(Config{ServiceID: "svc", NodeID: "node", AuditStoreFailureStrategy: strategy})
			if err != nil {
				t.Fatalf("Init: %v", err)
			}
			held := e.envStores["FASTEN_AUDIT_DSN"]
			emitted := make(chan struct{})
			go func() {
				defer close(emitted)
				e.Emit(context.Background(), "USER_CREATED", Target("u-1"))
			}()
			waitClosed(t, hung.entered, "the insert to start")

			start := time.Now()
			closed := make(chan bool, 1)
			go func() { closed <- e.Close(100 * time.Millisecond) }()
			waitFor(t, 2*time.Second, "Close to stop using the store", func() bool {
				return e.currentAuditStore() == nil
			})
			emitPromptly(t, e)
			select {
			case ok := <-closed:
				if ok {
					t.Fatal("Close returned true with an insert still running")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Close did not return")
			}
			if took := time.Since(start); took > 2*time.Second {
				t.Fatalf("Close took %v", took)
			}
			emitPromptly(t, e)
			if err := held.db.Ping(); err != nil {
				t.Fatalf("the store was closed under the running insert: %v", err)
			}

			hung.unblock()
			waitClosed(t, emitted, "the hung emit to return")
			waitFor(t, 10*time.Second, "the store to close", func() bool { return held.db.Ping() != nil })
		})
	}
}

// Init switches emits to the new store at once while an insert hangs on
// the old one, and closes the old store once that insert returns.
func TestEnvDSN_InitDoesNotStallEmitsBehindAHungInsert(t *testing.T) {
	e := envEngine(t)
	dir := t.TempDir()
	t.Setenv("FASTEN_AUDIT_DSN", dir+"/a.db")
	hung := hangAuditStore(t)
	if err := initRaise(e, Config{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	held := e.envStores["FASTEN_AUDIT_DSN"]
	emitted := make(chan struct{})
	go func() {
		defer close(emitted)
		e.Emit(context.Background(), "USER_CREATED", Target("u-1"))
	}()
	waitClosed(t, hung.entered, "the insert to start")

	t.Setenv("FASTEN_AUDIT_DSN", dir+"/b.db")
	inited := make(chan error, 1)
	go func() { inited <- initRaise(e, Config{}) }()
	waitFor(t, 2*time.Second, "Init to switch stores", func() bool {
		s := e.currentAuditStore()
		return s != nil && s != AuditRepository(hung)
	})
	emitPromptly(t, e)
	if got := len(auditRows(t, dir+"/b.db")); got != 1 {
		t.Fatalf("b.db rows %d, want 1", got)
	}
	select {
	case err := <-inited:
		t.Fatalf("Init returned (%v) while an insert on the old store was running", err)
	default:
	}
	if err := held.db.Ping(); err != nil {
		t.Fatalf("the old store was closed under the running insert: %v", err)
	}

	hung.unblock()
	select {
	case err := <-inited:
		if err != nil {
			t.Fatalf("Init: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Init did not return once the insert did")
	}
	waitClosed(t, emitted, "the hung emit to return")
	if err := held.db.Ping(); err == nil {
		t.Fatal("the old store is still open")
	}
	if got := len(auditRows(t, dir+"/a.db")); got != 1 {
		t.Fatalf("a.db rows %d, want the row that was hung", got)
	}
}

// A Close after one that timed out waits, up to its own timeout, for the
// stores the first one left open.
func TestEnvDSN_LaterCloseWaitsForAnEarlierClose(t *testing.T) {
	e := envEngine(t)
	t.Setenv("FASTEN_AUDIT_DSN", t.TempDir()+"/a.db")
	hung := hangAuditStore(t)
	if err := initRaise(e, Config{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	held := e.envStores["FASTEN_AUDIT_DSN"]
	emitted := make(chan struct{})
	go func() {
		defer close(emitted)
		e.Emit(context.Background(), "USER_CREATED", Target("u-1"))
	}()
	waitClosed(t, hung.entered, "the insert to start")

	if e.Close(50 * time.Millisecond) {
		t.Fatal("Close returned true with an insert still running")
	}
	start := time.Now()
	if e.Close(50 * time.Millisecond) {
		t.Fatal("a later Close returned true with the store still open")
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("the later Close took %v", took)
	}

	closed := make(chan bool, 1)
	go func() { closed <- e.Close(10 * time.Second) }()
	hung.unblock()
	select {
	case ok := <-closed:
		if !ok {
			t.Fatal("Close returned false once the store had closed")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not return")
	}
	if err := held.db.Ping(); err == nil {
		t.Fatal("the store is still open")
	}
	waitClosed(t, emitted, "the hung emit to return")
}

// The rollback of a failed Init removes the database file it created, not
// a journal file that appeared meanwhile.
func TestEnvDSN_RollbackLeavesJournalFiles(t *testing.T) {
	e := envEngine(t)
	dir := t.TempDir()
	bad := dir + "/bad.db"
	if err := os.WriteFile(bad, []byte("not a database, just text that is long enough"), 0o600); err != nil {
		t.Fatal(err)
	}
	journal := dir + "/new.db-journal"
	testHookEnvOpened = func(es *envStore) {
		if es.name == "FASTEN_AUDIT_DSN" {
			if err := os.WriteFile(journal, nil, 0o600); err != nil {
				t.Error(err)
			}
		}
	}
	t.Cleanup(func() { testHookEnvOpened = nil })
	t.Setenv("FASTEN_AUDIT_DSN", dir+"/new.db")
	t.Setenv("FASTEN_SYSLOG_DSN", bad)
	if err := initRaise(e, Config{}); err == nil {
		t.Fatal("want an Init error")
	}
	if exists(dir + "/new.db") {
		t.Fatal("the failed Init left new.db")
	}
	if !exists(journal) {
		t.Fatal("the rollback removed a journal file it did not create")
	}
}

// The reader can serve while Close releases the stores.
func TestEnvDSN_CloseWhileReaderServes(t *testing.T) {
	e := envEngine(t)
	dir := t.TempDir()
	t.Setenv("FASTEN_AUDIT_DSN", dir+"/a.db")
	t.Setenv("FASTEN_API_DSN", dir+"/api.db")
	t.Setenv("FASTEN_SYSLOG_DSN", dir+"/sys.db")
	if err := initRaise(e, Config{}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	h := e.NewReader(WithoutAuth())
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for _, path := range []string{"/sys", "/api", "/audit"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", path, nil))
			}
		}()
	}
	time.Sleep(20 * time.Millisecond)
	if !e.Close(5 * time.Second) {
		t.Error("Close returned false")
	}
	time.Sleep(20 * time.Millisecond)
	close(stop)
	wg.Wait()
	for _, stream := range []string{"audit", "api", "sys"} {
		if got := e.streamSource(stream); got != "ring" {
			t.Fatalf("%s streamSource=%q, want ring", stream, got)
		}
	}
}
