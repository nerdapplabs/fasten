package fasten

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Queue mode: rows go through the fasten-core drainer and the store seals
// them (spec/drainer-conformance.md §7 vectors, chain-replication §2.1).

type flakyStore struct {
	*SQLiteStore
	mu       sync.Mutex
	fail     int
	failIf   func(Row) bool
	panicIf  func(Row) bool
	delay    time.Duration
	gate     chan struct{} // when set, the first insert waits for it to close
	attempts int
}

func (s *flakyStore) AllocateAndInsertOriginated(ctx context.Context, row Row) (Row, error) {
	s.mu.Lock()
	s.attempts++
	failing := s.attempts <= s.fail || (s.failIf != nil && s.failIf(row))
	panicking := s.panicIf != nil && s.panicIf(row)
	delay := s.delay
	gate := s.gate
	if s.attempts > 1 {
		gate = nil
	}
	s.mu.Unlock()
	if gate != nil {
		<-gate
	}
	time.Sleep(delay)
	if panicking {
		panic("store bug")
	}
	if failing {
		return row, errors.New("store down")
	}
	return s.SQLiteStore.AllocateAndInsertOriginated(ctx, row)
}

func (s *flakyStore) tries() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.attempts
}

func newFlakyStore(t *testing.T, fail int) *flakyStore {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	db.SetMaxOpenConns(1) // SQLite allows one writer; extra connections get "database is locked"
	inner, err := NewSQLiteStore(db, "fasten_audit")
	if err != nil {
		t.Fatal(err)
	}
	return &flakyStore{SQLiteStore: inner, fail: fail}
}

func (s *flakyStore) rows(t *testing.T) []Row {
	t.Helper()
	rows, err := s.SQLiteStore.Query(context.Background(), Filter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func initQueue(t *testing.T, store AuditRepository, cfg Config) {
	t.Helper()
	cfg.ServiceID, cfg.NodeID, cfg.AuditStore = "svc", "node", store
	cfg.AuditStoreFailureStrategy = "queue"
	cfg.DisableQueueJitter = true
	if cfg.QueueRetryInitial == 0 {
		cfg.QueueRetryInitial = 10 * time.Millisecond
	}
	if cfg.QueueRetryMax == 0 {
		cfg.QueueRetryMax = 50 * time.Millisecond
	}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init: %v", err)
	}
}

func emitN(t *testing.T, n int) []Row {
	t.Helper()
	out := make([]Row, n)
	for i := range out {
		r, err := Emit(context.Background(), "USER_CREATED", Target("u"))
		if err != nil {
			t.Fatalf("Emit: %v", err)
		}
		out[i] = r
	}
	return out
}

func waitForTries(t *testing.T, s *flakyStore, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for s.tries() < n && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if s.tries() < n {
		t.Fatalf("store saw %d attempts, want %d", s.tries(), n)
	}
}

func sysEvents(t *testing.T, event string) []SyslogRow {
	t.Helper()
	rows, err := Default.GetTransport().QuerySyslog(1000, StreamQuery{})
	if err != nil {
		t.Fatal(err)
	}
	var out []SyslogRow
	for _, r := range rows {
		if r["event"] == event {
			out = append(out, r)
		}
	}
	return out
}

func TestQueueOutageThenRecovery(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	store := newFlakyStore(t, 2)
	initQueue(t, store, Config{})
	emitN(t, 1)
	if !Flush(2 * time.Second) {
		t.Fatal("Flush timed out")
	}
	if got := len(store.rows(t)); got != 1 {
		t.Fatalf("rows = %d, want 1", got)
	}
	if store.tries() < 3 {
		t.Fatalf("attempts = %d, want >= 3", store.tries())
	}
	if s := GetQueueStats(); s == nil || s.DeadLetteredTotal != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestQueueDeadLetterAfterMaxAttempts(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	store := newFlakyStore(t, math.MaxInt32)
	initQueue(t, store, Config{QueueDrainMaxAttempts: 3})
	emitN(t, 1)
	Flush(2 * time.Second)
	if s := GetQueueStats(); s == nil || s.DeadLetteredTotal != 1 || s.Depth != 0 {
		t.Fatalf("stats = %+v", s)
	}
	if store.tries() != 3 {
		t.Fatalf("attempts = %d, want 3", store.tries())
	}
	if !Default.auditWriteSwallowed.Load() {
		t.Fatal("a dead-lettered row must mark the engine degraded")
	}
}

func TestQueueDrainedRowsAreSealedInEmitOrder(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	store := newFlakyStore(t, 1)
	initQueue(t, store, Config{})
	emitted := emitN(t, 3)
	if !Flush(2 * time.Second) {
		t.Fatal("Flush timed out")
	}
	rows := store.rows(t)
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	bySeq := map[int64]string{}
	for _, r := range rows {
		if r.Hash == "" {
			t.Fatalf("row %s stored unsealed", r.ID)
		}
		bySeq[r.MonotonicSeq] = r.ID
	}
	for i, e := range emitted {
		if bySeq[int64(i+1)] != e.ID {
			t.Fatalf("seq %d = %s, want %s", i+1, bySeq[int64(i+1)], e.ID)
		}
		if e.Hash != "" {
			t.Fatal("Emit cannot know the seal in queue mode (spec §8)")
		}
	}
	if res := VerifyChain(rows); !res.OK {
		t.Fatalf("chain must verify: %+v", res)
	}
}

func TestQueueFullQueueLosesNothingUnderConcurrentEmits(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	store := newFlakyStore(t, 0)
	store.delay = 10 * time.Millisecond
	initQueue(t, store, Config{QueueCapacity: 2})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); emitN(t, 1) }()
	}
	wg.Wait()
	if !Flush(5 * time.Second) {
		t.Fatal("Flush timed out")
	}
	if got := len(store.rows(t)); got != 8 {
		t.Fatalf("rows = %d, want 8", got)
	}
	if s := GetQueueStats(); s == nil || s.HighWater > 2 {
		t.Fatalf("stats = %+v", s)
	}
}

func TestQueueEmitsRacingUninstallAreAllStored(t *testing.T) {
	registerTestCodes(t)
	for round := 0; round < 20; round++ {
		resetGlobals(t)
		store := newFlakyStore(t, 0)
		store.delay = time.Millisecond
		initQueue(t, store, Config{QueueCapacity: 2})
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); emitN(t, 1) }()
		}
		Default.uninstallDrainer()
		wg.Wait()
		if got := len(store.rows(t)); got != 16 {
			t.Fatalf("round %d: rows = %d, want 16", round, got)
		}
		if Default.auditWriteSwallowed.Load() {
			t.Fatalf("round %d: engine marked degraded", round)
		}
	}
}

func TestQueueRowsAtStopAreRecoveredOrReportedLost(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	store := newFlakyStore(t, 2) // "good" fails its first try and its try at stop
	store.failIf = func(r Row) bool { return r.Target == "bad" }
	initQueue(t, store, Config{QueueRetryInitial: 10 * time.Second, QueueRetryMax: 10 * time.Second})
	good, _ := Emit(context.Background(), "USER_CREATED", Target("good"))
	bad, _ := Emit(context.Background(), "USER_CREATED", Target("bad"))
	waitForTries(t, store, 1) // "good" failed once and is in backoff
	Default.uninstallDrainer()
	rows := store.rows(t)
	if len(rows) != 1 || rows[0].ID != good.ID {
		t.Fatalf("stored %+v, want only %s", rows, good.ID)
	}
	if !Default.auditWriteSwallowed.Load() {
		t.Fatal("a row lost at stop must mark the engine degraded")
	}
	if ev := sysEvents(t, "audit_drain_lost_at_stop"); len(ev) != 1 || ev[0]["row_id"] != bad.ID {
		t.Fatalf("lost events = %v", ev)
	}
	if ev := sysEvents(t, "audit_drain_recovered_at_stop"); len(ev) != 1 || len(ev[0]["row_ids"].([]any)) != 1 {
		t.Fatalf("recovered events = %v", ev)
	}
}

func TestQueueEmitAfterDrainerStoppedIsStored(t *testing.T) { // V-12
	registerTestCodes(t)
	resetGlobals(t)
	store := newFlakyStore(t, 0)
	initQueue(t, store, Config{})
	Default.uninstallDrainer()
	r := emitN(t, 1)[0]
	if r.Hash == "" {
		t.Fatal("row should be stored synchronously")
	}
	if len(sysEvents(t, "audit_drain_abandoned")) != 1 || len(sysEvents(t, "audit_drain_stored_inline")) != 1 {
		t.Fatal("want audit_drain_abandoned then audit_drain_stored_inline")
	}
}

func TestQueueReinitWhileDrainingDoesNotOverlapTheDrainThread(t *testing.T) {
	// The drain thread runs engine code; Init must retire it before writing
	// engine fields (caught by -race otherwise).
	registerTestCodes(t)
	resetGlobals(t)
	store := newFlakyStore(t, 0)
	store.delay = 5 * time.Millisecond
	initQueue(t, store, Config{})
	emitN(t, 20)
	initQueue(t, store, Config{})
	if !Flush(5 * time.Second) {
		t.Fatal("Flush timed out")
	}
	if got := len(store.rows(t)); got != 20 {
		t.Fatalf("rows = %d, want 20", got)
	}
}

func TestQueueReinitKeepsTheFlagForTheSameStore(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	store := newFlakyStore(t, math.MaxInt32)
	initQueue(t, store, Config{QueueDrainMaxAttempts: 2})
	emitN(t, 1)
	Flush(2 * time.Second)
	initQueue(t, store, Config{})
	if !Default.auditWriteSwallowed.Load() {
		t.Fatal("a re-init on the same store must keep its hole reported")
	}
	initQueue(t, newFlakyStore(t, 0), Config{})
	if Default.auditWriteSwallowed.Load() {
		t.Fatal("a re-init on a new store clears the flag")
	}
}

// valueStore is a store whose dynamic type is not comparable.
type valueStore struct {
	*flakyStore
	tags []string
}

func (s valueStore) AllocateAndInsertOriginated(ctx context.Context, row Row) (Row, error) {
	return s.flakyStore.AllocateAndInsertOriginated(ctx, row)
}

func TestQueueNonComparableStoreUsesTheDrainerAndReportsLoss(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	inner := newFlakyStore(t, math.MaxInt32)
	initQueue(t, valueStore{flakyStore: inner, tags: []string{"x"}}, Config{QueueDrainMaxAttempts: 2})
	emitN(t, 1)
	Flush(2 * time.Second)
	if s := GetQueueStats(); s == nil || s.DeadLetteredTotal != 1 {
		t.Fatalf("stats = %+v, want the row dead-lettered by the drainer", s)
	}
	if !Default.auditWriteSwallowed.Load() {
		t.Fatal("a dead-lettered row must mark the engine degraded")
	}
}

func TestQueuePanickingStoreIsAFailedInsert(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	store := newFlakyStore(t, 0)
	store.panicIf = func(Row) bool { return true }
	initQueue(t, store, Config{QueueDrainMaxAttempts: 2})
	emitN(t, 1)
	Flush(2 * time.Second)
	if s := GetQueueStats(); s == nil || s.DeadLetteredTotal != 1 {
		t.Fatalf("stats = %+v", s)
	}
	if !Default.auditWriteSwallowed.Load() {
		t.Fatal("a dead-lettered row must mark the engine degraded")
	}
}

func TestQueueRowsRecoveredAtStopKeepEmitOrder(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	store := newFlakyStore(t, 0)
	tried := map[string]int{}
	// Each row fails its first try, and every try fails until all three
	// have had one: the drainer gives up on them all at stop.
	store.failIf = func(r Row) bool {
		tried[r.ID]++
		return tried[r.ID] == 1 || store.attempts < 4
	}
	initQueue(t, store, Config{QueueRetryInitial: 10 * time.Second, QueueRetryMax: 10 * time.Second})
	emitted := emitN(t, 3)
	waitForTries(t, store, 1)
	Default.uninstallDrainer()
	rows := store.rows(t)
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	bySeq := map[int64]string{}
	for _, r := range rows {
		bySeq[r.MonotonicSeq] = r.ID
	}
	for i, e := range emitted {
		if bySeq[int64(i+1)] != e.ID {
			t.Fatalf("seq %d = %s, want %s", i+1, bySeq[int64(i+1)], e.ID)
		}
	}
}

func TestQueueFlushWaitsForARetiringDrainer(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	store := newFlakyStore(t, 2) // first try and the try at stop fail
	initQueue(t, store, Config{QueueRetryInitial: 10 * time.Second, QueueRetryMax: 10 * time.Second})
	emitN(t, 1)
	waitForTries(t, store, 1)
	store.mu.Lock()
	store.delay = 200 * time.Millisecond // the inline store at stop is slow
	store.mu.Unlock()
	go Default.uninstallDrainer()
	for Default.activeDrainer() != nil {
		time.Sleep(time.Millisecond)
	}
	if !Flush(5 * time.Second) {
		t.Fatal("Flush timed out")
	}
	if got := len(store.rows(t)); got != 1 {
		t.Fatalf("Flush returned before the row was stored: rows = %d", got)
	}
}

func TestQueueOldStoreLosingRowsDoesNotDegradeTheNewOne(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	old := newFlakyStore(t, math.MaxInt32)
	initQueue(t, old, Config{QueueRetryInitial: 10 * time.Second, QueueRetryMax: 10 * time.Second})
	emitN(t, 1)
	waitForTries(t, old, 1)
	initQueue(t, newFlakyStore(t, 0), Config{})
	if Default.auditWriteSwallowed.Load() {
		t.Fatal("rows lost by the old store must not degrade the new one")
	}
	if old.tries() < 3 {
		t.Fatalf("old store attempts = %d, want >= 3", old.tries())
	}
}

func TestQueueMaxAttemptsOverflowIsRejected(t *testing.T) {
	if math.MaxInt <= math.MaxUint32 {
		t.Skip("int cannot exceed MaxUint32 here")
	}
	registerTestCodes(t)
	resetGlobals(t)
	err := Init(Config{ServiceID: "svc", NodeID: "node", AuditStore: newFlakyStore(t, 0),
		QueueDrainMaxAttempts: math.MaxUint32 + 1})
	if err == nil {
		t.Fatal("want an error for QueueDrainMaxAttempts > MaxUint32")
	}
}

func TestQueueEmitReachingARetiredDrainerStoresInline(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	store := newFlakyStore(t, 0)
	initQueue(t, store, Config{})
	entered, release := make(chan struct{}), make(chan struct{})
	testHookEnqueue = func() { close(entered); <-release }
	t.Cleanup(func() { testHookEnqueue = nil })
	done := make(chan Row)
	go func() { done <- emitN(t, 1)[0] }()
	<-entered
	testHookEnqueue = nil
	Default.uninstallDrainer() // closes the drainer this emit already holds
	close(release)
	r := <-done
	if r.Hash == "" {
		t.Fatal("row should be stored inline once the drainer is closed")
	}
	if ev := sysEvents(t, "audit_drain_stored_inline"); len(ev) != 1 || ev[0]["row_id"] != r.ID {
		t.Fatalf("stored-inline events = %v", ev)
	}
	// The handle was closed under it, so fasten-core reported nothing.
	if ev := sysEvents(t, "audit_drain_abandoned"); len(ev) != 1 || ev[0]["reason"] != "enqueue_refused" {
		t.Fatalf("abandoned events = %v", ev)
	}
	if got := len(store.rows(t)); got != 1 {
		t.Fatalf("rows = %d, want 1", got)
	}
}

// drainOrder returns the drain-state events, oldest first.
func drainOrder(t *testing.T) []string {
	t.Helper()
	rows, err := Default.GetTransport().QuerySyslog(1000, StreamQuery{})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for i := len(rows) - 1; i >= 0; i-- { // the ring returns newest first
		switch ev, _ := rows[i]["event"].(string); ev {
		case "audit_drain_failed", "audit_drain_degraded", "audit_drain_recovered":
			out = append(out, ev)
		}
	}
	return out
}

func TestQueueV8ThresholdEventsAreDebounced(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	store := newFlakyStore(t, 0)
	store.gate = make(chan struct{})
	initQueue(t, store, Config{QueueCapacity: 10})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); emitN(t, 1) }()
	}
	wg.Wait()
	close(store.gate) // depth rose 1..8 with no dip below 50 %
	if !Flush(5 * time.Second) {
		t.Fatal("Flush timed out")
	}
	if n := len(sysEvents(t, "audit_queue_high_water")); n != 1 {
		t.Fatalf("audit_queue_high_water x%d, want 1", n)
	}
	if n := len(sysEvents(t, "audit_queue_near_full")); n != 1 {
		t.Fatalf("audit_queue_near_full x%d, want 1", n)
	}
}

func TestQueueV10DeadLetterReachesTheSysStream(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	store := newFlakyStore(t, math.MaxInt32)
	initQueue(t, store, Config{QueueDrainMaxAttempts: 3,
		QueueRetryInitial: time.Millisecond, QueueRetryMax: 5 * time.Millisecond})
	emitN(t, 1)
	Flush(2 * time.Second)
	if len(sysEvents(t, "audit_drain_dead_letter")) != 1 {
		t.Fatal("want one audit_drain_dead_letter on the sys stream")
	}
}

func TestQueueV11DrainStateEventsFireInOrder(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	store := newFlakyStore(t, 5)
	initQueue(t, store, Config{QueueRetryInitial: 10 * time.Millisecond, QueueRetryMax: 20 * time.Millisecond})
	emitN(t, 1)
	if !Flush(5 * time.Second) {
		t.Fatal("Flush timed out")
	}
	got := drainOrder(t)
	want := []string{"audit_drain_failed", "audit_drain_degraded", "audit_drain_recovered"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("events = %v, want %v", got, want)
	}
}

func TestQueueV1HappyPath(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	store := newFlakyStore(t, 0)
	initQueue(t, store, Config{QueueCapacity: 100})
	emitN(t, 2)
	if !Flush(time.Second) {
		t.Fatal("Flush timed out")
	}
	if got := len(store.rows(t)); got != 2 {
		t.Fatalf("rows = %d, want 2", got)
	}
}

func TestQueueV2V3V6RaiseMode(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node", AuditStore: newFlakyStore(t, math.MaxInt32),
		AuditStoreFailureStrategy: "raise"}); err != nil {
		t.Fatal(err)
	}
	_, err := Emit(context.Background(), "USER_CREATED", Target("u-1"))
	var ase *AuditStoreError
	if !errors.As(err, &ase) || !strings.Contains(err.Error(), "store down") { // V-2
		t.Fatalf("err = %v, want an AuditStoreError with \"store down\"", err)
	}
	if GetQueueStats() != nil { // V-3
		t.Fatal("raise mode has no drainer")
	}
	if !Flush(100 * time.Millisecond) { // V-6
		t.Fatal("Flush is a no-op in raise mode")
	}
}

func TestQueueV5StatsAfterDrain(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	initQueue(t, newFlakyStore(t, 0), Config{QueueCapacity: 100})
	emitN(t, 1)
	if !Flush(time.Second) {
		t.Fatal("Flush timed out")
	}
	s := GetQueueStats()
	if s == nil || s.Depth != 0 || s.Capacity != 100 || s.HighWater < 1 || s.DrainedTotal != 1 ||
		s.RetryCountActive != 0 || s.LastError != "" {
		t.Fatalf("stats = %+v", s)
	}
}

func TestQueueV7HighWaterNeverDecreases(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	store := newFlakyStore(t, 0)
	store.gate = make(chan struct{})
	initQueue(t, store, Config{QueueCapacity: 10})
	emitN(t, 5)
	close(store.gate)
	Flush(time.Second)
	hw1 := GetQueueStats().HighWater
	emitN(t, 1)
	Flush(time.Second)
	if hw1 != 5 || GetQueueStats().HighWater < hw1 {
		t.Fatalf("high_water %d then %d, want 5 then >= 5", hw1, GetQueueStats().HighWater)
	}
}

func TestQueueV9SyncFallbackFailureIsReported(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	initQueue(t, newFlakyStore(t, math.MaxInt32), Config{})
	Default.uninstallDrainer()
	emitN(t, 1)
	if len(sysEvents(t, "audit_sync_fallback_failed")) != 1 {
		t.Fatal("want audit_sync_fallback_failed")
	}
}

func TestQueueDoctorReportsTheDeadLetter(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	initQueue(t, newFlakyStore(t, math.MaxInt32), Config{QueueDrainMaxAttempts: 2,
		QueueRetryInitial: time.Millisecond, QueueRetryMax: 5 * time.Millisecond})
	emitN(t, 1)
	Flush(2 * time.Second)
	body, code := getJSON(t, NewReader(), "/audit/doctor")
	q, _ := body["queue"].(map[string]any)
	if code != 200 || q["dead_lettered_total"] != float64(1) || q["drained_total"] != float64(0) {
		t.Fatalf("doctor queue = %v (status %d)", q, code)
	}
}

func TestQueueEmitsWhileTheOldDrainerRetiresAreQueued(t *testing.T) {
	// Init swaps in the new drainer before it retires the old one, so a row
	// emitted while the old one drains is retried, not written once inline.
	registerTestCodes(t)
	resetGlobals(t)
	initQueue(t, newFlakyStore(t, 0), Config{})
	next := newFlakyStore(t, 2)
	var emitted []Row
	testHookRetire = func() { emitted = emitN(t, 1) }
	t.Cleanup(func() { testHookRetire = nil })
	initQueue(t, next, Config{})
	testHookRetire = nil
	if !Flush(2 * time.Second) {
		t.Fatal("Flush timed out")
	}
	rows := next.rows(t)
	if len(emitted) != 1 || len(rows) != 1 || rows[0].ID != emitted[0].ID {
		t.Fatalf("stored %v, want the row emitted during re-init", rows)
	}
	if Default.auditWriteSwallowed.Load() {
		t.Fatal("nothing was lost")
	}
}

func TestQueueRowRefusedAtStopGetsOneAbandonedEvent(t *testing.T) {
	// fasten-core reports a row it refuses at stop; the engine must not
	// report it again.
	registerTestCodes(t)
	resetGlobals(t)
	store := newFlakyStore(t, 0)
	store.gate = make(chan struct{})
	initQueue(t, store, Config{QueueCapacity: 1})
	emitN(t, 1) // the held row takes the only slot
	blocked := make(chan struct{})
	go func() { defer close(blocked); emitN(t, 1) }()
	deadline := time.Now().Add(5 * time.Second)
	for Default.activeDrainer().pendingLen() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	closed := make(chan struct{})
	go func() { defer close(closed); Default.uninstallDrainer() }()
	for len(sysEvents(t, "audit_drain_abandoned")) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	close(store.gate)
	<-blocked
	<-closed
	ev := sysEvents(t, "audit_drain_abandoned")
	if len(ev) != 1 || ev[0]["reason"] != "drainer_stopped" {
		t.Fatalf("abandoned events = %v, want one from fasten-core", ev)
	}
	if got := len(store.rows(t)); got != 2 {
		t.Fatalf("rows = %d, want 2", got)
	}
}
