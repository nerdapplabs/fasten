// P1-15 cross-language: same wire/API semantics as Python's
// tests/test_audit_queue.py — happy path, slow store, outage+recovery,
// queue full blocks, raise mode, sys self-report, queue_stats, flush.
package fasten

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── Stub stores ────────────────────────────────────────────────────────────

type recordingStore struct {
	mu   sync.Mutex
	rows []Row
}

func (s *recordingStore) Insert(_ context.Context, r Row) error {
	s.mu.Lock()
	s.rows = append(s.rows, r)
	s.mu.Unlock()
	return nil
}
func (s *recordingStore) Query(_ context.Context, _ Filter) ([]Row, error) { return nil, nil }
func (s *recordingStore) ListUnshipped(_ context.Context, _ int) ([]Row, error) {
	return nil, nil
}
func (s *recordingStore) MarkShipped(_ context.Context, _ []string) error    { return nil }
func (s *recordingStore) Purge(_ context.Context, _ time.Time, _ bool) (int, error) { return 0, nil }

func (s *recordingStore) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.rows)
}

type slowStore struct {
	recordingStore
	delay time.Duration
}

func (s *slowStore) Insert(ctx context.Context, r Row) error {
	time.Sleep(s.delay)
	return s.recordingStore.Insert(ctx, r)
}

type brokenStore struct {
	mu       sync.Mutex
	attempts int32
	msg      string
}

func (s *brokenStore) Insert(_ context.Context, _ Row) error {
	atomic.AddInt32(&s.attempts, 1)
	return errors.New(s.msg)
}
func (s *brokenStore) Query(_ context.Context, _ Filter) ([]Row, error) { return nil, nil }
func (s *brokenStore) ListUnshipped(_ context.Context, _ int) ([]Row, error) {
	return nil, nil
}
func (s *brokenStore) MarkShipped(_ context.Context, _ []string) error    { return nil }
func (s *brokenStore) Purge(_ context.Context, _ time.Time, _ bool) (int, error) { return 0, nil }

type flakyStore struct {
	mu        sync.Mutex
	attempts  int32
	success   int32
	failFirst int32
}

func (s *flakyStore) Insert(_ context.Context, _ Row) error {
	n := atomic.AddInt32(&s.attempts, 1)
	if n <= s.failFirst {
		return errors.New("transient")
	}
	atomic.AddInt32(&s.success, 1)
	return nil
}
func (s *flakyStore) Query(_ context.Context, _ Filter) ([]Row, error) { return nil, nil }
func (s *flakyStore) ListUnshipped(_ context.Context, _ int) ([]Row, error) {
	return nil, nil
}
func (s *flakyStore) MarkShipped(_ context.Context, _ []string) error    { return nil }
func (s *flakyStore) Purge(_ context.Context, _ time.Time, _ bool) (int, error) { return 0, nil }

// ── Test helpers ───────────────────────────────────────────────────────────

func resetState() {
	Default.ResetForTests()
	regMu.Lock()
	_registry = map[Code]Meta{}
	regMu.Unlock()
}

func setupQueueMode(t *testing.T, store AuditRepository, opts ...func(*Config)) {
	t.Helper()
	resetState()
	if err := Register("user", map[Code]Meta{
		"USER_CREATED": {
			Domain:         "user",
			Category:       "account",
			Action:         "create",
			Severity:       SevInfo,
			Description:    "test",
			Emitter:        "test",
			RetentionClass: RetLong,
		},
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	cfg := Config{
		ServiceID:                 "svc",
		NodeID:                    "node",
		AuditStore:                store,
		AuditStoreFailureStrategy: "queue",
		QueueCapacity:             100,
	}
	for _, o := range opts {
		o(&cfg)
	}
	if err := Init(cfg); err != nil {
		t.Fatalf("init: %v", err)
	}
	t.Cleanup(resetState)
}

func setupRaiseMode(t *testing.T, store AuditRepository) {
	t.Helper()
	resetState()
	if err := Register("user", map[Code]Meta{
		"USER_CREATED": {
			Domain: "user", Category: "account", Action: "create",
			Severity: SevInfo, Description: "test", Emitter: "test",
			RetentionClass: RetLong,
		},
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := Init(Config{
		ServiceID:                 "svc",
		NodeID:                    "node",
		AuditStore:                store,
		AuditStoreFailureStrategy: "raise",
	}); err != nil {
		t.Fatalf("init: %v", err)
	}
	t.Cleanup(resetState)
}

// ── #1 happy path ──────────────────────────────────────────────────────────

func TestQueueModeDrainsWithinOneSecond(t *testing.T) {
	store := &recordingStore{}
	setupQueueMode(t, store)
	ctx := context.Background()
	if _, err := Emit(ctx, "USER_CREATED", Target("u-1")); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if _, err := Emit(ctx, "USER_CREATED", Target("u-2")); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if !Flush(time.Second) {
		t.Fatal("flush timed out")
	}
	if store.count() != 2 {
		t.Fatalf("want 2 rows; got %d", store.count())
	}
}

func TestQueueModeEmitReturnsImmediatelyUnderSlowStore(t *testing.T) {
	store := &slowStore{delay: 50 * time.Millisecond}
	setupQueueMode(t, store)
	ctx := context.Background()
	t0 := time.Now()
	for i := 0; i < 10; i++ {
		if _, err := Emit(ctx, "USER_CREATED", Target("u")); err != nil {
			t.Fatalf("emit: %v", err)
		}
	}
	elapsed := time.Since(t0)
	// 10 emits * 50ms sync would be 500ms+. Async should be < 100ms.
	if elapsed >= 100*time.Millisecond {
		t.Fatalf("emit() should return immediately; took %s", elapsed)
	}
	if !Flush(2 * time.Second) {
		t.Fatal("flush timed out")
	}
	if store.count() != 10 {
		t.Fatalf("want 10 rows; got %d", store.count())
	}
}

// ── #2 raise mode ──────────────────────────────────────────────────────────

func TestRaiseModeReturnsAuditStoreError(t *testing.T) {
	store := &brokenStore{msg: "store down"}
	setupRaiseMode(t, store)
	_, err := Emit(context.Background(), "USER_CREATED", Target("u-1"))
	if err == nil {
		t.Fatal("expected error in raise mode")
	}
	var aerr *AuditStoreError
	if !errors.As(err, &aerr) {
		t.Fatalf("expected *AuditStoreError; got %T", err)
	}
	if aerr.Err.Error() != "store down" {
		t.Fatalf("unwrapped: %v", aerr.Err)
	}
}

func TestRaiseModeDoesNotInstallDrainer(t *testing.T) {
	store := &recordingStore{}
	setupRaiseMode(t, store)
	if Default.activeDrainer() != nil {
		t.Fatal("raise mode must not install a drainer")
	}
	if GetQueueStats() != nil {
		t.Fatal("queue_stats must be nil in raise mode")
	}
}

// ── #3 outage + recovery ───────────────────────────────────────────────────

func TestOutageThenRecoveryDrainsPendingRows(t *testing.T) {
	store := &flakyStore{failFirst: 2}
	setupQueueMode(t, store, func(c *Config) {
		c.QueueRetryInitial = 10 * time.Millisecond
		c.QueueRetryMax = 50 * time.Millisecond
		c.DisableQueueJitter = true
	})
	if _, err := Emit(context.Background(), "USER_CREATED", Target("u-1")); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if !Flush(2 * time.Second) {
		t.Fatal("flush timed out — drainer did not recover")
	}
	if atomic.LoadInt32(&store.success) != 1 {
		t.Fatalf("want 1 success; got %d", store.success)
	}
	if atomic.LoadInt32(&store.attempts) < 3 {
		t.Fatalf("want >=3 attempts (2 fail + 1 success); got %d", store.attempts)
	}
}

// ── #4 queue full blocks emit ──────────────────────────────────────────────

func TestQueueFullBlocksEmitDoesNotSilentlyDrop(t *testing.T) {
	store := &brokenStore{msg: "store down"}
	setupQueueMode(t, store, func(c *Config) {
		c.QueueCapacity = 2
		c.QueueRetryInitial = 10 * time.Second // never retries during the test
		c.DisableQueueJitter = true
	})
	ctx := context.Background()
	if _, err := Emit(ctx, "USER_CREATED", Target("u-1")); err != nil {
		t.Fatalf("emit-1: %v", err)
	}
	if _, err := Emit(ctx, "USER_CREATED", Target("u-2")); err != nil {
		t.Fatalf("emit-2: %v", err)
	}

	finished := make(chan struct{})
	blocked := make(chan struct{})
	go func() {
		close(blocked)
		_, _ = Emit(ctx, "USER_CREATED", Target("u-3"))
		close(finished)
	}()
	<-blocked
	select {
	case <-finished:
		t.Fatal("emit() must block when queue is full and store is unavailable")
	case <-time.After(200 * time.Millisecond):
		// good — still blocked
	}

	// Stopping the drainer pops rows + releases slots → unblocks emit.
	Default.uninstallDrainer()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("emit should unblock once queue space frees")
	}
}

// ── #5 sys self-report ────────────────────────────────────────────────────

func TestDrainerFirstFailureEmitsWarnToSys(t *testing.T) {
	store := &flakyStore{failFirst: 1}
	setupQueueMode(t, store, func(c *Config) {
		c.QueueRetryInitial = 5 * time.Millisecond
		c.QueueRetryMax = 20 * time.Millisecond
		c.DisableQueueJitter = true
	})
	if _, err := Emit(context.Background(), "USER_CREATED", Target("u-1")); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if !Flush(2 * time.Second) {
		t.Fatal("flush timed out")
	}
	rows := Default.xport.QuerySyslog(100, "", "", "")
	events := map[string]bool{}
	for _, r := range rows {
		if e, ok := r["event"].(string); ok {
			events[e] = true
		}
	}
	if !events["audit_drain_failed"] {
		t.Fatalf("expected first-failure warn; got events %v", events)
	}
	if !events["audit_drain_recovered"] {
		t.Fatalf("expected recovery info; got events %v", events)
	}
}

func TestDrainerDegradedAfter5Failures(t *testing.T) {
	store := &brokenStore{msg: "store down"}
	setupQueueMode(t, store, func(c *Config) {
		c.QueueRetryInitial = 5 * time.Millisecond
		c.QueueRetryMax = 20 * time.Millisecond
		c.DisableQueueJitter = true
	})
	if _, err := Emit(context.Background(), "USER_CREATED", Target("u-1")); err != nil {
		t.Fatalf("emit: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		rows := Default.xport.QuerySyslog(100, "", "", "")
		for _, r := range rows {
			if r["event"] == "audit_drain_degraded" {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("audit_drain_degraded never fired after 5+ failures")
}

func TestQueueHighWaterEmitsWarnAt50pct(t *testing.T) {
	store := &brokenStore{msg: "store down"}
	setupQueueMode(t, store, func(c *Config) {
		c.QueueCapacity = 4
		c.QueueRetryInitial = 5 * time.Second
		c.DisableQueueJitter = true
	})
	for i := 0; i < 2; i++ {
		if _, err := Emit(context.Background(), "USER_CREATED", Target("u")); err != nil {
			t.Fatalf("emit: %v", err)
		}
	}
	time.Sleep(100 * time.Millisecond)
	rows := Default.xport.QuerySyslog(100, "", "", "")
	events := map[string]bool{}
	for _, r := range rows {
		if e, ok := r["event"].(string); ok {
			events[e] = true
		}
	}
	if !events["audit_queue_high_water"] {
		t.Fatalf("expected high-water warn; got events %v", events)
	}
}

// ── #6 queue_stats + flush ─────────────────────────────────────────────────

func TestPublicFlushBlocksUntilDrained(t *testing.T) {
	store := &recordingStore{}
	setupQueueMode(t, store)
	for i := 0; i < 5; i++ {
		if _, err := Emit(context.Background(), "USER_CREATED", Target("u")); err != nil {
			t.Fatalf("emit: %v", err)
		}
	}
	if !Flush(2 * time.Second) {
		t.Fatal("flush timed out")
	}
	if store.count() != 5 {
		t.Fatalf("want 5; got %d", store.count())
	}
}

func TestPublicFlushNoOpInRaiseMode(t *testing.T) {
	store := &recordingStore{}
	setupRaiseMode(t, store)
	if _, err := Emit(context.Background(), "USER_CREATED", Target("u-1")); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if !Flush(100 * time.Millisecond) {
		t.Fatal("Flush() must return true in raise mode (no queue)")
	}
}

func TestQueueStatsFields(t *testing.T) {
	store := &recordingStore{}
	setupQueueMode(t, store)
	if _, err := Emit(context.Background(), "USER_CREATED", Target("u-1")); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if !Flush(time.Second) {
		t.Fatal("flush timed out")
	}
	s := GetQueueStats()
	if s == nil {
		t.Fatal("expected non-nil stats")
	}
	if s.Depth != 0 {
		t.Errorf("depth want 0; got %d", s.Depth)
	}
	if s.Capacity != 100 {
		t.Errorf("capacity want 100; got %d", s.Capacity)
	}
	if s.HighWater < 1 {
		t.Errorf("high_water want >=1; got %d", s.HighWater)
	}
	if s.DrainedTotal != 1 {
		t.Errorf("drained_total want 1; got %d", s.DrainedTotal)
	}
	if s.RetryCountActive != 0 {
		t.Errorf("retry_count_active want 0; got %d", s.RetryCountActive)
	}
	if s.LastError != "" {
		t.Errorf("last_error want empty; got %q", s.LastError)
	}
}

func TestQueueStatsHighWaterMonotonic(t *testing.T) {
	store := &recordingStore{}
	setupQueueMode(t, store, func(c *Config) { c.QueueCapacity = 10 })
	for i := 0; i < 5; i++ {
		if _, err := Emit(context.Background(), "USER_CREATED", Target("u")); err != nil {
			t.Fatalf("emit: %v", err)
		}
	}
	if !Flush(time.Second) {
		t.Fatal("flush timed out")
	}
	high := GetQueueStats().HighWater
	if _, err := Emit(context.Background(), "USER_CREATED", Target("u-x")); err != nil {
		t.Fatalf("emit: %v", err)
	}
	if !Flush(time.Second) {
		t.Fatal("flush timed out")
	}
	if got := GetQueueStats().HighWater; got < high {
		t.Errorf("high_water regressed: %d → %d", high, got)
	}
}

// REVIEW #19: AuditStoreFailureStrategy must accept any case (parity
// with Python). Earlier the switch matched only lowercase, so "Queue"
// or "RAISE" silently failed init.
func TestInit_StrategyCaseInsensitive(t *testing.T) {
	for _, s := range []string{"Queue", "QUEUE", "Raise", "RAISE", "qUeUe"} {
		t.Run(s, func(t *testing.T) {
			resetState()
			if err := Register("user", map[Code]Meta{
				"USER_CREATED": {
					Domain: "user", Category: "account", Action: "create",
					Severity: SevInfo, Description: "test", Emitter: "test",
					RetentionClass: RetLong,
				},
			}); err != nil {
				t.Fatalf("register: %v", err)
			}
			err := Init(Config{
				ServiceID:                 "svc",
				NodeID:                    "node",
				AuditStore:                &recordingStore{},
				AuditStoreFailureStrategy: s,
			})
			if err != nil {
				t.Fatalf("strategy %q rejected: %v", s, err)
			}
			t.Cleanup(resetState)
		})
	}
}

func TestInit_StrategyInvalidValueErrorMentionsValue(t *testing.T) {
	resetState()
	defer resetState()
	if err := Register("user", map[Code]Meta{
		"USER_CREATED": {
			Domain: "user", Category: "account", Action: "create",
			Severity: SevInfo, Description: "test", Emitter: "test",
			RetentionClass: RetLong,
		},
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	err := Init(Config{
		ServiceID:                 "svc",
		NodeID:                    "node",
		AuditStore:                &recordingStore{},
		AuditStoreFailureStrategy: "weird",
	})
	if err == nil {
		t.Fatal("init must reject unknown strategy")
	}
	// Error must include the offending value so adopters can debug
	// typos without re-reading the docs.
	msg := err.Error()
	if !contains(msg, "\"weird\"") {
		t.Errorf("error must mention the bad value; got: %q", msg)
	}
}

// REVIEW #20: ring buffer used `rb.buf = rb.buf[1:]` to drop the
// oldest entry, which only advanced the slice header — the original
// backing array kept growing one element per push past capacity.
// Now uses a true circular index. Push past 10x capacity must keep
// the underlying array length bounded at exactly cap.
func TestRingBuffer_NoUnboundedGrowth(t *testing.T) {
	rb := newRingBuffer[int](16)
	for i := 0; i < 16*100; i++ {
		rb.Push(i)
	}
	if got := rb.Len(); got != 16 {
		t.Errorf("logical Len() want 16; got %d", got)
	}
	if got := cap(rb.buf); got != 16 {
		t.Errorf("backing array cap should stay at the configured size 16; got %d", got)
	}
	// Snapshot is newest-first and contains exactly 16 entries.
	all := rb.All()
	if len(all) != 16 {
		t.Fatalf("All() len want 16; got %d", len(all))
	}
	if all[0] != 16*100-1 {
		t.Errorf("newest entry want %d; got %d", 16*100-1, all[0])
	}
	if all[15] != 16*100-16 {
		t.Errorf("oldest of the 16 retained want %d; got %d", 16*100-16, all[15])
	}
}

// ── P1-22: Go drainer panic-recovery ─────────────────────────────────────

type panicStore struct{}

func (s *panicStore) Insert(_ context.Context, _ Row) error  { panic("store exploded") }
func (s *panicStore) Query(_ context.Context, _ Filter) ([]Row, error) { return nil, nil }
func (s *panicStore) ListUnshipped(_ context.Context, _ int) ([]Row, error) {
	return nil, nil
}
func (s *panicStore) MarkShipped(_ context.Context, _ []string) error    { return nil }
func (s *panicStore) Purge(_ context.Context, _ time.Time, _ bool) (int, error) { return 0, nil }

// TestDrainerSurvivesStorePanic asserts that a panicking store.Insert emits
// audit_drain_recovered_from_panic to the sys stream and that subsequent
// Emit + QueueStats calls do not panic or hang.
func TestDrainerSurvivesStorePanic(t *testing.T) {
	setupQueueMode(t, &panicStore{}, func(c *Config) {
		c.QueueRetryInitial = 5 * time.Millisecond
		c.QueueRetryMax = 20 * time.Millisecond
		c.DisableQueueJitter = true
	})

	if _, err := Emit(context.Background(), "USER_CREATED", Target("u-1")); err != nil {
		t.Fatalf("emit: %v", err)
	}

	// Allow time for the drainer goroutine to run and recover.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rows := Default.xport.QuerySyslog(100, "", "", "")
		for _, r := range rows {
			if r["event"] == "audit_drain_recovered_from_panic" {
				// Drainer survived. Verify subsequent calls don't hang or panic.
				_, _ = Emit(context.Background(), "USER_CREATED", Target("u-2"))
				_ = GetQueueStats()
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("audit_drain_recovered_from_panic sys event never fired after store panic")
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
