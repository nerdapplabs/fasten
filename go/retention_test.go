package fasten

import (
	"context"
	"database/sql"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// ── duration parser ──────────────────────────────────────────────────────

func TestParseRetentionDuration_Accepts(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"30s", 30 * time.Second},
		{"15m", 15 * time.Minute},
		{"1h", time.Hour},
		{"2h30m", 2*time.Hour + 30*time.Minute}, // time.ParseDuration native
		{"24h", 24 * time.Hour},
		{"7d", 7 * 24 * time.Hour},
		{"", 0}, // empty = disabled, not an error
	}
	for _, c := range cases {
		got, err := parseRetentionDuration(c.in)
		if err != nil {
			t.Errorf("parseRetentionDuration(%q) error: %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("parseRetentionDuration(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParseRetentionDuration_Rejects(t *testing.T) {
	bad := []string{"7", "d", "0d", "-1d", "week", "1d12h", "3.5d"}
	for _, s := range bad {
		if _, err := parseRetentionDuration(s); err == nil {
			t.Errorf("parseRetentionDuration(%q) should have failed", s)
		}
	}
}

// ── purger loop ──────────────────────────────────────────────────────────

// fakeStreamStore counts Purge invocations + captures cutoff strings, so a
// test can assert both cadence and the exact cutoff formula (now-retention).
type fakeStreamStore struct {
	StreamRepository
	calls   atomic.Int64
	cutoffs []string
	mu      chanCollector
}

type chanCollector struct{ ch chan string }

func (f *fakeStreamStore) Purge(before string) (int64, error) {
	f.calls.Add(1)
	if f.mu.ch != nil {
		f.mu.ch <- before
	}
	return 0, nil
}

func TestStartPurger_RunsImmediatelyAndUsesNowMinusRetention(t *testing.T) {
	f := &fakeStreamStore{mu: chanCollector{ch: make(chan string, 4)}}
	fixed := time.Date(2026, 8, 21, 10, 0, 0, 0, time.UTC)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startPurger(ctx, retentionParams{
		stream: "api", store: f, retention: 7 * 24 * time.Hour,
		checkInterval: 100 * time.Millisecond,
		nowFn:         func() time.Time { return fixed },
	})

	select {
	case got := <-f.mu.ch:
		// cutoff = 2026-08-21 - 7d = 2026-08-14T10:00:00Z
		if got[:20] != "2026-08-14T10:00:00Z"[:20] {
			t.Errorf("cutoff = %q, want prefix 2026-08-14T10:00:00Z", got)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("first purge did not fire within 1s")
	}
}

func TestStartPurger_KeepsRunningAfterError(t *testing.T) {
	// A store that always returns an error must not stop the loop; the
	// onError hook must fire and the second tick still lands.
	fail := &failingStreamStore{}
	var errCount atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startPurger(ctx, retentionParams{
		stream: "sys", store: fail, retention: time.Hour,
		checkInterval: 50 * time.Millisecond,
		onError:       func(string, error) { errCount.Add(1) },
	})
	// Wait for at least 3 attempts.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && errCount.Load() < 3 {
		time.Sleep(20 * time.Millisecond)
	}
	if errCount.Load() < 3 {
		t.Fatalf("loop must survive errors; got only %d ticks", errCount.Load())
	}
}

// failingStreamStore always errors on Purge — used to prove the loop
// survives repeated failures.
type failingStreamStore struct{ StreamRepository }

func (*failingStreamStore) Purge(string) (int64, error) {
	return 0, errPurgeFail
}

type errStrRet string

func (e errStrRet) Error() string { return string(e) }

var errPurgeFail = errStrRet("simulated purge failure")

// ── engine wiring ────────────────────────────────────────────────────────

func TestEngine_RetentionSpawnsCancellableGoroutine(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)

	sdb, _ := sql.Open("sqlite", ":memory:")
	t.Cleanup(func() { sdb.Close() })
	ss, err := NewStreamStore(sdb, "syslog_ret")
	if err != nil {
		t.Fatalf("NewStreamStore: %v", err)
	}
	if err := Init(Config{ServiceID: "svc", NodeID: "node",
		SyslogStore:     ss,
		RetentionSyslog: 24 * time.Hour,
	}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if Default.retentionCancel == nil {
		t.Fatal("Init with RetentionSyslog must set retentionCancel")
	}
	// Re-init with no retention must cancel the old goroutine.
	if err := Init(Config{ServiceID: "svc", NodeID: "node", SyslogStore: ss}); err != nil {
		t.Fatalf("re-Init: %v", err)
	}
	if Default.retentionCancel != nil {
		t.Fatal("re-Init without retention must clear retentionCancel")
	}
}

func TestEngine_MalformedRetentionEnvIsInitError(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	t.Setenv("FASTEN_RETENTION_SYSLOG", "not-a-duration")
	sdb, _ := sql.Open("sqlite", ":memory:")
	t.Cleanup(func() { sdb.Close() })
	ss, _ := NewStreamStore(sdb, "syslog_bad")
	err := Init(Config{ServiceID: "svc", NodeID: "node", SyslogStore: ss})
	if err == nil {
		t.Fatal("bad FASTEN_RETENTION_SYSLOG must fail Init loudly, not silently disable")
	}
}
