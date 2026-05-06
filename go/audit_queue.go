// P1-15: bounded audit queue + background drainer goroutine.
//
// When Init's AuditStoreFailureStrategy is "queue" (the v1.0 default),
// Emit() pushes audit rows onto a bounded in-memory queue and a single
// drainer goroutine writes them to the store with exponential backoff
// (100 ms → 60 s, ±20 % jitter). Store failures stay off the request
// path; capacity covers queued + in-flight retry combined, so emit()
// blocks only when the audit pipeline is genuinely saturated.
//
// The drainer self-reports state transitions to the sys stream so
// adopters see audit-pipeline health through the channel they already
// monitor:
//
//	{"shape":"sys","level":"warn","event":"audit_drain_failed", ...}
//	{"shape":"sys","level":"error","event":"audit_drain_degraded", ...}
//	{"shape":"sys","level":"warn","event":"audit_queue_high_water", ...}
//	{"shape":"sys","level":"error","event":"audit_queue_near_full", ...}
//	{"shape":"sys","level":"info","event":"audit_drain_recovered", ...}
//
// See fasten-cloud/issues/P1-15-audit-store-failure-handling.md for the
// full design.
package fasten

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"
)

// AuditStoreError wraps an underlying store error for the "raise"
// strategy. Use errors.As to recover the cause:
//
//	var aerr *AuditStoreError
//	if errors.As(err, &aerr) { /* aerr.Err = sqlite3, psycopg, ... */ }
type AuditStoreError struct{ Err error }

func (e *AuditStoreError) Error() string {
	if e.Err == nil {
		return "fasten audit store: <nil>"
	}
	return "fasten audit store: " + e.Err.Error()
}
func (e *AuditStoreError) Unwrap() error { return e.Err }

// QueueStats is the snapshot returned by QueueStats(). Depth is total
// occupied capacity (queued + in-flight retry) — the value that
// determines whether the next Emit() blocks.
type QueueStats struct {
	Depth              int     `json:"depth"`
	Capacity           int     `json:"capacity"`
	HighWater          int     `json:"high_water"`
	DrainedTotal       int     `json:"drained_total"`
	RetryCountActive   int     `json:"retry_count_active"`
	InBackoffSeconds   float64 `json:"in_backoff_seconds"`
	LastError          string  `json:"last_error"`
	DeadLetteredTotal  int     `json:"dead_lettered_total"`
	DeadLetterDepth    int     `json:"dead_letter_depth"`
	CapacitySemantics  string  `json:"capacity_semantics"`
}

// auditQueueDrainer — single bounded queue + single drainer goroutine.
type auditQueueDrainer struct {
	store        AuditRepository
	sysLog       func(level, event string, fields map[string]any)
	capacity     int
	retryInitial time.Duration
	retryMax     time.Duration
	retryJitter  bool
	maxAttempts  int

	q     chan Row
	slots chan struct{} // counting semaphore — capacity slots
	stop  chan struct{}
	wg    sync.WaitGroup

	mu                sync.Mutex
	highWater         int
	drainedTotal      int
	retryCount        int
	inBackoffUntil    time.Time
	lastError         string
	failureBurstAt    time.Time
	inFlight          int
	warnHWFired       bool
	errHWFired        bool
	degradedFired     bool
	deadLetteredTotal int
	dlq               []Row // bounded ring; newest prepended, cap 10
}

const (
	hwWarnPct     = 0.50
	hwErrPct      = 0.80
	degradedAfter = 5
)

func newAuditDrainer(
	store AuditRepository,
	sysLog func(string, string, map[string]any),
	capacity int,
	retryInitial, retryMax time.Duration,
	retryJitter bool,
	maxAttempts int,
) *auditQueueDrainer {
	d := &auditQueueDrainer{
		store:        store,
		sysLog:       sysLog,
		capacity:     capacity,
		retryInitial: retryInitial,
		retryMax:     retryMax,
		retryJitter:  retryJitter,
		maxAttempts:  maxAttempts,
		q:            make(chan Row, capacity),
		slots:        make(chan struct{}, capacity),
		stop:         make(chan struct{}),
	}
	d.wg.Add(1)
	go d.run()
	return d
}

// put pushes a row onto the queue. Blocks if all capacity slots
// (queued + in-flight retry combined) are taken.
func (d *auditQueueDrainer) put(row Row) {
	// Acquire a slot — blocks when capacity is saturated. Released by
	// drainer on successful insert or shutdown abandon.
	d.slots <- struct{}{}
	d.q <- row

	used := len(d.slots)
	d.mu.Lock()
	if used > d.highWater {
		d.highWater = used
	}
	cap := d.capacity
	warnFired := d.warnHWFired
	errFired := d.errHWFired
	if cap > 0 {
		pct := float64(used) / float64(cap)
		if pct >= hwErrPct && !errFired {
			d.errHWFired = true
		} else if pct >= hwWarnPct && !warnFired {
			d.warnHWFired = true
		} else if pct < hwWarnPct {
			d.warnHWFired = false
			d.errHWFired = false
		}
	}
	// Capture transition flags to fire after unlock (sysLog must not run
	// under the stats mutex).
	fireErr := d.errHWFired && !errFired
	fireWarn := d.warnHWFired && !warnFired && !fireErr
	d.mu.Unlock()

	if fireErr {
		d.sysLog("error", "audit_queue_near_full", map[string]any{
			"depth": used, "capacity": cap,
		})
	} else if fireWarn {
		d.sysLog("warn", "audit_queue_high_water", map[string]any{
			"depth": used, "capacity": cap,
		})
	}
}

// stats returns a snapshot. Depth = queued + in-flight retry.
func (d *auditQueueDrainer) stats() QueueStats {
	d.mu.Lock()
	defer d.mu.Unlock()
	bo := 0.0
	if rem := time.Until(d.inBackoffUntil); rem > 0 {
		bo = rem.Seconds()
	}
	return QueueStats{
		Depth:             len(d.slots),
		Capacity:          d.capacity,
		HighWater:         d.highWater,
		DrainedTotal:      d.drainedTotal,
		RetryCountActive:  d.retryCount,
		InBackoffSeconds:  roundFloat(bo, 3),
		LastError:         d.lastError,
		DeadLetteredTotal: d.deadLetteredTotal,
		DeadLetterDepth:   len(d.dlq),
		CapacitySemantics: "block",
	}
}

// flush blocks until every pending row reaches the store (or shutdown
// abandon), or the timeout elapses. Returns true iff drained.
//
// Uses len(d.slots) — the capacity semaphore — as the canonical
// "rows pending" signal because the slot is acquired before the
// queue.put + released only after successful insert, so it covers the
// transient window where a row has been popped from d.q but
// d.inFlight has not yet been incremented in drainOne. Checking q +
// inFlight separately allowed flush() to return prematurely during
// that gap (race surfaced by run-to-run flake on TestPublicFlush*).
func (d *auditQueueDrainer) flush(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if len(d.slots) == 0 {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return len(d.slots) == 0
}

// shutdown signals the drainer to stop and waits up to timeout. Pending
// rows in the queue get one best-effort attempt (in-shutdown mode);
// rows that fail their final attempt are abandoned.
func (d *auditQueueDrainer) shutdown(timeout time.Duration) {
	select {
	case <-d.stop:
		// already closed
	default:
		close(d.stop)
	}
	done := make(chan struct{})
	go func() { d.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(timeout):
	}
}

func (d *auditQueueDrainer) run() {
	defer d.wg.Done()
	for {
		select {
		case <-d.stop:
			// Best-effort drain of pending rows so atexit / shutdown
			// flush doesn't lose them. Each attempt is one-shot under
			// in-shutdown mode (see drainOne).
			for {
				select {
				case row := <-d.q:
					d.drainOne(row, true)
				default:
					return
				}
			}
		case row := <-d.q:
			d.drainOne(row, false)
		}
	}
}

// drainOne keeps retrying until the store accepts the row, the stop
// signal arrives, or (in shutdown mode) the first attempt fails.
func (d *auditQueueDrainer) drainOne(row Row, inShutdown bool) {
	d.mu.Lock()
	d.inFlight++
	d.mu.Unlock()

	slotReleased := false
	defer func() {
		d.mu.Lock()
		d.inFlight--
		d.mu.Unlock()
		if !slotReleased {
			<-d.slots
		}
	}()
	// Panic-recovery: a panicking store.Insert kills the goroutine and hangs
	// every subsequent emit on the buffered channel forever with no signal.
	// Python's BLE001 catch and Rust's lock_or_recover both prevent this;
	// defer recover() is the Go equivalent.
	defer func() {
		if r := recover(); r != nil {
			d.sysLog("error", "audit_drain_recovered_from_panic", map[string]any{
				"error":  fmt.Sprintf("%v", r),
				"row_id": row.ID,
			})
		}
	}()

	attempt := 0
	for {
		attempt++
		err := d.store.Insert(context.Background(), row)
		if err == nil {
			d.onSuccess()
			<-d.slots
			slotReleased = true
			return
		}
		if attempt >= d.maxAttempts {
			d.onDeadLetter(row, attempt, err)
			<-d.slots
			slotReleased = true
			return
		}
		d.onFailure(err)
		if inShutdown {
			<-d.slots
			slotReleased = true
			return
		}
		if d.waitBackoff() {
			<-d.slots
			slotReleased = true
			return
		}
	}
}

func (d *auditQueueDrainer) onDeadLetter(row Row, attempt int, err error) {
	msg := err.Error()
	d.mu.Lock()
	d.deadLetteredTotal++
	d.retryCount = 0
	d.lastError = msg
	if len(d.dlq) >= 10 {
		d.dlq = d.dlq[1:] // drop oldest
	}
	d.dlq = append(d.dlq, row)
	d.mu.Unlock()
	d.sysLog("error", "audit_drain_dead_letter", map[string]any{
		"row_id":        row.ID,
		"attempt_count": attempt,
		"last_error":    msg,
	})
}

func (d *auditQueueDrainer) onFailure(err error) {
	msg := err.Error()
	d.mu.Lock()
	first := d.retryCount == 0
	if first {
		d.failureBurstAt = time.Now()
	}
	d.retryCount++
	d.lastError = msg
	rc := d.retryCount
	bo := time.Until(d.inBackoffUntil).Seconds()
	if bo < 0 {
		bo = 0
	}
	crossedDegraded := false
	if d.retryCount >= degradedAfter && !d.degradedFired {
		d.degradedFired = true
		crossedDegraded = true
	}
	d.mu.Unlock()

	if first {
		d.sysLog("warn", "audit_drain_failed", map[string]any{"error": msg})
	}
	if crossedDegraded {
		d.sysLog("error", "audit_drain_degraded", map[string]any{
			"retry_count":        rc,
			"in_backoff_seconds": roundFloat(bo, 3),
			"last_error":         msg,
		})
	}
}

func (d *auditQueueDrainer) onSuccess() {
	var recoveredAfter float64
	d.mu.Lock()
	if d.retryCount > 0 && !d.failureBurstAt.IsZero() {
		recoveredAfter = time.Since(d.failureBurstAt).Seconds()
	}
	d.retryCount = 0
	d.inBackoffUntil = time.Time{}
	d.failureBurstAt = time.Time{}
	d.lastError = ""
	d.degradedFired = false
	d.drainedTotal++
	d.mu.Unlock()

	if recoveredAfter > 0 {
		d.sysLog("info", "audit_drain_recovered", map[string]any{
			"recovery_after_seconds": roundFloat(recoveredAfter, 3),
		})
	}
}

// waitBackoff sleeps the current backoff window. Returns true if stop
// was signalled mid-sleep so the drainer can exit promptly.
func (d *auditQueueDrainer) waitBackoff() bool {
	d.mu.Lock()
	n := d.retryCount
	d.mu.Unlock()
	delay := d.retryInitial
	for i := 1; i < n; i++ {
		delay *= 2
		if delay >= d.retryMax {
			delay = d.retryMax
			break
		}
	}
	if delay > d.retryMax {
		delay = d.retryMax
	}
	if d.retryJitter {
		j := float64(delay) * 0.2
		delay += time.Duration((rand.Float64()*2 - 1) * j)
		if delay < 0 {
			delay = 0
		}
	}
	d.mu.Lock()
	d.inBackoffUntil = time.Now().Add(delay)
	d.mu.Unlock()
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-d.stop:
		return true
	case <-t.C:
		return false
	}
}

// ── Module-level singleton ─────────────────────────────────────────────────

var (
	_drainer   *auditQueueDrainer
	_drainerMu sync.Mutex
)

func installDrainer(
	store AuditRepository,
	sysLog func(string, string, map[string]any),
	capacity int,
	retryInitial, retryMax time.Duration,
	retryJitter bool,
	maxAttempts int,
) *auditQueueDrainer {
	_drainerMu.Lock()
	defer _drainerMu.Unlock()
	if _drainer != nil {
		_drainer.flush(5 * time.Second)
		_drainer.shutdown(2 * time.Second)
	}
	_drainer = newAuditDrainer(store, sysLog, capacity, retryInitial, retryMax, retryJitter, maxAttempts)
	return _drainer
}

func uninstallDrainer() {
	_drainerMu.Lock()
	defer _drainerMu.Unlock()
	if _drainer != nil {
		_drainer.shutdown(2 * time.Second)
		_drainer = nil
	}
}

func activeDrainer() *auditQueueDrainer {
	_drainerMu.Lock()
	defer _drainerMu.Unlock()
	return _drainer
}

// GetQueueStats returns a snapshot of the active drainer, or nil in
// raise mode (no drainer running). Mirrors the existing GetTransport
// accessor naming.
func GetQueueStats() *QueueStats {
	d := activeDrainer()
	if d == nil {
		return nil
	}
	s := d.stats()
	return &s
}

// Flush blocks until pending audit rows are drained, or timeout
// elapses. Returns true iff every queued row reached the store. Useful
// for k8s preStop hooks, CLI subcommand exit paths, and tests. No-op +
// returns true in raise mode (no queue to drain).
func Flush(timeout time.Duration) bool {
	d := activeDrainer()
	if d == nil {
		return true
	}
	return d.flush(timeout)
}

func roundFloat(f float64, digits int) float64 {
	pow := 1.0
	for i := 0; i < digits; i++ {
		pow *= 10
	}
	return float64(int64(f*pow+0.5)) / pow
}
