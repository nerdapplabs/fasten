package fasten

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// FR1 retention (spec §1) — background age-based purge for stream stores.
//
// The stream stores already expose Purge(before string) (age-based delete
// backed by idx_{table}_ts). This file is the driver: a goroutine per
// configured stream that wakes on a ticker, computes cutoff = now - retention,
// and calls Purge. Errors are logged via drainerSysLog and the loop keeps
// running so a transient database blip doesn't stop future purges.
//
// Shutdown is cooperative: the caller-owned context.CancelFunc must fire
// on Engine reset / atexit.

// parseRetentionDuration accepts time.ParseDuration's forms (30s, 15m, 1h,
// 2h30m) plus a small day extension ("7d" / "30d") that Go's time package
// doesn't understand. Zero is disabled. Compound day+time is rejected
// (deliberate — no "1d12h"); pass hours instead.
func parseRetentionDuration(s string) (time.Duration, error) {
	token := strings.TrimSpace(s)
	if token == "" {
		return 0, nil
	}
	if strings.HasSuffix(token, "d") {
		n, err := strconv.Atoi(token[:len(token)-1])
		if err != nil {
			return 0, fmt.Errorf("retention duration %q: expected integer before d", s)
		}
		if n <= 0 {
			return 0, fmt.Errorf("retention duration %q: must be positive", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(token)
	if err != nil {
		return 0, fmt.Errorf("retention duration %q: %w", s, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("retention duration %q: must be positive", s)
	}
	return d, nil
}

// retentionParams is what the engine hands to startPurger: the wired stream,
// its store, the retention window, and the tick interval. checkInterval is
// injected so tests don't have to wait an hour to see the second tick.
type retentionParams struct {
	stream        string
	store         StreamRepository
	retention     time.Duration
	checkInterval time.Duration
	// nowFn injects a fixed clock for tests. Nil defaults to time.Now.
	nowFn func() time.Time
	// onError is called after every failed Purge so the engine can pipe the
	// miss through drainerSysLog. Nil is fine (drop).
	onError func(stream string, err error)
}

// startPurger spawns a goroutine that runs an age-based purge on p.store
// every p.checkInterval. Returns immediately; the caller cancels via ctx.
// The first purge runs on entry (no waiting a full interval), so operators
// see the effect on Init rather than an hour later.
func startPurger(ctx context.Context, p retentionParams) {
	if p.checkInterval <= 0 {
		p.checkInterval = time.Hour
	}
	if p.nowFn == nil {
		p.nowFn = time.Now
	}
	go func() {
		// tick immediately, then every checkInterval
		fire := func() {
			cutoff := p.nowFn().Add(-p.retention).UTC().Format(time.RFC3339Nano)
			if _, err := p.store.Purge(cutoff); err != nil && p.onError != nil {
				p.onError(p.stream, err)
			}
		}
		fire()
		t := time.NewTicker(p.checkInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				fire()
			}
		}
	}()
}
