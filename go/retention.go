package fasten

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
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

// parseRetentionDuration accepts a single positive integer + one unit
// suffix from {s, m, h, d} — matching the Python parser in
// python/fasten/retention.py verbatim so FASTEN_RETENTION_API=<value>
// means the same thing on both SDKs. Empty = disabled. Compound
// forms ("2h30m", "1d12h") and fractional forms ("1.5h") are rejected
// deliberately; pass a single-unit value ("150m", "36h").
var _retentionUnits = map[byte]time.Duration{
	's': time.Second, 'm': time.Minute,
	'h': time.Hour, 'd': 24 * time.Hour,
}

func parseRetentionDuration(s string) (time.Duration, error) {
	token := strings.TrimSpace(s)
	if token == "" {
		return 0, nil
	}
	if len(token) < 2 {
		return 0, fmt.Errorf("retention duration %q: unit must be one of s/m/h/d (e.g. \"7d\", \"24h\")", s)
	}
	unit, ok := _retentionUnits[token[len(token)-1]]
	if !ok {
		return 0, fmt.Errorf("retention duration %q: unit must be one of s/m/h/d (e.g. \"7d\", \"24h\")", s)
	}
	n, err := strconv.Atoi(token[:len(token)-1])
	if err != nil {
		return 0, fmt.Errorf("retention duration %q: expected integer before the unit", s)
	}
	if n <= 0 {
		return 0, fmt.Errorf("retention duration %q: must be positive", s)
	}
	return time.Duration(n) * unit, nil
}

// retentionParams is what the engine hands to startPurger: the wired stream,
// its store, the retention window, and the tick interval. checkInterval is
// injected so tests don't have to wait an hour to see the second tick.
type retentionParams struct {
	stream string
	// store/retention drive the age purge. Both zero/nil for the audit
	// stream, which is redaction-only: deleting a row from a hash-chained
	// stream is what VerifyChain reports as tampering (spec §7.1).
	store     StreamRepository
	retention time.Duration
	// piiRetention/redactFn drive the PII horizon. redactFn is
	// Engine.RedactExpired, so the spec §7.2 event is written — the store
	// methods alone destroy the data and record nothing.
	piiRetention  time.Duration
	redactFn      func(ctx context.Context, before time.Time) error
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
// see the effect on Init rather than an hour later. wg (nil-safe) lets the
// caller Wait for the goroutine to actually exit after cancel — required
// because Engine fields the onError callback reads (via drainerSysLog) are
// swapped by the next Init, and cancel alone doesn't bound exit timing.
func startPurger(ctx context.Context, wg *sync.WaitGroup, p retentionParams) {
	if p.checkInterval <= 0 {
		p.checkInterval = time.Hour
	}
	if p.nowFn == nil {
		p.nowFn = time.Now
	}
	if wg != nil {
		wg.Add(1)
	}
	go func() {
		if wg != nil {
			defer wg.Done()
		}
		// tick immediately, then every checkInterval
		// Two horizons, two labels. One shared path would let a redaction
		// failure skip the age purge, and report both the same way.
		fire := func() {
			now := p.nowFn()
			if p.piiRetention > 0 && p.redactFn != nil {
				if err := p.redactFn(ctx, now.Add(-p.piiRetention)); err != nil && p.onError != nil {
					p.onError(p.stream+"/pii-redaction", err)
				}
			}
			if p.retention > 0 && p.store != nil {
				cutoff := canonicalTS(now.Add(-p.retention))
				if _, err := p.store.Purge(cutoff); err != nil && p.onError != nil {
					p.onError(p.stream+"/age-purge", err)
				}
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
