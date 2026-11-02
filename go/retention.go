package fasten

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Retention (spec §1): one goroutine per configured stream wakes on a ticker
// and purges rows older than the retention window. Errors are reported and
// the loop keeps going. Cancel the context to stop it.

var _retentionUnits = map[byte]time.Duration{
	's': time.Second, 'm': time.Minute,
	'h': time.Hour, 'd': 24 * time.Hour,
}

// parseRetentionDuration accepts a positive integer and one unit from
// s, m, h, d (e.g. "7d", "36h"), the same as the Python SDK. Empty means
// disabled. Compound ("2h30m") and fractional ("1.5h") values are rejected.
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

// retentionParams configures startPurger for one stream. checkInterval is
// settable so tests don't wait an hour.
type retentionParams struct {
	stream string
	// store and retention drive the age purge. Both are unset for the audit
	// stream: deleting from a hash chain shows up as tampering (spec §7.1),
	// so audit rows are only redacted.
	store     StreamRepository
	retention time.Duration
	// redactFn is Engine.RedactExpired, which also writes the spec §7.2
	// event that the store methods alone don't.
	piiRetention  time.Duration
	redactFn      func(ctx context.Context, before time.Time) error
	checkInterval time.Duration
	// nowFn defaults to time.Now.
	nowFn func() time.Time
	// onError, if set, is called after each failed purge or redaction.
	onError func(stream string, err error)
}

// startPurger runs the purge once right away and then every checkInterval
// until ctx is cancelled. If wg is non-nil the caller can Wait for the
// goroutine to exit; the next Init needs that because onError reads Engine
// fields that Init replaces.
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
		// Redaction and age purge run and report separately, so a redaction
		// failure doesn't skip the purge.
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
