package fasten

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// Engine holds all runtime state for one fasten deployment context.
//
// The package-level functions (Init, Emit, ...) use Default. To run several
// independent configurations in one process, create Engines directly:
//
//	a := &fasten.Engine{}
//	a.Init(fasten.Config{ServiceID: "tenant-a", AuditStore: storeA})
//	a.Emit(ctx, "ORDER_PLACED", fasten.Target("order/123"))
type Engine struct {
	conf        atomic.Pointer[engineConfig] // nil before Init
	auditStore  AuditRepository              // written under storeMu
	xport       atomic.Pointer[Transport]
	apiStore    StreamRepository // nil = in memory only; written under storeMu
	syslogStore StreamRepository // nil = in memory only; written under storeMu
	seq         int64            // accessed via atomic ops

	// persistedStreams holds the streams that have a store ("audit", "api",
	// "sys"); the reader reports completeness from it. Nil (before Init)
	// means none. Written under storeMu.
	persistedStreams map[string]bool

	// storeMu guards the store fields. It is held only to read or change
	// them, never across a store call.
	storeMu sync.RWMutex
	// auditInserts counts the inserts running on auditStore. An emit adds
	// to it under storeMu; a new store gets a new one, so the old store is
	// closed once the old count reaches zero.
	auditInserts *sync.WaitGroup

	// envStores holds the stores Init opened from FASTEN_*_DSN, by
	// variable, so a re-init with the same DSN keeps them.
	envStores map[string]*envStore

	unchainedStoreLogged  atomic.Bool
	auditChainUnavailable atomic.Bool

	// prevHash is reset by Init and ResetForTests but never used: the store
	// allocates seq and prev_hash (spec §2.1).
	hashMu   sync.Mutex
	prevHash string

	drainerMu sync.Mutex
	drainer   *cFastenDrainer
	retired   chan struct{} // closed once the last drainer taken out has been retired
	closing   *closeCall    // the Close in progress, if any
	storeGen  atomic.Int64  // bumped when Init switches to another audit store
	closed    atomic.Bool   // Close has run and Init has not since

	// pendingClose, guarded by drainerMu, is closed once the stores a
	// timed-out Close left open are closed.
	pendingClose chan struct{}

	// auditWriteSwallowed is set when an audit insert error was swallowed.
	// It's kept here as well as on the store because AuditRepository
	// doesn't require NoteWriteFailure. It stays set until the next Init.
	auditWriteSwallowed atomic.Bool

	// Redaction settings for this Engine. redactMu guards Init's writes
	// against reads from Emit. Empty values mean the core defaults.
	redactMu            sync.RWMutex
	redactExtraKeysJSON string
	redactReplacement   string

	// retentionCancel stops this Engine's purger goroutines and retentionWg
	// waits for them, so their stores are closed only once they have exited.
	// startRetention sets new ones each time.
	retentionCancel context.CancelFunc
	retentionWg     *sync.WaitGroup

	// Tenant scope for reader endpoints, set via
	// NewReader(WithTenantScope(...)). Nil = single-tenant mode
	// (no scope enforced, ?tenant_id= honoured as-is).
	tenantScope            func(*http.Request) (string, bool)
	enforceTenantIsolation bool

	// Set only on the scratch Engine NewReader collects its options into.
	readerAuth   func(http.Handler) http.Handler
	readerNoAuth bool
}

// Default is the package-level Engine used by all free-function API calls.
var Default = &Engine{}

// engineConfig is the configuration Init sets. Init stores a new one, so an
// emit that loads it once sees one Init's values.
type engineConfig struct {
	serviceID       string
	nodeID          string
	tenantID        string
	failureStrategy string
	searchEnabled   bool // free-text search (/logs/search, q=)
}

// config returns the configuration of the last Init, or the zero one before
// Init.
func (e *Engine) config() *engineConfig {
	if c := e.conf.Load(); c != nil {
		return c
	}
	return &engineConfig{}
}

// configureRedaction sets this Engine's extra redact keys and replacement
// from config, or else from FASTEN_REDACT_KEYS (comma-separated) and
// FASTEN_REDACT_REPLACEMENT. Both are always set, so a repeat Init doesn't
// keep the previous values.
func (e *Engine) configureRedaction(extraKeys []string, replacement string) {
	if len(extraKeys) == 0 {
		if env := envOr("FASTEN_REDACT_KEYS", ""); env != "" {
			for _, k := range strings.Split(env, ",") {
				if k = strings.TrimSpace(k); k != "" {
					extraKeys = append(extraKeys, k)
				}
			}
		}
	}
	extraJSON := ""
	if len(extraKeys) > 0 {
		if b, err := json.Marshal(extraKeys); err == nil {
			extraJSON = string(b)
		}
	}
	replacement = firstNonEmpty(replacement, envOr("FASTEN_REDACT_REPLACEMENT", ""))
	// A replacement that isn't UTF-8 is treated as unset (the default
	// "***"), as in the other SDKs.
	if !utf8.ValidString(replacement) {
		replacement = ""
	}

	e.redactMu.Lock()
	e.redactExtraKeysJSON = extraJSON
	e.redactReplacement = replacement
	e.redactMu.Unlock()
}

// Init configures this Engine. See Config.
//
// Everything that can fail is checked before Init changes anything, so a
// failed Init leaves the Engine as it was.
func (e *Engine) Init(cfg Config) error {
	if n := cfg.QueueDrainMaxAttempts; n > 0 && uint64(n) > math.MaxUint32 {
		return fmt.Errorf("fasten.Init: QueueDrainMaxAttempts must be at most %d (got %d)",
			uint32(math.MaxUint32), n)
	}
	serviceID := firstNonEmpty(cfg.ServiceID, envOr("FASTEN_SERVICE_ID", ""))
	nodeID := firstNonEmpty(cfg.NodeID, envOr("FASTEN_NODE_ID", ""))
	if serviceID == "" || nodeID == "" {
		return errors.New("fasten.Init: ServiceID and NodeID are required")
	}
	// A nil *SQLiteStore in the interface isn't == nil, so every later nil
	// check would pass and the first method call would panic. Normalise it
	// once here.
	if isTypedNil(cfg.AuditStore) {
		cfg.AuditStore = nil
	}
	strategy := strings.ToLower(firstNonEmpty(
		cfg.AuditStoreFailureStrategy,
		envOr("FASTEN_AUDIT_STORE_FAILURE_STRATEGY", ""),
		"queue",
	))
	switch strategy {
	case "queue", "raise":
	default:
		return fmt.Errorf(
			"fasten.Init: AuditStoreFailureStrategy must be %q or %q (got %q)",
			"queue", "raise", strategy,
		)
	}
	// Stores not passed in Config are opened from FASTEN_AUDIT_DSN,
	// FASTEN_API_DSN and FASTEN_SYSLOG_DSN.
	slots, err := planEnvStores(cfg, e.envStores)
	if err != nil {
		return err
	}
	hasAPI := cfg.APIStore != nil || hasSlot(slots, "FASTEN_API_DSN")
	hasSys := cfg.SyslogStore != nil || hasSlot(slots, "FASTEN_SYSLOG_DSN")
	if err := assertPersistStreams(cfg.PersistStreams, hasAPI, hasSys); err != nil {
		return err
	}
	ret, err := retentionFromEnv(cfg.RetentionAPI, cfg.RetentionSyslog, cfg.RetentionPII)
	if err != nil {
		return err
	}
	// A store opened from a DSN can always redact.
	if ret.pii > 0 && cfg.AuditStore != nil {
		if _, ok := cfg.AuditStore.(RedactionRepository); !ok {
			return fmt.Errorf(
				"fasten.Init: RetentionPII is set but audit store %T does not "+
					"implement RedactionRepository (spec §7.1): personal data "+
					"would never be redacted", cfg.AuditStore)
		}
	}
	next, err := e.openEnvStores(slots)
	if err != nil {
		return err
	}
	// Nothing below fails.
	if es := next["FASTEN_AUDIT_DSN"]; es != nil {
		cfg.AuditStore = es.store.(AuditRepository)
	}
	if es := next["FASTEN_API_DSN"]; es != nil {
		cfg.APIStore = es.store.(StreamRepository)
	}
	if es := next["FASTEN_SYSLOG_DSN"]; es != nil {
		cfg.SyslogStore = es.store.(StreamRepository)
	}
	unused := e.unusedEnvStores(next)
	e.envStores = next

	e.conf.Store(&engineConfig{
		serviceID:       serviceID,
		nodeID:          nodeID,
		tenantID:        firstNonEmpty(cfg.TenantID, envOr("FASTEN_TENANT_ID", "")),
		failureStrategy: strategy,
		searchEnabled:   cfg.SearchEnabled || isTruthy(envOr("FASTEN_SEARCH_ENABLED", "")),
	})

	// Emits use the new store at once. Inserts still running on the
	// previous one are waited for below, before it is closed.
	var prevStore AuditRepository
	var prevInserts *sync.WaitGroup
	e.storeMu.Lock()
	if !sameStore(e.auditStore, cfg.AuditStore) {
		prevStore, prevInserts = e.auditStore, e.auditInserts
		e.auditStore = cfg.AuditStore
		e.auditInserts = &sync.WaitGroup{}
		// A new store starts with no swallowed writes; re-init on the same
		// store keeps them.
		e.storeGen.Add(1)
		e.auditWriteSwallowed.Store(false)
	}
	e.storeMu.Unlock()
	if testHookStoreSwitched != nil {
		testHookStoreSwitched()
	}

	// e.seq is no longer read; the store allocates seq (spec §2.1).
	if seeder, ok := cfg.AuditStore.(SeqSeeder); ok {
		if max, err := seeder.MaxMonotonicSeq(context.Background(), serviceID, nodeID); err == nil {
			atomic.StoreInt64(&e.seq, max)
		}
	}

	e.hashMu.Lock()
	e.prevHash = "genesis"
	e.hashMu.Unlock()
	x := NewTransport(2000)
	// Sys and api rows are redacted before they are stored; see
	// Transport.redactRow.
	x.redact = e.redactDetail
	// Stream rows without a request_id get this boot id until the first
	// real request arrives.
	x.serviceID = serviceID
	x.bootRequestID = MintSentinel("boot", serviceID)
	x.APIStore = cfg.APIStore
	x.SyslogStore = cfg.SyslogStore
	prevX, pushed := e.swapTransport(x)
	e.warnUnreadDSNEnv()
	e.storeMu.Lock()
	e.apiStore = cfg.APIStore
	e.syslogStore = cfg.SyslogStore
	e.persistedStreams = persistedStreams(cfg.AuditStore, cfg.APIStore, cfg.SyslogStore)
	e.storeMu.Unlock()

	e.configureRedaction(cfg.ExtraRedactKeys, cfg.RedactReplacement)

	var nextDrainer *cFastenDrainer
	if strategy == "queue" && e.auditStore != nil {
		capacity := cfg.QueueCapacity
		if capacity <= 0 {
			capacity = 100
		}
		retryInitialMs := cfg.QueueRetryInitial.Milliseconds()
		if retryInitialMs <= 0 {
			retryInitialMs = 100
		}
		retryMaxMs := cfg.QueueRetryMax.Milliseconds()
		if retryMaxMs <= 0 {
			retryMaxMs = 60_000
		}
		maxAttempts := cfg.QueueDrainMaxAttempts
		if maxAttempts <= 0 {
			maxAttempts = 50
		}
		nextDrainer = e.newDrainer(
			e.auditStore,
			capacity, retryInitialMs, retryMaxMs, !cfg.DisableQueueJitter, maxAttempts,
		)
	}
	// Swap in the new drainer, then retire the old one: emits keep being
	// queued while it drains, and its rows and events keep its own config.
	old, done := e.swapDrainer(nextDrainer)
	e.closed.Store(false)
	e.retireOld(old, done, 5*time.Second, time.Time{})
	// The old drainer and the streams no longer write to these; nor will
	// retention once it has stopped.
	e.stopRetention()
	if prevStore != nil && slices.ContainsFunc(unused, func(s *envStore) bool { return s.store == prevStore }) {
		<-insertsDone(prevInserts)
	}
	if prevX != nil && slices.ContainsFunc(unused, func(s *envStore) bool {
		return s.store == prevX.APIStore || s.store == prevX.SyslogStore
	}) {
		<-pushed
	}
	e.closeStores(e.out(), unused)
	e.startRetention(ret)
	return nil
}

// persistedStreams returns the streams that have a store.
func persistedStreams(audit AuditRepository, api, syslog StreamRepository) map[string]bool {
	m := map[string]bool{}
	if audit != nil {
		m["audit"] = true
	}
	if api != nil {
		m["api"] = true
	}
	if syslog != nil {
		m["sys"] = true
	}
	return m
}

// assertPersistStreams checks that the streams named in PersistStreams (or
// FASTEN_PERSIST_STREAMS) are exactly the ones with stores attached. With
// neither set there is nothing to check.
func assertPersistStreams(fromConfig []string, hasAPI, hasSys bool) error {
	named := fromConfig
	if named == nil {
		if s := envOr("FASTEN_PERSIST_STREAMS", ""); s != "" {
			for _, part := range strings.Split(s, ",") {
				if p := strings.TrimSpace(part); p != "" {
					named = append(named, p)
				}
			}
		} else {
			return nil
		}
	}
	namedSet := map[string]bool{}
	for _, s := range named {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if s != "api" && s != "sys" {
			return fmt.Errorf(
				"fasten.Init: PersistStreams contains unknown stream %q "+
					"(only \"api\" and \"sys\" are valid; audit persistence "+
					"is driven by AuditStore, not PersistStreams)", s)
		}
		namedSet[s] = true
	}
	have := map[string]bool{}
	if hasAPI {
		have["api"] = true
	}
	if hasSys {
		have["sys"] = true
	}
	var missingStore, unlisted []string
	for s := range namedSet {
		if !have[s] {
			missingStore = append(missingStore, s)
		}
	}
	for s := range have {
		if !namedSet[s] {
			unlisted = append(unlisted, s)
		}
	}
	if len(missingStore) == 0 && len(unlisted) == 0 {
		return nil
	}
	sort.Strings(missingStore)
	sort.Strings(unlisted)
	var parts []string
	if len(missingStore) > 0 {
		parts = append(parts, fmt.Sprintf(
			"named in PersistStreams but no store attached: %v", missingStore))
	}
	if len(unlisted) > 0 {
		parts = append(parts, fmt.Sprintf(
			"store attached but not in PersistStreams: %v", unlisted))
	}
	return fmt.Errorf("fasten.Init: PersistStreams / stores mismatch: %s",
		strings.Join(parts, "; "))
}

// retentionWindows are the retention settings Init starts purgers with.
type retentionWindows struct {
	api, sys, pii time.Duration
}

// retentionFromEnv returns each retention from Config or, if that is zero,
// the env var. An invalid env value is an Init error.
func retentionFromEnv(apiRet, sysRet, piiRet time.Duration) (retentionWindows, error) {
	for _, r := range []struct {
		name string
		d    *time.Duration
	}{
		{"FASTEN_RETENTION_API", &apiRet},
		{"FASTEN_RETENTION_SYSLOG", &sysRet},
		{"FASTEN_RETENTION_PII", &piiRet},
	} {
		if *r.d != 0 {
			continue
		}
		if s := envOr(r.name, ""); s != "" {
			d, err := parseRetentionDuration(s)
			if err != nil {
				return retentionWindows{}, fmt.Errorf("fasten.Init: %s: %w", r.name, err)
			}
			*r.d = d
		}
	}
	return retentionWindows{api: apiRet, sys: sysRet, pii: piiRet}, nil
}

// startRetention stops any running purgers and starts one for each stream
// that has a store and a positive retention. Init has checked that the
// audit store can redact.
func (e *Engine) startRetention(ret retentionWindows) {
	e.stopRetention()

	if (ret.api == 0 || e.apiStore == nil) &&
		(ret.sys == 0 || e.syslogStore == nil) &&
		(ret.pii == 0 || e.auditStore == nil) {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	wg := &sync.WaitGroup{}
	e.retentionCancel = cancel
	e.retentionWg = wg
	// A purge can outlive Close and run into the next Init.
	serviceID := e.config().serviceID
	onErr := func(stream string, err error) {
		e.sysLogTo(sysOut{e.xport.Load(), serviceID}, "error", "retention_purge_failed", map[string]any{
			// Type-only, not err.Error() — driver error strings can carry
			// the offending row value; sys is redacted key-pattern only.
			"stream": stream, "error_type": fmt.Sprintf("%T", err),
		})
	}
	if ret.api > 0 && e.apiStore != nil {
		startPurger(ctx, wg, retentionParams{
			stream: "api", store: e.apiStore, retention: ret.api,
			checkInterval: time.Hour, onError: onErr,
		})
	}
	if ret.sys > 0 && e.syslogStore != nil {
		startPurger(ctx, wg, retentionParams{
			stream: "sys", store: e.syslogStore, retention: ret.sys,
			checkInterval: time.Hour, onError: onErr,
		})
	}
	// Audit rows are only redacted, never purged, so no store or retention.
	if ret.pii > 0 && e.auditStore != nil {
		startPurger(ctx, wg, retentionParams{
			stream: "audit", piiRetention: ret.pii,
			redactFn: func(ctx context.Context, before time.Time) error {
				_, err := e.RedactExpired(ctx, before, "retention")
				return err
			},
			checkInterval: time.Hour, onError: onErr,
		})
	}
}

// cancelRetention cancels any running purgers and returns a channel that is
// closed once they have exited.
func (e *Engine) cancelRetention() <-chan struct{} {
	if e.retentionCancel != nil {
		e.retentionCancel()
		e.retentionCancel = nil
	}
	wg := e.retentionWg
	e.retentionWg = nil
	done := make(chan struct{})
	if wg == nil {
		close(done)
		return done
	}
	go func() {
		wg.Wait()
		close(done)
	}()
	return done
}

// stopRetention cancels any running purgers and waits for them to exit.
func (e *Engine) stopRetention() {
	<-e.cancelRetention()
}

// Emit produces an audit row for a registered code.
func (e *Engine) Emit(ctx context.Context, code Code, opts ...EmitOption) (Row, error) {
	return e.emitRow(ctx, code, false, opts...)
}

// emitRow is Emit with an explicit durability requirement.
//
// With durable=true a store error is always returned, even in queue mode,
// and the row is never handed to the drainer. Only the spec §7.2 redaction
// record uses it, since the caller destroys data once the row is stored.
func (e *Engine) emitRow(ctx context.Context, code Code, durable bool, opts ...EmitOption) (Row, error) {
	c := e.config()
	if c.serviceID == "" {
		return Row{}, errors.New("fasten.Init() must be called before Emit()")
	}
	m, ok := metaOf(code)
	if !ok {
		return Row{}, fmt.Errorf("fasten: unknown audit code %q: call Register() first", code)
	}

	rid := RequestIDFromContext(ctx)
	if rid == "" {
		rid = MintID()
	}

	id := "evt-" + mintLong()

	var tid *string
	if c.tenantID != "" {
		t := c.tenantID
		tid = &t
	}
	row := Row{
		WireVersion:  "1",
		ID:           id,
		OriginID:     id,
		MonotonicSeq: 0, // allocated by the store
		Timestamp:    time.Now().UTC(),
		Code:         code,
		Action:       m.Action,
		Severity:     m.Severity,
		ServiceID:    c.serviceID,
		SourceNodeID: c.nodeID,
		TenantID:     tid,
		Actor:        "system",
		ActorKind:    "service",
		Target:       "",
		Category:     m.Category,
		Domain:       m.Domain,
		Method:       "sdk",
		RequestID:    rid,
		Detail:       map[string]any{},
		PiiInDetail:  m.PiiInDetail,
	}
	for _, opt := range opts {
		opt(&row)
	}

	// Redact before sealing so the hash covers the detail that is stored.
	if m.PiiInDetail {
		passthrough := make(map[string]bool, len(m.DetailPassthroughKeys))
		for _, k := range m.DetailPassthroughKeys {
			passthrough[k] = true
		}
		kept := map[string]any{}
		for k, v := range row.Detail {
			if passthrough[k] {
				kept[k] = v
			}
		}
		kept = e.redactAuditDetail(kept)
		kept["_redacted"] = "***"
		kept["_pii_in_detail"] = true
		row.Detail = kept
	} else {
		row.Detail = e.redactAuditDetail(row.Detail)
	}

	// monotonic_seq, prev_hash and hash are not set here. The store
	// allocates them and seals the row inside the insert transaction (spec
	// §2.1), so several engines on one node still produce one chain.
	//
	// With no audit store there is nothing to allocate against, so the row goes
	// out unsealed (hash "") per spec §8.1. VerifyChain skips hashless rows, so
	// such a stream verifies vacuously rather than failing. Fabricating an
	// in-memory sequence here would be the exact non-conformance §2.1 forbids:
	// it cannot survive a restart or a second process, so it is a chain in
	// appearance only.

	if x := e.xport.Load(); x != nil {
		x.WriteAudit(rowToMap(row))
	}
	return e.storeAudit(ctx, c.failureStrategy, row, durable)
}

// storeAudit stores an emitted row in the audit store, if there is one.
func (e *Engine) storeAudit(ctx context.Context, strategy string, row Row, durable bool) (Row, error) {
	store, gen, done := e.useAuditStore()
	if store == nil {
		return row, nil
	}
	defer done()
	if strategy != "queue" {
		// "raise": the error is returned.
		sealed, err := e.allocateAndStore(ctx, store, e.out(), row)
		if err != nil {
			return row, &AuditStoreError{Err: err}
		}
		return sealed, nil
	}
	// The drainer retries the insert; the store seals the row when it
	// lands (spec §2.1, §8). A durable emit must not return before the
	// row is persisted, so it takes the synchronous path, and so does
	// a row the drainer refuses.
	d := e.activeDrainer()
	queued, refused := false, false
	switch {
	case durable:
	case d != nil && d.gen != gen:
		// Init is switching stores: store it inline in the new one.
	case d == nil && e.closed.Load():
		// After Close, rows are stored inline.
	case d == nil:
		// No drainer to take the row (spec §7 V-12).
		refused = true
		e.drainerSysLog("error", "audit_drain_abandoned", map[string]any{
			"reason": "no_drainer", "row_id": row.ID,
		})
	default:
		var reported bool
		queued, reported = d.enqueue(row)
		refused = !queued
		if refused && !reported {
			// fasten-core reports only the rows it refused at stop.
			e.drainerSysLog("error", "audit_drain_abandoned", map[string]any{
				"reason": "enqueue_refused", "row_id": row.ID,
			})
		}
	}
	if queued {
		return row, nil
	}
	sealed, ferr := e.allocateAndStore(ctx, store, e.out(), row)
	if ferr == nil {
		if refused {
			// Follows the abandoned event.
			e.drainerSysLog("info", "audit_drain_stored_inline", map[string]any{"row_id": row.ID})
		}
		return sealed, nil
	}
	if durable {
		return row, &AuditStoreError{Err: ferr}
	}
	// The error is swallowed, so mark the audit stream degraded.
	e.markWriteLost(store, gen)
	e.drainerSysLog("error", "audit_sync_fallback_failed", map[string]any{
		// Type-only — see retention_purge_failed comment.
		"error_type": fmt.Sprintf("%T", ferr),
		"row_id":     row.ID,
	})
	return row, nil
}

// useAuditStore returns the audit store and its generation, and counts an
// insert on the store until done is called; the store is not closed before
// then. The store is nil when there is none.
func (e *Engine) useAuditStore() (store AuditRepository, gen int64, done func()) {
	e.storeMu.RLock()
	defer e.storeMu.RUnlock()
	if e.auditStore == nil {
		return nil, 0, nil
	}
	e.auditInserts.Add(1)
	return e.auditStore, e.storeGen.Load(), e.auditInserts.Done
}

// currentAuditStore returns the audit store, or nil.
func (e *Engine) currentAuditStore() AuditRepository {
	e.storeMu.RLock()
	defer e.storeMu.RUnlock()
	return e.auditStore
}

// insertsDone returns a channel closed once the inserts counted in wg have
// returned. A nil wg counts none.
func insertsDone(wg *sync.WaitGroup) <-chan struct{} {
	done := make(chan struct{})
	if wg == nil {
		close(done)
		return done
	}
	go func() {
		wg.Wait()
		close(done)
	}()
	return done
}

// swapTransport makes x the transport and retires the previous one, which
// it returns with a channel closed once the pushes running on it have
// returned.
func (e *Engine) swapTransport(x *Transport) (*Transport, <-chan struct{}) {
	prev := e.xport.Swap(x)
	if prev == nil {
		return nil, insertsDone(nil)
	}
	return prev, prev.retire(x)
}

// allDone returns a channel closed once every channel in chs is closed.
func allDone(chs ...<-chan struct{}) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		for _, ch := range chs {
			<-ch
		}
		close(done)
	}()
	return done
}

// GetTransport returns the active Transport (ring buffers + stdout). Nil before Init.
func (e *Engine) GetTransport() *Transport { return e.xport.Load() }

// GetQueueStats returns a snapshot of the drainer state, or nil in raise mode.
func (e *Engine) GetQueueStats() *QueueStats {
	d := e.activeDrainer()
	if d == nil {
		return nil
	}
	raw := d.statsJSON()
	if raw == "null" || raw == "" {
		return nil
	}
	var s QueueStats
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return nil
	}
	return &s
}

// Flush blocks until pending audit rows drain, or timeout elapses.
func (e *Engine) Flush(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	e.drainerMu.Lock()
	retired := e.retired
	e.drainerMu.Unlock()
	if retired != nil {
		select {
		case <-retired:
		case <-time.After(timeout):
			return false
		}
	}
	d := e.activeDrainer()
	if d == nil {
		return true
	}
	return d.flush(time.Until(deadline))
}

// Close flushes pending audit rows for up to half of timeout, then stops the
// drainer and stores any row it still holds. A row not stored once timeout
// has passed is reported lost (audit_drain_lost_at_stop). Call it on
// shutdown: Flush alone leaves a row that is still being retried unreported
// at exit.
//
// Close then stops retention and closes the stores Init opened from
// FASTEN_AUDIT_DSN, FASTEN_API_DSN and FASTEN_SYSLOG_DSN. Stores passed in
// Config are not closed. Until the next Init, which opens the DSN stores
// again, a sys or api row goes to the in-memory ring, and to its store only
// when that store was passed in Config. An audit row goes to stdout, and is
// stored only when its store was passed in Config: then it is inserted
// inline as it is emitted. A row for a store opened from FASTEN_AUDIT_DSN
// goes to stdout only, unsealed.
//
// Returns false if a row was lost, a store did not close, or a store call
// or purge was still running at timeout. Such a call is left to finish in
// the background: a row it was storing is reported lost then, and the DSN
// stores are closed once it returns. A second Close while one is running
// waits for it, up to its own timeout, and returns the same result. A later
// Close also waits, up to its own timeout, for stores an earlier Close left
// open, and returns false if they still are.
func (e *Engine) Close(timeout time.Duration) bool {
	e.drainerMu.Lock()
	if c := e.closing; c != nil {
		e.drainerMu.Unlock()
		select {
		case <-c.done:
			return c.ok
		case <-time.After(timeout):
			return false
		}
	}
	c := &closeCall{done: make(chan struct{})}
	e.closing = c
	e.drainerMu.Unlock()

	c.ok = e.close(timeout)
	e.drainerMu.Lock()
	e.closing = nil
	e.drainerMu.Unlock()
	close(c.done)
	return c.ok
}

// closeCall is a Close in progress; ok is set before done is closed.
type closeCall struct {
	done chan struct{}
	ok   bool
}

func (e *Engine) close(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	e.drainerMu.Lock()
	earlier := e.pendingClose
	e.drainerMu.Unlock()
	d := e.activeDrainer()
	var lost int64
	if d != nil {
		lost = d.lost.Load()
	}
	e.closed.Store(true)
	e.Flush(timeout / 2)
	// From here an emit does not wait on a store opened from the
	// environment, however long a call already running on it takes.
	purged := e.cancelRetention()
	stores, inserts := e.releaseEnvStores()
	old, done := e.swapDrainer(nil)
	var retiring chan struct{}
	if old != nil {
		retired := make(chan struct{})
		go func() {
			e.retireOld(old, done, 0, deadline)
			close(retired)
		}()
		if !waitUntil(retired, deadline) {
			retiring = retired
			old.reportUnstored()
			// Flush on a drainer a later Init installs must not wait on this one.
			e.drainerMu.Lock()
			if e.retired == done {
				e.retired = nil
			}
			e.drainerMu.Unlock()
		}
	}
	if !waitUntil(purged, deadline) || retiring != nil || !waitUntil(inserts, deadline) {
		// The old drainer, a purger or an insert still uses the stores.
		out := e.out()
		pending := make(chan struct{})
		e.drainerMu.Lock()
		e.pendingClose = pending
		e.drainerMu.Unlock()
		go func() {
			<-purged
			if retiring != nil {
				<-retiring
			}
			<-inserts
			e.closeStores(out, stores)
			if earlier != nil {
				<-earlier
			}
			e.drainerMu.Lock()
			if e.pendingClose == pending {
				e.pendingClose = nil
			}
			e.drainerMu.Unlock()
			close(pending)
		}()
		return false
	}
	closed := e.closeStores(e.out(), stores)
	if earlier != nil && !waitUntil(earlier, deadline) {
		return false
	}
	return (d == nil || d.lost.Load() == lost) && closed
}

// waitUntil waits for done to be closed until deadline, and reports whether
// it was.
func waitUntil(done <-chan struct{}, deadline time.Time) bool {
	select {
	case <-done:
		return true
	default:
	}
	t := time.NewTimer(time.Until(deadline))
	defer t.Stop()
	select {
	case <-done:
		return true
	case <-t.C:
		return false
	}
}

// marshalWithShape encodes row plus a "shape" key without modifying row. The
// ring holds rows by reference, so writing to row would race readers.
func marshalWithShape(row map[string]any, shape string) ([]byte, error) {
	out := make(map[string]any, len(row)+1)
	for k, v := range row {
		out[k] = v
	}
	out["shape"] = shape
	return json.Marshal(out)
}

// LogSys writes a structured {shape:"sys"} line via this Engine.
func (e *Engine) LogSys(ctx context.Context, level, event string, kv []any) {
	row := SyslogRow{
		"level":      level,
		"event":      event,
		"timestamp":  canonicalTS(time.Now()),
		"request_id": RequestIDFromContext(ctx),
		"service_id": e.config().serviceID,
	}
	for i := 0; i+1 < len(kv); i += 2 {
		k, ok := kv[i].(string)
		if !ok {
			continue
		}
		row[k] = kv[i+1]
	}
	// Uniform PII scrub — key-pattern redactor over both structured kv and
	// stdout NDJSON, so caller-supplied secrets (fasten.LogError(ctx,
	// "auth_failed", "password", pw)) never hit stdout, the ring, or the
	// persistent store. PushSyslog would redact anyway; scrub the local
	// copy up front so the stdout NDJSON also sees the redacted form.
	row = SyslogRow(e.redactDetail(row))
	if x := e.xport.Load(); x != nil {
		x.PushSyslog(row)
	}
	if b, err := marshalWithShape(row, "sys"); err == nil {
		fmt.Println(string(b))
	}
}

// ResetForTests resets all runtime state to pre-Init defaults. Tests only.
func (e *Engine) ResetForTests() {
	e.uninstallDrainer()
	e.stopRetention()
	stores, inserts := e.releaseEnvStores()
	<-inserts
	e.closeStores(e.out(), stores)
	e.conf.Store(nil)
	e.storeMu.Lock()
	e.auditStore = nil
	e.auditInserts = nil
	e.apiStore = nil
	e.syslogStore = nil
	e.persistedStreams = nil
	e.storeMu.Unlock()
	e.swapTransport(nil)
	atomic.StoreInt64(&e.seq, 0)
	e.closed.Store(false)
	e.auditWriteSwallowed.Store(false)
	e.hashMu.Lock()
	e.prevHash = ""
	e.hashMu.Unlock()
	e.redactMu.Lock()
	e.redactExtraKeysJSON = ""
	e.redactReplacement = ""
	e.redactMu.Unlock()
}

// SearchEnabled reports whether free-text search is enabled.
func (e *Engine) SearchEnabled() bool { return e.config().searchEnabled }

// isTruthy parses a boolean-ish env value ("1", "true", "yes", "on").
func isTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// newDrainer builds a drainer for store, capturing the engine's current
// transport, service id and store generation. Nil if it could not start.
func (e *Engine) newDrainer(
	store AuditRepository,
	capacity int,
	retryInitialMs, retryMaxMs int64,
	retryJitter bool,
	maxAttempts int,
) *cFastenDrainer {
	d, err := newCFastenDrainer(
		e, store, capacity, retryInitialMs, retryMaxMs, retryJitter, maxAttempts,
	)
	if err != nil {
		e.drainerSysLog("error", "audit_drainer_install_failed",
			map[string]any{"error_type": fmt.Sprintf("%T", err)})
		return nil
	}
	return d
}

// swapDrainer installs next (nil removes the drainer) and returns the one it
// replaced, with a channel Flush waits on until retireOld closes it. With no
// drainer to replace, Flush keeps waiting on the one still being retired.
func (e *Engine) swapDrainer(next *cFastenDrainer) (*cFastenDrainer, chan struct{}) {
	e.drainerMu.Lock()
	defer e.drainerMu.Unlock()
	old := e.drainer
	e.drainer = next
	if old == nil {
		return nil, nil
	}
	done := make(chan struct{})
	e.retired = done
	return old, done
}

// testHookStoreSwitched, when set, runs in Init once emits use the new
// audit store, before the new drainer is installed.
var testHookStoreSwitched func()

// testHookRetire, when set, runs before a replaced drainer is retired.
var testHookRetire func()

// retireOld gives old up to flushFor to drain, then stops it and stores what
// it did not write, up to deadline if one is set.
func (e *Engine) retireOld(old *cFastenDrainer, done chan struct{}, flushFor time.Duration, deadline time.Time) {
	if old == nil {
		return
	}
	if testHookRetire != nil {
		testHookRetire()
	}
	old.retire(flushFor, deadline)
	close(done)
}

func (e *Engine) uninstallDrainer() {
	old, done := e.swapDrainer(nil)
	e.retireOld(old, done, 0, time.Time{})
}

func (e *Engine) activeDrainer() *cFastenDrainer {
	e.drainerMu.Lock()
	defer e.drainerMu.Unlock()
	return e.drainer
}

// allocateAndStore inserts the row through the store's
// AllocateAndInsertOriginated (spec §2.1) and writes the sealed row to
// stdout (spec §8).
//
// Falls back to the legacy unallocated Insert for adopter stores that predate
// the interface, and says so once, because VerifyChain SKIPS hashless rows and
// would otherwise report verified over a fully unchained table.
func (e *Engine) allocateAndStore(ctx context.Context, store AuditRepository, out sysOut, row Row) (Row, error) {
	type allocator interface {
		AllocateAndInsertOriginated(context.Context, Row) (Row, error)
	}
	a, ok := store.(allocator)
	if !ok {
		if e.unchainedStoreLogged.CompareAndSwap(false, true) {
			e.auditChainUnavailable.Store(true)
			e.sysLogTo(out, "error", "audit_chain_unavailable", map[string]any{
				"store":  fmt.Sprintf("%T", store),
				"reason": "store has no AllocateAndInsertOriginated (spec 2.1); rows written unsealed",
			})
		}
		return row, store.Insert(ctx, row)
	}
	sealed, err := a.AllocateAndInsertOriginated(ctx, row)
	if err != nil {
		return row, err
	}
	if out.xport != nil && sealed.Hash != "" {
		out.xport.WriteAudit(rowToMap(sealed))
	}
	return sealed, nil
}

// markWriteLost records that a row did not reach store, of store generation
// gen: durable history has a hole. The engine flag only covers its current
// store; re-init onto another store clears it, onto the same store keeps it.
func (e *Engine) markWriteLost(store AuditRepository, gen int64) {
	if gen == e.storeGen.Load() {
		e.auditWriteSwallowed.Store(true)
	}
	if nwf, ok := store.(interface{ NoteWriteFailure() }); ok {
		nwf.NoteWriteFailure()
	}
}

// sameStore reports whether a and b are the same store. Unlike a == b it
// does not panic on a store type that isn't comparable; such a store counts
// as a different one.
func sameStore(a, b AuditRepository) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	t := reflect.TypeOf(a)
	return t == reflect.TypeOf(b) && t.Comparable() && a == b
}

// isTypedNil reports whether v is nil or holds a nil pointer, map, slice,
// func, channel or interface.
func isTypedNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return rv.IsNil()
	}
	return false
}

// sysOut is where a sealed row's stdout line and sys events go: the engine's
// current transport, or the one a drainer captured at install.
type sysOut struct {
	xport     *Transport
	serviceID string
}

func (e *Engine) out() sysOut { return sysOut{e.xport.Load(), e.config().serviceID} }

// drainerSysLog writes an internal event to the sys stream and to stderr.
func (e *Engine) drainerSysLog(level, event string, fields map[string]any) {
	e.sysLogTo(e.out(), level, event, fields)
}

func (e *Engine) sysLogTo(out sysOut, level, event string, fields map[string]any) {
	row := SyslogRow{
		"level":      level,
		"event":      event,
		"timestamp":  canonicalTS(time.Now()),
		"request_id": "",
		"service_id": out.serviceID,
	}
	for k, v := range fields {
		row[k] = v
	}
	// Fields commonly include an "error" carrying a driver error string
	// that can quote the offending row value (Postgres NotNullViolation
	// cites the column). Redact the local copy before both the transport
	// push AND the direct stderr write — PushSyslog would redact its
	// own copy, but the stderr line uses this local `row`.
	row = SyslogRow(e.redactDetail(row))
	if out.xport != nil {
		out.xport.PushSyslog(row)
	}
	if b, err := marshalWithShape(row, "sys"); err == nil {
		fmt.Fprintln(os.Stderr, string(b))
	}
}
