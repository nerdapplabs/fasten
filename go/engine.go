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
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Engine holds all runtime state for one fasten deployment context.
//
// The package-level free functions (Init, Emit, …) delegate to Default.
// Applications that need multiple isolated fasten configurations in one
// process — multi-tenant services, test isolation — construct Engine
// instances directly:
//
//	a := &fasten.Engine{}
//	a.Init(fasten.Config{ServiceID: "tenant-a", AuditStore: storeA})
//	a.Emit(ctx, "ORDER_PLACED", fasten.Target("order/123"))
type Engine struct {
	serviceID       string
	nodeID          string
	tenantID        string
	auditStore      AuditRepository
	xport           *Transport
	apiStore        StreamRepository // FR1: opt-in api persistence, nil = ring-only
	syslogStore     StreamRepository // FR1: opt-in sys persistence, nil = ring-only
	seq             int64            // accessed via atomic ops
	failureStrategy string
	searchEnabled   bool // FR3: opt-in free-text search (/logs/search, q=)

	// Streams classified as backed by the durable store rather than a bounded
	// ring. Drives the per-stream completeness flag on every reader read. A
	// stream is present only when it actually has a store: audit when an audit
	// store is configured, api/sys when a stream store is. A nil map (never
	// Init'd) reads as all-ring.
	persistedStreams map[string]bool

	// P1-23: tamper-evidence hash chain. hashMu serialises seq + prevHash
	// assignment so concurrent Emit calls produce a consistent, gapless chain.
	unchainedStoreLogged  atomic.Bool
	auditChainUnavailable atomic.Bool
	hashMu                sync.Mutex
	prevHash              string // "genesis" until first Emit

	drainerMu sync.Mutex
	drainer   *cFastenDrainer
	retired   chan struct{} // closed once the last drainer taken out has been retired
	storeGen  atomic.Int64  // bumped when Init switches to another audit store

	// Engine-side "at least one audit-store insert was swallowed" flag.
	// Tracked here (not only on the store) because AuditRepository does not
	// require NoteWriteFailure: an adopter-supplied store fails the type
	// assertion in the sync-fallback path and the swallow would otherwise be
	// invisible, leaving completeness reporting "store" over durable history
	// that has holes. Sticky — a hole doesn't heal.
	auditWriteSwallowed atomic.Bool

	// Redaction customization (parity with Python FASTEN_REDACT_KEYS /
	// FASTEN_REDACT_REPLACEMENT). Engine-scoped so multi-tenant callers
	// running more than one Engine keep isolated redact config — see the
	// package doc comment above. redactMu guards concurrent Init writes vs.
	// Emit-goroutine reads (redactDetail runs on the caller's thread).
	// Empty JSON / empty replacement = core defaults.
	redactMu            sync.RWMutex
	redactExtraKeysJSON string
	redactReplacement   string

	// FR1 retention (spec §1) — cancel func for every purger goroutine
	// spawned on this Engine. Init stops the previous set before wiring the
	// new one; ResetForTests + shutdown stop unconditionally. retentionWg
	// counts live purgers so stopRetention can Wait: cancel alone doesn't
	// bound goroutine exit, and an in-flight purger racing the next Init's
	// e.xport swap surfaces as a -race data race (drainerSysLog reads xport).
	retentionCancel context.CancelFunc
	retentionWg     sync.WaitGroup

	// P1-44 tenant isolation on reader endpoints. Wired via
	// NewReader(WithTenantScope(...)). Nil = single-tenant mode
	// (no scope enforced, ?tenant_id= honoured as-is).
	tenantScope            func(*http.Request) (string, bool)
	enforceTenantIsolation bool
}

// Default is the package-level Engine used by all free-function API calls.
var Default = &Engine{}

// Init configures this Engine. See the package-level Config docs for details.
// streamStoreFromEnvDSN builds a SQLite stream store from an env-var DSN, or
// returns (nil, nil) if the env var is unset. Postgres DSNs are rejected: Go
// bundles no Postgres driver, so a Postgres stream store must be wired
// explicitly via Config with a caller-opened *sql.DB.
func streamStoreFromEnvDSN(envVar, table string) (*StreamStore, error) {
	dsn := envOr(envVar, "")
	if dsn == "" {
		return nil, nil
	}
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		return nil, fmt.Errorf("fasten.Init: %s is a Postgres DSN; Go does not "+
			"autoload Postgres stream stores (no bundled driver) — pass an "+
			"explicit APIStore/SyslogStore", envVar)
	}
	s, err := OpenStreamStore(dsn, table)
	if err != nil {
		return nil, fmt.Errorf("fasten.Init: %s: %w", envVar, err)
	}
	return s, nil
}

// configureRedaction resolves the extra redact keys + replacement token from
// explicit config, else env (FASTEN_REDACT_KEYS comma-separated /
// FASTEN_REDACT_REPLACEMENT), and stores them on this Engine's redact fields.
// Always sets both (resetting to defaults when unconfigured) so a repeat Init
// on the same Engine doesn't leak the prior configuration. Engine-scoped so
// multiple Engines in one process keep isolated redact config — the earlier
// package-global lived here as a race hazard: concurrent Init on one Engine
// silently reset a sibling Engine's redact keys mid-Emit.
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

	e.redactMu.Lock()
	e.redactExtraKeysJSON = extraJSON
	e.redactReplacement = replacement
	e.redactMu.Unlock()
}

func (e *Engine) Init(cfg Config) error {
	if n := cfg.QueueDrainMaxAttempts; n > 0 && uint64(n) > math.MaxUint32 {
		return fmt.Errorf("fasten.Init: QueueDrainMaxAttempts must be at most %d (got %d)",
			uint32(math.MaxUint32), n)
	}
	prevStore := e.auditStore

	e.serviceID = firstNonEmpty(cfg.ServiceID, envOr("FASTEN_SERVICE_ID", ""))
	e.nodeID = firstNonEmpty(cfg.NodeID, envOr("FASTEN_NODE_ID", ""))
	e.tenantID = firstNonEmpty(cfg.TenantID, envOr("FASTEN_TENANT_ID", ""))

	if e.serviceID == "" || e.nodeID == "" {
		return errors.New("fasten.Init: ServiceID and NodeID are required")
	}
	// Normalise a TYPED NIL to a real nil, once, here.
	//
	// A caller passing a nil *SQLiteStore gives us an interface that is
	// non-nil (it carries a type) wrapping a nil pointer. Every `!= nil` check
	// downstream then passes, type assertions succeed, and the first method
	// call dereferences 0x0 — which is exactly how re-landing this wiring
	// panicked in MaxMonotonicSeq. Fixing it at the source beats guarding
	// every call site, because the next call site added would miss the guard.
	e.auditStore = cfg.AuditStore
	if isTypedNil(e.auditStore) {
		e.auditStore = nil
		cfg.AuditStore = nil
	}
	// Re-init on a fresh store clears the sticky degrade — a hole in the
	// previous store's history doesn't apply to this one.
	if !sameStore(prevStore, e.auditStore) {
		e.storeGen.Add(1)
		e.auditWriteSwallowed.Store(false)
	}

	// Seed monotonic_seq from the store if it supports it, so post-restart
	// rows never collide with pre-restart rows on (timestamp, seq). Scoped to
	// THIS engine's own (service_id, source_node_id) sub-chain — never the
	// global MAX — because monotonic_seq is a per-node counter and seeding
	// from a foreign origin's rows (ingested via IngestReplicated) would break
	// this node's own tamper chain.
	if seeder, ok := cfg.AuditStore.(SeqSeeder); ok {
		if max, err := seeder.MaxMonotonicSeq(context.Background(), e.serviceID, e.nodeID); err == nil {
			atomic.StoreInt64(&e.seq, max)
		}
	}

	// P1-23: initialise hash chain. "genesis" is the sentinel for the first
	// row in a chain. Cross-restart continuity requires seeding from the store;
	// absent a HashSeeder interface, we restart cleanly from "genesis".
	e.hashMu.Lock()
	e.prevHash = "genesis"
	e.hashMu.Unlock()
	e.xport = NewTransport(2000)
	// Uniform PII scrub for every sys/api push. See Transport.redactRow.
	e.xport.redact = e.redactDetail
	// Sentinel invariant: one stable boot-window id per process, in effect for
	// context-less stream rows until the first real request arrives.
	e.xport.serviceID = e.serviceID
	e.xport.bootRequestID = MintSentinel("boot", e.serviceID)
	// FR1: attach opt-in stream stores as write-through sinks + read source,
	// and flip their completeness class to store-backed. A stream is
	// store-backed only when it actually has a store — audit included: in
	// stdout-only mode (no audit store) audit stays ring, so a read never
	// claims a durable store that does not exist.
	// Env-var DSN autoload (parity with the Python SDK): if a stream store was
	// not passed explicitly, build a SQLite-backed one from FASTEN_API_DSN /
	// FASTEN_SYSLOG_DSN. SQLite only — Go bundles no Postgres driver, so a
	// Postgres DSN must be wired as an explicit *sql.DB-backed store.
	apiStore := cfg.APIStore
	if apiStore == nil {
		s, err := streamStoreFromEnvDSN("FASTEN_API_DSN", "api_log")
		if err != nil {
			return err
		}
		if s != nil {
			apiStore = s
		}
	}
	syslogStore := cfg.SyslogStore
	if syslogStore == nil {
		s, err := streamStoreFromEnvDSN("FASTEN_SYSLOG_DSN", "syslog")
		if err != nil {
			return err
		}
		if s != nil {
			syslogStore = s
		}
	}
	e.apiStore = apiStore
	e.syslogStore = syslogStore
	e.xport.APIStore = apiStore
	e.xport.SyslogStore = syslogStore

	// #58 PersistStreams assertion — every named stream needs a store,
	// every attached store needs to be named. Env fallback: comma-separated
	// list in FASTEN_PERSIST_STREAMS. Nil = fall back to derivation (the
	// existing behaviour and still the default).
	if err := e.assertPersistStreams(cfg.PersistStreams, apiStore, syslogStore); err != nil {
		return err
	}

	e.persistedStreams = map[string]bool{}
	if cfg.AuditStore != nil {
		e.persistedStreams["audit"] = true
	}
	if apiStore != nil {
		e.persistedStreams["api"] = true
	}
	if syslogStore != nil {
		e.persistedStreams["sys"] = true
	}
	// FR3: search is off unless explicitly enabled, via config or env.
	e.searchEnabled = cfg.SearchEnabled || isTruthy(envOr("FASTEN_SEARCH_ENABLED", ""))

	// Redaction customization (parity with Python FASTEN_REDACT_KEYS/REPLACEMENT).
	e.configureRedaction(cfg.ExtraRedactKeys, cfg.RedactReplacement)

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
	e.failureStrategy = strategy

	var next *cFastenDrainer
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
		next = e.newDrainer(
			e.auditStore,
			capacity, retryInitialMs, retryMaxMs, !cfg.DisableQueueJitter, maxAttempts,
		)
	}
	// Swap in the new drainer, then retire the old one: emits keep being
	// queued while it drains, and its rows and events keep its own config.
	old, done := e.swapDrainer(next)
	e.retireOld(old, done, 5*time.Second)

	// FR1 retention (§1). Env-var overrides zero-valued fields.
	if err := e.startRetention(cfg.RetentionAPI, cfg.RetentionSyslog, cfg.RetentionPII); err != nil {
		return err
	}
	return nil
}

// assertPersistStreams: when PersistStreams is set (or FASTEN_PERSIST_STREAMS
// is), the named streams must exactly match the attached stream stores —
// bidirectional. A named stream without a store would make completeness lie
// "store" over rows the stream never persisted; an attached store not in the
// allowlist is surprise IO on a stream the operator thought was ring-only.
// Nil / empty env = skip (fall back to derivation, the pre-existing default).
func (e *Engine) assertPersistStreams(fromConfig []string, apiStore, syslogStore StreamRepository) error {
	named := fromConfig
	if named == nil {
		if s := envOr("FASTEN_PERSIST_STREAMS", ""); s != "" {
			for _, part := range strings.Split(s, ",") {
				if p := strings.TrimSpace(part); p != "" {
					named = append(named, p)
				}
			}
		} else {
			return nil // no config, no env → derivation
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
	if apiStore != nil {
		have["api"] = true
	}
	if syslogStore != nil {
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
	return fmt.Errorf("fasten.Init: PersistStreams / stores mismatch — %s",
		strings.Join(parts, "; "))
}

// startRetention stops any previous purgers and spawns fresh ones for every
// stream that has both a store attached AND a positive retention (either
// from Config or the env-var override). Empty / invalid env values are a
// hard Init error rather than a silent fall-through — an operator who set
// FASTEN_RETENTION_SYSLOG=foo needs to hear about it, not have their
// history grow forever behind a green completeness flag.
func (e *Engine) startRetention(apiRet, sysRet, piiRet time.Duration) error {
	// Env override: only when Config was zero. Empty env = disabled.
	if apiRet == 0 {
		if s := envOr("FASTEN_RETENTION_API", ""); s != "" {
			d, err := parseRetentionDuration(s)
			if err != nil {
				return fmt.Errorf("fasten.Init: FASTEN_RETENTION_API: %w", err)
			}
			apiRet = d
		}
	}
	if sysRet == 0 {
		if s := envOr("FASTEN_RETENTION_SYSLOG", ""); s != "" {
			d, err := parseRetentionDuration(s)
			if err != nil {
				return fmt.Errorf("fasten.Init: FASTEN_RETENTION_SYSLOG: %w", err)
			}
			sysRet = d
		}
	}
	if piiRet == 0 {
		if s := envOr("FASTEN_RETENTION_PII", ""); s != "" {
			d, err := parseRetentionDuration(s)
			if err != nil {
				return fmt.Errorf("fasten.Init: FASTEN_RETENTION_PII: %w", err)
			}
			piiRet = d
		}
	}

	// Stop any previous generation before starting a new one AND wait for
	// its goroutines to actually exit — a re-Init on the same Engine leaves
	// an orphan goroutine hammering the old store otherwise, and its
	// drainerSysLog error path races the new Init's e.xport swap.
	e.stopRetention()

	// Nothing configured on any stream → no goroutine.
	if (apiRet == 0 || e.apiStore == nil) &&
		(sysRet == 0 || e.syslogStore == nil) &&
		(piiRet == 0 || e.auditStore == nil) {
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	e.retentionCancel = cancel
	onErr := func(stream string, err error) {
		e.drainerSysLog("error", "retention_purge_failed", map[string]any{
			// Type-only, not err.Error() — driver error strings can carry
			// the offending row value; sys is redacted key-pattern only.
			"stream": stream, "error_type": fmt.Sprintf("%T", err),
		})
	}
	if apiRet > 0 && e.apiStore != nil {
		startPurger(ctx, &e.retentionWg, retentionParams{
			stream: "api", store: e.apiStore, retention: apiRet,
			checkInterval: time.Hour, onError: onErr,
		})
	}
	if sysRet > 0 && e.syslogStore != nil {
		startPurger(ctx, &e.retentionWg, retentionParams{
			stream: "sys", store: e.syslogStore, retention: sysRet,
			checkInterval: time.Hour, onError: onErr,
		})
	}
	// P1-55 audit PII horizon. No store/retention: redaction only.
	if piiRet > 0 && e.auditStore != nil {
		if _, ok := e.auditStore.(RedactionRepository); !ok {
			return fmt.Errorf(
				"fasten.Init: RetentionPII is set but audit store %T does not "+
					"implement RedactionRepository (spec §7.1) — personal data "+
					"would never be redacted", e.auditStore)
		}
		startPurger(ctx, &e.retentionWg, retentionParams{
			stream: "audit", piiRetention: piiRet,
			redactFn: func(ctx context.Context, before time.Time) error {
				_, err := e.RedactExpired(ctx, before, "retention")
				return err
			},
			checkInterval: time.Hour, onError: onErr,
		})
	}
	return nil
}

// stopRetention cancels any live purger goroutines and Waits for them to
// exit. Safe to call when none are running. Must be paired: cancel alone
// leaks a goroutine that races the next Init.
func (e *Engine) stopRetention() {
	if e.retentionCancel != nil {
		e.retentionCancel()
		e.retentionCancel = nil
	}
	e.retentionWg.Wait()
}

// Emit produces an audit row for a registered code.
func (e *Engine) Emit(ctx context.Context, code Code, opts ...EmitOption) (Row, error) {
	return e.emitRow(ctx, code, false, opts...)
}

// emitRow is Emit with an explicit durability requirement.
//
// durable=true means the caller is about to do something irreversible on the
// strength of this row existing, so a persist failure must reach it: queue
// mode's swallow and the drainer's fire-and-forget enqueue are both bypassed.
// Only the spec §7.2 redaction record uses it.
func (e *Engine) emitRow(ctx context.Context, code Code, durable bool, opts ...EmitOption) (Row, error) {
	if e.serviceID == "" {
		return Row{}, errors.New("fasten.Init() must be called before Emit()")
	}
	m, ok := metaOf(code)
	if !ok {
		return Row{}, fmt.Errorf("fasten: unknown audit code %q — call Register() first", code)
	}

	rid := RequestIDFromContext(ctx)
	if rid == "" {
		rid = MintID()
	}

	id := "evt-" + mintLong()

	var tid *string
	if e.tenantID != "" {
		tid = &e.tenantID
	}
	row := Row{
		WireVersion:  "1",
		ID:           id,
		OriginID:     id,
		MonotonicSeq: 0, // assigned under hashMu below
		Timestamp:    time.Now().UTC(),
		Code:         code,
		Action:       m.Action,
		Severity:     m.Severity,
		ServiceID:    e.serviceID,
		SourceNodeID: e.nodeID,
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

	// Redact BEFORE sealing so the hash covers exactly the detail that is
	// stored — matches Python emit(), which redacts detail before building the
	// row it hashes. Sealing over the pre-redaction detail (the previous Go
	// order) meant the stored row's redacted detail no longer reproduced its
	// own hash, so Go-sealed rows failed Go VerifyChain.
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
		kept = e.redactDetail(kept)
		kept["_redacted"] = "***"
		kept["_pii_in_detail"] = true
		row.Detail = kept
	} else {
		row.Detail = e.redactDetail(row.Detail)
	}

	// P1-23: assign seq + seal the hash chain atomically so concurrent Emit
	// calls produce a gapless, correctly-ordered chain. seq is incremented here
	// (not via atomic.AddInt64 earlier) to keep seq and prevHash in lock-step.
	//
	// Seal is the ONE canonical seal path (see verify.go): it stamps
	// CanonicalFormID="1", sets PrevHash, and hashes with the SAME canonical form
	// VerifyChain uses, so Go Emit ↔ Go VerifyChain ↔ Python seal/to_dict all
	// agree on a single field set (canonical_form_id + pii_in_detail-excluded,
	// shipped_at:null, prev_hash always present, Python-isoformat timestamps,
	// sorted keys, non-ASCII \uXXXX-escaped).
	// monotonic_seq / prev_hash / hash are NOT assigned here (spec §2.1). The
	// store allocates them inside the insert transaction, so N engines on one
	// node produce ONE chain instead of N rows all claiming seq 1 — which
	// VerifyChain reports as a prev_hash break, a false tamper signal with no
	// attacker involved.
	//
	// With no audit store there is nothing to allocate against, so the row goes
	// out unsealed (hash "") per spec §8.1. VerifyChain skips hashless rows, so
	// such a stream verifies vacuously rather than failing. Fabricating an
	// in-memory sequence here would be the exact non-conformance §2.1 forbids:
	// it cannot survive a restart or a second process, so it is a chain in
	// appearance only.

	if e.xport != nil {
		e.xport.WriteAudit(rowToMap(row))
	}

	if e.auditStore != nil {
		if e.failureStrategy == "queue" {
			// The drainer retries the insert; the store seals the row when it
			// lands (spec §2.1, §8). A durable emit must not return before the
			// row is persisted, so it takes the synchronous path, and so does
			// a row the drainer refuses.
			gen := e.storeGen.Load()
			d := e.activeDrainer()
			refused := false
			switch {
			case durable:
			case d != nil && d.gen != gen:
				// Init is switching stores: store it inline in the new one.
			case d == nil:
				// No drainer to take the row (spec §7 V-12).
				refused = true
				e.drainerSysLog("error", "audit_drain_abandoned", map[string]any{
					"reason": "no_drainer", "row_id": row.ID,
				})
			default:
				queued, reported := d.enqueue(row)
				refused = !queued
				if refused && !reported {
					// fasten-core reports only the rows it refused at stop.
					e.drainerSysLog("error", "audit_drain_abandoned", map[string]any{
						"reason": "enqueue_refused", "row_id": row.ID,
					})
				}
			}
			if durable || d == nil || refused {
				sealed, ferr := e.allocateAndStore(ctx, e.auditStore, e.out(), row)
				if ferr == nil {
					row = sealed
				}
				if ferr != nil && durable {
					return row, &AuditStoreError{Err: ferr}
				}
				if ferr != nil {
					// Swallowed on the hot path → durable history has a hole;
					// degrade the audit completeness flag.
					e.markWriteLost(e.auditStore, gen)
					e.drainerSysLog("error", "audit_sync_fallback_failed", map[string]any{
						// Type-only — see retention_purge_failed comment.
						"error_type": fmt.Sprintf("%T", ferr),
						"row_id":     row.ID,
					})
				} else if refused {
					// Follows the abandoned event.
					e.drainerSysLog("info", "audit_drain_stored_inline", map[string]any{"row_id": row.ID})
				}
			}
		} else {
			// "raise" strategy — same allocating path as the queue branch
			// (spec §2.1); only the error handling differs.
			sealed, err := e.allocateAndStore(ctx, e.auditStore, e.out(), row)
			if err != nil {
				return row, &AuditStoreError{Err: err}
			}
			row = sealed
		}
	}
	return row, nil
}

// GetTransport returns the active Transport (ring buffers + stdout). Nil before Init.
func (e *Engine) GetTransport() *Transport { return e.xport }

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

// marshalWithShape renders row as a JSON line tagged with its stream shape
// WITHOUT mutating row. Once a row has been handed to PushSyslog/PushAPI the
// ring holds it by reference and a store may have persisted it, so writing
// row["shape"] afterwards would (1) race a concurrent reader iterating the ring
// snapshot — a fatal "concurrent map read and map write" — and (2) leave the
// persisted copy missing the shape the ring copy carries. Tagging a shallow
// copy keeps the shared row untouched (mirroring the Python transport, which
// builds {"shape": ..., **row} for stdout).
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
		"service_id": e.serviceID,
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
	if e.xport != nil {
		e.xport.PushSyslog(row)
	}
	if b, err := marshalWithShape(row, "sys"); err == nil {
		fmt.Println(string(b))
	}
}

// ResetForTests resets all runtime state to pre-Init defaults.
// Only for test fixtures — do not call in production code.
func (e *Engine) ResetForTests() {
	e.uninstallDrainer()
	e.serviceID = ""
	e.nodeID = ""
	e.tenantID = ""
	e.auditStore = nil
	e.xport = nil
	e.apiStore = nil
	e.syslogStore = nil
	e.persistedStreams = nil
	e.searchEnabled = false
	atomic.StoreInt64(&e.seq, 0)
	e.failureStrategy = ""
	e.auditWriteSwallowed.Store(false)
	e.hashMu.Lock()
	e.prevHash = ""
	e.hashMu.Unlock()
	e.redactMu.Lock()
	e.redactExtraKeysJSON = ""
	e.redactReplacement = ""
	e.redactMu.Unlock()
	e.stopRetention()
}

// SearchEnabled reports whether FR3 free-text search is enabled on this engine.
func (e *Engine) SearchEnabled() bool { return e.searchEnabled }

// isTruthy parses a boolean-ish env value ("1", "true", "yes", "on").
func isTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// ── Drainer management (per-Engine) ──────────────────────────────────────────

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
// replaced, with a channel Flush waits on until retireOld closes it.
func (e *Engine) swapDrainer(next *cFastenDrainer) (*cFastenDrainer, chan struct{}) {
	e.drainerMu.Lock()
	defer e.drainerMu.Unlock()
	old := e.drainer
	e.drainer = next
	done := make(chan struct{})
	e.retired = done
	return old, done
}

// testHookRetire, when set, runs before a replaced drainer is retired.
var testHookRetire func()

// retireOld gives old up to flushFor to drain, then stops it and stores what
// it did not write.
func (e *Engine) retireOld(old *cFastenDrainer, done chan struct{}, flushFor time.Duration) {
	if old != nil {
		if testHookRetire != nil {
			testHookRetire()
		}
		old.retire(flushFor)
	}
	close(done)
}

func (e *Engine) uninstallDrainer() {
	old, done := e.swapDrainer(nil)
	e.retireOld(old, done, 0)
}

func (e *Engine) activeDrainer() *cFastenDrainer {
	e.drainerMu.Lock()
	defer e.drainerMu.Unlock()
	return e.drainer
}

// drainerSysLog bridges drainer events to the sys stream via stderr.
// allocateAndStore performs the store-allocated seal (spec §2.1) and the
// phase-2 stdout write (spec §8).
//
// Falls back to the legacy unallocated Insert for adopter stores that predate
// the interface — and says so once, because VerifyChain SKIPS hashless rows and
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

// isTypedNil reports whether v is an interface holding a nil pointer, map,
// slice, func or channel. Such a value is NOT equal to nil as an interface,
// so a plain `v != nil` check lets it through and the first method call
// panics.
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

func (e *Engine) out() sysOut { return sysOut{e.xport, e.serviceID} }

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
