package fasten

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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
	seq             int64        // accessed via atomic ops
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
	hashMu   sync.Mutex
	prevHash string // "genesis" until first Emit

	drainerMu sync.Mutex
	drainer   *cFastenDrainer

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
	// new one; ResetForTests + shutdown stop unconditionally.
	retentionCancel context.CancelFunc
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
	e.serviceID = firstNonEmpty(cfg.ServiceID, envOr("FASTEN_SERVICE_ID", ""))
	e.nodeID = firstNonEmpty(cfg.NodeID, envOr("FASTEN_NODE_ID", ""))
	e.tenantID = firstNonEmpty(cfg.TenantID, envOr("FASTEN_TENANT_ID", ""))

	if e.serviceID == "" || e.nodeID == "" {
		return errors.New("fasten.Init: ServiceID and NodeID are required")
	}
	e.auditStore = cfg.AuditStore
	// Re-init on a fresh store clears the sticky degrade — a hole in the
	// previous store's history doesn't apply to this one.
	e.auditWriteSwallowed.Store(false)

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
		e.installDrainer(
			e.auditStore,
			capacity, retryInitialMs, retryMaxMs, !cfg.DisableQueueJitter, maxAttempts,
		)
	} else {
		e.uninstallDrainer()
	}

	// FR1 retention (§1). Env-var overrides zero-valued fields.
	if err := e.startRetention(cfg.RetentionAPI, cfg.RetentionSyslog); err != nil {
		return err
	}
	return nil
}

// startRetention stops any previous purgers and spawns fresh ones for every
// stream that has both a store attached AND a positive retention (either
// from Config or the env-var override). Empty / invalid env values are a
// hard Init error rather than a silent fall-through — an operator who set
// FASTEN_RETENTION_SYSLOG=foo needs to hear about it, not have their
// history grow forever behind a green completeness flag.
func (e *Engine) startRetention(apiRet, sysRet time.Duration) error {
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

	// Stop any previous generation before starting a new one — a re-Init on
	// the same Engine leaves an orphan goroutine hammering the old store
	// otherwise.
	if e.retentionCancel != nil {
		e.retentionCancel()
		e.retentionCancel = nil
	}

	// Nothing configured on either stream → no goroutine.
	if (apiRet == 0 || e.apiStore == nil) && (sysRet == 0 || e.syslogStore == nil) {
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	e.retentionCancel = cancel
	onErr := func(stream string, err error) {
		e.drainerSysLog("error", "retention_purge_failed", map[string]any{
			"stream": stream, "error": err.Error(),
		})
	}
	if apiRet > 0 && e.apiStore != nil {
		startPurger(ctx, retentionParams{
			stream: "api", store: e.apiStore, retention: apiRet,
			checkInterval: time.Hour, onError: onErr,
		})
	}
	if sysRet > 0 && e.syslogStore != nil {
		startPurger(ctx, retentionParams{
			stream: "sys", store: e.syslogStore, retention: sysRet,
			checkInterval: time.Hour, onError: onErr,
		})
	}
	return nil
}

// Emit produces an audit row for a registered code.
func (e *Engine) Emit(ctx context.Context, code Code, opts ...EmitOption) (Row, error) {
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
	e.hashMu.Lock()
	atomic.AddInt64(&e.seq, 1)
	row.MonotonicSeq = atomic.LoadInt64(&e.seq)
	row = Seal(e.prevHash, row)
	e.prevHash = row.Hash
	e.hashMu.Unlock()

	if e.xport != nil {
		e.xport.WriteAudit(rowToMap(row))
	}

	if e.auditStore != nil {
		if e.failureStrategy == "queue" {
			d := e.activeDrainer()
			if d != nil {
				d.enqueue(row)
			} else {
				if ferr := e.auditStore.Insert(ctx, row); ferr != nil {
					// Swallowed on the hot path → durable history has a hole;
					// degrade the audit completeness flag. Set the engine flag
					// unconditionally (adopter stores may not implement
					// NoteWriteFailure); also call the store's notifier when
					// present so store-side reporting is accurate too.
					e.auditWriteSwallowed.Store(true)
					if nwf, ok := e.auditStore.(interface{ NoteWriteFailure() }); ok {
						nwf.NoteWriteFailure()
					}
					e.drainerSysLog("error", "audit_sync_fallback_failed", map[string]any{
						"error":  ferr.Error(),
						"row_id": row.ID,
					})
				}
			}
		} else {
			if err := e.auditStore.Insert(ctx, row); err != nil {
				return row, &AuditStoreError{Err: err}
			}
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
	d := e.activeDrainer()
	if d == nil {
		return true
	}
	return d.flush(timeout)
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
		"timestamp":  time.Now().UTC().Format(time.RFC3339Nano),
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
	if e.retentionCancel != nil {
		e.retentionCancel()
		e.retentionCancel = nil
	}
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

func (e *Engine) installDrainer(
	store AuditRepository,
	capacity int,
	retryInitialMs, retryMaxMs int64,
	retryJitter bool,
	maxAttempts int,
) {
	d, err := newCFastenDrainer(
		store, capacity, retryInitialMs, retryMaxMs, retryJitter, uint32(maxAttempts),
	)
	if err != nil {
		e.drainerSysLog("error", "audit_drainer_install_failed", map[string]any{"error": err.Error()})
		return
	}
	e.drainerMu.Lock()
	old := e.drainer
	e.drainer = d
	e.drainerMu.Unlock()
	if old != nil {
		old.flush(5 * time.Second)
		old.close()
	}
}

func (e *Engine) uninstallDrainer() {
	e.drainerMu.Lock()
	old := e.drainer
	e.drainer = nil
	e.drainerMu.Unlock()
	if old != nil {
		old.close()
	}
}

func (e *Engine) activeDrainer() *cFastenDrainer {
	e.drainerMu.Lock()
	defer e.drainerMu.Unlock()
	return e.drainer
}

// drainerSysLog bridges drainer events to the sys stream via stderr.
func (e *Engine) drainerSysLog(level, event string, fields map[string]any) {
	row := SyslogRow{
		"level":      level,
		"event":      event,
		"timestamp":  time.Now().UTC().Format(time.RFC3339Nano),
		"request_id": "",
		"service_id": e.serviceID,
	}
	for k, v := range fields {
		row[k] = v
	}
	if e.xport != nil {
		e.xport.PushSyslog(row)
	}
	if b, err := marshalWithShape(row, "sys"); err == nil {
		fmt.Fprintln(os.Stderr, string(b))
	}
}
