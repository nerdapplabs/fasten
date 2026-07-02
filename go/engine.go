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
	seq             int64 // accessed via atomic ops
	failureStrategy string

	// Streams classified as backed by the durable store rather than a bounded
	// ring. Drives the per-stream completeness flag on every reader read.
	// Seeded in Init from defaultPersistedStreams ({"audit"}) — audit is the
	// only store-backed stream today; Phase 1 wires this from config so api/sys
	// can persist too.
	persistedStreams map[string]bool

	// P1-23: tamper-evidence hash chain. hashMu serialises seq + prevHash
	// assignment so concurrent Emit calls produce a consistent, gapless chain.
	hashMu   sync.Mutex
	prevHash string // "genesis" until first Emit

	drainerMu sync.Mutex
	drainer   *cFastenDrainer
}

// Default is the package-level Engine used by all free-function API calls.
var Default = &Engine{}

// Init configures this Engine. See the package-level Config docs for details.
func (e *Engine) Init(cfg Config) error {
	e.serviceID = firstNonEmpty(cfg.ServiceID, envOr("FASTEN_SERVICE_ID", ""))
	e.nodeID    = firstNonEmpty(cfg.NodeID,    envOr("FASTEN_NODE_ID", ""))
	e.tenantID  = firstNonEmpty(cfg.TenantID,  envOr("FASTEN_TENANT_ID", ""))

	if e.serviceID == "" || e.nodeID == "" {
		return errors.New("fasten.Init: ServiceID and NodeID are required")
	}
	e.auditStore = cfg.AuditStore

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
	// Per-engine copy of the durability default so callers may mutate this
	// engine's map (Phase 1 config) without touching the package-level default.
	e.persistedStreams = make(map[string]bool, len(defaultPersistedStreams))
	for stream, persisted := range defaultPersistedStreams {
		e.persistedStreams[stream] = persisted
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
		kept = RedactDetail(kept)
		kept["_redacted"] = "***"
		kept["_pii_in_detail"] = true
		row.Detail = kept
	} else {
		row.Detail = RedactDetail(row.Detail)
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
	row["shape"] = "sys"
	if b, err := json.Marshal(row); err == nil {
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
	e.persistedStreams = nil
	atomic.StoreInt64(&e.seq, 0)
	e.failureStrategy = ""
	e.hashMu.Lock()
	e.prevHash = ""
	e.hashMu.Unlock()
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
	row["shape"] = "sys"
	if b, err := json.Marshal(row); err == nil {
		fmt.Fprintln(os.Stderr, string(b))
	}
}
