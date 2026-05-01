// Package fasten — audit + correlation SDK for Go services.
//
// Zero external dependencies. Three streams: syslog, api-log, audit.
// One request_id carried across every emission via context.
//
// Usage:
//
//	fasten.Register("my-domain", map[fasten.Code]fasten.Meta{
//	    "MY_CODE": {Action: "created", Severity: fasten.SevInfo, ...},
//	})
//	fasten.Init(fasten.Config{ServiceID: "my-svc", NodeID: "node-1", AuditStore: store})
//	fasten.Emit(ctx, "MY_CODE", fasten.Target("resource/123"))
//
// See ../README.md for the full design.
package fasten

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
)

// codeKeyRe validates audit-code identifiers — UPPER_SNAKE_CASE.
var codeKeyRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

// ── FASTEN GENERATED ─ source: spec/row-schema.json ─ run: python spec/codegen.py ──
type Severity string

const (
	SevDebug    Severity = "debug"  // Low-level diagnostic, filtered in production
	SevInfo     Severity = "info"  // Normal operational event (default)
	SevWarn     Severity = "warn"  // Potentially problematic, not yet an error
	SevError    Severity = "error"  // Operation failed, requires attention
	SevCritical Severity = "critical"  // Severe failure, may impact availability
)

type RetentionClass string

const (
	RetShort  RetentionClass = "short"  // Default 30 days
	RetMedium RetentionClass = "medium"  // Default 180 days (default)
	RetLong   RetentionClass = "long"  // Default 1095 days (3 years)
)

type ActorKind string

const (
	ActorUser     ActorKind = "user"  // Human user (browser, mobile, CLI on behalf of a user)
	ActorService  ActorKind = "service"  // Internal service or daemon (default)
	ActorSchedule ActorKind = "schedule"  // Cron job or task scheduler
	ActorAgent    ActorKind = "agent"  // AI agent
)

const (
	MethodHTTP      = "http"  // HTTP/HTTPS request (REST, GraphQL, gRPC-web, webhook)
	MethodMQTT      = "mqtt"  // MQTT message (IoT telemetry, device command)
	MethodCLI       = "cli"  // CLI command typed by a human
	MethodScheduler = "scheduler"  // Automated cron or task scheduler
	MethodUI        = "ui"  // Web or desktop UI action, human-initiated
	MethodAgentTool = "agent_tool"  // AI agent tool call
	MethodSDK       = "sdk"  // Direct SDK call, no transport shim active. Default. (default)
)

const RedactReplacement = "***"

// RedactPatterns are the default PII field key patterns (case-insensitive regex on keys).
var RedactPatterns = []string{
	"api[_-]?key",
	"password",
	"passwd",
	"token",
	"secret",
	"authorization",
	"bearer",
	"m2m[_-]?key",
	"cert[_-]?private",
	"private[_-]?key",
	"access_key",
	"session_id",
	"cookie",
	"credential",
	"auth",
}
// ── END FASTEN GENERATED ──────────────────────────────────────────────────

// ── Anchors ───────────────────────────────────────────────────────────────

type Anchor string

const (
	Who         Anchor = "who"
	What        Anchor = "what"
	When        Anchor = "when"
	Where       Anchor = "where"
	Whom        Anchor = "whom"
	How         Anchor = "how"
	Correlation Anchor = "correlation"
)

// ── Row ───────────────────────────────────────────────────────────────────

// Row is the canonical audit row — lossless conversion to CloudEvent / OTel.
type Row struct {
	ID           string         `json:"id"`
	OriginID     string         `json:"origin_id"`
	MonotonicSeq int64          `json:"monotonic_seq"`
	Timestamp    time.Time      `json:"timestamp"`
	Code         Code           `json:"code"`
	Action       string         `json:"action"`
	Severity     Severity       `json:"severity"`
	ServiceID    string         `json:"service_id"`
	SourceNodeID string         `json:"source_node_id"`
	TenantID     string         `json:"tenant_id,omitempty"`
	Actor        string         `json:"actor"`
	ActorKind    string         `json:"actor_kind"`
	Target       string         `json:"target"`
	Category     string         `json:"category"`
	Domain       Domain         `json:"domain"`
	Method       string         `json:"method"`
	RequestID    string         `json:"request_id"`
	Detail       map[string]any `json:"detail"`
	// P1-5: stamped true when the code declares PiiInDetail=true. Lets the
	// retention sweep + compliance reports filter PII rows distinctly.
	PiiInDetail bool       `json:"pii_in_detail"`
	ShippedAt   *time.Time `json:"shipped_at,omitempty"`
}

// ── Code catalog ──────────────────────────────────────────────────────────

type Code string

// Domain is a plain string — adopters define their own vocabulary.
type Domain string

// Meta is the per-code metadata registered once at startup.
//
// ID is optional in adopter code — Register fills it from the map key
// at registration time. Setting ID explicitly is allowed but must
// match the map key (mismatch is a typo, never a feature).
//
// PiiInDetail=true (P1-5) carries three enforced runtime effects:
//
//  1. RetentionClass is forced to RetShort at register-time. Any other
//     declared retention class triggers a WARNING in the registration log.
//  2. The Detail payload is force-redacted on Emit, regardless of key
//     names: by default the whole map becomes
//     {"_redacted":"***", "_pii_in_detail": true}. Adopters who genuinely
//     need fields preserved declare them in DetailPassthroughKeys.
//  3. Audit rows carry a PiiInDetail bool so retention sweeps and
//     compliance reports can filter PII rows distinctly.
type Meta struct {
	ID             Code
	Domain         Domain
	Category       string
	Action         string
	Severity       Severity
	Description    string
	Emitter        string
	RetentionClass RetentionClass
	HighVolume     bool
	PiiInDetail    bool
	// DetailPassthroughKeys: when PiiInDetail=true, only these keys (if any)
	// survive Emit. Everything else is replaced. Empty = scrub everything.
	DetailPassthroughKeys []string
}

var (
	regMu      sync.RWMutex
	_registry  = map[Code]Meta{}
)

// Register adds a batch of codes for a domain.
//
// Validation runs in this order; first failure returns an error:
//   - key shape: UPPER_SNAKE_CASE identifier
//   - Meta.ID empty → fill from map key; set → must match key
//   - Meta.Domain must match domain
//   - duplicate code across registrations
//
// Drop Meta.ID in new code; the map key is the single source of truth:
//
//	fasten.Register("user", map[fasten.Code]fasten.Meta{
//	    "USER_CREATED": {Domain: "user", Action: "create", Severity: fasten.SevInfo, ...},
//	})
func Register(domain Domain, codes map[Code]Meta) error {
	regMu.Lock()
	defer regMu.Unlock()
	for c, m := range codes {
		if !codeKeyRe.MatchString(string(c)) {
			return fmt.Errorf("fasten.Register: code key %q must be UPPER_SNAKE_CASE", c)
		}
		if m.ID == "" {
			m.ID = c
		} else if m.ID != c {
			return fmt.Errorf(
				"fasten.Register: map key %q disagrees with Meta.ID=%q. "+
					"Drop Meta.ID (it fills from the key) or fix the mismatch.",
				c, m.ID,
			)
		}
		if m.Domain != domain {
			return fmt.Errorf("fasten.Register: code %q declares domain %q but registered under %q", c, m.Domain, domain)
		}

		// P1-5 #1: PiiInDetail forces RetentionClass=RetShort.
		if m.PiiInDetail && m.RetentionClass != RetShort && m.RetentionClass != "" {
			fmt.Fprintf(os.Stderr,
				"fasten: code %s has PiiInDetail=true; "+
					"RetentionClass forced to short (was %s).\n",
				c, m.RetentionClass)
			m.RetentionClass = RetShort
		}

		if _, exists := _registry[c]; exists {
			return fmt.Errorf("fasten.Register: duplicate code %q", c)
		}
		_registry[c] = m
	}
	return nil
}

// MustRegister is like Register but panics on error. Safe to call in init().
func MustRegister(domain Domain, codes map[Code]Meta) {
	if err := Register(domain, codes); err != nil {
		panic(err)
	}
}

func metaOf(c Code) (Meta, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	m, ok := _registry[c]
	return m, ok
}

// ── Correlation context ───────────────────────────────────────────────────

type ctxKey int

const requestIDKey ctxKey = 1

// MintID returns a new 12-character hex request id.
func MintID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// WithRequestID returns ctx with the id as the ambient correlation id.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestIDFromContext reads the ambient id ("" if unset).
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

// ── Init + globals ────────────────────────────────────────────────────────

var (
	_serviceID        string
	_nodeID           string
	_tenantID         string
	_auditStore       AuditRepository
	_transport        *Transport
	_seq              int64
	_failureStrategy  string // "queue" (P1-15 default) | "raise"
)

// Config for Init. AuditStore nil → audit rows are written to stdout only.
//
// AuditStoreFailureStrategy (P1-15) governs how Emit reacts when the
// store rejects a row:
//
//   - "queue" (default) — Emit pushes rows onto a bounded in-memory
//     queue and returns immediately. A background drainer goroutine
//     writes to the store with exponential backoff. Emit blocks only
//     when QueueCapacity (queued + in-flight retry) is saturated.
//   - "raise" — Emit calls Insert synchronously and returns the
//     wrapped error (*AuditStoreError). Useful for tests and adopters
//     who want loud failures during configuration debugging.
//
// Falls back to env var FASTEN_AUDIT_STORE_FAILURE_STRATEGY when the
// field is empty.
type Config struct {
	ServiceID  string
	NodeID     string
	TenantID   string
	AuditStore AuditRepository

	// P1-15
	AuditStoreFailureStrategy string        // "queue" (default) | "raise"
	QueueCapacity             int           // default 100
	QueueRetryInitial         time.Duration // default 100 * time.Millisecond
	QueueRetryMax             time.Duration // default 60 * time.Second
	DisableQueueJitter        bool          // zero (default) = jitter ON
}

// Init configures fasten. Must be called once before Emit.
// Falls back to env vars FASTEN_SERVICE_ID, FASTEN_NODE_ID, FASTEN_TENANT_ID,
// and FASTEN_AUDIT_STORE_FAILURE_STRATEGY.
func Init(cfg Config) error {
	_serviceID = firstNonEmpty(cfg.ServiceID, envOr("FASTEN_SERVICE_ID", ""))
	_nodeID = firstNonEmpty(cfg.NodeID, envOr("FASTEN_NODE_ID", ""))
	_tenantID = firstNonEmpty(cfg.TenantID, envOr("FASTEN_TENANT_ID", ""))

	if _serviceID == "" || _nodeID == "" {
		return errors.New("fasten.Init: ServiceID and NodeID are required")
	}
	_auditStore = cfg.AuditStore
	_transport = NewTransport(2000)

	// P1-15: failure strategy + drainer wiring.
	strategy := firstNonEmpty(
		cfg.AuditStoreFailureStrategy,
		envOr("FASTEN_AUDIT_STORE_FAILURE_STRATEGY", ""),
		"queue",
	)
	switch strategy {
	case "queue", "raise":
	default:
		return errInvalidStrategy
	}
	_failureStrategy = strategy

	if strategy == "queue" && _auditStore != nil {
		capacity := cfg.QueueCapacity
		if capacity <= 0 {
			capacity = 100
		}
		retryInitial := cfg.QueueRetryInitial
		if retryInitial <= 0 {
			retryInitial = 100 * time.Millisecond
		}
		retryMax := cfg.QueueRetryMax
		if retryMax <= 0 {
			retryMax = 60 * time.Second
		}
		installDrainer(
			_auditStore,
			drainerSysLog,
			capacity,
			retryInitial,
			retryMax,
			!cfg.DisableQueueJitter,
		)
	} else {
		// Raise mode (or no store) — no drainer thread.
		uninstallDrainer()
	}
	return nil
}

// drainerSysLog bridges the drainer to the sys stream. Non-recursive:
// writes to the in-memory ring + stdout only, never through Emit.
func drainerSysLog(level, event string, fields map[string]any) {
	row := SyslogRow{
		"level":      level,
		"event":      event,
		"timestamp":  time.Now().UTC().Format(time.RFC3339Nano),
		"request_id": "",
		"service_id": _serviceID,
	}
	for k, v := range fields {
		row[k] = v
	}
	if _transport != nil {
		_transport.PushSyslog(row)
	}
	row["shape"] = "sys"
	if b, err := json.Marshal(row); err == nil {
		fmt.Println(string(b))
	}
}

// Transport returns the active transport (ring buffers + stdout).
// Returns nil before Init is called.
func GetTransport() *Transport { return _transport }

// ── Emit options ──────────────────────────────────────────────────────────

type EmitOption func(*Row)

func Target(t string) EmitOption        { return func(r *Row) { r.Target = t } }
func Actor(a, kind string) EmitOption   { return func(r *Row) { r.Actor = a; r.ActorKind = kind } }
func WithDetail(d map[string]any) EmitOption { return func(r *Row) { r.Detail = d } }
func WithMethod(m string) EmitOption    { return func(r *Row) { r.Method = m } }

// ── Emit ──────────────────────────────────────────────────────────────────

// Emit produces an audit row for a registered code.
// Returns an error if Init has not been called or the code is not registered.
func Emit(ctx context.Context, code Code, opts ...EmitOption) (Row, error) {
	if _serviceID == "" {
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

	seq := atomic.AddInt64(&_seq, 1)
	id := "evt-" + mintLong()

	row := Row{
		ID:           id,
		OriginID:     id,
		MonotonicSeq: seq,
		Timestamp:    time.Now().UTC(),
		Code:         code,
		Action:       m.Action,
		Severity:     m.Severity,
		ServiceID:    _serviceID,
		SourceNodeID: _nodeID,
		TenantID:     _tenantID,
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

	// P1-5 #2: PiiInDetail force-redacts the entire detail map regardless
	// of key names. Adopters who genuinely need fields preserved declare
	// them in Meta.DetailPassthroughKeys.
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
		// Run the secret-key redactor on the kept subset (api_key etc.
		// is scrubbed even when in passthrough).
		kept = RedactDetail(kept)
		kept["_redacted"] = "***"
		kept["_pii_in_detail"] = true
		row.Detail = kept
	} else {
		row.Detail = RedactDetail(row.Detail)
	}

	// Stdout write happens BEFORE any store routing. Two reasons:
	//   1. Under sustained queue-full outage, drainer.put() blocks. If
	//      stdout came after, even Docker / journald log capture stalls
	//      — adopters lose the recoverable audit trail at the worst
	//      possible moment.
	//   2. In raise mode, the row should still reach stdout even if the
	//      sync insert errors — preserves the "stdout is always honest"
	//      contract.
	if _transport != nil {
		_transport.WriteAudit(rowToMap(row))
	}

	// P1-15: route store insert through the drainer (queue mode) or
	// call synchronously and wrap the store error (raise mode).
	if _auditStore != nil {
		if _failureStrategy == "queue" {
			d := activeDrainer()
			if d != nil {
				d.put(row)
			} else {
				// Defensive fallback — strategy says queue but drainer
				// isn't installed (e.g. tests bypassed Init). Sync
				// insert so the row isn't silently dropped.
				_ = _auditStore.Insert(ctx, row)
			}
		} else {
			if err := _auditStore.Insert(ctx, row); err != nil {
				return row, &AuditStoreError{Err: err}
			}
		}
	}
	return row, nil
}

// ── Built-in structured log (sys stream) ─────────────────────────────────
//
// Adopters get NDJSON sys lines without bringing slog wiring or any
// external lib. Auto-stamps request_id from ctx and service_id from Init.
// For a slog handler integration that still chains to your existing slog
// pipeline, see NewSlogHandler in slog.go.

// LogInfo writes a {shape:"sys"} NDJSON line to stdout.
// Pairs come as key1, value1, key2, value2, ... (slog-style).
func LogInfo(ctx context.Context, event string, kv ...any)  { logSys(ctx, "info", event, kv) }
func LogWarn(ctx context.Context, event string, kv ...any)  { logSys(ctx, "warn", event, kv) }
func LogError(ctx context.Context, event string, kv ...any) { logSys(ctx, "error", event, kv) }
func LogDebug(ctx context.Context, event string, kv ...any) { logSys(ctx, "debug", event, kv) }

func logSys(ctx context.Context, level, event string, kv []any) {
	row := SyslogRow{
		"level":      level,
		"event":      event,
		"timestamp":  time.Now().UTC().Format(time.RFC3339Nano),
		"request_id": RequestIDFromContext(ctx),
		"service_id": _serviceID,
	}
	for i := 0; i+1 < len(kv); i += 2 {
		k, ok := kv[i].(string)
		if !ok {
			continue
		}
		row[k] = kv[i+1]
	}
	if _transport != nil {
		_transport.PushSyslog(row)
	}
	row["shape"] = "sys"
	if b, err := json.Marshal(row); err == nil {
		fmt.Println(string(b))
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────

func mintLong() string {
	b := make([]byte, 10)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func rowToMap(r Row) map[string]any {
	d := map[string]any{
		"id": r.ID, "origin_id": r.OriginID, "monotonic_seq": r.MonotonicSeq,
		"timestamp": r.Timestamp.Format(time.RFC3339Nano),
		"code": string(r.Code), "action": r.Action, "severity": string(r.Severity),
		"service_id": r.ServiceID, "source_node_id": r.SourceNodeID, "tenant_id": r.TenantID,
		"actor": r.Actor, "actor_kind": r.ActorKind,
		"target": r.Target, "category": r.Category, "domain": string(r.Domain),
		"method": r.Method, "request_id": r.RequestID, "detail": r.Detail,
		"pii_in_detail": r.PiiInDetail,
	}
	if r.ShippedAt != nil {
		d["shipped_at"] = r.ShippedAt.Format(time.RFC3339Nano)
	}
	return d
}

// ── AuditRepository interface ─────────────────────────────────────────────

// AuditRepository is the durable store contract.
type AuditRepository interface {
	Insert(ctx context.Context, row Row) error
	Query(ctx context.Context, f Filter) ([]Row, error)
	ListUnshipped(ctx context.Context, limit int) ([]Row, error)
	MarkShipped(ctx context.Context, ids []string) error
	Purge(ctx context.Context, before time.Time, respectUnshipped bool) (int, error)
}

// Filter — query parameters for AuditRepository.Query.
type Filter struct {
	RequestID    string
	Code         Code
	Domain       Domain
	SourceNodeID string
	Since        time.Time
	Until        time.Time
	Limit        int
}
