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
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/nerdapplabs/fasten/go/fastenctx"
)

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
	WireVersion  string         `json:"wire_version"`
	ID           string         `json:"id"`
	OriginID     string         `json:"origin_id"`
	MonotonicSeq int64          `json:"monotonic_seq"`
	Timestamp    time.Time      `json:"timestamp"`
	Code         Code           `json:"code"`
	Action       string         `json:"action"`
	Severity     Severity       `json:"severity"`
	ServiceID    string         `json:"service_id"`
	SourceNodeID string         `json:"source_node_id"`
	// TenantID is always emitted (null when absent) per the "always emit the
	// key" convention so readers see a consistent shape across SDKs.
	TenantID     *string        `json:"tenant_id"`
	Actor        string         `json:"actor"`
	ActorKind    string         `json:"actor_kind"`
	Target       string         `json:"target"`
	Category     string         `json:"category"`
	Domain       Domain         `json:"domain"`
	Method       string         `json:"method"`
	RequestID    string         `json:"request_id"`
	Detail       map[string]any `json:"detail"`
	// P1-5: stamped true when the code declares PiiInDetail=true.
	PiiInDetail bool       `json:"pii_in_detail"`
	ShippedAt   *time.Time `json:"shipped_at,omitempty"`
	// CanonicalFormID names the hashed canonical form that sealed this row. "1"
	// is the current (and only) form. It is INCLUDED in the hashed bytes so the
	// form choice is itself tamper-evident; VerifyChain dispatches on it and
	// rejects unknown ids. See verify.go for the form definitions.
	CanonicalFormID string `json:"canonical_form_id,omitempty"`
	// P1-23: tamper-evidence hash chain. PrevHash is the hex SHA-256 of the
	// preceding row in the (service_id, source_node_id) sequence, or "genesis"
	// for the first row. Hash is SHA-256 of canonical JSON of this row with
	// the "hash" key excluded. Rows written before hash-chain support have
	// empty strings; verify_chain skips them.
	PrevHash string `json:"prev_hash,omitempty"`
	Hash     string `json:"hash,omitempty"`
}

// UnmarshalJSON decodes a Row, preserving the EXACT numeric tokens in Detail.
//
// This is load-bearing for cross-language hash compatibility. The canonical row
// hash is computed over the JSON rendering of Detail, and Python json.dumps
// renders a whole-number float as "999.0" while Go's default encoder renders the
// float64 it gets from a plain unmarshal as "999". A Python-sealed row whose
// detail carries a whole-number float (e.g. a setpoint value 75.0) would then be
// rejected by VerifyChain on the Go side — a silent cross-language break.
//
// Decoding Detail with UseNumber keeps each value as a json.Number holding its
// original token ("999.0", "12.5", "7", "1e+20"), which canonicalJSON re-emits
// verbatim — so Go reproduces Python's rendering byte-for-byte regardless of how
// the number was written. The rest of the Row decodes normally.
func (r *Row) UnmarshalJSON(data []byte) error {
	type rowAlias Row // alias drops the method set, preventing infinite recursion
	aux := struct {
		Detail json.RawMessage `json:"detail"`
		*rowAlias
	}{rowAlias: (*rowAlias)(r)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if len(aux.Detail) == 0 || string(aux.Detail) == "null" {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(aux.Detail))
	dec.UseNumber()
	var detail map[string]any
	if err := dec.Decode(&detail); err != nil {
		return err
	}
	r.Detail = detail
	return nil
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
	regMu     sync.RWMutex
	_registry = map[Code]Meta{}
)

// rustMeta is the JSON shape the Rust catalog engine expects and returns.
type rustMeta struct {
	Domain                string   `json:"domain"`
	Category              string   `json:"category"`
	Action                string   `json:"action"`
	Severity              string   `json:"severity"`
	Description           string   `json:"description"`
	Emitter               string   `json:"emitter"`
	ID                    string   `json:"id"`
	RetentionClass        string   `json:"retention_class"`
	HighVolume            bool     `json:"high_volume"`
	PiiInDetail           bool     `json:"pii_in_detail"`
	DetailPassthroughKeys []string `json:"detail_passthrough_keys"`
}

func marshalCodesForRust(domain string, codes map[Code]Meta) (string, error) {
	m := make(map[string]rustMeta, len(codes))
	for k, meta := range codes {
		rc := string(meta.RetentionClass)
		if rc == "" {
			rc = "medium"
		}
		passthrough := meta.DetailPassthroughKeys
		if passthrough == nil {
			passthrough = []string{}
		}
		m[string(k)] = rustMeta{
			Domain:                string(meta.Domain),
			Category:              meta.Category,
			Action:                meta.Action,
			Severity:              string(meta.Severity),
			Description:           meta.Description,
			Emitter:               meta.Emitter,
			ID:                    string(meta.ID),
			RetentionClass:        rc,
			HighVolume:            meta.HighVolume,
			PiiInDetail:           meta.PiiInDetail,
			DetailPassthroughKeys: passthrough,
		}
	}
	b, err := json.Marshal(m)
	return string(b), err
}

func unmarshalMetaJSON(s string) (Meta, bool) {
	var rm rustMeta
	if err := json.Unmarshal([]byte(s), &rm); err != nil {
		return Meta{}, false
	}
	return Meta{
		ID:                    Code(rm.ID),
		Domain:                Domain(rm.Domain),
		Category:              rm.Category,
		Action:                rm.Action,
		Severity:              Severity(rm.Severity),
		Description:           rm.Description,
		Emitter:               rm.Emitter,
		RetentionClass:        RetentionClass(rm.RetentionClass),
		HighVolume:            rm.HighVolume,
		PiiInDetail:           rm.PiiInDetail,
		DetailPassthroughKeys: rm.DetailPassthroughKeys,
	}, true
}

// clearBothRegistries clears the Go-side cache and the Rust global registry.
// For test teardown only — do not call in production code.
func clearBothRegistries() {
	regMu.Lock()
	for k := range _registry {
		delete(_registry, k)
	}
	regMu.Unlock()
	coreRegistryClear()
}

// Register adds a batch of codes for a domain.
//
// All validation (UPPER_SNAKE_CASE key shape, Meta.ID fill/mismatch,
// domain match, duplicate detection, pii_in_detail→RetShort) is delegated
// to fasten-core (Rust) so the logic is canonical across all SDKs.
// On success the Go-side cache is populated from the Rust-validated state.
//
// Drop Meta.ID in new code; the map key is the single source of truth:
//
//	fasten.Register("user", map[fasten.Code]fasten.Meta{
//	    "USER_CREATED": {Domain: "user", Action: "create", Severity: fasten.SevInfo, ...},
//	})
func Register(domain Domain, codes map[Code]Meta) error {
	codesJSON, err := marshalCodesForRust(string(domain), codes)
	if err != nil {
		return fmt.Errorf("fasten.Register: %w", err)
	}
	if err := coreRegisterCodes(string(domain), codesJSON); err != nil {
		return err // already prefixed with "fasten.Register: "
	}
	regMu.Lock()
	defer regMu.Unlock()
	for name := range codes {
		metaJSON, _ := coreMetaOfJSON(string(name))
		if metaJSON != "" && metaJSON != "{}" {
			if m, ok := unmarshalMetaJSON(metaJSON); ok {
				_registry[name] = m
			}
		}
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

// MintID returns a new 12-character hex request id.
func MintID() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// WithRequestID returns ctx with the id as the ambient correlation id.
//
// Delegates to the zero-dependency fastenctx subpackage so the context key
// is identical to the one fastenctx (and the HTTP RequestID middleware) use.
func WithRequestID(ctx context.Context, id string) context.Context {
	return fastenctx.WithRequestID(ctx, id)
}

// RequestIDFromContext reads the ambient id ("" if unset).
//
// Delegates to fastenctx — same key as WithRequestID above.
func RequestIDFromContext(ctx context.Context) string {
	return fastenctx.RequestIDFromContext(ctx)
}

// ── Audit-store failure handling ──────────────────────────────────────────

// AuditStoreError wraps an underlying store error for the "raise"
// strategy. Use errors.As to recover the cause:
//
//	var aerr *AuditStoreError
//	if errors.As(err, &aerr) { /* aerr.Err = sqlite3 / postgres err */ }
type AuditStoreError struct{ Err error }

func (e *AuditStoreError) Error() string {
	if e.Err == nil {
		return "fasten audit store: <nil>"
	}
	return "fasten audit store: " + e.Err.Error()
}
func (e *AuditStoreError) Unwrap() error { return e.Err }

// QueueStats is the snapshot returned by GetQueueStats(). Depth is total
// occupied capacity (queued + in-flight retry) — the value that
// determines whether the next Emit() blocks.
type QueueStats struct {
	Depth             int     `json:"depth"`
	Capacity          int     `json:"capacity"`
	HighWater         int     `json:"high_water"`
	DrainedTotal      int     `json:"drained_total"`
	RetryCountActive  int     `json:"retry_count_active"`
	InBackoffSeconds  float64 `json:"in_backoff_seconds"`
	LastError         string  `json:"last_error"`
	DeadLetteredTotal int     `json:"dead_lettered_total"`
	DeadLetterDepth   int     `json:"dead_letter_depth"`
	CapacitySemantics string  `json:"capacity_semantics"`
}

// ── Init + free-function wrappers ─────────────────────────────────────────

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
	QueueDrainMaxAttempts     int           // default 50; row → DLQ after this many failures
}

// Init configures fasten. Delegates to Default.Init.
func Init(cfg Config) error { return Default.Init(cfg) }

// GetTransport returns the active transport of the Default engine.
func GetTransport() *Transport { return Default.GetTransport() }

// Flush blocks until the Default engine's pending rows drain.
func Flush(timeout time.Duration) bool { return Default.Flush(timeout) }

// GetQueueStats returns the Default engine's drainer snapshot.
func GetQueueStats() *QueueStats { return Default.GetQueueStats() }

// ── Emit options ──────────────────────────────────────────────────────────

type EmitOption func(*Row)

func Target(t string) EmitOption             { return func(r *Row) { r.Target = t } }
func Actor(a, kind string) EmitOption        { return func(r *Row) { r.Actor = a; r.ActorKind = kind } }
func WithDetail(d map[string]any) EmitOption { return func(r *Row) { r.Detail = d } }
func WithMethod(m string) EmitOption         { return func(r *Row) { r.Method = m } }

// Emit produces an audit row via the Default engine.
func Emit(ctx context.Context, code Code, opts ...EmitOption) (Row, error) {
	return Default.Emit(ctx, code, opts...)
}

// ── Built-in structured log (sys stream) ─────────────────────────────────
//
// Adopters get NDJSON sys lines without bringing slog wiring or any
// external lib. Auto-stamps request_id from ctx and service_id from Init.
// For a slog handler integration that still chains to your existing slog
// pipeline, see NewSlogHandler in slog.go.

// LogInfo / LogWarn / LogError / LogDebug write {shape:"sys"} NDJSON lines.
// Pairs come as key1, value1, key2, value2, ... (slog-style).
func LogInfo(ctx context.Context, event string, kv ...any)  { Default.LogSys(ctx, "info", event, kv) }
func LogWarn(ctx context.Context, event string, kv ...any)  { Default.LogSys(ctx, "warn", event, kv) }
func LogError(ctx context.Context, event string, kv ...any) { Default.LogSys(ctx, "error", event, kv) }
func LogDebug(ctx context.Context, event string, kv ...any) { Default.LogSys(ctx, "debug", event, kv) }

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
		"wire_version": r.WireVersion,
		"id": r.ID, "origin_id": r.OriginID, "monotonic_seq": r.MonotonicSeq,
		"timestamp": r.Timestamp.Format(time.RFC3339Nano),
		"code": string(r.Code), "action": r.Action, "severity": string(r.Severity),
		"service_id": r.ServiceID, "source_node_id": r.SourceNodeID, "tenant_id": func() any {
			if r.TenantID != nil { return *r.TenantID }; return nil
		}(),
		"actor": r.Actor, "actor_kind": r.ActorKind,
		"target": r.Target, "category": r.Category, "domain": string(r.Domain),
		"method": r.Method, "request_id": r.RequestID, "detail": r.Detail,
		"pii_in_detail": r.PiiInDetail,
		"canonical_form_id": func() string {
			if r.CanonicalFormID == "" { return "1" }; return r.CanonicalFormID
		}(),
		"prev_hash": r.PrevHash,
	}
	if r.ShippedAt != nil {
		d["shipped_at"] = r.ShippedAt.Format(time.RFC3339Nano)
	}
	if r.Hash != "" {
		d["hash"] = r.Hash
	}
	return d
}

// ── AuditRepository interface ─────────────────────────────────────────────

// SeqSeeder is an optional extension of AuditRepository. Stores that implement
// it allow Init() to seed monotonic_seq from persisted rows so post-restart
// rows never collide on (timestamp, seq) with pre-restart rows.
//
// The seed MUST be scoped to the engine's own (serviceID, sourceNodeID): the
// tamper chain is per-node and monotonic_seq is a per-node counter, so seeding
// from an unscoped global MAX would break this node's own chain once it has
// ingested replicated rows from another origin.
type SeqSeeder interface {
	MaxMonotonicSeq(ctx context.Context, serviceID, sourceNodeID string) (int64, error)
}

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
	// AfterSeq is a cursor: only return rows with monotonic_seq > AfterSeq.
	// Set to the last row's MonotonicSeq from the previous page to paginate.
	AfterSeq int64
}
