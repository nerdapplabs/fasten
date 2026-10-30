// Package fasten is an audit and correlation SDK for Go services.
//
// It has three streams (syslog, api log, audit) and carries one request_id
// through all of them via context.
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
	SevDebug    Severity = "debug"    // Low-level diagnostic, filtered in production
	SevInfo     Severity = "info"     // Normal operational event (default)
	SevWarn     Severity = "warn"     // Potentially problematic, not yet an error
	SevError    Severity = "error"    // Operation failed, requires attention
	SevCritical Severity = "critical" // Severe failure, may impact availability
)

type RetentionClass string

const (
	RetShort  RetentionClass = "short"  // Default 30 days
	RetMedium RetentionClass = "medium" // Default 180 days (default)
	RetLong   RetentionClass = "long"   // Default 1095 days (3 years)
)

type ActorKind string

const (
	ActorUser     ActorKind = "user"     // Human user (browser, mobile, CLI on behalf of a user)
	ActorService  ActorKind = "service"  // Internal service or daemon (default)
	ActorSchedule ActorKind = "schedule" // Cron job or task scheduler
	ActorAgent    ActorKind = "agent"    // AI agent
)

const (
	MethodHTTP      = "http"       // HTTP/HTTPS request (REST, GraphQL, gRPC-web, webhook)
	MethodMQTT      = "mqtt"       // MQTT message (IoT telemetry, device command)
	MethodCLI       = "cli"        // CLI command typed by a human
	MethodScheduler = "scheduler"  // Automated cron or task scheduler
	MethodUI        = "ui"         // Web or desktop UI action, human-initiated
	MethodAgentTool = "agent_tool" // AI agent tool call
	MethodSDK       = "sdk"        // Direct SDK call, no transport shim active. Default. (default)
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

// Row is an audit row. It converts to CloudEvent or OTel without loss.
type Row struct {
	WireVersion  string    `json:"wire_version"`
	ID           string    `json:"id"`
	OriginID     string    `json:"origin_id"`
	MonotonicSeq int64     `json:"monotonic_seq"`
	Timestamp    time.Time `json:"timestamp"`
	Code         Code      `json:"code"`
	Action       string    `json:"action"`
	Severity     Severity  `json:"severity"`
	ServiceID    string    `json:"service_id"`
	SourceNodeID string    `json:"source_node_id"`
	// TenantID is always present in JSON (null when unset), as in the other SDKs.
	TenantID  *string        `json:"tenant_id"`
	Actor     string         `json:"actor"`
	ActorKind string         `json:"actor_kind"`
	Target    string         `json:"target"`
	Category  string         `json:"category"`
	Domain    Domain         `json:"domain"`
	Method    string         `json:"method"`
	RequestID string         `json:"request_id"`
	Detail    map[string]any `json:"detail"`
	// PiiInDetail is true when the code declares PiiInDetail.
	PiiInDetail bool       `json:"pii_in_detail"`
	ShippedAt   *time.Time `json:"shipped_at,omitempty"`
	// CanonicalFormID names the canonical form the row was sealed with ("2"
	// for new rows; empty means "1"). It is part of the hashed bytes, and
	// VerifyChain rejects unknown ids. See verify.go.
	CanonicalFormID string `json:"canonical_form_id,omitempty"`
	// PrevHash is the Hash of the preceding row from the same
	// source_node_id, or "genesis" for the first row. Hash is the
	// SHA-256 of the row's canonical form. Rows written before the hash chain
	// existed have both empty, and VerifyChain skips them.
	PrevHash string `json:"prev_hash,omitempty"`
	Hash     string `json:"hash,omitempty"`

	// Form "2" (spec §1.4) hashes DetailCommitment instead of Detail, so
	// Detail can be removed for retention without changing the hash.
	// DetailSalt is stored but not hashed, and is cleared on redaction. Both
	// are empty on form "1" rows.
	DetailSalt       string `json:"detail_salt,omitempty"`
	DetailCommitment string `json:"detail_commitment,omitempty"`
}

// UnmarshalJSON decodes a Row, keeping the exact number tokens in Detail.
//
// Python writes a whole-number float as "999.0", but a float64 re-encodes as
// "999", so a Python-sealed row would fail VerifyChain here. With UseNumber
// each value keeps its original token, which canonicalJSON writes back as is.
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

type Code string

// Domain is a plain string; callers define their own domains.
type Domain string

// Meta is the per-code metadata registered once at startup.
//
// ID is optional; Register fills it from the map key. If set, it must match
// the key.
//
// PiiInDetail=true has three effects:
//
//  1. Register sets RetentionClass to RetShort, whatever was declared.
//  2. Emit replaces Detail with {"_redacted":"***", "_pii_in_detail": true},
//     keeping only the keys listed in DetailPassthroughKeys.
//  3. Rows carry PiiInDetail, which Config.RetentionPII uses to expire the
//     stored Detail (Engine.RedactExpired, spec §7.1, §7.2).
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
	// DetailPassthroughKeys are the Detail keys kept when PiiInDetail is
	// set. Empty means none.
	DetailPassthroughKeys []string
}

var (
	regMu     sync.RWMutex
	_registry = map[Code]Meta{}
)

// rustMeta is the JSON shape fasten-core's catalog reads and returns.
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

// clearBothRegistries clears the Go cache and fasten-core's catalog. Tests only.
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
// Validation (UPPER_SNAKE_CASE keys, Meta.ID, domain, duplicates, and
// pii_in_detail forcing RetShort) is done by fasten-core, shared by all
// SDKs. On success the Go cache is filled from fasten-core's result.
//
// Meta.ID can be left out; the map key is used:
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

// MustRegister is like Register but panics on error.
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

// The request id helpers below call package fastenctx, which has no cgo.

// MintID returns a new 12-character hex request id.
func MintID() string { return fastenctx.MintID() }

// SentinelKinds is fastenctx.SentinelKinds.
var SentinelKinds = fastenctx.SentinelKinds

// MintSentinel returns a sentinel request_id such as
// "orphan-svc-ab12cd34ef56". It panics on an unknown kind.
func MintSentinel(kind, serviceID string) string { return fastenctx.MintSentinel(kind, serviceID) }

// RequestIDKind returns the sentinel kind of requestID, or "request".
func RequestIDKind(requestID string) string { return fastenctx.RequestIDKind(requestID) }

// IsSentinel reports whether requestID is a sentinel rather than a real id.
func IsSentinel(requestID string) bool { return fastenctx.IsSentinel(requestID) }

// WithRequestID returns a copy of ctx carrying id as the request id.
func WithRequestID(ctx context.Context, id string) context.Context {
	return fastenctx.WithRequestID(ctx, id)
}

// RequestIDFromContext returns the request id in ctx, or "".
func RequestIDFromContext(ctx context.Context) string {
	return fastenctx.RequestIDFromContext(ctx)
}

// Background returns ctx with a bg- sentinel request_id if it has none, so
// work outside a request (goroutines, workers) still gets a request_id
// (spec §5.1, §8.1). Use BackgroundKind for "sched" or "lib".
func Background(ctx context.Context) context.Context { return BackgroundKind(ctx, "bg") }

// BackgroundKind is Background with an explicit sentinel namespace.
func BackgroundKind(ctx context.Context, kind string) context.Context {
	if RequestIDFromContext(ctx) == "" {
		return WithRequestID(ctx, MintSentinel(kind, Default.serviceID))
	}
	return ctx
}

// Go runs fn in a new goroutine with Background(ctx).
func Go(ctx context.Context, fn func(context.Context)) {
	c := Background(ctx)
	go fn(c)
}

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

// QueueStats is returned by GetQueueStats(). Depth counts queued and
// retrying rows; Emit blocks when it reaches Capacity.
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

// Config for Init. With a nil AuditStore, audit rows only go to stdout.
//
// AuditStoreFailureStrategy (or FASTEN_AUDIT_STORE_FAILURE_STRATEGY) sets
// how Emit writes to the store:
//
//   - "queue" (default): Emit writes the row to the store directly. A
//     store error is logged, not returned, and the audit stream is marked
//     degraded. Rows don't go through the drainer queue until fasten-core
//     can allocate seq (spec §2.1).
//   - "raise": Emit calls Insert directly and returns any error as
//     *AuditStoreError.
type Config struct {
	ServiceID  string
	NodeID     string
	TenantID   string
	AuditStore AuditRepository

	// APIStore and SyslogStore persist the api and sys streams. Nil keeps
	// the stream in memory only. Use NewStreamStore (SQLite) or
	// NewPostgresStreamStore; the caller owns the *sql.DB.
	APIStore    StreamRepository
	SyslogStore StreamRepository

	// SearchEnabled (or FASTEN_SEARCH_ENABLED) turns on free-text search
	// (/logs/search and q=). It is off by default because it is a linear
	// scan. Without a SyslogStore, sys search still reports "search
	// requires sys persistence".
	SearchEnabled bool

	// ExtraRedactKeys are added to the built-in key patterns;
	// RedactReplacement replaces "***". If empty they are read from
	// FASTEN_REDACT_KEYS (comma-separated) and FASTEN_REDACT_REPLACEMENT.
	ExtraRedactKeys   []string
	RedactReplacement string

	AuditStoreFailureStrategy string        // "queue" (default) | "raise"
	QueueCapacity             int           // default 100
	QueueRetryInitial         time.Duration // default 100 * time.Millisecond
	QueueRetryMax             time.Duration // default 60 * time.Second
	DisableQueueJitter        bool          // zero (default) = jitter ON
	QueueDrainMaxAttempts     int           // default 50; then the row goes to the dead-letter queue

	// RetentionAPI and RetentionSyslog (spec §1) purge older rows from the
	// stream stores, on Init and then hourly. Zero disables. If zero they
	// are read from FASTEN_RETENTION_API and FASTEN_RETENTION_SYSLOG, as a
	// number and one unit, e.g. "7d" or "24h" (see parseRetentionDuration).
	RetentionAPI    time.Duration
	RetentionSyslog time.Duration

	// RetentionPII destroys Detail and DetailSalt on audit rows older than
	// this whose code has PiiInDetail (or RetShort). Zero disables; also read
	// from FASTEN_RETENTION_PII. Audit rows are redacted, never deleted:
	// deleting chain rows shows up as tampering (spec §7.1).
	RetentionPII time.Duration

	// PersistStreams (or FASTEN_PERSIST_STREAMS, comma-separated) lists the
	// streams expected to be persisted. If set, Init fails unless it matches
	// the streams that have stores attached, in both directions. If nil,
	// attached stores decide. "audit" isn't allowed; use AuditStore.
	PersistStreams []string
}

// Init configures fasten. Delegates to Default.Init.
func Init(cfg Config) error { return Default.Init(cfg) }

// GetTransport returns the active transport of the Default engine.
func GetTransport() *Transport { return Default.GetTransport() }

// Flush blocks until the Default engine's pending rows drain.
func Flush(timeout time.Duration) bool { return Default.Flush(timeout) }

// GetQueueStats returns the Default engine's drainer snapshot.
func GetQueueStats() *QueueStats { return Default.GetQueueStats() }

type EmitOption func(*Row)

func Target(t string) EmitOption             { return func(r *Row) { r.Target = t } }
func Actor(a, kind string) EmitOption        { return func(r *Row) { r.Actor = a; r.ActorKind = kind } }
func WithDetail(d map[string]any) EmitOption { return func(r *Row) { r.Detail = d } }
func WithMethod(m string) EmitOption         { return func(r *Row) { r.Method = m } }

// Emit produces an audit row via the Default engine.
func Emit(ctx context.Context, code Code, opts ...EmitOption) (Row, error) {
	return Default.Emit(ctx, code, opts...)
}

// LogInfo, LogWarn, LogError and LogDebug write {shape:"sys"} NDJSON lines
// with request_id from ctx and service_id from Init. kv is key, value
// pairs, as in slog. To use slog instead, see NewSlogHandler.
func LogInfo(ctx context.Context, event string, kv ...any)  { Default.LogSys(ctx, "info", event, kv) }
func LogWarn(ctx context.Context, event string, kv ...any)  { Default.LogSys(ctx, "warn", event, kv) }
func LogError(ctx context.Context, event string, kv ...any) { Default.LogSys(ctx, "error", event, kv) }
func LogDebug(ctx context.Context, event string, kv ...any) { Default.LogSys(ctx, "debug", event, kv) }

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
		"id":           r.ID, "origin_id": r.OriginID, "monotonic_seq": r.MonotonicSeq,
		"timestamp": canonicalTS(r.Timestamp),
		"code":      string(r.Code), "action": r.Action, "severity": string(r.Severity),
		"service_id": r.ServiceID, "source_node_id": r.SourceNodeID, "tenant_id": func() any {
			if r.TenantID != nil {
				return *r.TenantID
			}
			return nil
		}(),
		"actor": r.Actor, "actor_kind": r.ActorKind,
		"target": r.Target, "category": r.Category, "domain": string(r.Domain),
		"method": r.Method, "request_id": r.RequestID, "detail": r.Detail,
		"pii_in_detail": r.PiiInDetail,
		"canonical_form_id": func() string {
			if r.CanonicalFormID == "" {
				return "1"
			}
			return r.CanonicalFormID
		}(),
		"prev_hash": r.PrevHash,
	}
	if r.ShippedAt != nil {
		d["shipped_at"] = canonicalTS(*r.ShippedAt)
	}
	if r.Hash != "" {
		d["hash"] = r.Hash
	}
	return d
}

// SeqSeeder is an optional AuditRepository extension returning the highest
// stored monotonic_seq for (serviceID, sourceNodeID). Init still calls it,
// but the store allocates seq on insert (spec §2.1), so the result is not
// used.
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

// Filter holds the parameters for AuditRepository.Query.
type Filter struct {
	RequestID    string
	Code         Code
	Domain       Domain
	SourceNodeID string
	TenantID     string
	Actor        string
	Target       string
	Since        time.Time
	Until        time.Time
	Limit        int
	// AfterSeq is the paging cursor: only rows with monotonic_seq < AfterSeq
	// are returned. Set it to next_after (the smallest MonotonicSeq of the
	// previous page). Unlike Offset it isn't shifted by new rows.
	AfterSeq int64
	// Offset is the alternative page-number cursor (SQL OFFSET), for UIs that
	// want total/limit/offset. Drifts as rows are inserted; prefer AfterSeq.
	Offset int
}
