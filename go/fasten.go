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
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
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
	ShippedAt    *time.Time     `json:"shipped_at,omitempty"`
}

// ── Code catalog ──────────────────────────────────────────────────────────

type Code string

// Domain is a plain string — adopters define their own vocabulary.
type Domain string

// Meta is the per-code metadata registered once at startup.
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
}

var (
	regMu      sync.RWMutex
	_registry  = map[Code]Meta{}
)

// Register adds a batch of codes. Returns error on duplicates or domain mismatch.
func Register(domain Domain, codes map[Code]Meta) error {
	regMu.Lock()
	defer regMu.Unlock()
	for c, m := range codes {
		if _, exists := _registry[c]; exists {
			return fmt.Errorf("fasten: duplicate code %q", c)
		}
		if m.Domain != domain {
			return fmt.Errorf("fasten: code %q declares domain %q but registered under %q", c, m.Domain, domain)
		}
		m.ID = c
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
	_serviceID  string
	_nodeID     string
	_tenantID   string
	_auditStore AuditRepository
	_transport  *Transport
	_seq        int64
)

// Config for Init. AuditStore nil → audit rows are written to stdout only.
type Config struct {
	ServiceID  string
	NodeID     string
	TenantID   string
	AuditStore AuditRepository
}

// Init configures fasten. Must be called once before Emit.
// Falls back to env vars FASTEN_SERVICE_ID, FASTEN_NODE_ID, FASTEN_TENANT_ID.
func Init(cfg Config) error {
	_serviceID = firstNonEmpty(cfg.ServiceID, envOr("FASTEN_SERVICE_ID", ""))
	_nodeID = firstNonEmpty(cfg.NodeID, envOr("FASTEN_NODE_ID", ""))
	_tenantID = firstNonEmpty(cfg.TenantID, envOr("FASTEN_TENANT_ID", ""))

	if _serviceID == "" || _nodeID == "" {
		return errors.New("fasten.Init: ServiceID and NodeID are required")
	}
	_auditStore = cfg.AuditStore
	_transport = NewTransport(2000)
	return nil
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
	}
	for _, opt := range opts {
		opt(&row)
	}

	if _auditStore != nil {
		_ = _auditStore.Insert(ctx, row)
	}
	if _transport != nil {
		_transport.WriteAudit(rowToMap(row))
	}
	return row, nil
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
