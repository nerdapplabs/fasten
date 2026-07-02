package fasten

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// ── Request ID middleware ─────────────────────────────────────────────────

// RequestID is a stdlib http.Handler middleware that mints or honours
// X-Request-ID and sets it in the context for the duration of the request.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = MintID()
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(WithRequestID(r.Context(), id)))
	})
}

// ── API log middleware ────────────────────────────────────────────────────

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Status() int {
	if r.status == 0 {
		return http.StatusOK
	}
	return r.status
}

// APILogger pushes each inbound HTTP request into fasten's API ring buffer.
// Skips paths that match any of skipPaths (e.g. "/_system/health").
func APILogger(skipPaths ...string) func(http.Handler) http.Handler {
	skip := make(map[string]bool, len(skipPaths))
	for _, p := range skipPaths {
		skip[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if skip[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w}
			next.ServeHTTP(rec, r)
			if Default.xport != nil {
				Default.xport.PushAPI(APIRow{
					"method":      r.Method,
					"path":        r.URL.Path,
					"status":      rec.Status(),
					"duration_ms": time.Since(start).Milliseconds(),
					"request_id":  RequestIDFromContext(r.Context()),
					"timestamp":   start.UTC().Format(time.RFC3339Nano),
				})
			}
		})
	}
}

// ── Reader ────────────────────────────────────────────────────────────────

// NewReader returns an http.Handler bound to this Engine serving:
//
//	GET /sys               — syslog ring buffer
//	GET /api               — api-log ring buffer
//	GET /audit             — audit store query (?request_id=, ?code=, ?domain=,
//	                         ?since=, ?until=, ?limit=, ?after=<monotonic_seq>)
//	GET /audit/doctor      — audit pipeline health
//
// SECURITY: these endpoints expose internal state (queue stats, init config,
// raw audit rows). Mount them behind authentication middleware or restrict
// them to internal network interfaces before exposing to untrusted callers.
//
// Mount with chi: r.Mount("/api/v1/logs", fasten.NewReader())
// Mount with stdlib mux: mux.Handle("/api/v1/logs/", http.StripPrefix("/api/v1/logs", fasten.NewReader()))
func (e *Engine) NewReader() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /sys", e.handleSys)
	mux.HandleFunc("GET /api", e.handleAPI)
	mux.HandleFunc("GET /audit/doctor", e.handleAuditDoctor)
	mux.HandleFunc("GET /audit", e.handleAudit)
	return mux
}

// NewReader is a package-level shorthand for Default.NewReader().
func NewReader() http.Handler { return Default.NewReader() }

// defaultPersistedStreams is the durability default applied when an engine was
// never Init'd (nil persistedStreams): audit is the only store-backed stream
// today. Init seeds a per-engine copy from this; streamSource falls back to it
// so the default lives in exactly one declarative place — mirroring the Python
// router's frozenset({"audit"}), and keeping the resolver free of any
// hardcoded stream name.
var defaultPersistedStreams = map[string]bool{"audit": true}

// streamSource reports whether a stream is backed by the durable store or a
// bounded ring, so consumers stay honest about gaps.
//
// This is the stream's configured *durability class*, not a per-response gap
// signal: it says whether the stream CAN lose rows, never whether THIS response
// did. A ring that overflowed and evicted older matching rows still reports
// "ring" — identical to an empty ring that lost nothing; there is no truncation
// flag here. (Per-response truncation honesty is deferred to Phase 1.)
//
// error/uninitialised reads still carry it so the response shape stays uniform
// (the `error` key is what signals a read actually failed). Defaults to "ring"
// unless the stream is in persistedStreams; a nil map (engine never Init'd)
// falls back to defaultPersistedStreams.
func (e *Engine) streamSource(stream string) string {
	persisted := e.persistedStreams
	if persisted == nil {
		persisted = defaultPersistedStreams
	}
	if persisted[stream] {
		return "store"
	}
	return "ring"
}

func (e *Engine) handleSys(w http.ResponseWriter, r *http.Request) {
	if e.xport == nil {
		writeJSON(w, map[string]any{"rows": []any{}, "completeness": map[string]string{"sys": e.streamSource("sys")}, "error": "fasten not initialised"})
		return
	}
	q := r.URL.Query()
	limit := intParam(q.Get("limit"), 100)
	rows := e.xport.QuerySyslog(limit, q.Get("level"), q.Get("request_id"), q.Get("service_id"))
	if rows == nil {
		rows = []SyslogRow{}
	}
	writeJSON(w, map[string]any{"rows": rows, "completeness": map[string]string{"sys": e.streamSource("sys")}})
}

func (e *Engine) handleAPI(w http.ResponseWriter, r *http.Request) {
	if e.xport == nil {
		writeJSON(w, map[string]any{"rows": []any{}, "completeness": map[string]string{"api": e.streamSource("api")}, "error": "fasten not initialised"})
		return
	}
	q := r.URL.Query()
	limit := intParam(q.Get("limit"), 100)
	rows := e.xport.QueryAPI(limit, q.Get("method"), q.Get("path"), q.Get("request_id"))
	if rows == nil {
		rows = []APIRow{}
	}
	writeJSON(w, map[string]any{"rows": rows, "completeness": map[string]string{"api": e.streamSource("api")}})
}

func (e *Engine) handleAudit(w http.ResponseWriter, r *http.Request) {
	if e.auditStore == nil {
		writeJSON(w, map[string]any{"rows": []any{}, "completeness": map[string]string{"audit": e.streamSource("audit")}, "error": "audit store not configured"})
		return
	}
	q := r.URL.Query()
	f := Filter{
		RequestID:    q.Get("request_id"),
		Code:         Code(q.Get("code")),
		Domain:       Domain(q.Get("domain")),
		SourceNodeID: q.Get("source_node_id"),
		Limit:        intParam(q.Get("limit"), 100),
	}
	if s := q.Get("since"); s != "" {
		f.Since, _ = time.Parse(time.RFC3339, s)
	}
	if u := q.Get("until"); u != "" {
		f.Until, _ = time.Parse(time.RFC3339, u)
	}
	// Cursor-based pagination: ?after=<monotonic_seq> returns the next page.
	// Use the lowest MonotonicSeq from the previous response as the cursor.
	if a := q.Get("after"); a != "" {
		if n, err := strconv.ParseInt(a, 10, 64); err == nil && n > 0 {
			f.AfterSeq = n
		}
	}
	rows, err := e.auditStore.Query(r.Context(), f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// convert to []map[string]any for consistent JSON
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, rowToMap(row))
	}
	// Return next_after cursor: the smallest monotonic_seq in this page so
	// the caller can pass ?after=<next_after> for the preceding page.
	// (Results are newest-first, so the last row has the smallest seq.)
	var nextAfter *int64
	if len(rows) > 0 {
		v := rows[len(rows)-1].MonotonicSeq
		nextAfter = &v
	}
	writeJSON(w, map[string]any{"rows": out, "next_after": nextAfter, "completeness": map[string]string{"audit": e.streamSource("audit")}})
}

func (e *Engine) handleAuditDoctor(w http.ResponseWriter, r *http.Request) {
	store := e.auditStore
	storeBlock := map[string]any{
		"kind":           nil,
		"reachable":      false,
		"rows":           nil,
		"last_insert_at": nil,
		"last_error":     nil,
	}
	if store != nil {
		storeBlock["kind"] = fmt.Sprintf("%T", store)
		func() {
			defer func() {
				if p := recover(); p != nil {
					storeBlock["last_error"] = fmt.Sprintf("panic: %v", p)
				}
			}()
			if counter, ok := store.(interface{ Count(context.Context) (int, error) }); ok {
				n, err := counter.Count(r.Context())
				if err != nil {
					storeBlock["last_error"] = err.Error()
				} else {
					storeBlock["rows"] = n
					storeBlock["reachable"] = true
				}
			} else {
				storeBlock["reachable"] = true
			}
		}()
	}

	var queueBlock any
	if qs := e.GetQueueStats(); qs != nil {
		queueBlock = qs
	}

	xportBlock := map[string]any{
		"stdout_active":     e.xport != nil,
		"syslog_ring_depth": 0,
		"api_ring_depth":    0,
	}
	if e.xport != nil {
		xportBlock["syslog_ring_depth"] = e.xport.SyslogDepth()
		xportBlock["api_ring_depth"] = e.xport.APIDepth()
	}

	initBlock := map[string]any{
		"service_id":       e.serviceID,
		"node_id":          e.nodeID,
		"tenant_id":        e.tenantID,
		"failure_strategy": e.failureStrategy,
	}

	writeJSON(w, map[string]any{
		"store":     storeBlock,
		"queue":     queueBlock,
		"transport": xportBlock,
		"init":      initBlock,
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func intParam(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return def
	}
	if n > 1000 {
		return 1000
	}
	return n
}

// contextKey for stdlib context (unexported, avoids collision).
var _ context.Context = context.Background() // compile-time check
