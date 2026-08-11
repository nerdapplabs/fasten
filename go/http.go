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
	mux.HandleFunc("GET /correlate", e.handleCorrelate)
	mux.HandleFunc("GET /audit/doctor", e.handleAuditDoctor)
	mux.HandleFunc("GET /audit", e.handleAudit)
	return mux
}

// NewReader is a package-level shorthand for Default.NewReader().
func NewReader() http.Handler { return Default.NewReader() }

// streamSource reports whether a stream is backed by the durable store or a
// bounded ring, so consumers stay honest about gaps.
//
// This is the stream's configured *durability class*, not a per-response gap
// signal: it says whether the stream CAN lose rows, never whether THIS response
// did. A ring that overflowed and evicted older matching rows still reports
// "ring" — identical to an empty ring that lost nothing; there is no truncation
// flag here. (For /correlate, the totals-vs-counts pair is the per-response
// truncation signal.)
//
// A stream is "store" only when it actually has a store (audit included), so a
// stdout-only or never-Init'd engine reports "ring" rather than advertising a
// durable store that was never configured. persistedStreams is nil until Init;
// indexing a nil map yields false, so that case resolves to "ring".
//
// error/uninitialised reads still carry the flag so the response shape stays
// uniform (the `error` key is what signals a read actually failed).
//
// A store-backed stream whose sink has swallowed at least one persist
// failure reports "store-degraded": reads are still served from the store,
// but durable history has known holes (rows that live only in the ring,
// which store-backed reads never consult), so plain "store" would assert a
// durability the data no longer has. Sticky for the store's lifetime.
func (e *Engine) streamSource(stream string) string {
	if !e.persistedStreams[stream] {
		return "ring"
	}
	var st *StreamStore
	switch stream {
	case "api":
		st = e.apiStore
	case "sys":
		st = e.syslogStore
	}
	if st != nil && st.Degraded() {
		return "store-degraded"
	}
	return "store"
}

func (e *Engine) handleSys(w http.ResponseWriter, r *http.Request) {
	if e.xport == nil {
		writeJSON(w, map[string]any{"rows": []any{}, "completeness": map[string]string{"sys": e.streamSource("sys")}, "error": "fasten not initialised"})
		return
	}
	q := r.URL.Query()
	limit := intParam(q.Get("limit"), 100)
	rows, err := e.xport.QuerySyslog(limit, StreamQuery{
		Level:     q.Get("level"),
		RequestID: q.Get("request_id"),
		ServiceID: q.Get("service_id"),
		Event:     q.Get("event"),
		Since:     q.Get("since"),
		Until:     q.Get("until"),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
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
	rows, err := e.xport.QueryAPI(limit, StreamQuery{
		Method:    q.Get("method"),
		Path:      q.Get("path"),
		RequestID: q.Get("request_id"),
		Status:    q.Get("status"),
		Since:     q.Get("since"),
		Until:     q.Get("until"),
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []APIRow{}
	}
	writeJSON(w, map[string]any{"rows": rows, "completeness": map[string]string{"api": e.streamSource("api")}})
}

// filterCounter is the optional filtered-count capability of an audit store,
// used for /correlate totals. The built-in SQLite and Postgres stores
// implement it; adopter stores that don't fall back to totals == counts.
type filterCounter interface {
	CountFiltered(ctx context.Context, f Filter) (int, error)
}

// handleCorrelate is the unified correlation read (FR2): every stream for one
// request_id in a single call. Fans out to the existing per-stream query paths
// (audit store + sys/api rings-or-stores) and assembles them — no new query
// semantics. completeness reports each stream's durability class, and totals
// reports how many matching rows the backing source holds — counts is how
// many this capped response returned, so counts < totals means the response
// is truncated (raise limit or page the per-stream endpoints).
func (e *Engine) handleCorrelate(w http.ResponseWriter, r *http.Request) {
	rid := r.URL.Query().Get("request_id")
	if rid == "" {
		http.Error(w, "request_id is required", http.StatusBadRequest)
		return
	}
	limit := intParam(r.URL.Query().Get("limit"), 100)

	audit := []map[string]any{}
	auditTotal := 0
	if e.auditStore != nil {
		rows, err := e.auditStore.Query(r.Context(), Filter{RequestID: rid, Limit: limit})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, row := range rows {
			audit = append(audit, rowToMap(row))
		}
		auditTotal = len(audit)
		if counter, ok := e.auditStore.(filterCounter); ok {
			if n, err := counter.CountFiltered(r.Context(), Filter{RequestID: rid}); err == nil {
				auditTotal = n
			}
		}
	}

	api := []APIRow{}
	sys := []SyslogRow{}
	apiTotal, sysTotal := 0, 0
	if e.xport != nil {
		a, err := e.xport.QueryAPI(limit, StreamQuery{RequestID: rid})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if a != nil {
			api = a
		}
		s, err := e.xport.QuerySyslog(limit, StreamQuery{RequestID: rid})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if s != nil {
			sys = s
		}
		if apiTotal, err = e.xport.CountAPI(StreamQuery{RequestID: rid}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if sysTotal, err = e.xport.CountSyslog(StreamQuery{RequestID: rid}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	writeJSON(w, map[string]any{
		"request_id": rid,
		"audit":      audit,
		"api":        api,
		"sys":        sys,
		"counts":     map[string]int{"audit": len(audit), "api": len(api), "sys": len(sys)},
		"totals":     map[string]int{"audit": auditTotal, "api": apiTotal, "sys": sysTotal},
		"completeness": map[string]string{
			"audit": e.streamSource("audit"),
			"api":   e.streamSource("api"),
			"sys":   e.streamSource("sys"),
		},
	})
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
			if counter, ok := store.(interface {
				Count(context.Context) (int, error)
			}); ok {
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
