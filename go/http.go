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

// NewReader returns an http.Handler serving:
//
//	GET /sys           — syslog ring buffer
//	GET /api           — api-log ring buffer
//	GET /audit         — audit SQLite store
//	GET /audit/doctor  — audit pipeline health (P1-15)
//
// Mount with chi: r.Mount("/api/v1/logs", fasten.NewReader())
// Mount with stdlib mux: mux.Handle("/api/v1/logs/", http.StripPrefix("/api/v1/logs", fasten.NewReader()))
func NewReader() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /sys", handleSys)
	mux.HandleFunc("GET /api", handleAPI)
	mux.HandleFunc("GET /audit/doctor", handleAuditDoctor)
	mux.HandleFunc("GET /audit", handleAudit)
	return mux
}

func handleSys(w http.ResponseWriter, r *http.Request) {
	if Default.xport == nil {
		writeJSON(w, map[string]any{"rows": []any{}, "error": "fasten not initialised"})
		return
	}
	q := r.URL.Query()
	limit := intParam(q.Get("limit"), 100)
	rows := Default.xport.QuerySyslog(limit, q.Get("level"), q.Get("request_id"), q.Get("service_id"))
	if rows == nil {
		rows = []SyslogRow{}
	}
	writeJSON(w, map[string]any{"rows": rows})
}

func handleAPI(w http.ResponseWriter, r *http.Request) {
	if Default.xport == nil {
		writeJSON(w, map[string]any{"rows": []any{}, "error": "fasten not initialised"})
		return
	}
	q := r.URL.Query()
	limit := intParam(q.Get("limit"), 100)
	rows := Default.xport.QueryAPI(limit, q.Get("method"), q.Get("path"), q.Get("request_id"))
	if rows == nil {
		rows = []APIRow{}
	}
	writeJSON(w, map[string]any{"rows": rows})
}

func handleAudit(w http.ResponseWriter, r *http.Request) {
	if Default.auditStore == nil {
		writeJSON(w, map[string]any{"rows": []any{}, "error": "audit store not configured"})
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
	rows, err := Default.auditStore.Query(r.Context(), f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// convert to []map[string]any for consistent JSON
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, rowToMap(row))
	}
	writeJSON(w, map[string]any{"rows": out})
}

func handleAuditDoctor(w http.ResponseWriter, r *http.Request) {
	store := Default.auditStore
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
	if qs := Default.GetQueueStats(); qs != nil {
		queueBlock = qs
	}

	xportBlock := map[string]any{
		"stdout_active":    Default.xport != nil,
		"syslog_ring_depth": 0,
		"api_ring_depth":    0,
	}
	if Default.xport != nil {
		xportBlock["syslog_ring_depth"] = Default.xport.SyslogDepth()
		xportBlock["api_ring_depth"] = Default.xport.APIDepth()
	}

	initBlock := map[string]any{
		"service_id":       Default.serviceID,
		"node_id":          Default.nodeID,
		"tenant_id":        Default.tenantID,
		"failure_strategy": Default.failureStrategy,
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
