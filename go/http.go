package fasten

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// RequestID is middleware that reads X-Request-ID, or mints one, and puts it
// in the request context and the response header.
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

// APILogger records each request in fasten's api stream, except for paths
// in skipPaths (e.g. "/_system/health").
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
					"timestamp":   canonicalTS(start),
				})
			}
		})
	}
}

// NewReader returns an http.Handler for this Engine's stores and settings,
// serving:
//
//	GET /sys               syslog rows (?q= search when enabled)
//	GET /api               api log rows
//	GET /audit             audit rows (?request_id=, ?code=, ?domain=,
//	                       ?since=, ?until=, ?limit=, ?after=<monotonic_seq>)
//	GET /audit/doctor      audit pipeline health
//	GET /search            free-text search (?streams= audit, api, sys; default sys)
//	GET /correlate         audit, api and sys rows for one request_id
//	GET /topology          emitting nodes, services and tenants
//
// SECURITY: these endpoints expose internal state (queue stats, init config,
// raw audit rows, full log payloads). Mount them behind authentication
// middleware or restrict them to internal network interfaces before exposing
// to untrusted callers.
//
// Mount with chi: r.Mount("/api/v1/logs", fasten.NewReader())
// Mount with stdlib mux: mux.Handle("/api/v1/logs/", http.StripPrefix("/api/v1/logs", fasten.NewReader()))
//
// For a reader with different stores or settings from Default, create a
// separate Engine and call its NewReader:
//
//	e2 := &fasten.Engine{}
//	_ = e2.Init(fasten.Config{ServiceID: "svc", NodeID: "n", SearchEnabled: true,
//	    AuditStore: replica, APIStore: apiStore}) // read-replica / multi-store
//	mux.Handle("/logs/", http.StripPrefix("/logs", e2.NewReader()))
//
// Tenant isolation: on shared-store multi-tenant deployments wire
//
//	fasten.NewReader(fasten.WithTenantScope(fn), fasten.EnforceTenantIsolation())
//
// where `fn func(*http.Request) (tenant string, ok bool)` returns the
// resolved tenant from the (already-authenticated) request. Every reader
// endpoint (/audit, /correlate, /search, /sys, /api, /topology) then
// injects that tenant into the store filter and IGNORES any caller
// ?tenant_id=. Without the hook, ?tenant_id= is honoured as-is — safe
// for single-tenant deployments, unsafe on any shared-store multi-
// tenant fleet.
func (e *Engine) NewReader(opts ...ReaderOption) http.Handler {
	// Options are collected into a SCRATCH Engine, never applied to e.
	// Applying them to e mutated shared state: fasten.NewReader() targets the
	// package-level Default, so a second reader silently re-scoped the first
	// and two policies on one engine were impossible. The scratch value exists
	// only to keep ReaderOption's public signature (func(*Engine)) intact.
	scratch := &Engine{}
	for _, opt := range opts {
		opt(scratch)
	}
	rc := readerConfig{
		tenantScope:            scratch.tenantScope,
		enforceTenantIsolation: scratch.enforceTenantIsolation,
	}
	if rc.enforceTenantIsolation && rc.tenantScope == nil {
		panic("fasten.NewReader(EnforceTenantIsolation()) requires WithTenantScope(fn) — " +
			"wire (r) -> (tenant, ok) from your auth layer, or drop " +
			"EnforceTenantIsolation() for a single-tenant deployment.")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /sys", e.handleSys)
	mux.HandleFunc("GET /api", e.handleAPI)
	mux.HandleFunc("GET /search", e.handleSearch)
	mux.HandleFunc("GET /correlate", e.handleCorrelate)
	mux.HandleFunc("GET /topology", e.handleTopology)
	mux.HandleFunc("GET /audit/doctor", e.handleAuditDoctor)
	mux.HandleFunc("GET /audit", e.handleAudit)

	// Carry this reader's config on the request, so handlers stay *Engine
	// methods and resolveTenant reads per-reader scope instead of engine state.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(w, r.WithContext(
			context.WithValue(r.Context(), readerConfigKey{}, rc)))
	})
}

// readerConfig is the per-reader scope policy. It lives on the request rather
// than on the Engine so two readers over one engine can hold different
// policies.
type readerConfig struct {
	tenantScope            func(*http.Request) (string, bool)
	enforceTenantIsolation bool
}

type readerConfigKey struct{}

// readerConfigFrom returns the config for the reader handling r, falling back
// to the engine fields for callers that invoke handlers outside NewReader
// (tests, and any adopter wiring handlers directly).
func (e *Engine) readerConfigFrom(r *http.Request) readerConfig {
	if rc, ok := r.Context().Value(readerConfigKey{}).(readerConfig); ok {
		return rc
	}
	return readerConfig{
		tenantScope:            e.tenantScope,
		enforceTenantIsolation: e.enforceTenantIsolation,
	}
}

// NewReader is a package-level shorthand for Default.NewReader().
func NewReader(opts ...ReaderOption) http.Handler { return Default.NewReader(opts...) }

// ReaderOption configures a reader constructed by NewReader.
type ReaderOption func(*Engine)

// WithTenantScope wires a tenant-resolution hook. See NewReader's doc.
// The hook returns (tenant, ok) — ok=false signals unauthenticated, and
// the handler responds 401 with no rows leaked.
func WithTenantScope(fn func(*http.Request) (string, bool)) ReaderOption {
	return func(e *Engine) { e.tenantScope = fn }
}

// EnforceTenantIsolation refuses to construct the reader unless
// WithTenantScope is also wired. Set this on any shared-store multi-
// tenant deployment so a mis-configured reader can't ship without
// tenant enforcement.
func EnforceTenantIsolation() ReaderOption {
	return func(e *Engine) { e.enforceTenantIsolation = true }
}

// resolveTenant runs the scope hook. It returns:
//   - ("", true) when no hook is wired (single-tenant mode)
//   - (tenant, true) when the hook returns a scope
//   - ("", false) when the hook returns ok=false or an empty tenant; a 401
//     has been written and the caller must return
func (e *Engine) resolveTenant(w http.ResponseWriter, r *http.Request) (string, bool) {
	rc := e.readerConfigFrom(r)
	if rc.tenantScope == nil {
		return "", true
	}
	t, ok := rc.tenantScope(r)
	if !ok || t == "" {
		// t == "" is a resolved-but-blank scope. Every downstream branch tests
		// `tenant != ""` / `scope == ""` and treats blank as "no filter", so
		// letting it through turns isolation into a full cross-tenant read —
		// the same defect fixed on the Python side.
		http.Error(w, "unauthenticated: tenant scope unresolved", http.StatusUnauthorized)
		return "", false
	}
	return t, true
}

// scopeStreamRows post-filters sys/api rows by tenant. See the Python
// _scope_stream_rows for the reasoning (tenant_id is a payload key,
// not a lifted index column). scope="" is single-tenant mode.
func scopeSyslogRows(rows []SyslogRow, scope string) []SyslogRow {
	if scope == "" {
		if rows == nil {
			return []SyslogRow{} // never marshal as null
		}
		return rows
	}
	out := make([]SyslogRow, 0, len(rows))
	for _, r := range rows {
		if t, _ := r["tenant_id"].(string); t == scope {
			out = append(out, r)
		}
	}
	return out
}

func scopeAPIRows(rows []APIRow, scope string) []APIRow {
	if scope == "" {
		if rows == nil {
			return []APIRow{} // never marshal as null
		}
		return rows
	}
	out := make([]APIRow, 0, len(rows))
	for _, r := range rows {
		if t, _ := r["tenant_id"].(string); t == scope {
			out = append(out, r)
		}
	}
	return out
}

// streamSource returns the completeness value for a stream: "store" if it
// has a store, "store-degraded" if that store has missed writes, else "ring".
// It describes the stream, not one response: a ring that has dropped rows
// still says "ring". For /correlate, counts vs totals shows truncation.
func (e *Engine) streamSource(stream string) string {
	if !e.persistedStreams[stream] {
		return "ring"
	}
	if stream == "audit" {
		// Audit's degraded state comes from the audit store and drainer.
		if e.auditDegraded() {
			return "store-degraded"
		}
		return "store"
	}
	var st StreamRepository
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

// auditDegraded reports whether an audit write was swallowed (engine or
// store flag) or the drainer dead-lettered a row.
func (e *Engine) auditDegraded() bool {
	if e.auditWriteSwallowed.Load() {
		return true
	}
	if d, ok := e.auditStore.(interface{ Degraded() bool }); ok && d.Degraded() {
		return true
	}
	if qs := e.GetQueueStats(); qs != nil && qs.DeadLetteredTotal > 0 {
		return true
	}
	return false
}

func (e *Engine) handleSys(w http.ResponseWriter, r *http.Request) {
	tenant, tok := e.resolveTenant(w, r)
	if !tok {
		return
	}
	if e.xport == nil {
		writeJSON(w, map[string]any{"rows": []any{}, "completeness": map[string]string{"sys": e.streamSource("sys")}, "error": "fasten not initialised"})
		return
	}
	q := r.URL.Query()
	comp := map[string]string{"sys": e.streamSource("sys")}
	if qtext := q.Get("q"); qtext != "" {
		// Free-text search must be enabled and time-bounded (§4.1).
		if msg := e.searchGuard(qtext, q.Get("since")); msg != "" {
			writeJSON(w, map[string]any{"rows": []any{}, "completeness": comp, "error": msg})
			return
		}
		// q= can't be combined with structured filters. Reject rather than
		// ignore them, or ?q=timeout&level=error would return more than asked.
		var dropped []string
		for _, name := range []string{"level", "request_id", "service_id", "event"} {
			if q.Get(name) != "" {
				dropped = append(dropped, name)
			}
		}
		if len(dropped) > 0 {
			http.Error(w, "q= is a free-text search and cannot be combined with "+
				"structured filters ("+strings.Join(dropped, ", ")+"). Use one or "+
				"the other — structured filters run over the store index; q= runs "+
				"over the raw payload.", http.StatusBadRequest)
			return
		}
		limit, lerr := parseSearchLimit(q.Get("limit"))
		if lerr != nil {
			http.Error(w, lerr.Error(), http.StatusUnprocessableEntity)
			return
		}
		since, serr := parseWindowTS("since", q.Get("since"))
		if serr != nil {
			http.Error(w, serr.Error(), http.StatusUnprocessableEntity)
			return
		}
		until, uerr := parseWindowTS("until", q.Get("until"))
		if uerr != nil {
			http.Error(w, uerr.Error(), http.StatusUnprocessableEntity)
			return
		}
		rows, ok, err := e.xport.SearchSyslog(qtext, since, until, limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !ok {
			writeJSON(w, map[string]any{"rows": []any{}, "completeness": comp,
				"error": "search requires sys persistence: configure a syslog store"})
			return
		}
		if rows == nil {
			rows = []SyslogRow{}
		}
		writeJSON(w, map[string]any{"rows": scopeSyslogRows(rows, tenant), "completeness": comp})
		return
	}
	limit, lerr := parseLimit(q.Get("limit"), 100, 1000)
	if lerr != nil {
		http.Error(w, lerr.Error(), http.StatusUnprocessableEntity)
		return
	}
	since, serr := parseWindowTS("since", q.Get("since"))
	if serr != nil {
		http.Error(w, serr.Error(), http.StatusUnprocessableEntity)
		return
	}
	until, uerr := parseWindowTS("until", q.Get("until"))
	if uerr != nil {
		http.Error(w, uerr.Error(), http.StatusUnprocessableEntity)
		return
	}
	rows, err := e.xport.QuerySyslog(limit, StreamQuery{
		Level:     q.Get("level"),
		RequestID: q.Get("request_id"),
		ServiceID: q.Get("service_id"),
		Event:     q.Get("event"),
		Since:     since,
		Until:     until,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []SyslogRow{}
	}
	writeJSON(w, map[string]any{"rows": scopeSyslogRows(rows, tenant), "completeness": comp})
}

// MaxQueryLength is the maximum accepted length of ?q= on /sys, /api,
// and /search. Rejects a naive attempt to DoS the store's LIKE pattern
// with a multi-MB query. Same limit as the Python SDK.
const MaxQueryLength = 1024

// searchGuard returns "" when a q= read is allowed, else the reason it is not:
// search must be explicitly enabled (§4.1) and time-bounded (since= mandatory,
// no unbounded scans). Also caps q= length so a caller can't hand the store
// a multi-MB LIKE pattern that runs quadratic per row.
func (e *Engine) searchGuard(q, since string) string {
	// Count runes, not bytes, to match Python's max_length (characters).
	if utf8.RuneCountInString(q) > MaxQueryLength {
		return fmt.Sprintf("q= is capped at %d characters", MaxQueryLength)
	}
	if !e.searchEnabled {
		return "search disabled — set search.enabled (FASTEN_SEARCH_ENABLED=true) to enable free-text q="
	}
	if since == "" {
		return "q= search requires a 'since' bound (no unbounded scans)"
	}
	return ""
}

// handleSearch serves free-text search (§4.1): enabled via SearchEnabled,
// time-bounded, capped, unranked. Each match carries its request_id for
// /correlate.
//
// ?streams= is a comma-separated subset of audit, api, sys (default sys). A
// stream without a store gets an entry in errors rather than an empty list
// that would look like "no matches".
func (e *Engine) handleSearch(w http.ResponseWriter, r *http.Request) {
	tenant, tok := e.resolveTenant(w, r)
	if !tok {
		return
	}
	q := r.URL.Query()
	qtext := q.Get("q")

	// Check streams= first, so ?streams=foo is a 400 whatever else is wrong.
	valid := map[string]bool{"audit": true, "api": true, "sys": true}
	wanted := []string{"sys"}
	if s := q.Get("streams"); s != "" {
		wanted = wanted[:0]
		for _, p := range strings.Split(s, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if !valid[p] {
				http.Error(w,
					fmt.Sprintf("streams=%q: unknown stream %q (valid: audit, api, sys)", s, p),
					http.StatusBadRequest)
				return
			}
			wanted = append(wanted, p)
		}
		if len(wanted) == 0 {
			wanted = []string{"sys"}
		}
	}
	completeness := map[string]string{}
	countsEmpty := map[string]int{}
	for _, s := range wanted {
		completeness[s] = e.streamSource(s)
		countsEmpty[s] = 0
	}

	fail := func(msg string) {
		writeJSON(w, map[string]any{"matches": []any{}, "counts": countsEmpty,
			"completeness": completeness, "error": msg})
	}
	if qtext == "" {
		fail("q= is required")
		return
	}
	if msg := e.searchGuard(qtext, q.Get("since")); msg != "" {
		fail(msg)
		return
	}
	if e.xport == nil {
		fail("fasten not initialised")
		return
	}
	limit, lerr := parseSearchLimit(q.Get("limit"))
	if lerr != nil {
		http.Error(w, lerr.Error(), http.StatusUnprocessableEntity)
		return
	}
	since, serr := parseWindowTS("since", q.Get("since"))
	if serr != nil {
		http.Error(w, serr.Error(), http.StatusUnprocessableEntity)
		return
	}
	until, uerr := parseWindowTS("until", q.Get("until"))
	if uerr != nil {
		http.Error(w, uerr.Error(), http.StatusUnprocessableEntity)
		return
	}
	matches := []map[string]any{}
	counts := map[string]int{}
	errs := map[string]string{}
	// Fixed stream order (sys, api, audit), as in /correlate.
	wantSet := map[string]bool{}
	for _, s := range wanted {
		wantSet[s] = true
	}
	for _, stream := range []string{"sys", "api", "audit"} {
		if !wantSet[stream] {
			continue
		}
		switch stream {
		case "sys":
			rows, ok, err := e.xport.SearchSyslog(qtext, since, until, limit)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if !ok {
				errs["sys"] = "requires sys persistence: configure a syslog store"
				counts["sys"] = 0
				continue
			}
			rows = scopeSyslogRows(rows, tenant)
			counts["sys"] = len(rows)
			for _, row := range rows {
				matches = append(matches, map[string]any{
					"stream": "sys", "request_id": row["request_id"],
					"ts": row["timestamp"], "summary": row["event"], "row": row,
				})
			}
		case "api":
			rows, ok, err := e.xport.SearchAPI(qtext, since, until, limit)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if !ok {
				errs["api"] = "requires api persistence: configure an api store"
				counts["api"] = 0
				continue
			}
			rows = scopeAPIRows(rows, tenant)
			counts["api"] = len(rows)
			for _, row := range rows {
				summary := ""
				if m, _ := row["method"].(string); m != "" {
					summary = m + " " + fmt.Sprint(row["path"])
				}
				matches = append(matches, map[string]any{
					"stream": "api", "request_id": row["request_id"],
					"ts": row["timestamp"], "summary": strings.TrimSpace(summary), "row": row,
				})
			}
		case "audit":
			searcher, ok := e.auditStore.(interface {
				Search(ctx context.Context, q, since, until, tenantID string, limit int) ([]Row, error)
			})
			if e.auditStore == nil || !ok {
				errs["audit"] = "requires an audit store with a Search method"
				counts["audit"] = 0
				continue
			}
			// Tenant scope pushed into the store (SQL WHERE tenant_id=?)
			// when resolveTenant returned a scope; "" is single-tenant.
			rows, err := searcher.Search(r.Context(), qtext, since, until, tenant, limit)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			counts["audit"] = len(rows)
			for _, row := range rows {
				ts := ""
				if !row.Timestamp.IsZero() {
					ts = canonicalTS(row.Timestamp)
				}
				matches = append(matches, map[string]any{
					"stream": "audit", "request_id": row.RequestID,
					"ts": ts, "summary": string(row.Code), "row": rowToMap(row),
				})
			}
		}
	}
	resp := map[string]any{
		"matches": matches, "counts": counts, "completeness": completeness,
	}
	if len(errs) > 0 {
		resp["errors"] = errs
	}
	writeJSON(w, resp)
}

func (e *Engine) handleAPI(w http.ResponseWriter, r *http.Request) {
	tenant, tok := e.resolveTenant(w, r)
	if !tok {
		return
	}
	if e.xport == nil {
		writeJSON(w, map[string]any{"rows": []any{}, "completeness": map[string]string{"api": e.streamSource("api")}, "error": "fasten not initialised"})
		return
	}
	q := r.URL.Query()
	if _, ok := q["q"]; ok {
		// /api doesn't take q=; api search goes through /search?streams=api.
		http.Error(w, "free-text q= not accepted on /api — use /search?streams=api "+
			"(or /logs/sys?q= for syslog only)", http.StatusBadRequest)
		return
	}
	limit, lerr := parseLimit(q.Get("limit"), 100, 1000)
	if lerr != nil {
		http.Error(w, lerr.Error(), http.StatusUnprocessableEntity)
		return
	}
	since, serr := parseWindowTS("since", q.Get("since"))
	if serr != nil {
		http.Error(w, serr.Error(), http.StatusUnprocessableEntity)
		return
	}
	until, uerr := parseWindowTS("until", q.Get("until"))
	if uerr != nil {
		http.Error(w, uerr.Error(), http.StatusUnprocessableEntity)
		return
	}
	rows, err := e.xport.QueryAPI(limit, StreamQuery{
		Method:    q.Get("method"),
		Path:      q.Get("path"),
		RequestID: q.Get("request_id"),
		Status:    q.Get("status"),
		Since:     since,
		Until:     until,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if rows == nil {
		rows = []APIRow{}
	}
	writeJSON(w, map[string]any{"rows": scopeAPIRows(rows, tenant), "completeness": map[string]string{"api": e.streamSource("api")}})
}

// filterCounter is an optional audit store method used for totals. The
// SQLite and Postgres stores implement it; without it the audit total is
// null.
type filterCounter interface {
	CountFiltered(ctx context.Context, f Filter) (int, error)
}

// handleCorrelate returns the audit, api and sys rows for one request_id,
// using the same queries as the per-stream endpoints. counts is what this
// response holds and totals is what the source holds, so counts < totals
// means it was truncated.
func (e *Engine) handleCorrelate(w http.ResponseWriter, r *http.Request) {
	tenant, tok := e.resolveTenant(w, r)
	if !tok {
		return
	}
	rid := r.URL.Query().Get("request_id")
	if rid == "" {
		http.Error(w, "request_id is required", http.StatusBadRequest)
		return
	}
	limit, lerr := parseLimit(r.URL.Query().Get("limit"), 100, 1000)
	if lerr != nil {
		http.Error(w, lerr.Error(), http.StatusUnprocessableEntity)
		return
	}

	audit := []map[string]any{}
	var auditTotal *int
	if e.auditStore != nil {
		// Tenant pushed down to the store filter — prevents the
		// X-Request-ID pivot attack where tenant B guesses/replays a
		// known tenant-A request_id to read A's rows.
		rows, err := e.auditStore.Query(r.Context(), Filter{RequestID: rid, TenantID: tenant, Limit: limit})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, row := range rows {
			audit = append(audit, rowToMap(row))
		}
		if counter, ok := e.auditStore.(filterCounter); ok {
			if n, err := counter.CountFiltered(r.Context(), Filter{RequestID: rid, TenantID: tenant}); err == nil {
				auditTotal = &n
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
		api = scopeAPIRows(a, tenant)
		s, err := e.xport.QuerySyslog(limit, StreamQuery{RequestID: rid})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sys = scopeSyslogRows(s, tenant)
		// Stream count APIs don't take tenant_id; when a scope is active
		// use the post-filter len to keep totals consistent with what
		// the caller can actually see.
		if tenant != "" {
			apiTotal = len(api)
			sysTotal = len(sys)
		} else {
			if apiTotal, err = e.xport.CountAPI(StreamQuery{RequestID: rid}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if sysTotal, err = e.xport.CountSyslog(StreamQuery{RequestID: rid}); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}

	// truncated is counts < totals per stream. If the audit total is unknown
	// (null), so is audit's truncated.
	var auditTruncated any
	if auditTotal != nil {
		auditTruncated = len(audit) < *auditTotal
	}
	// map[string]any so audit can be null.
	totals := map[string]any{"api": apiTotal, "sys": sysTotal}
	if auditTotal != nil {
		totals["audit"] = *auditTotal
	} else {
		totals["audit"] = nil
	}
	writeJSON(w, map[string]any{
		"request_id": rid,
		"audit":      audit,
		"api":        api,
		"sys":        sys,
		"counts":     map[string]int{"audit": len(audit), "api": len(api), "sys": len(sys)},
		"totals":     totals,
		"truncated": map[string]any{
			"audit": auditTruncated,
			"api":   len(api) < apiTotal,
			"sys":   len(sys) < sysTotal,
		},
		"completeness": map[string]string{
			"audit": e.streamSource("audit"),
			"api":   e.streamSource("api"),
			"sys":   e.streamSource("sys"),
		},
	})
}

func (e *Engine) handleAudit(w http.ResponseWriter, r *http.Request) {
	tenant, tok := e.resolveTenant(w, r)
	if !tok {
		return
	}
	if e.auditStore == nil {
		writeJSON(w, map[string]any{"rows": []any{}, "completeness": map[string]string{"audit": e.streamSource("audit")}, "error": "audit store not configured"})
		return
	}
	q := r.URL.Query()
	auditLimit, lerr := parseLimit(q.Get("limit"), 100, 1000)
	if lerr != nil {
		http.Error(w, lerr.Error(), http.StatusUnprocessableEntity)
		return
	}
	offset64, oerr := parseNonNegInt("offset", q.Get("offset"), 0)
	if oerr != nil {
		http.Error(w, oerr.Error(), http.StatusUnprocessableEntity)
		return
	}
	since, serr := parseRFC3339("since", q.Get("since"))
	if serr != nil {
		http.Error(w, serr.Error(), http.StatusUnprocessableEntity)
		return
	}
	until, uerr := parseRFC3339("until", q.Get("until"))
	if uerr != nil {
		http.Error(w, uerr.Error(), http.StatusUnprocessableEntity)
		return
	}
	// ?after=<monotonic_seq> pages on from the previous response's
	// next_after. Seq starts at 1, so after=0 is rejected rather than
	// treated as no cursor.
	after, aerr := parseNonNegInt("after", q.Get("after"), 0)
	if aerr != nil {
		http.Error(w, aerr.Error(), http.StatusUnprocessableEntity)
		return
	}
	if q.Get("after") != "" && after == 0 {
		http.Error(w, "after must be >= 1 (MonotonicSeq starts at 1; 0 is not a valid cursor)",
			http.StatusUnprocessableEntity)
		return
	}
	// When tenantScope is wired, override any caller-supplied
	// ?tenant_id= with the resolved scope. Without the hook, ?tenant_id=
	// is honoured as-is (single-tenant / legacy call sites).
	tenantParam := q.Get("tenant_id")
	if tenant != "" {
		tenantParam = tenant
	}
	f := Filter{
		RequestID:    q.Get("request_id"),
		Code:         Code(q.Get("code")),
		Domain:       Domain(q.Get("domain")),
		SourceNodeID: q.Get("source_node_id"),
		TenantID:     tenantParam,
		Actor:        q.Get("actor"),
		Target:       q.Get("target"),
		Limit:        auditLimit,
		Offset:       int(offset64),
		Since:        since,
		Until:        until,
		AfterSeq:     after,
	}
	rows, err := e.auditStore.Query(r.Context(), f)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, rowToMap(row))
	}
	// Both offset paging (total, limit, offset) and cursor paging
	// (next_after, the smallest seq on this page, passed back as ?after=)
	// are reported. total is null when it can't be counted, meaning "may
	// have more"; len(rows) would be capped at limit.
	var total *int
	if counter, ok := e.auditStore.(filterCounter); ok {
		// CountFiltered ignores Limit, Offset and AfterSeq.
		if n, cerr := counter.CountFiltered(r.Context(), f); cerr == nil {
			total = &n
		}
	}
	var nextAfter *int64
	if len(rows) > 0 {
		v := rows[len(rows)-1].MonotonicSeq
		nextAfter = &v
	}
	writeJSON(w, map[string]any{
		"rows":         out,
		"total":        total,
		"limit":        auditLimit,
		"offset":       int(offset64),
		"next_after":   nextAfter,
		"completeness": map[string]string{"audit": e.streamSource("audit")},
	})
}

// sourceAggregator is an optional audit store method for /topology. The
// SQLite store implements it.
type sourceAggregator interface {
	Sources(ctx context.Context, since, until time.Time) ([]map[string]any, error)
}

// handleTopology lists who is writing to the audit store: one entry per
// (source_node_id, service_id, tenant_id) with row counts and first and last
// timestamps, plus the number of distinct nodes, services and tenants.
func (e *Engine) handleTopology(w http.ResponseWriter, r *http.Request) {
	tenant, tok := e.resolveTenant(w, r)
	if !tok {
		return
	}
	empty := map[string]any{"sources": []any{}, "nodes": 0, "services": 0, "tenants": 0}
	if e.auditStore == nil {
		empty["error"] = "audit store not configured"
		writeJSON(w, empty)
		return
	}
	agg, ok := e.auditStore.(sourceAggregator)
	if !ok {
		empty["error"] = "store does not support topology aggregation"
		writeJSON(w, empty)
		return
	}
	q := r.URL.Query()
	since, serr := parseRFC3339("since", q.Get("since"))
	if serr != nil {
		http.Error(w, serr.Error(), http.StatusUnprocessableEntity)
		return
	}
	until, uerr := parseRFC3339("until", q.Get("until"))
	if uerr != nil {
		http.Error(w, uerr.Error(), http.StatusUnprocessableEntity)
		return
	}
	sources, err := agg.Sources(r.Context(), since, until)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if sources == nil {
		sources = []map[string]any{}
	}
	if tenant != "" {
		// Post-filter fleet enumeration by the resolved tenant.
		filtered := sources[:0]
		for _, s := range sources {
			if t, _ := s["tenant_id"].(string); t == tenant {
				filtered = append(filtered, s)
			}
		}
		sources = filtered
	}
	nodes, services, tenants := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, s := range sources {
		nodes[fmt.Sprint(s["source_node_id"])] = true
		services[fmt.Sprint(s["service_id"])] = true
		if t, ok := s["tenant_id"].(string); ok && t != "" {
			tenants[t] = true
		}
	}
	writeJSON(w, map[string]any{
		"sources":  sources,
		"nodes":    len(nodes),
		"services": len(services),
		"tenants":  len(tenants),
	})
}

func (e *Engine) handleAuditDoctor(w http.ResponseWriter, r *http.Request) {
	// Scope like every other handler. Without this the endpoint 200s to a
	// caller that /audit 401s, and leaks the global row count, the host
	// tenant_id, a cross-tenant chain sample, and raw driver errors carrying
	// DSN host/user.
	tenant, ok := e.resolveTenant(w, r)
	if !ok {
		return
	}
	_ = tenant
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
		// Multi-worker awareness: callers can confirm which OS process they hit.
		"worker_pid": os.Getpid(),
	}

	// Redaction is always applied (RedactDetail) once the engine is initialised.
	redactorBlock := map[string]any{"active": e.serviceID != ""}

	// Spot-check the tamper chain over this node's latest rows.
	// breaks is nil until verification actually runs; 0 when the chain is
	// clean, 1+ when broken. Never report 0 for "we didn't check" — a
	// status page colouring on this field would read green (parity with
	// Python's /audit/doctor, PR #59 finding 10).
	chainBlock := map[string]any{
		"verified":         nil,
		"breaks":           nil,
		"last_verified_at": nil,
	}
	if store != nil {
		recent, err := store.Query(r.Context(), Filter{SourceNodeID: e.nodeID, Limit: 50})
		switch {
		case err != nil:
			// Store reachable but the query failed. Surface the error so
			// operators see verification is broken rather than seeing a green
			// status page (same shape as the storeBlock's last_error above).
			chainBlock["error"] = "query failed"
			chainBlock["reason"] = err.Error()
		case len(recent) > 0:
			res := VerifyChain(recent)
			breaks := 0
			if !res.OK {
				breaks = 1
			}
			chainBlock = map[string]any{
				"verified":         res.OK,
				"breaks":           breaks,
				"first_break_at":   res.FirstBreakAt,
				"reason":           res.Reason,
				"last_verified_at": canonicalNow(),
			}
		}
		// len(recent) == 0 case: leave chainBlock as (nil, nil, nil) —
		// verification didn't run (no rows to verify is not an error, but
		// it's also not "clean").
	}

	writeJSON(w, map[string]any{
		"store":     storeBlock,
		"queue":     queueBlock,
		"transport": xportBlock,
		"redactor":  redactorBlock,
		"init":      initBlock,
		"chain":     chainBlock,
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// parseLimit parses ?limit=. Empty gives def; anything other than an integer
// in [1, max] is an error (the handler answers 422).
func parseLimit(s string, def, max int) (int, error) {
	if s == "" {
		return def, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("limit must be an integer")
	}
	if n < 1 || n > max {
		return 0, fmt.Errorf("limit must be between 1 and %d", max)
	}
	return n, nil
}

// parseNonNegInt parses ?offset=, ?after= and the like. Empty gives def;
// a non-integer or negative value is an error.
func parseNonNegInt(name, s string, def int64) (int64, error) {
	if s == "" {
		return def, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s must be a non-negative integer", name)
	}
	if n < 0 {
		return 0, fmt.Errorf("%s must be non-negative", name)
	}
	return n, nil
}

// parseRFC3339 parses ?since= or ?until=. Empty gives the zero time; a
// malformed value is an error rather than no bound.
func parseRFC3339(name, s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s must be RFC3339 (e.g. 2026-08-21T10:00:00Z): %v", name, err)
	}
	return t, nil
}

// parseWindowTS parses ?since= or ?until= and returns it in the canonical
// form (spec §4.3), so it compares correctly as a string against stored
// timestamps whatever RFC3339 form the caller used. Empty stays empty.
func parseWindowTS(name, s string) (string, error) {
	if s == "" {
		return "", nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return "", fmt.Errorf("%s must be RFC3339 (e.g. 2026-08-21T10:00:00Z): %v", name, err)
	}
	return canonicalTS(t), nil
}

// parseSearchLimit parses the search ?limit=: default 50, max 200.
func parseSearchLimit(s string) (int, error) {
	if s == "" {
		return 50, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("limit must be an integer")
	}
	if n < 1 || n > 200 {
		return 0, fmt.Errorf("limit must be between 1 and 200")
	}
	return n, nil
}
