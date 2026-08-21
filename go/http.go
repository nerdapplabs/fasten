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

// NewReader returns an http.Handler bound to this Engine's configuration
// (stores, SearchEnabled, persisted streams), serving:
//
//	GET /sys               — syslog ring / store (?q= search when enabled)
//	GET /api               — api-log ring / store
//	GET /audit             — audit store query (?request_id=, ?code=, ?domain=,
//	                         ?since=, ?until=, ?limit=, ?after=<monotonic_seq>)
//	GET /audit/doctor      — audit pipeline health
//	GET /search            — cross-stream free-text search (sys-only in v1)
//	GET /correlate         — request_id → merged audit/api/sys view
//	GET /topology          — service_id → event aggregation
//
// SECURITY: these endpoints expose internal state (queue stats, init config,
// raw audit rows, full log payloads). Mount them behind authentication
// middleware or restrict them to internal network interfaces before exposing
// to untrusted callers.
//
// Mount with chi: r.Mount("/api/v1/logs", fasten.NewReader())
// Mount with stdlib mux: mux.Handle("/api/v1/logs/", http.StripPrefix("/api/v1/logs", fasten.NewReader()))
//
// Per-reader overrides (the equivalent of Python's router(persist_streams=,
// search_enabled=, store=, transport=)) are achieved by binding the reader to a
// separately-configured *Engine rather than passing options to NewReader:
//
//	e2 := &fasten.Engine{}
//	_ = e2.Init(fasten.Config{ServiceID: "svc", NodeID: "n", SearchEnabled: true,
//	    AuditStore: replica, APIStore: apiStore}) // read-replica / multi-store
//	mux.Handle("/logs/", http.StripPrefix("/logs", e2.NewReader()))
//
// so a reader can point at different stores or a different search/persistence
// policy than the process-wide Default engine.
func (e *Engine) NewReader() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /sys", e.handleSys)
	mux.HandleFunc("GET /api", e.handleAPI)
	mux.HandleFunc("GET /search", e.handleSearch)
	mux.HandleFunc("GET /correlate", e.handleCorrelate)
	mux.HandleFunc("GET /topology", e.handleTopology)
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
	if stream == "audit" {
		// Audit is not a transport stream — its degraded signal comes from the
		// audit store + drainer, not the api/sys StreamStores.
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

// auditDegraded reports whether audit durable history has known holes: the
// audit store swallowed a persist failure (sync fallback path) or the drainer
// dead-lettered at least one row (async path).
//
// The engine-side flag is checked even when the store itself doesn't expose
// Degraded (an adopter AuditRepository may not implement NoteWriteFailure —
// see Engine.auditWriteSwallowed).
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
	if e.xport == nil {
		writeJSON(w, map[string]any{"rows": []any{}, "completeness": map[string]string{"sys": e.streamSource("sys")}, "error": "fasten not initialised"})
		return
	}
	q := r.URL.Query()
	comp := map[string]string{"sys": e.streamSource("sys")}
	if qtext := q.Get("q"); qtext != "" {
		// FR3 escape hatch on the sys read: gated + time-bounded (§4.1).
		if msg := e.searchGuard(qtext, q.Get("since")); msg != "" {
			writeJSON(w, map[string]any{"rows": []any{}, "completeness": comp, "error": msg})
			return
		}
		// Reject q= combined with structured chips rather than silently
		// dropping them (parity with /api?q= — see the reject just below in
		// handleAPI). An operator who narrows with ?q=timeout&level=error
		// must not get a superset back with no signal that the chip was
		// ignored.
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
		rows, ok, err := e.xport.SearchSyslog(qtext, q.Get("since"), q.Get("until"), limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !ok {
			writeJSON(w, map[string]any{"rows": []any{}, "completeness": comp,
				"error": "search requires sys persistence — configure a syslog store (FR1)"})
			return
		}
		if rows == nil {
			rows = []SyslogRow{}
		}
		writeJSON(w, map[string]any{"rows": rows, "completeness": comp})
		return
	}
	limit, lerr := parseLimit(q.Get("limit"), 100, 1000)
	if lerr != nil {
		http.Error(w, lerr.Error(), http.StatusUnprocessableEntity)
		return
	}
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
	writeJSON(w, map[string]any{"rows": rows, "completeness": comp})
}

// searchGuard returns "" when a q= read is allowed, else the reason it is not:
// search must be explicitly enabled (§4.1) and time-bounded (since= mandatory,
// no unbounded scans).
func (e *Engine) searchGuard(q, since string) string {
	if !e.searchEnabled {
		return "search disabled — set search.enabled (FASTEN_SEARCH_ENABLED=true) to enable free-text q="
	}
	if since == "" {
		return "q= search requires a 'since' bound (no unbounded scans)"
	}
	return ""
}

// handleSearch is the FR3 free-text escape hatch (§4.1): time-bounded,
// hard-capped, no ranking, opt-in via SearchEnabled. Returns matches carrying
// request_id so a consumer can hand one to /correlate.
//
// ?streams= is a comma-separated subset of {audit, api, sys}. Default: sys.
// Each named stream must have a store — ring-only streams produce a
// per-stream error (errors.<stream>) rather than an empty list that reads
// as "no matches".
func (e *Engine) handleSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	qtext := q.Get("q")

	// Parse streams= before the guard — a bad ?streams=foo fails loudly
	// rather than falling through.
	valid := map[string]bool{"audit": true, "api": true, "sys": true}
	wanted := []string{"sys"} // default
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

	since := q.Get("since")
	until := q.Get("until")
	matches := []map[string]any{}
	counts := map[string]int{}
	errs := map[string]string{}
	// Stable stream order in the response so a UI can render tabs
	// deterministically. Sys first (the historical default), then api,
	// then audit — mirrors the /correlate response order.
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
				errs["sys"] = "requires sys persistence — configure a syslog store (FR1)"
				counts["sys"] = 0
				continue
			}
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
				errs["api"] = "requires api persistence — configure an api store (FR1)"
				counts["api"] = 0
				continue
			}
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
				Search(ctx context.Context, q, since, until string, limit int) ([]Row, error)
			})
			if e.auditStore == nil || !ok {
				errs["audit"] = "requires an audit store with a Search method (FR1)"
				counts["audit"] = 0
				continue
			}
			rows, err := searcher.Search(r.Context(), qtext, since, until, limit)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			counts["audit"] = len(rows)
			for _, row := range rows {
				ts := ""
				if !row.Timestamp.IsZero() {
					ts = row.Timestamp.UTC().Format(time.RFC3339Nano)
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
	if e.xport == nil {
		writeJSON(w, map[string]any{"rows": []any{}, "completeness": map[string]string{"api": e.streamSource("api")}, "error": "fasten not initialised"})
		return
	}
	q := r.URL.Query()
	if _, ok := q["q"]; ok {
		// Free-text search is sys-only in v1 (§9). Reject rather than
		// silently drop, so callers can't assume q= works on the api stream.
		http.Error(w, "free-text q= not accepted on /api — use /search?streams=api "+
			"(or /logs/sys?q= for syslog only)", http.StatusBadRequest)
		return
	}
	limit, lerr := parseLimit(q.Get("limit"), 100, 1000)
	if lerr != nil {
		http.Error(w, lerr.Error(), http.StatusUnprocessableEntity)
		return
	}
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
	limit, lerr := parseLimit(r.URL.Query().Get("limit"), 100, 1000)
	if lerr != nil {
		http.Error(w, lerr.Error(), http.StatusUnprocessableEntity)
		return
	}

	audit := []map[string]any{}
	// auditTotal is *int so a count failure (or missing filterCounter capability)
	// reports null rather than lying with len(rows) — which is capped at limit,
	// so counts == totals and truncated would read false when the caller has 100
	// of 4,000 rows. Spec §4.1 makes counts-vs-totals the normative truncation
	// signal; a null total is honest, a total equal to the cap is a lie
	// (PR #59 finding 9).
	var auditTotal *int
	if e.auditStore != nil {
		rows, err := e.auditStore.Query(r.Context(), Filter{RequestID: rid, Limit: limit})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		for _, row := range rows {
			audit = append(audit, rowToMap(row))
		}
		if counter, ok := e.auditStore.(filterCounter); ok {
			if n, err := counter.CountFiltered(r.Context(), Filter{RequestID: rid}); err == nil {
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

	// Truncation is counts < totals per stream. The pair is authoritative; this
	// boolean is a convenience so every caller doesn't re-derive the inequality
	// (and get it subtly wrong). Reported per stream. audit total may be null
	// (count failure or no filterCounter capability), in which case truncated
	// is also null — an honest "unknown", not a spurious false.
	var auditTruncated any
	if auditTotal != nil {
		auditTruncated = len(audit) < *auditTotal
	}
	// totals must marshal as {audit: null, api: N, sys: N} on count failure.
	// A map[string]int can't hold nil, so use map[string]any.
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
	// Cursor-based pagination: ?after=<monotonic_seq> returns the next page.
	// Use the lowest MonotonicSeq from the previous response as the cursor.
	after, aerr := parseNonNegInt("after", q.Get("after"), 0)
	if aerr != nil {
		http.Error(w, aerr.Error(), http.StatusUnprocessableEntity)
		return
	}
	f := Filter{
		RequestID:    q.Get("request_id"),
		Code:         Code(q.Get("code")),
		Domain:       Domain(q.Get("domain")),
		SourceNodeID: q.Get("source_node_id"),
		TenantID:     q.Get("tenant_id"),
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
	// convert to []map[string]any for consistent JSON
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, rowToMap(row))
	}
	// Dual pagination (FR5): offset (total/limit/offset) for page-number UIs and
	// cursor (next_after) as the canonical, insert-stable model. next_after is
	// the smallest monotonic_seq in this page (results are newest-first), passed
	// back as ?after= to page forward into older rows. Both are always reported.
	// total is *int so a count failure (or no filterCounter) reports null rather
	// than falling back to len(rows) — which is capped at limit, so a paginating
	// caller can't tell page N is the last one. Null = unknown; consumers should
	// treat that as "may have more" (PR #59 finding 9).
	var total *int
	if counter, ok := e.auditStore.(filterCounter); ok {
		// CountFiltered ignores Limit/Offset/AfterSeq → the full filtered count.
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

// sourceAggregator is the optional fleet-topology capability of an audit store.
// The built-in SQLite store implements it; stores that don't cause /topology to
// report "store does not support topology aggregation".
type sourceAggregator interface {
	Sources(ctx context.Context, since, until time.Time) ([]map[string]any, error)
}

// handleTopology reports who is emitting into the store — one entry per distinct
// (source_node_id, service_id, tenant_id) with row counts and first/last-seen —
// plus distinct node/service/tenant counts. No separate topology table: the
// fleet view falls out of the rows already recorded, so it can't drift. Parity
// with the Python /topology.
func (e *Engine) handleTopology(w http.ResponseWriter, r *http.Request) {
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

	// Spot-check the tamper chain over this node's latest rows (best-effort).
	chainBlock := map[string]any{"verified": nil, "breaks": 0, "last_verified_at": nil}
	if store != nil {
		if recent, err := store.Query(r.Context(), Filter{SourceNodeID: e.nodeID, Limit: 50}); err == nil && len(recent) > 0 {
			res := VerifyChain(recent)
			breaks := 0
			if !res.OK {
				breaks = 1
			}
			chainBlock = map[string]any{
				"verified":       res.OK,
				"breaks":         breaks,
				"first_break_at": res.FirstBreakAt,
				"reason":         res.Reason,
			}
		}
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

// parseLimit parses the ?limit= param for the structured-query endpoints.
// Empty -> def. A present value must be an integer in [1, max]; anything else
// (non-integer, non-positive, over max) is a caller error, returned so the
// handler can answer 422 — parity with Python's Query(ge=1, le=max), which
// rejects rather than silently coercing to the default or clamping.
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

// parseNonNegInt parses ?offset=, ?after=, etc. Same policy as parseLimit:
// empty -> def, non-integer / negative -> caller error. Fixes the silent
// coercion where ?after=12a3 fell back to 0 and re-served page one, so a
// client paging to exhaustion looped forever (PR #59 finding 8).
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

// parseRFC3339 parses ?since= / ?until= strictly. A malformed value used to
// zero-out the bound silently, which dropped the whole window and returned
// an aggregate over all history under HTTP 200 (PR #59 finding 8).
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

// parseSearchLimit resolves the FR3 result cap: default 50, hard max 200.
// Rejects non-integer / out-of-range rather than silently coercing.
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

// contextKey for stdlib context (unexported, avoids collision).
var _ context.Context = context.Background() // compile-time check
