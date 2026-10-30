package fasten

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// FR5 reader parity: /audit honours actor/target/tenant_id, /topology exists,
// and /audit/doctor carries the redactor/chain/worker_pid blocks — matching the
// Python reader.

func initAuditReader(t *testing.T) {
	t.Helper()
	resetGlobals(t)
	registerTestCodes(t)
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := NewSQLiteStore(db, "audit_parity")
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	if err := Init(Config{ServiceID: "svc", NodeID: "node", AuditStore: store, AuditStoreFailureStrategy: "raise"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
}

func emitRow(t *testing.T, rid, actor, target string) {
	t.Helper()
	ctx := WithRequestID(context.Background(), rid)
	if _, err := Emit(ctx, "USER_CREATED", Target(target), Actor(actor, "user")); err != nil {
		t.Fatalf("Emit: %v", err)
	}
}

func TestAudit_ActorAndTargetFilters(t *testing.T) {
	initAuditReader(t)
	emitRow(t, "r1", "alice", "u-1")
	emitRow(t, "r2", "bob", "u-2")

	body, _ := getJSON(t, NewReader(), "/audit?actor=alice")
	rows, _ := body["rows"].([]any)
	if len(rows) != 1 || rows[0].(map[string]any)["actor"] != "alice" {
		t.Errorf("actor filter: %v", rows)
	}

	body, _ = getJSON(t, NewReader(), "/audit?target=u-2")
	rows, _ = body["rows"].([]any)
	if len(rows) != 1 || rows[0].(map[string]any)["target"] != "u-2" {
		t.Errorf("target filter: %v", rows)
	}
}

func TestTopology_AggregatesSources(t *testing.T) {
	initAuditReader(t)
	emitRow(t, "r1", "alice", "u-1")
	emitRow(t, "r2", "bob", "u-2")

	body, _ := getJSON(t, NewReader(), "/topology")
	sources, _ := body["sources"].([]any)
	if len(sources) != 1 {
		t.Fatalf("sources=%v, want 1 (same node/service/tenant)", sources)
	}
	s0 := sources[0].(map[string]any)
	if s0["rows"] != float64(2) || s0["source_node_id"] != "node" || s0["service_id"] != "svc" {
		t.Errorf("source=%v", s0)
	}
	if body["nodes"] != float64(1) || body["services"] != float64(1) {
		t.Errorf("counts: nodes=%v services=%v", body["nodes"], body["services"])
	}
}

func TestTopology_NoStore(t *testing.T) {
	resetGlobals(t)
	body, _ := getJSON(t, (&Engine{}).NewReader(), "/topology") // never Init'd
	if body["error"] == nil {
		t.Errorf("want error when no store, got %v", body)
	}
}

func TestAuditDoctor_HasParityBlocks(t *testing.T) {
	initAuditReader(t)
	emitRow(t, "r1", "alice", "u-1")

	body, _ := getJSON(t, NewReader(), "/audit/doctor")
	if _, ok := body["redactor"]; !ok {
		t.Error("doctor missing redactor block")
	}
	if _, ok := body["chain"]; !ok {
		t.Error("doctor missing chain block")
	}
	initBlock, _ := body["init"].(map[string]any)
	if _, ok := initBlock["worker_pid"]; !ok {
		t.Error("doctor init missing worker_pid")
	}
	chain, _ := body["chain"].(map[string]any)
	if chain["verified"] != true {
		t.Errorf("chain block not verified: %v", chain)
	}
	if chain["breaks"] != float64(0) {
		t.Errorf("verified chain must report breaks:0 not %v", chain["breaks"])
	}
	if chain["last_verified_at"] == nil {
		t.Error("verified chain must stamp last_verified_at")
	}
}

// PR #59 finding 10 (Go parity with Python's a2bbc16 fix): when the chain
// check never runs, the doctor must NOT report breaks:0 — a status page
// colouring on that field would show green over a store that was never
// actually verified.
func TestAuditDoctor_EmptyStoreReportsBreaksNull(t *testing.T) {
	initAuditReader(t) // fresh store, no rows emitted
	body, _ := getJSON(t, NewReader(), "/audit/doctor")
	chain, _ := body["chain"].(map[string]any)
	if chain["verified"] != nil {
		t.Errorf("empty store must not set verified; got %v", chain["verified"])
	}
	if chain["breaks"] != nil {
		t.Errorf("empty store must report breaks:null (not verified); got %v", chain["breaks"])
	}
	if chain["last_verified_at"] != nil {
		t.Errorf("empty store must not stamp last_verified_at; got %v", chain["last_verified_at"])
	}
}

func TestAuditDoctor_NoStoreReportsBreaksNull(t *testing.T) {
	// A stdout-only engine has no audit store; the chain block must be all
	// nulls, never breaks:0.
	resetGlobals(t)
	registerTestCodes(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	body, _ := getJSON(t, NewReader(), "/audit/doctor")
	chain, _ := body["chain"].(map[string]any)
	if chain["verified"] != nil || chain["breaks"] != nil {
		t.Errorf("stdout-only engine must report chain nulls; got %v", chain)
	}
}

// PR #59 finding 10: a query error must surface an `error` field, not
// silently collapse to breaks:0.
func TestAuditDoctor_QueryErrorSurfacesError(t *testing.T) {
	resetGlobals(t)
	registerTestCodes(t)
	broken := &brokenQueryStore{}
	if err := Init(Config{ServiceID: "svc", NodeID: "node", AuditStore: broken,
		AuditStoreFailureStrategy: "raise"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	body, _ := getJSON(t, NewReader(), "/audit/doctor")
	chain, _ := body["chain"].(map[string]any)
	if chain["error"] == nil {
		t.Errorf("chain block must carry error when query fails; got %v", chain)
	}
	if chain["breaks"] != nil {
		t.Errorf("query-failed chain must report breaks:null (not 0); got %v", chain["breaks"])
	}
}

// brokenQueryStore is an AuditRepository whose Query always errors. Any
// non-Query call is fine so Init + Emit still work.
type brokenQueryStore struct{}

func (*brokenQueryStore) Insert(context.Context, Row) error { return nil }
func (*brokenQueryStore) Query(context.Context, Filter) ([]Row, error) {
	return nil, errBrokenQuery
}
func (*brokenQueryStore) ListUnshipped(context.Context, int) ([]Row, error) { return nil, nil }
func (*brokenQueryStore) MarkShipped(context.Context, []string) error        { return nil }
func (*brokenQueryStore) Purge(context.Context, time.Time, bool) (int, error) {
	return 0, nil
}

var errBrokenQuery = errBrokenStr("simulated query failure")

type errBrokenStr string

func (e errBrokenStr) Error() string { return string(e) }

// countFailingStore also fails CountFiltered, so the doctor's store check errors.
type countFailingStore struct{ brokenQueryStore }

func (*countFailingStore) CountFiltered(context.Context, Filter) (int, error) {
	return 0, errBrokenQuery
}

// Store errors can quote SQL and the database host and user. They go to the
// sys log; the response carries fixed text.
func TestReader_StoreErrorsStayOutOfResponses(t *testing.T) {
	resetGlobals(t)
	registerTestCodes(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node", AuditStore: &countFailingStore{},
		AuditStoreFailureStrategy: "raise"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	rec := httptest.NewRecorder()
	NewReader().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/audit", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("/audit: want 500, got %d", rec.Code)
	}
	if body := rec.Body.String(); strings.Contains(body, errBrokenQuery.Error()) {
		t.Errorf("/audit 500 body carries the store error: %q", body)
	}

	body, _ := getJSON(t, NewReader(), "/audit/doctor")
	store := body["store"].(map[string]any)
	chain := body["chain"].(map[string]any)
	if store["last_error"] == nil || chain["reason"] == nil {
		t.Fatalf("doctor must still flag both failed checks; got store=%v chain=%v", store, chain)
	}
	for _, v := range []any{store["last_error"], chain["reason"]} {
		if strings.Contains(v.(string), errBrokenQuery.Error()) {
			t.Errorf("doctor carries the store error: %q", v)
		}
	}

	logged, err := GetTransport().QuerySyslog(50, StreamQuery{})
	if err != nil {
		t.Fatalf("QuerySyslog: %v", err)
	}
	events := map[string]bool{}
	for _, row := range logged {
		for _, v := range row {
			if s, ok := v.(string); ok && strings.Contains(s, errBrokenQuery.Error()) {
				t.Errorf("sys line carries the store error: %v", row)
			}
		}
		if row["error_type"] == "fasten.errBrokenStr" {
			events[row["event"].(string)] = true
		}
	}
	if !events["reader_query_failed"] || !events["doctor_check_failed"] {
		t.Errorf("store errors must reach the sys log by type; got %v", events)
	}
}

// countOnlyStore has the unscoped Count but not CountFiltered.
type countOnlyStore struct{ brokenQueryStore }

func (*countOnlyStore) Count(context.Context) (int, error) { return 7, nil }

func TestAuditDoctor_CountOnlyStoreStillReportsRows(t *testing.T) {
	resetGlobals(t)
	registerTestCodes(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node", AuditStore: &countOnlyStore{},
		AuditStoreFailureStrategy: "raise"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	body, _ := getJSON(t, NewReader(), "/audit/doctor")
	if rows := body["store"].(map[string]any)["rows"]; rows != float64(7) {
		t.Errorf("unscoped doctor must use Count; got %v", rows)
	}
	h := NewReader(WithTenantScope(func(*http.Request) (string, bool) { return "tenant-a", true }))
	body, _ = getJSON(t, h, "/audit/doctor")
	store := body["store"].(map[string]any)
	if store["rows"] != nil || store["reachable"] != true {
		t.Errorf("scoped doctor must not report an unscoped count; got %v", store)
	}
}
