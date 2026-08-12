package fasten

import (
	"context"
	"database/sql"
	"testing"

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
}
