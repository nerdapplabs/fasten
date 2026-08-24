package fasten

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// §8.1 background-work correlation — Background / Go mint a bg- sentinel when the
// context has no request_id, else inherit it. Parity with the Python
// fasten.background / fasten.go.

func TestBackground_MintsBGWhenNoContext(t *testing.T) {
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	rid := RequestIDFromContext(Background(context.Background()))
	if RequestIDKind(rid) != "bg" {
		t.Errorf("kind=%q, want bg (%q)", RequestIDKind(rid), rid)
	}
}

func TestBackground_InheritsActive(t *testing.T) {
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	ctx := WithRequestID(context.Background(), "req-real")
	if got := RequestIDFromContext(Background(ctx)); got != "req-real" {
		t.Errorf("got %q, want req-real (must not override a real id)", got)
	}
}

func TestGo_RunsUnderBGContext(t *testing.T) {
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	done := make(chan string, 1)
	Go(context.Background(), func(ctx context.Context) { done <- RequestIDFromContext(ctx) })
	if rid := <-done; RequestIDKind(rid) != "bg" {
		t.Errorf("kind=%q, want bg (%q)", RequestIDKind(rid), rid)
	}
}

func TestGo_InheritsParent(t *testing.T) {
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	done := make(chan string, 1)
	Go(WithRequestID(context.Background(), "req-parent"), func(ctx context.Context) {
		done <- RequestIDFromContext(ctx)
	})
	if rid := <-done; rid != "req-parent" {
		t.Errorf("got %q, want req-parent", rid)
	}
}

func TestBackground_SysLogCorrelatable(t *testing.T) {
	resetGlobals(t)
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	ss, err := NewStreamStore(db, "syslog")
	if err != nil {
		t.Fatalf("NewStreamStore: %v", err)
	}
	if err := Init(Config{ServiceID: "svc", NodeID: "node", SyslogStore: ss}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	ctx := Background(context.Background())
	rid := RequestIDFromContext(ctx)
	Default.LogSys(ctx, "info", "worker.tick", nil)

	rows, err := ss.Query(10, map[string]string{"request_id": rid}, "", "")
	must(t, err)
	if len(rows) != 1 || rows[0]["event"] != "worker.tick" {
		t.Errorf("bg sys row not correlatable: %v", rows)
	}
	if RequestIDKind(rid) != "bg" {
		t.Errorf("kind=%q, want bg", RequestIDKind(rid))
	}
}
