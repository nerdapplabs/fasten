package fasten

import (
	"database/sql"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// #58 PersistStreams — explicit allowlist that must exactly match the set of
// stream stores attached. Bidirectional error surfaces both directions of a
// mismatch. Preserves the "store means store" honesty when unset.

func newStreamTable(t *testing.T, table string) *StreamStore {
	t.Helper()
	db, _ := sql.Open("sqlite", ":memory:")
	t.Cleanup(func() { db.Close() })
	s, err := NewStreamStore(db, table)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPersistStreams_NilFallsBackToDerivation(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node",
		SyslogStore: newStreamTable(t, "s_derive"),
	}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if got := Default.streamSource("sys"); got != "store" {
		t.Errorf("nil PersistStreams should fall back to derivation; sys=%q", got)
	}
}

func TestPersistStreams_MatchesAttachedStores(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node",
		SyslogStore:    newStreamTable(t, "s_match"),
		PersistStreams: []string{"sys"},
	}); err != nil {
		t.Fatalf("Init should succeed on matching PersistStreams + store: %v", err)
	}
}

func TestPersistStreams_NamedButNoStore(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	err := Init(Config{ServiceID: "svc", NodeID: "node",
		PersistStreams: []string{"sys"},
	})
	if err == nil {
		t.Fatal("PersistStreams=[sys] without SyslogStore must fail loudly")
	}
	if !strings.Contains(err.Error(), "no store attached") {
		t.Errorf("error should name the mismatch direction; got %q", err.Error())
	}
}

func TestPersistStreams_StoreAttachedButUnlisted(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	err := Init(Config{ServiceID: "svc", NodeID: "node",
		SyslogStore:    newStreamTable(t, "s_unlisted"),
		PersistStreams: []string{},
	})
	if err == nil {
		t.Fatal("SyslogStore attached without \"sys\" in PersistStreams must fail loudly")
	}
	if !strings.Contains(err.Error(), "not in PersistStreams") {
		t.Errorf("error should name the mismatch direction; got %q", err.Error())
	}
}

func TestPersistStreams_BothMismatchesReported(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	err := Init(Config{ServiceID: "svc", NodeID: "node",
		APIStore:       newStreamTable(t, "api_x"), // attached, not named
		PersistStreams: []string{"sys"},             // named, no store
	})
	if err == nil {
		t.Fatal("both-direction mismatch must fail")
	}
	msg := err.Error()
	if !strings.Contains(msg, "no store attached") || !strings.Contains(msg, "not in PersistStreams") {
		t.Errorf("both directions should appear in the single error; got %q", msg)
	}
}

func TestPersistStreams_RejectsUnknownStreamNames(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	for _, bad := range []string{"audit", "syslog", "foo"} {
		err := Init(Config{ServiceID: "svc", NodeID: "node",
			PersistStreams: []string{bad},
		})
		if err == nil || !strings.Contains(err.Error(), "unknown stream") {
			t.Errorf("PersistStreams=[%q] must fail with 'unknown stream'; got %v", bad, err)
		}
	}
}

func TestPersistStreams_ReadsFromEnv(t *testing.T) {
	registerTestCodes(t)
	resetGlobals(t)
	t.Setenv("FASTEN_PERSIST_STREAMS", "sys")
	if err := Init(Config{ServiceID: "svc", NodeID: "node",
		SyslogStore: newStreamTable(t, "s_env"),
	}); err != nil {
		t.Fatalf("env-driven match should succeed: %v", err)
	}

	// env-driven mismatch also fails
	resetGlobals(t)
	t.Setenv("FASTEN_PERSIST_STREAMS", "api")
	err := Init(Config{ServiceID: "svc", NodeID: "node"})
	if err == nil || !strings.Contains(err.Error(), "no store attached") {
		t.Errorf("env-driven mismatch must fail; got %v", err)
	}
}
