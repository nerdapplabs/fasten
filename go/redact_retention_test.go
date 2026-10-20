package fasten

import (
	"context"
	"database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// P1-55 — the Go PII horizon, driven from Config rather than by hand.
//
// The Python equivalent of this passed for weeks against wiring that did not
// exist: the mechanism was tested by calling the purger directly with a stream
// name the Engine never produced. These tests go through Init.

const (
	piiCode Code = "GOPII_USER_EXPORTED"
	opsCode Code = "GOPII_SERVICE_PINGED"
)

func registerPIICodes(t *testing.T) {
	t.Helper()
	if _, ok := metaOf(piiCode); ok {
		return
	}
	err := Register("gopiidemo", map[Code]Meta{
		piiCode: {
			ID: piiCode, Domain: "gopiidemo", Category: "data", Action: "export",
			Severity: SevInfo, Description: "export", Emitter: "t",
			PiiInDetail: true, // forces RetShort
		},
		opsCode: {
			ID: opsCode, Domain: "gopiidemo", Category: "ops", Action: "ping",
			Severity: SevInfo, Description: "ping", Emitter: "t",
			RetentionClass: RetLong,
		},
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
}

// agedForm2Row seals a form-"2" row AT an old timestamp. Backdating after the
// seal would rewrite a hashed field, which VerifyChain correctly calls
// tampering.
func agedForm2Row(t *testing.T, store *SQLiteStore, code Code, id string, detail map[string]any, age time.Duration) Row {
	t.Helper()
	salt := "0123456789abcdef0123456789abcdef"
	row := Row{
		WireVersion: "1", ID: id, OriginID: id, MonotonicSeq: 0,
		Timestamp: time.Now().UTC().Add(-age).Truncate(time.Microsecond),
		Code:      code, Action: "x", Severity: SevInfo,
		ServiceID: "svc", SourceNodeID: "node-1",
		Actor: "system", ActorKind: "service", Target: "t",
		Category: "c", Domain: "gopiidemo", Method: "sdk", RequestID: "req-1",
		Detail:          detail,
		CanonicalFormID: "2",
		DetailSalt:      salt,
	}
	row.DetailCommitment = detailCommitment(salt, detail)
	sealed, err := store.AllocateAndInsertOriginated(context.Background(), row)
	if err != nil {
		t.Fatalf("seal %s: %v", id, err)
	}
	return sealed
}

func TestGoPII_ConfigDestroysPIIAndRecordsIt(t *testing.T) {
	registerPIICodes(t)
	db, err := sql.Open("sqlite", t.TempDir()+"/audit.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := NewSQLiteStore(db, "fasten_audit")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	pii := agedForm2Row(t, store, piiCode, "evt-gopii-1",
		map[string]any{"email": "a@b.c"}, 40*24*time.Hour)
	ops := agedForm2Row(t, store, opsCode, "evt-gopii-2",
		map[string]any{"n": float64(1)}, 40*24*time.Hour)

	e := &Engine{}
	if err := e.Init(Config{
		ServiceID: "svc", NodeID: "node-1", AuditStore: store,
		RetentionPII: 30 * 24 * time.Hour,
	}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer e.stopRetention()

	// The first tick runs on Init; it is on another goroutine, so await it.
	var rows []Row
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		rows, err = store.Query(ctx, Filter{Limit: 50})
		if err != nil {
			t.Fatal(err)
		}
		done := false
		for _, r := range rows {
			if r.ID == pii.ID && r.Detail == nil {
				done = true
			}
		}
		if done {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	byID := map[string]Row{}
	for _, r := range rows {
		byID[r.ID] = r
	}
	if got := byID[pii.ID]; got.Detail != nil {
		t.Fatalf("PII detail survived its horizon under Config: %v", got.Detail)
	}
	if got := byID[pii.ID]; got.DetailSalt != "" {
		t.Errorf("salt survived — the commitment digest stays guessable")
	}
	if got := byID[ops.ID]; got.Detail == nil {
		t.Errorf("a RetLong non-PII row was swept up")
	}

	// spec §7.2: the destruction is itself a chained row.
	var redactions []Row
	for _, r := range rows {
		if r.Code == CodeAuditRowRedacted {
			redactions = append(redactions, r)
		}
	}
	if len(redactions) != 1 {
		t.Fatalf("AUDIT_ROW_REDACTED rows = %d want 1 — the §7.2 event was not written", len(redactions))
	}
	if got := redactions[0].Detail["redacted_seq"]; got != float64(pii.MonotonicSeq) && got != pii.MonotonicSeq {
		t.Errorf("redacted_seq = %v (%T) want %d", got, got, pii.MonotonicSeq)
	}
	if res := VerifyChain(rows); !res.OK {
		t.Fatalf("redaction broke the chain it is meant to preserve: %s", res.Reason)
	}
}

func TestGoPII_RowsAreRedactedNotDeleted(t *testing.T) {
	registerPIICodes(t)
	db, _ := sql.Open("sqlite", t.TempDir()+"/audit.db")
	defer db.Close()
	store, err := NewSQLiteStore(db, "fasten_audit")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	pii := agedForm2Row(t, store, piiCode, "evt-gopii-keep",
		map[string]any{"email": "a@b.c"}, 4000*24*time.Hour)

	e := &Engine{}
	if err := e.Init(Config{
		ServiceID: "svc", NodeID: "node-1", AuditStore: store,
		RetentionPII: 24 * time.Hour,
	}); err != nil {
		t.Fatal(err)
	}
	defer e.stopRetention()

	// The goto version of this fell through on timeout and then only asserted
	// the row existed — which it did, unredacted. It could not fail.
	redacted := false
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !redacted {
		rows, _ := store.Query(ctx, Filter{Limit: 50})
		for _, r := range rows {
			if r.ID == pii.ID && r.Detail == nil {
				redacted = true
			}
		}
		if !redacted {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if !redacted {
		t.Fatal("PII detail was never redacted")
	}
	rows, _ := store.Query(ctx, Filter{Limit: 50})
	found := false
	for _, r := range rows {
		if r.ID == pii.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("the audit row was DELETED, not redacted")
	}
	if res := VerifyChain(rows); !res.OK {
		t.Fatalf("chain broken: %s", res.Reason)
	}
}

func TestGoPII_InitFailsWhenStoreCannotRedact(t *testing.T) {
	registerPIICodes(t)
	// A store with no RedactionRepository: configuring a horizon it cannot
	// honour must fail at Init, not run a purger that silently does nothing.
	e := &Engine{}
	err := e.Init(Config{
		ServiceID: "svc", NodeID: "node-1",
		AuditStore:   noRedactStore{},
		RetentionPII: 30 * 24 * time.Hour,
	})
	if err == nil {
		e.stopRetention()
		t.Fatal("Init accepted a PII horizon the store cannot honour")
	}
}

type noRedactStore struct{ AuditRepository }

func TestGoPII_CodeSetDerivedFromCatalog(t *testing.T) {
	registerPIICodes(t)
	got := piiCodes()
	var hasPII, hasOps bool
	for _, c := range got {
		if c == piiCode {
			hasPII = true
		}
		if c == opsCode {
			hasOps = true
		}
	}
	if !hasPII {
		t.Error("PiiInDetail code not derived from the catalog")
	}
	if hasOps {
		t.Error("a RetLong non-PII code was swept up")
	}
}
