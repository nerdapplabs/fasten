package fasten

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// Sensitive-data leakage: every sys/api push path must redact.
//
// Before this pass, only Emit (audit) called e.redactDetail. Adopter
// direct-push via t.PushSyslog(SyslogRow{"password": "x"}), plus
// fasten.LogError/SlogHandler.Handle, all landed the secret in the ring,
// the persistent store, and stdout.
//
// Also pins the persist-failure stderr line to a type-only message —
// Postgres INSERT errors quote row values in the message text.

func initRedactStreams(t *testing.T) {
	t.Helper()
	resetGlobals(t)
	registerTestCodes(t)
	if err := Init(Config{ServiceID: "svc", NodeID: "node"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
}

// captureStdout replaces os.Stdout with a pipe for the duration of fn and
// returns whatever fn caused fasten to print.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stdout
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = orig })
	fn()
	w.Close()
	buf, _ := io.ReadAll(r)
	return string(buf)
}

// captureStderr — same for os.Stderr.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = orig })
	fn()
	w.Close()
	buf, _ := io.ReadAll(r)
	return string(buf)
}

// ── sys stream: PushSyslog redacts ───────────────────────────────────────

func TestPushSyslog_RedactsPIIKeys(t *testing.T) {
	initRedactStreams(t)
	tr := GetTransport()
	tr.PushSyslog(SyslogRow{
		"event":    "auth_failed",
		"level":    "error",
		"password": "hunter2",
		"api_key":  "sk-real-key",
		"user":     "alice@example.com",
		"request_id": "r-1",
	})
	rows, err := tr.QuerySyslog(10, StreamQuery{})
	if err != nil {
		t.Fatalf("QuerySyslog: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	row := rows[0]
	if row["password"] != "***" {
		t.Errorf("password not redacted: %v", row["password"])
	}
	if row["api_key"] != "***" {
		t.Errorf("api_key not redacted: %v", row["api_key"])
	}
	if row["user"] != "alice@example.com" {
		t.Errorf("non-PII user field must pass through, got %v", row["user"])
	}
}

// ── api stream: PushAPI redacts ──────────────────────────────────────────

func TestPushAPI_RedactsPIIKeys(t *testing.T) {
	initRedactStreams(t)
	tr := GetTransport()
	tr.PushAPI(APIRow{
		"method":        "POST",
		"path":          "/login",
		"status":        401,
		"password":      "hunter2",
		"authorization": "Bearer secret-token",
		"request_id":    "r-1",
	})
	rows, err := tr.QueryAPI(10, StreamQuery{})
	if err != nil {
		t.Fatalf("QueryAPI: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	row := rows[0]
	if row["password"] != "***" || row["authorization"] != "***" {
		t.Errorf("api password/auth not redacted: %v", row)
	}
	if row["path"] != "/login" {
		t.Errorf("non-PII path field must pass through: %v", row["path"])
	}
}

// ── fasten.LogSys / LogError etc. redact ─────────────────────────────────

func TestLogSys_RedactsUserSuppliedSecretKV(t *testing.T) {
	initRedactStreams(t)
	stdout := captureStdout(t, func() {
		LogError(context.Background(), "auth_failed",
			"password", "hunter2",
			"api_key", "sk-real",
			"user", "alice")
	})
	if strings.Contains(stdout, "hunter2") {
		t.Errorf("LogError stdout must not contain the raw password: %q", stdout)
	}
	if strings.Contains(stdout, "sk-real") {
		t.Errorf("LogError stdout must not contain the raw api_key: %q", stdout)
	}
	// Ring must also be redacted (same call went through PushSyslog).
	tr := GetTransport()
	rows, _ := tr.QuerySyslog(10, StreamQuery{})
	if len(rows) != 1 || rows[0]["password"] != "***" {
		t.Errorf("ring row not redacted: %v", rows)
	}
}

// ── SlogHandler.Handle redacts fasten's own sys stream ───────────────────

func TestSlogHandler_RedactsPushToFastenRing(t *testing.T) {
	initRedactStreams(t)
	// Wrap a discard handler — we're testing fasten's ring, not the
	// underlying handler's output.
	base := slog.NewJSONHandler(io.Discard, nil)
	logger := slog.New(NewSlogHandler(base))
	logger.Warn("bad", "password", "hunter2", "token", "secret-jwt")

	tr := GetTransport()
	rows, _ := tr.QuerySyslog(10, StreamQuery{})
	if len(rows) != 1 {
		t.Fatalf("want 1 slog row, got %d", len(rows))
	}
	if rows[0]["password"] != "***" || rows[0]["token"] != "***" {
		t.Errorf("slog attrs not redacted into fasten's sys stream: %v", rows[0])
	}
}

// ── persist-failure stderr: type-only, no exception message ──────────────

// brokenStreamStore.Insert returns an error whose message quotes a secret.
type brokenStreamStore struct{ StreamRepository }

func (*brokenStreamStore) Insert(map[string]any) error {
	return errors.New("password=hunter2 violates constraint xyz")
}
func (*brokenStreamStore) NoteWriteFailure() {}

func TestPersistFailure_StderrIsTypeOnly(t *testing.T) {
	initRedactStreams(t)
	tr := GetTransport()
	tr.SyslogStore = &brokenStreamStore{}

	stderr := captureStderr(t, func() {
		tr.PushSyslog(SyslogRow{"event": "e", "level": "info", "request_id": "r"})
	})
	if strings.Contains(stderr, "hunter2") {
		t.Errorf("persist-failure stderr must not leak exception message: %q", stderr)
	}
	if !strings.Contains(stderr, "persist failed") {
		t.Errorf("stderr should still name the failure: %q", stderr)
	}
}

// ── audit store path also redacts (existing behaviour, pinned for parity) ─

func TestAuditEmit_RedactsThroughStore(t *testing.T) {
	resetGlobals(t)
	registerTestCodes(t)
	db, _ := sql.Open("sqlite", ":memory:")
	t.Cleanup(func() { db.Close() })
	store, _ := NewSQLiteStore(db, "audit_pii")
	if err := Init(Config{ServiceID: "svc", NodeID: "node", AuditStore: store,
		AuditStoreFailureStrategy: "raise"}); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if _, err := Emit(context.Background(), "USER_CREATED",
		Target("u-1"),
		WithDetail(map[string]any{"password": "hunter2", "note": "ok"})); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	rows, err := store.Query(context.Background(), Filter{Limit: 1})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 1 || rows[0].Detail["password"] != "***" {
		t.Errorf("audit password not redacted through store: %v", rows[0].Detail)
	}
}

// Ensure bytes package is used only via captureStdout/Stderr; silence
// unused-import complaint if the compiler ever elides them.
var _ = bytes.NewReader(nil)
