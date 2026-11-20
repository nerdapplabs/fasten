package fasten

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// The Go store on a table the JS SqliteStore created. spec/js-sqlite-ddl.sql
// is the DDL the JS store runs on a new file (the JS suite keeps it current).
// The node-js rows of spec/js-sealed-form2.json go in by plain SQL, with each
// detail column holding the text the JS store wrote, then the Go store
// appends a row to the same chain and the whole chain verifies.
func TestJSSQLiteTable_GoAppendsAndVerifies(t *testing.T) {
	ddl, err := os.ReadFile("../spec/js-sqlite-ddl.sql")
	if err != nil {
		t.Skipf("spec/js-sqlite-ddl.sql not written yet (run the JS suite): %v", err)
	}
	raw, err := os.ReadFile("../spec/js-sealed-form2.json")
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "js.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, string(ddl)); err != nil {
		t.Fatalf("JS DDL: %v", err)
	}

	var ids []string
	var tip string
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSuffix(line, ",")
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var r map[string]any
		dec := json.NewDecoder(strings.NewReader(line))
		dec.UseNumber()
		if err := dec.Decode(&r); err != nil {
			t.Fatalf("parse vector line: %v", err)
		}
		// encoding/json cannot hold the unpaired surrogates on node-js-u16.
		if r["source_node_id"] != "node-js" {
			continue
		}
		// The detail text is the line's last field, as the JS store wrote it.
		cut := strings.Index(line, `,"detail":`)
		detail := line[cut+len(`,"detail":`) : len(line)-1]
		str := func(k string) any {
			if v, ok := r[k].(string); ok {
				return v
			}
			return nil
		}
		orEmpty := func(k string) string {
			v, _ := r[k].(string)
			return v
		}
		_, err := db.ExecContext(ctx, `INSERT INTO audit_log (id, wire_version, origin_id,
			monotonic_seq, timestamp, code, action, severity, service_id, source_node_id,
			tenant_id, actor, actor_kind, target, category, domain, method, request_id,
			pii_in_detail, shipped_at, canonical_form_id, prev_hash, hash, detail_salt,
			detail_commitment, detail) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,NULL,?,?,?,?,?,?)`,
			str("id"), str("wire_version"), str("origin_id"), string(r["monotonic_seq"].(json.Number)),
			str("timestamp"), str("code"), str("action"), str("severity"), str("service_id"),
			str("source_node_id"), str("tenant_id"), str("actor"), str("actor_kind"), str("target"),
			str("category"), str("domain"), str("method"), str("request_id"),
			str("canonical_form_id"), str("prev_hash"), str("hash"), orEmpty("detail_salt"),
			orEmpty("detail_commitment"), detail)
		if err != nil {
			t.Fatalf("insert %v: %v", r["id"], err)
		}
		ids = append(ids, orEmpty("id"))
		tip = orEmpty("hash")
	}
	if len(ids) != 5 {
		t.Fatalf("node-js rows = %d want 5", len(ids))
	}

	store, err := NewSQLiteStore(db, "audit_log")
	if err != nil {
		t.Fatalf("NewSQLiteStore on the JS table: %v", err)
	}
	id := "evt-" + strings.Repeat("a", 20)
	tenant := "t-go"
	sealed, err := store.AllocateAndInsertOriginated(ctx, Row{
		WireVersion: "1", ID: id, OriginID: id,
		Timestamp: time.Now().UTC().Truncate(time.Microsecond),
		Code:      "GO_APPEND", Action: "write", Severity: "info",
		ServiceID: "gateway", SourceNodeID: "node-js", TenantID: &tenant,
		Actor: "go", ActorKind: "service", Target: "u-1", Domain: "vector",
		Method: "sdk", RequestID: "req-go", Detail: map[string]any{"n": 1.5, "who": "go"},
	})
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if sealed.MonotonicSeq != 6 || sealed.PrevHash != tip {
		t.Fatalf("appended at seq %d after %q, want 6 after %q", sealed.MonotonicSeq, sealed.PrevHash, tip)
	}

	rows, err := store.ChainTail(ctx, "node-js", 100)
	if err != nil {
		t.Fatalf("ChainTail: %v", err)
	}
	if len(rows) != 6 {
		t.Fatalf("chain rows = %d want 6", len(rows))
	}
	for i, want := range append(ids, id) {
		if rows[i].ID != want {
			t.Fatalf("row %d = %s want %s", i, rows[i].ID, want)
		}
	}
	if res := VerifyChain(rows); !res.OK {
		t.Fatalf("Go rejects a JS table with its own row appended: %s", res.Reason)
	}
}
