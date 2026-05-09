package fasten

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"time"
)

// envOr reads an env var with a fallback default.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// SQLiteStore is an AuditRepository backed by a *sql.DB.
// The caller is responsible for importing the SQLite driver and opening the DB.
//
// Usage:
//
//	import _ "github.com/mattn/go-sqlite3" // or modernc.org/sqlite
//	db, _ := sql.Open("sqlite3", "./fasten.db")
//	store := fasten.NewSQLiteStore(db, "fasten_audit")
type SQLiteStore struct {
	db    *sql.DB
	table string
}

// validIdentifierRe gates tableName against SQL injection. Every Insert /
// Query / migrate string-substitutes `s.table` into the SQL via fmt.Sprintf
// (parameterized identifiers aren't supported by SQLite's API), so a
// hostile or accidentally-attacker-controlled table name would punch
// through. Multi-tenant adopters who derive a suffix from a JWT claim
// or env var without their own validation are the realistic blast radius.
var validIdentifierRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// NewSQLiteStore creates and migrates the audit table, then returns the store.
// tableName must be a plain SQL identifier (^[A-Za-z_][A-Za-z0-9_]*$); any
// other value is rejected to prevent SQL injection — see store.go regex
// note above.
func NewSQLiteStore(db *sql.DB, tableName string) (*SQLiteStore, error) {
	if tableName == "" {
		tableName = "fasten_audit"
	}
	if !validIdentifierRe.MatchString(tableName) {
		return nil, fmt.Errorf(
			"fasten SQLiteStore: tableName %q is not a valid SQL identifier "+
				"(must match %s) — table names are string-substituted into SQL "+
				"because SQLite's API does not parameterize identifiers",
			tableName, validIdentifierRe.String())
	}
	s := &SQLiteStore{db: db, table: tableName}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("fasten SQLiteStore migrate: %w", err)
	}
	return s, nil
}

func (s *SQLiteStore) migrate() error {
	ddl := fmt.Sprintf(`
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS %s (
    id            TEXT PRIMARY KEY,
    origin_id     TEXT NOT NULL,
    monotonic_seq INTEGER NOT NULL,
    timestamp     TEXT NOT NULL,
    code          TEXT NOT NULL,
    action        TEXT NOT NULL,
    severity      TEXT NOT NULL,
    service_id    TEXT NOT NULL,
    source_node_id TEXT NOT NULL,
    tenant_id     TEXT,
    actor         TEXT NOT NULL,
    actor_kind    TEXT NOT NULL,
    target        TEXT NOT NULL,
    category      TEXT NOT NULL,
    domain        TEXT NOT NULL,
    method        TEXT NOT NULL,
    request_id    TEXT NOT NULL,
    detail        TEXT NOT NULL,
    pii_in_detail INTEGER NOT NULL DEFAULT 0,
    shipped_at    TEXT
);
CREATE INDEX IF NOT EXISTS idx_%s_req ON %s(request_id);
CREATE INDEX IF NOT EXISTS idx_%s_code ON %s(code);
CREATE INDEX IF NOT EXISTS idx_%s_ts ON %s(timestamp);
CREATE INDEX IF NOT EXISTS idx_%s_unshipped ON %s(shipped_at) WHERE shipped_at IS NULL;
`, s.table,
		s.table, s.table,
		s.table, s.table,
		s.table, s.table,
		s.table, s.table,
	)
	if _, err := s.db.Exec(ddl); err != nil {
		return err
	}
	// P1-5: idempotent migration for legacy tables that pre-date pii_in_detail.
	// PRAGMA table_info returns one row per column.
	rows, err := s.db.Query(fmt.Sprintf("PRAGMA table_info(%s)", s.table))
	if err != nil {
		return err
	}
	hasCol := false
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		if name == "pii_in_detail" {
			hasCol = true
		}
	}
	rows.Close()
	if !hasCol {
		if _, err := s.db.Exec(fmt.Sprintf(
			"ALTER TABLE %s ADD COLUMN pii_in_detail INTEGER NOT NULL DEFAULT 0",
			s.table,
		)); err != nil {
			return err
		}
	}
	// Partial index sits outside the CREATE TABLE so it works on both fresh
	// and legacy-migrated tables.
	_, err = s.db.Exec(fmt.Sprintf(
		"CREATE INDEX IF NOT EXISTS idx_%s_pii ON %s(pii_in_detail) WHERE pii_in_detail = 1",
		s.table, s.table,
	))
	return err
}

func (s *SQLiteStore) Insert(ctx context.Context, row Row) error {
	detail, err := json.Marshal(row.Detail)
	if err != nil {
		detail = []byte("{}")
	}
	var shippedAt *string
	if row.ShippedAt != nil {
		v := row.ShippedAt.Format(time.RFC3339Nano)
		shippedAt = &v
	}
	piiFlag := 0
	if row.PiiInDetail {
		piiFlag = 1
	}
	_, err = s.db.ExecContext(ctx,
		fmt.Sprintf(`INSERT OR IGNORE INTO %s VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, s.table),
		row.ID, row.OriginID, row.MonotonicSeq,
		row.Timestamp.Format(time.RFC3339Nano),
		string(row.Code), row.Action, string(row.Severity),
		row.ServiceID, row.SourceNodeID, row.TenantID,
		row.Actor, row.ActorKind,
		row.Target, row.Category, string(row.Domain),
		row.Method, row.RequestID,
		string(detail),
		piiFlag,
		shippedAt,
	)
	return err
}

func (s *SQLiteStore) Query(ctx context.Context, f Filter) ([]Row, error) {
	where, args := filterToSQL(f)
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		fmt.Sprintf(`SELECT * FROM %s %s ORDER BY monotonic_seq DESC LIMIT ?`, s.table, where),
		append(args, limit)...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

func (s *SQLiteStore) ListUnshipped(ctx context.Context, limit int) ([]Row, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		fmt.Sprintf(`SELECT * FROM %s WHERE shipped_at IS NULL ORDER BY monotonic_seq ASC LIMIT ?`, s.table),
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

func (s *SQLiteStore) MarkShipped(ctx context.Context, ids []string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, id := range ids {
		if _, err := s.db.ExecContext(ctx,
			fmt.Sprintf(`UPDATE %s SET shipped_at=? WHERE id=?`, s.table), now, id,
		); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLiteStore) Purge(ctx context.Context, before time.Time, respectUnshipped bool) (int, error) {
	q := fmt.Sprintf(`DELETE FROM %s WHERE timestamp < ?`, s.table)
	args := []any{before.UTC().Format(time.RFC3339Nano)}
	if respectUnshipped {
		q += " AND shipped_at IS NOT NULL"
	}
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// Count returns the total number of rows in the audit table. Used by the
// /audit/doctor health endpoint to confirm store reachability.
func (s *SQLiteStore) Count(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM %s`, s.table)).Scan(&n)
	return n, err
}

// ── helpers ───────────────────────────────────────────────────────────────

func filterToSQL(f Filter) (string, []any) {
	var conds []string
	var args []any
	if f.RequestID != "" {
		conds = append(conds, "request_id = ?"); args = append(args, f.RequestID)
	}
	if f.Code != "" {
		conds = append(conds, "code = ?"); args = append(args, string(f.Code))
	}
	if f.Domain != "" {
		conds = append(conds, "domain = ?"); args = append(args, string(f.Domain))
	}
	if f.SourceNodeID != "" {
		conds = append(conds, "source_node_id = ?"); args = append(args, f.SourceNodeID)
	}
	if !f.Since.IsZero() {
		conds = append(conds, "timestamp >= ?"); args = append(args, f.Since.UTC().Format(time.RFC3339Nano))
	}
	if !f.Until.IsZero() {
		conds = append(conds, "timestamp <= ?"); args = append(args, f.Until.UTC().Format(time.RFC3339Nano))
	}
	if len(conds) == 0 {
		return "", args
	}
	where := "WHERE " + conds[0]
	for _, c := range conds[1:] {
		where += " AND " + c
	}
	return where, args
}

func scanRows(rows *sql.Rows) ([]Row, error) {
	var out []Row
	for rows.Next() {
		var r Row
		var ts, code, sev, domain string
		var detail string
		var piiFlag int
		var shippedAt *string
		if err := rows.Scan(
			&r.ID, &r.OriginID, &r.MonotonicSeq,
			&ts, &code, &r.Action, &sev,
			&r.ServiceID, &r.SourceNodeID, &r.TenantID,
			&r.Actor, &r.ActorKind,
			&r.Target, &r.Category, &domain,
			&r.Method, &r.RequestID, &detail, &piiFlag, &shippedAt,
		); err != nil {
			return nil, err
		}
		r.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		r.Code = Code(code)
		r.Severity = Severity(sev)
		r.Domain = Domain(domain)
		json.Unmarshal([]byte(detail), &r.Detail)
		r.PiiInDetail = piiFlag != 0
		if shippedAt != nil {
			t, _ := time.Parse(time.RFC3339Nano, *shippedAt)
			r.ShippedAt = &t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
