package fasten

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var validPgIdentifierRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$`)

// PostgresStore is an AuditRepository backed by a *sql.DB connected to PostgreSQL.
// The caller is responsible for importing the Postgres driver and opening the DB.
//
// Usage:
//
//	import _ "github.com/lib/pq"
//	db, _ := sql.Open("postgres", os.Getenv("DATABASE_URL"))
//	store, _ := fasten.NewPostgresStore(db, "public.fasten_audit")
type PostgresStore struct {
	db     *sql.DB
	table  string
	schema string
	bare   string
}

// NewPostgresStore creates and migrates the audit table, then returns the store.
// tableName may be a plain identifier or schema-qualified (schema.table).
func NewPostgresStore(db *sql.DB, tableName string) (*PostgresStore, error) {
	if tableName == "" {
		tableName = "fasten_audit"
	}
	if !validPgIdentifierRe.MatchString(tableName) {
		return nil, fmt.Errorf(
			"fasten PostgresStore: tableName %q is not a valid identifier "+
				"(must match %s) — table names are string-substituted into SQL",
			tableName, validPgIdentifierRe.String())
	}
	schema := ""
	bare := tableName
	if dot := strings.LastIndex(tableName, "."); dot >= 0 {
		schema = tableName[:dot]
		bare = tableName[dot+1:]
	}
	s := &PostgresStore{db: db, table: tableName, schema: schema, bare: bare}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("fasten PostgresStore migrate: %w", err)
	}
	return s, nil
}

func (s *PostgresStore) migrate() error {
	if s.schema != "" {
		if _, err := s.db.Exec(fmt.Sprintf(`CREATE SCHEMA IF NOT EXISTS %s`, s.schema)); err != nil {
			return err
		}
	}

	ddl := fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s (
    id             TEXT PRIMARY KEY,
    origin_id      TEXT NOT NULL,
    monotonic_seq  BIGINT NOT NULL,
    timestamp      TEXT NOT NULL,
    code           TEXT NOT NULL,
    action         TEXT NOT NULL,
    severity       TEXT NOT NULL,
    service_id     TEXT NOT NULL,
    source_node_id TEXT NOT NULL,
    tenant_id      TEXT,
    actor          TEXT NOT NULL,
    actor_kind     TEXT NOT NULL,
    target         TEXT NOT NULL,
    category       TEXT NOT NULL,
    domain         TEXT NOT NULL,
    method         TEXT NOT NULL,
    request_id     TEXT NOT NULL,
    detail         TEXT NOT NULL,
    pii_in_detail  SMALLINT NOT NULL DEFAULT 0,
    shipped_at     TEXT
);
CREATE INDEX IF NOT EXISTS idx_%s_req ON %s(request_id);
CREATE INDEX IF NOT EXISTS idx_%s_code ON %s(code);
CREATE INDEX IF NOT EXISTS idx_%s_ts ON %s(timestamp);
CREATE INDEX IF NOT EXISTS idx_%s_unshipped ON %s(shipped_at) WHERE shipped_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_%s_pii ON %s(pii_in_detail) WHERE pii_in_detail = 1;
`, s.table,
		s.bare, s.table,
		s.bare, s.table,
		s.bare, s.table,
		s.bare, s.table,
		s.bare, s.table,
	)
	if _, err := s.db.Exec(ddl); err != nil {
		return err
	}

	lookupSchema := "public"
	if s.schema != "" {
		lookupSchema = s.schema
	}
	rows, err := s.db.Query(
		`SELECT column_name FROM information_schema.columns WHERE table_name=$1 AND table_schema=$2`,
		s.bare, lookupSchema,
	)
	if err != nil {
		return err
	}
	hasCol := false
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		if name == "pii_in_detail" {
			hasCol = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if !hasCol {
		if _, err := s.db.Exec(fmt.Sprintf(
			`ALTER TABLE %s ADD COLUMN pii_in_detail SMALLINT NOT NULL DEFAULT 0`,
			s.table,
		)); err != nil {
			return err
		}
	}
	return nil
}

func (s *PostgresStore) Insert(ctx context.Context, row Row) error {
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
		fmt.Sprintf(`INSERT INTO %s VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20) ON CONFLICT (id) DO NOTHING`, s.table),
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

func (s *PostgresStore) Query(ctx context.Context, f Filter) ([]Row, error) {
	where, args := filterToPostgresSQL(f)
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	n := len(args) + 1
	rows, err := s.db.QueryContext(ctx,
		fmt.Sprintf(`SELECT * FROM %s %s ORDER BY monotonic_seq DESC LIMIT $%d`, s.table, where, n),
		append(args, limit)...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

func (s *PostgresStore) ListUnshipped(ctx context.Context, limit int) ([]Row, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		fmt.Sprintf(`SELECT * FROM %s WHERE shipped_at IS NULL ORDER BY monotonic_seq ASC LIMIT $1`, s.table),
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

func (s *PostgresStore) MarkShipped(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	placeholders := make([]string, len(ids))
	args := make([]any, 0, len(ids)+1)
	args = append(args, now)
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args = append(args, id)
	}
	q := fmt.Sprintf(
		`UPDATE %s SET shipped_at=$1 WHERE id IN (%s)`,
		s.table, strings.Join(placeholders, ","),
	)
	_, err := s.db.ExecContext(ctx, q, args...)
	return err
}

func (s *PostgresStore) Purge(ctx context.Context, before time.Time, respectUnshipped bool) (int, error) {
	q := fmt.Sprintf(`DELETE FROM %s WHERE timestamp < $1`, s.table)
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

// filterToPostgresSQL builds a WHERE clause using $N placeholders.
func filterToPostgresSQL(f Filter) (string, []any) {
	var conds []string
	var args []any
	n := 1
	if f.RequestID != "" {
		conds = append(conds, fmt.Sprintf("request_id = $%d", n)); args = append(args, f.RequestID); n++
	}
	if f.Code != "" {
		conds = append(conds, fmt.Sprintf("code = $%d", n)); args = append(args, string(f.Code)); n++
	}
	if f.Domain != "" {
		conds = append(conds, fmt.Sprintf("domain = $%d", n)); args = append(args, string(f.Domain)); n++
	}
	if f.SourceNodeID != "" {
		conds = append(conds, fmt.Sprintf("source_node_id = $%d", n)); args = append(args, f.SourceNodeID); n++
	}
	if !f.Since.IsZero() {
		conds = append(conds, fmt.Sprintf("timestamp >= $%d", n)); args = append(args, f.Since.UTC().Format(time.RFC3339Nano)); n++
	}
	if !f.Until.IsZero() {
		conds = append(conds, fmt.Sprintf("timestamp <= $%d", n)); args = append(args, f.Until.UTC().Format(time.RFC3339Nano))
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
