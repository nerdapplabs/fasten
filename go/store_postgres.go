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
    timestamp      TIMESTAMPTZ NOT NULL,
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
    shipped_at     TIMESTAMPTZ,
    wire_version   TEXT NOT NULL DEFAULT '1',
    hash           TEXT NOT NULL DEFAULT '',
    prev_hash      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_%s_req ON %s(request_id);
CREATE INDEX IF NOT EXISTS idx_%s_code ON %s(code);
CREATE INDEX IF NOT EXISTS idx_%s_ts ON %s(timestamp);
CREATE INDEX IF NOT EXISTS idx_%s_seq ON %s(monotonic_seq);
CREATE INDEX IF NOT EXISTS idx_%s_unshipped ON %s(shipped_at) WHERE shipped_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_%s_pii ON %s(pii_in_detail) WHERE pii_in_detail = 1;
`, s.table,
		s.bare, s.table,
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
		`SELECT column_name, data_type FROM information_schema.columns WHERE table_name=$1 AND table_schema=$2`,
		s.bare, lookupSchema,
	)
	if err != nil {
		return err
	}
	existing := map[string]string{} // name → data_type
	for rows.Next() {
		var name, dtype string
		if err := rows.Scan(&name, &dtype); err != nil {
			rows.Close()
			return err
		}
		existing[name] = dtype
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	// Idempotent column additions for tables created before a given column existed.
	type colDef struct{ name, ddl string }
	for _, col := range []colDef{
		{"pii_in_detail", "SMALLINT NOT NULL DEFAULT 0"},
		{"wire_version", "TEXT NOT NULL DEFAULT '1'"},
		{"hash", "TEXT NOT NULL DEFAULT ''"},
		{"prev_hash", "TEXT NOT NULL DEFAULT ''"},
	} {
		if _, ok := existing[col.name]; !ok {
			if _, err := s.db.Exec(fmt.Sprintf(
				`ALTER TABLE %s ADD COLUMN %s %s`, s.table, col.name, col.ddl,
			)); err != nil {
				return err
			}
		}
	}

	// Migrate legacy TEXT timestamp columns to TIMESTAMPTZ.
	if dtype, ok := existing["timestamp"]; ok && dtype == "text" {
		if _, err := s.db.Exec(fmt.Sprintf(
			`ALTER TABLE %s ALTER COLUMN timestamp TYPE TIMESTAMPTZ USING timestamp::TIMESTAMPTZ`,
			s.table,
		)); err != nil {
			return err
		}
	}
	if dtype, ok := existing["shipped_at"]; ok && dtype == "text" {
		if _, err := s.db.Exec(fmt.Sprintf(
			`ALTER TABLE %s ALTER COLUMN shipped_at TYPE TIMESTAMPTZ USING shipped_at::TIMESTAMPTZ`,
			s.table,
		)); err != nil {
			return err
		}
	}

	return nil
}

// pgAuditCols is the column list for Postgres — same logical order as auditCols
// in store.go but timestamp/shipped_at are native TIMESTAMPTZ so we scan
// directly into time.Time via scanRowsPg.
const pgAuditCols = `id, origin_id, monotonic_seq, timestamp, code, action, severity,` +
	` service_id, source_node_id, tenant_id, actor, actor_kind,` +
	` target, category, domain, method, request_id, detail,` +
	` pii_in_detail, shipped_at, wire_version, hash, prev_hash`

func (s *PostgresStore) Insert(ctx context.Context, row Row) error {
	detail, err := json.Marshal(row.Detail)
	if err != nil {
		detail = []byte("{}")
	}
	var shippedAt *time.Time
	if row.ShippedAt != nil {
		t := row.ShippedAt.UTC()
		shippedAt = &t
	}
	piiFlag := 0
	if row.PiiInDetail {
		piiFlag = 1
	}
	wv := row.WireVersion
	if wv == "" {
		wv = "1"
	}
	_, err = s.db.ExecContext(ctx,
		fmt.Sprintf(`INSERT INTO %s (%s) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23) ON CONFLICT (id) DO NOTHING`, s.table, pgAuditCols),
		row.ID, row.OriginID, row.MonotonicSeq,
		row.Timestamp.UTC(),
		string(row.Code), row.Action, string(row.Severity),
		row.ServiceID, row.SourceNodeID, row.TenantID,
		row.Actor, row.ActorKind,
		row.Target, row.Category, string(row.Domain),
		row.Method, row.RequestID,
		string(detail),
		piiFlag,
		shippedAt,
		wv, row.Hash, row.PrevHash,
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
		fmt.Sprintf(`SELECT %s FROM %s %s ORDER BY monotonic_seq DESC LIMIT $%d`, pgAuditCols, s.table, where, n),
		append(args, limit)...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRowsPg(rows)
}

func (s *PostgresStore) ListUnshipped(ctx context.Context, limit int) ([]Row, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		fmt.Sprintf(`SELECT %s FROM %s WHERE shipped_at IS NULL ORDER BY monotonic_seq ASC LIMIT $1`, pgAuditCols, s.table),
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRowsPg(rows)
}

func (s *PostgresStore) MarkShipped(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	now := time.Now().UTC()
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
	args := []any{before.UTC()}
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
		conds = append(conds, fmt.Sprintf("timestamp >= $%d", n)); args = append(args, f.Since.UTC()); n++
	}
	if !f.Until.IsZero() {
		conds = append(conds, fmt.Sprintf("timestamp <= $%d", n)); args = append(args, f.Until.UTC()); n++
	}
	if f.AfterSeq > 0 {
		conds = append(conds, fmt.Sprintf("monotonic_seq > $%d", n)); args = append(args, f.AfterSeq); n++
	}
	_ = n
	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// scanRowsPg scans rows from a Postgres query where timestamp/shipped_at are
// TIMESTAMPTZ columns (scanned as time.Time, not as strings).
func scanRowsPg(rows *sql.Rows) ([]Row, error) {
	var out []Row
	for rows.Next() {
		var r Row
		var code, sev, domain string
		var detail string
		var piiFlag int
		var shippedAt *time.Time
		var wv, hash, prevHash string
		if err := rows.Scan(
			&r.ID, &r.OriginID, &r.MonotonicSeq,
			&r.Timestamp, &code, &r.Action, &sev,
			&r.ServiceID, &r.SourceNodeID, &r.TenantID,
			&r.Actor, &r.ActorKind,
			&r.Target, &r.Category, &domain,
			&r.Method, &r.RequestID, &detail, &piiFlag, &shippedAt,
			&wv, &hash, &prevHash,
		); err != nil {
			return nil, err
		}
		r.Timestamp = r.Timestamp.UTC()
		r.Code = Code(code)
		r.Severity = Severity(sev)
		r.Domain = Domain(domain)
		json.Unmarshal([]byte(detail), &r.Detail)
		r.PiiInDetail = piiFlag != 0
		if shippedAt != nil {
			t := shippedAt.UTC()
			r.ShippedAt = &t
		}
		if wv != "" {
			r.WireVersion = wv
		} else {
			r.WireVersion = "1"
		}
		r.Hash = hash
		r.PrevHash = prevHash
		out = append(out, r)
	}
	return out, rows.Err()
}
