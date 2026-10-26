package fasten

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
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

	// writeFailures counts swallowed write errors. Non-zero marks the audit
	// stream "store-degraded" for the life of the store.
	writeFailures atomic.Int64
}

// NoteWriteFailure records a swallowed write error. Callers that return the
// Insert error themselves don't call it.
func (s *PostgresStore) NoteWriteFailure() { s.writeFailures.Add(1) }

// Degraded reports whether any write error was swallowed, which makes the
// audit stream "store-degraded".
func (s *PostgresStore) Degraded() bool { return s.writeFailures.Load() > 0 }

// NewPostgresStore creates and migrates the audit table, then returns the store.
// tableName may be a plain identifier or schema-qualified (schema.table).
func NewPostgresStore(db *sql.DB, tableName string) (*PostgresStore, error) {
	if tableName == "" {
		tableName = "fasten_audit"
	}
	if !validPgIdentifierRe.MatchString(tableName) {
		return nil, fmt.Errorf(
			"fasten PostgresStore: tableName %q is not a valid identifier "+
				"(must match %s): table names are string-substituted into SQL",
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
    prev_hash      TEXT NOT NULL DEFAULT '',
    canonical_form_id TEXT NOT NULL DEFAULT '1',
    detail_salt       TEXT NOT NULL DEFAULT '',
    detail_commitment TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_%s_req ON %s(request_id);
CREATE INDEX IF NOT EXISTS idx_%s_code ON %s(code);
CREATE INDEX IF NOT EXISTS idx_%s_ts ON %s(timestamp);
CREATE INDEX IF NOT EXISTS idx_%s_seq ON %s(monotonic_seq);
-- One node, one chain (spec §2). A duplicate seq fails on insert instead of
-- showing up later in verify_chain as tampering.
CREATE UNIQUE INDEX IF NOT EXISTS uq_%s_node_seq ON %s(source_node_id, monotonic_seq);
CREATE INDEX IF NOT EXISTS idx_%s_unshipped ON %s(shipped_at) WHERE shipped_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_%s_pii ON %s(pii_in_detail) WHERE pii_in_detail = 1;
`, s.table,
		s.bare, s.table, // idx_<t>_req
		s.bare, s.table, // idx_<t>_code
		s.bare, s.table, // idx_<t>_ts
		s.bare, s.table, // idx_<t>_seq
		s.bare, s.table, // uq_<t>_node_seq
		s.bare, s.table, // idx_<t>_unshipped
		s.bare, s.table, // idx_<t>_pii
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
	existing := map[string]string{} // name to data_type
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

	// Add columns missing from tables created by older versions.
	type colDef struct{ name, ddl string }
	for _, col := range []colDef{
		{"pii_in_detail", "SMALLINT NOT NULL DEFAULT 0"},
		{"wire_version", "TEXT NOT NULL DEFAULT '1'"},
		{"hash", "TEXT NOT NULL DEFAULT ''"},
		{"prev_hash", "TEXT NOT NULL DEFAULT ''"},
		{"canonical_form_id", "TEXT NOT NULL DEFAULT '1'"},
		{"detail_salt", "TEXT NOT NULL DEFAULT ''"},
		{"detail_commitment", "TEXT NOT NULL DEFAULT ''"},
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

// pgAuditCols is auditCols (store.go) for Postgres, where timestamp and
// shipped_at are TIMESTAMPTZ and scan straight into time.Time.
const pgAuditCols = `id, origin_id, monotonic_seq, timestamp, code, action, severity,` +
	` service_id, source_node_id, tenant_id, actor, actor_kind,` +
	` target, category, domain, method, request_id, detail,` +
	` pii_in_detail, shipped_at, wire_version, hash, prev_hash, canonical_form_id,` +
	// Form "2" (spec §1.4). See auditCols in store.go.
	` detail_salt, detail_commitment`

// insertRowExec inserts a row (ON CONFLICT DO NOTHING) on a *sql.DB or
// *sql.Tx. The originated and replicated checks are in the callers.
func (s *PostgresStore) insertRowExec(ctx context.Context, exec execContext, row Row) error {
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
	formID := row.CanonicalFormID
	if formID == "" {
		formID = "1"
	}
	_, err = exec.ExecContext(ctx,
		fmt.Sprintf(`INSERT INTO %s (%s) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26) ON CONFLICT (id) DO NOTHING`, s.table, pgAuditCols),
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
		wv, row.Hash, row.PrevHash, formID,
		row.DetailSalt, row.DetailCommitment,
	)
	return err
}

// insertRow inserts one row outside a transaction.
func (s *PostgresStore) insertRow(ctx context.Context, row Row) error {
	return s.insertRowExec(ctx, s.db, row)
}

// InsertOriginated inserts a row this node originated (origin_id == id).
func (s *PostgresStore) InsertOriginated(ctx context.Context, row Row) error {
	if row.OriginID != row.ID {
		return fmt.Errorf(
			"fasten InsertOriginated: requires origin_id == id (got origin_id=%q, id=%q); "+
				"use InsertReplicated for rows from another origin", row.OriginID, row.ID)
	}
	return s.insertRow(ctx, row)
}

// AllocateAndInsertOriginated allocates monotonic_seq and prev_hash, seals
// the row and inserts it in one transaction (spec §2.1), and returns the
// sealed row.
//
// It locks with pg_advisory_xact_lock on the node rather than SELECT ... FOR
// UPDATE on the tip row, because an empty table has no tip row to lock.
func (s *PostgresStore) AllocateAndInsertOriginated(ctx context.Context, row Row) (Row, error) {
	if row.OriginID != row.ID {
		return Row{}, fmt.Errorf(
			"fasten AllocateAndInsertOriginated: requires origin_id == id (got origin_id=%q, id=%q)",
			row.OriginID, row.ID)
	}
	// Truncate to microseconds before sealing. timestamptz rounds anything
	// finer, so the stored row would no longer match its hash.
	row.Timestamp = row.Timestamp.Truncate(time.Microsecond)
	if row.ShippedAt != nil {
		t := row.ShippedAt.Truncate(time.Microsecond)
		row.ShippedAt = &t
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Row{}, err
	}
	defer func() { _ = tx.Rollback() }()

	// A retry after a lost ack may find the row already committed. Return
	// the stored one rather than sealing a new seq that ON CONFLICT drops.
	var (
		exSeq                  int64
		exPrev, exHash, exForm string
	)
	err = tx.QueryRowContext(ctx,
		"SELECT monotonic_seq, prev_hash, hash, canonical_form_id FROM "+s.table+
			" WHERE id = $1", row.ID).Scan(&exSeq, &exPrev, &exHash, &exForm)
	if err == nil {
		row.MonotonicSeq, row.PrevHash, row.Hash, row.CanonicalFormID = exSeq, exPrev, exHash, exForm
		if cerr := tx.Commit(); cerr != nil {
			return Row{}, cerr
		}
		return row, nil
	} else if err != sql.ErrNoRows {
		return Row{}, err
	}

	if _, err := tx.ExecContext(ctx,
		"SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", row.SourceNodeID); err != nil {
		return Row{}, err
	}

	// Two queries: seq counts every row on the node (an unsealed row still
	// holds its number), while prev_hash comes from the last sealed row.
	var nextSeq int64
	if err := tx.QueryRowContext(ctx,
		"SELECT COALESCE(MAX(monotonic_seq), 0) FROM "+s.table+" WHERE source_node_id = $1",
		row.SourceNodeID).Scan(&nextSeq); err != nil {
		return Row{}, err
	}
	nextSeq++

	prevHash := "genesis"
	var tip string
	err = tx.QueryRowContext(ctx,
		"SELECT hash FROM "+s.table+" WHERE source_node_id = $1 AND hash <> '' "+
			"ORDER BY monotonic_seq DESC LIMIT 1", row.SourceNodeID).Scan(&tip)
	if err == nil && tip != "" {
		prevHash = tip
	} else if err != nil && err != sql.ErrNoRows {
		return Row{}, err
	}

	row.MonotonicSeq = nextSeq
	sealed := Seal(prevHash, row)
	if err := s.insertRowExec(ctx, tx, sealed); err != nil {
		return Row{}, err
	}
	if err := tx.Commit(); err != nil {
		return Row{}, err
	}
	return sealed, nil
}

// InsertReplicated inserts a sealed row replicated from another origin.
func (s *PostgresStore) InsertReplicated(ctx context.Context, row Row) error {
	if row.Hash == "" {
		return fmt.Errorf("fasten InsertReplicated: requires a sealed row (non-empty hash); row %q has no hash", row.ID)
	}
	return s.insertRow(ctx, row)
}

// insertReplicatedTx is InsertReplicated on the caller's transaction;
// IngestReplicated commits once for the batch.
func (s *PostgresStore) insertReplicatedTx(ctx context.Context, exec execContext, row Row) error {
	if row.Hash == "" {
		return fmt.Errorf("fasten insertReplicatedTx: requires a sealed row (non-empty hash); row %q has no hash", row.ID)
	}
	return s.insertRowExec(ctx, exec, row)
}

// Insert calls InsertOriginated. The drainer writes through it.
func (s *PostgresStore) Insert(ctx context.Context, row Row) error {
	return s.InsertOriginated(ctx, row)
}

func (s *PostgresStore) Query(ctx context.Context, f Filter) ([]Row, error) {
	where, args := filterToPostgresSQL(f)
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	// Cursor pagination: results are newest-first, so the next page is
	// monotonic_seq < AfterSeq. It's applied here rather than in
	// filterToPostgresSQL so CountFiltered still counts every match.
	if f.AfterSeq > 0 {
		n := len(args) + 1
		if where == "" {
			where = fmt.Sprintf("WHERE monotonic_seq < $%d", n)
		} else {
			where += fmt.Sprintf(" AND monotonic_seq < $%d", n)
		}
		args = append(args, f.AfterSeq)
	}
	limIdx := len(args) + 1
	offIdx := len(args) + 2
	// monotonic_seq is per source_node_id, so it only breaks
	// ties between equal timestamps (#68).
	rows, err := s.db.QueryContext(ctx,
		fmt.Sprintf(`SELECT %s FROM %s %s ORDER BY timestamp DESC, monotonic_seq DESC LIMIT $%d OFFSET $%d`, pgAuditCols, s.table, where, limIdx, offIdx),
		append(args, limit, offset)...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRowsPg(rows)
}

// CountFiltered counts rows matching f, ignoring Limit, so a capped read
// (e.g. /correlate) can report truncation.
func (s *PostgresStore) CountFiltered(ctx context.Context, f Filter) (int, error) {
	where, args := filterToPostgresSQL(f)
	var count int
	err := s.db.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT COUNT(*) FROM %s %s`, s.table, where), args...,
	).Scan(&count)
	return count, err
}

// Search does a case-insensitive substring match of q against detail
// (§4.1), from since, newest-first, up to limit, with no ranking. LIKE
// wildcards in q match literally. A non-empty tenantID scopes the query to
// one tenant; see SQLiteStore.Search.
func (s *PostgresStore) Search(ctx context.Context, q, since, until, tenantID string, limit int) ([]Row, error) {
	esc := escapeLikeLiteral(q)
	conds := []string{"timestamp >= $1", `detail::text ILIKE $2 ESCAPE E'\\'`}
	args := []any{since, "%" + esc + "%"}
	n := 3
	if until != "" {
		conds = append(conds, fmt.Sprintf("timestamp <= $%d", n))
		args = append(args, until)
		n++
	}
	if tenantID != "" {
		conds = append(conds, fmt.Sprintf("tenant_id = $%d", n))
		args = append(args, tenantID)
		n++
	}
	args = append(args, limit)
	sql := fmt.Sprintf(
		`SELECT %s FROM %s WHERE %s ORDER BY timestamp DESC, monotonic_seq DESC LIMIT $%d`,
		pgAuditCols, s.table, strings.Join(conds, " AND "), n,
	)
	rows, err := s.db.QueryContext(ctx, sql, args...)
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

// ListUnshippedOriginated returns unshipped rows this node originated, for
// (serviceID, sourceNodeID) with origin_id = id. Replicated rows are left out
// so they are never shipped upstream again.
func (s *PostgresStore) ListUnshippedOriginated(ctx context.Context, serviceID, sourceNodeID string, limit int) ([]Row, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		fmt.Sprintf(`SELECT %s FROM %s WHERE shipped_at IS NULL AND service_id = $1 AND source_node_id = $2 AND origin_id = id ORDER BY monotonic_seq ASC LIMIT $3`, pgAuditCols, s.table),
		serviceID, sourceNodeID, limit,
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
		conds = append(conds, fmt.Sprintf("request_id = $%d", n))
		args = append(args, f.RequestID)
		n++
	}
	if f.Code != "" {
		conds = append(conds, fmt.Sprintf("code = $%d", n))
		args = append(args, string(f.Code))
		n++
	}
	if f.Domain != "" {
		conds = append(conds, fmt.Sprintf("domain = $%d", n))
		args = append(args, string(f.Domain))
		n++
	}
	if f.SourceNodeID != "" {
		conds = append(conds, fmt.Sprintf("source_node_id = $%d", n))
		args = append(args, f.SourceNodeID)
		n++
	}
	if f.TenantID != "" {
		conds = append(conds, fmt.Sprintf("tenant_id = $%d", n))
		args = append(args, f.TenantID)
		n++
	}
	if f.Actor != "" {
		conds = append(conds, fmt.Sprintf("actor = $%d", n))
		args = append(args, f.Actor)
		n++
	}
	if f.Target != "" {
		conds = append(conds, fmt.Sprintf("target = $%d", n))
		args = append(args, f.Target)
		n++
	}
	if !f.Since.IsZero() {
		conds = append(conds, fmt.Sprintf("timestamp >= $%d", n))
		args = append(args, f.Since.UTC())
		n++
	}
	if !f.Until.IsZero() {
		conds = append(conds, fmt.Sprintf("timestamp <= $%d", n))
		args = append(args, f.Until.UTC())
		n++
	}
	// AfterSeq is applied in Query, so CountFiltered counts every match.
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
		var wv, hash, prevHash, formID string
		if err := rows.Scan(
			&r.ID, &r.OriginID, &r.MonotonicSeq,
			&r.Timestamp, &code, &r.Action, &sev,
			&r.ServiceID, &r.SourceNodeID, &r.TenantID,
			&r.Actor, &r.ActorKind,
			&r.Target, &r.Category, &domain,
			&r.Method, &r.RequestID, &detail, &piiFlag, &shippedAt,
			&wv, &hash, &prevHash, &formID,
			&r.DetailSalt, &r.DetailCommitment,
		); err != nil {
			return nil, err
		}
		r.Timestamp = r.Timestamp.UTC()
		r.Code = Code(code)
		r.Severity = Severity(sev)
		r.Domain = Domain(domain)
		// A malformed detail column is an error, not an empty map.
		if err := json.Unmarshal([]byte(detail), &r.Detail); err != nil {
			return nil, fmt.Errorf("scanRowsPg: row %q detail: %w", r.ID, err)
		}
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
		if formID != "" {
			r.CanonicalFormID = formID
		} else {
			r.CanonicalFormID = "1"
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListRedactionCandidates implements RedactionRepository (spec §7.1).
// See the SQLite implementation for the form-"1" rationale.
func (s *PostgresStore) ListRedactionCandidates(
	ctx context.Context, before time.Time, codes []Code,
) ([]RedactionCandidate, int, error) {
	if len(codes) == 0 {
		return nil, 0, nil
	}
	// Numbered placeholders rather than pq.Array, so this module doesn't
	// depend on lib/pq.
	placeholders := make([]string, len(codes))
	args := make([]any, 0, len(codes)+1)
	args = append(args, before.UTC())
	for i, c := range codes {
		placeholders[i] = fmt.Sprintf("$%d", i+2)
		args = append(args, string(c))
	}
	in := strings.Join(placeholders, ",")

	var skipped int64
	if err := s.db.QueryRowContext(ctx, fmt.Sprintf(
		`SELECT COUNT(*) FROM %s WHERE timestamp < $1 AND code IN (%s) `+
			`AND canonical_form_id <> '2' AND detail <> 'null'`, s.table, in),
		args...).Scan(&skipped); err != nil {
		return nil, 0, err
	}

	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(
		`SELECT id, monotonic_seq FROM %s WHERE timestamp < $1 AND code IN (%s) `+
			`AND canonical_form_id = '2' AND detail <> 'null' `+
			`ORDER BY monotonic_seq`, s.table, in),
		args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []RedactionCandidate
	for rows.Next() {
		var c RedactionCandidate
		if err := rows.Scan(&c.ID, &c.MonotonicSeq); err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, int(skipped), rows.Err()
}

// RedactRows implements RedactionRepository (spec §7.1). Idempotent: it targets
// ids, not a time window, so a retry destroys the same rows and returns the
// same list.
func (s *PostgresStore) RedactRows(ctx context.Context, ids []string) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	placeholders := make([]string, len(ids))
	args := make([]any, 0, len(ids))
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args = append(args, id)
	}
	if _, err := s.db.ExecContext(ctx, fmt.Sprintf(
		`UPDATE %s SET detail = 'null', detail_salt = '' `+
			`WHERE id IN (%s) AND canonical_form_id = '2'`,
		s.table, strings.Join(placeholders, ",")), args...); err != nil {
		return nil, err
	}
	return ids, nil
}
