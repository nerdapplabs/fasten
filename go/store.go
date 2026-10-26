package fasten

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
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

	// writeFailures counts swallowed write errors. Non-zero marks the audit
	// stream "store-degraded" for the life of the store.
	writeFailures atomic.Int64
}

// NoteWriteFailure records a swallowed write error. Callers that return the
// Insert error themselves don't call it.
func (s *SQLiteStore) NoteWriteFailure() { s.writeFailures.Add(1) }

// Degraded reports whether any write error was swallowed, which makes the
// audit stream "store-degraded".
func (s *SQLiteStore) Degraded() bool { return s.writeFailures.Load() > 0 }

// validIdentifierRe gates tableName against SQL injection. Every Insert /
// Query / migrate string-substitutes `s.table` into the SQL via fmt.Sprintf
// (parameterized identifiers aren't supported by SQLite's API), so a
// hostile or accidentally-attacker-controlled table name would punch
// through. Multi-tenant adopters who derive a suffix from a JWT claim
// or env var without their own validation are the realistic blast radius.
var validIdentifierRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// auditCols is the column order for every SELECT and INSERT, so scanRows
// doesn't depend on the table's physical column order.
const auditCols = `id, origin_id, monotonic_seq, timestamp, code, action, severity,` +
	` service_id, source_node_id, tenant_id, actor, actor_kind,` +
	` target, category, domain, method, request_id, detail,` +
	` pii_in_detail, shipped_at, wire_version, hash, prev_hash, canonical_form_id,` +
	// Form "2" columns (spec §1.4).
	` detail_salt, detail_commitment`

// NewSQLiteStore creates and migrates the audit table, then returns the store.
// tableName must be a plain SQL identifier (^[A-Za-z_][A-Za-z0-9_]*$); any
// other value is rejected to prevent SQL injection (see validIdentifierRe).
func NewSQLiteStore(db *sql.DB, tableName string) (*SQLiteStore, error) {
	if tableName == "" {
		tableName = "fasten_audit"
	}
	if !validIdentifierRe.MatchString(tableName) {
		return nil, fmt.Errorf(
			"fasten SQLiteStore: tableName %q is not a valid SQL identifier "+
				"(must match %s): table names are string-substituted into SQL "+
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
    shipped_at    TEXT,
    wire_version  TEXT NOT NULL DEFAULT '1',
    hash          TEXT NOT NULL DEFAULT '',
    prev_hash     TEXT NOT NULL DEFAULT '',
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
`, s.table,
		s.table, s.table,
		s.table, s.table,
		s.table, s.table,
		s.table, s.table,
		s.table, s.table,
		s.table, s.table, // uq_<table>_node_seq
	)
	if _, err := s.db.Exec(ddl); err != nil {
		return err
	}

	// Add columns missing from tables created by older versions.
	existing, err := s.existingColumns()
	if err != nil {
		return err
	}
	type colDef struct {
		name string
		ddl  string
	}
	for _, col := range []colDef{
		{"pii_in_detail", "INTEGER NOT NULL DEFAULT 0"},
		{"wire_version", "TEXT NOT NULL DEFAULT '1'"},
		{"hash", "TEXT NOT NULL DEFAULT ''"},
		{"prev_hash", "TEXT NOT NULL DEFAULT ''"},
		{"canonical_form_id", "TEXT NOT NULL DEFAULT '1'"},
		{"detail_salt", "TEXT NOT NULL DEFAULT ''"},
		{"detail_commitment", "TEXT NOT NULL DEFAULT ''"},
	} {
		if !existing[col.name] {
			if _, err := s.db.Exec(fmt.Sprintf(
				"ALTER TABLE %s ADD COLUMN %s %s", s.table, col.name, col.ddl,
			)); err != nil {
				return err
			}
		}
	}

	// Created after the column migration, since older tables may only now
	// have pii_in_detail.
	for _, idx := range []string{
		fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_pii ON %s(pii_in_detail) WHERE pii_in_detail = 1", s.table, s.table),
	} {
		if _, err := s.db.Exec(idx); err != nil {
			return err
		}
	}
	return nil
}

// existingColumns returns the table's column names.
func (s *SQLiteStore) existingColumns() (map[string]bool, error) {
	rows, err := s.db.Query(fmt.Sprintf("PRAGMA table_info(%s)", s.table))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return nil, err
		}
		cols[name] = true
	}
	return cols, rows.Err()
}

// insertRowExec inserts a row (INSERT OR IGNORE) on a *sql.DB, *sql.Conn or
// *sql.Tx. The originated and replicated checks are in the callers.
func (s *SQLiteStore) insertRowExec(ctx context.Context, exec execContext, row Row) error {
	detail, err := json.Marshal(row.Detail)
	if err != nil {
		detail = []byte("{}")
	}
	var shippedAt *string
	if row.ShippedAt != nil {
		v := canonicalTS(*row.ShippedAt)
		shippedAt = &v
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
		fmt.Sprintf(`INSERT OR IGNORE INTO %s (%s) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, s.table, auditCols),
		row.ID, row.OriginID, row.MonotonicSeq,
		canonicalTS(row.Timestamp),
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
func (s *SQLiteStore) insertRow(ctx context.Context, row Row) error {
	return s.insertRowExec(ctx, s.db, row)
}

// InsertOriginated inserts a row this node originated (origin_id == id).
func (s *SQLiteStore) InsertOriginated(ctx context.Context, row Row) error {
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
// The seq comes from the store rather than engine memory, so several engines
// sharing a store (services, forked workers) don't both write seq 1. BEGIN
// IMMEDIATE takes the write lock before the read, so two writers can't read
// the same tip.
func (s *SQLiteStore) AllocateAndInsertOriginated(ctx context.Context, row Row) (Row, error) {
	if row.OriginID != row.ID {
		return Row{}, fmt.Errorf(
			"fasten AllocateAndInsertOriginated: requires origin_id == id (got origin_id=%q, id=%q)",
			row.OriginID, row.ID)
	}
	// Truncate to microseconds before sealing, the same as PostgresStore,
	// so the hash covers only what the stored timestamp keeps.
	row.Timestamp = row.Timestamp.Truncate(time.Microsecond)
	if row.ShippedAt != nil {
		t := row.ShippedAt.Truncate(time.Microsecond)
		row.ShippedAt = &t
	}

	// BeginTx can't start an IMMEDIATE transaction and the caller owns the
	// DSN (so no _txlock=immediate), so run BEGIN IMMEDIATE by hand on a
	// dedicated connection.
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return Row{}, err
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return Row{}, fmt.Errorf("fasten: BEGIN IMMEDIATE: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			// Not ctx: if ctx is cancelled the ROLLBACK wouldn't run and the
			// connection would go back to the pool holding the write lock.
			_, _ = conn.ExecContext(context.WithoutCancel(ctx), "ROLLBACK")
		}
	}()

	// Two queries: seq counts every row on the node, sealed or not (an
	// unsealed row still holds its number), while prev_hash comes from the
	// last sealed row.
	var nextSeq int64
	if err := conn.QueryRowContext(ctx,
		"SELECT COALESCE(MAX(monotonic_seq), 0) FROM "+s.table+" WHERE source_node_id = ?",
		row.SourceNodeID).Scan(&nextSeq); err != nil {
		return Row{}, err
	}
	nextSeq++

	prevHash := "genesis"
	var tip string
	err = conn.QueryRowContext(ctx,
		"SELECT hash FROM "+s.table+" WHERE source_node_id = ? AND hash != '' "+
			"ORDER BY monotonic_seq DESC LIMIT 1", row.SourceNodeID).Scan(&tip)
	if err == nil && tip != "" {
		prevHash = tip
	} else if err != nil && err != sql.ErrNoRows {
		return Row{}, err
	}

	row.MonotonicSeq = nextSeq
	sealed := Seal(prevHash, row)
	if err := s.insertRowExec(ctx, conn, sealed); err != nil {
		return Row{}, err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return Row{}, err
	}
	committed = true
	return sealed, nil
}

// InsertReplicated inserts a sealed row replicated from another origin,
// outside a transaction. IngestReplicated uses insertReplicatedTx instead.
func (s *SQLiteStore) InsertReplicated(ctx context.Context, row Row) error {
	if row.Hash == "" {
		return fmt.Errorf("fasten InsertReplicated: requires a sealed row (non-empty hash); row %q has no hash", row.ID)
	}
	return s.insertRow(ctx, row)
}

// insertReplicatedTx is InsertReplicated on the caller's transaction;
// IngestReplicated commits once for the batch.
func (s *SQLiteStore) insertReplicatedTx(ctx context.Context, exec execContext, row Row) error {
	if row.Hash == "" {
		return fmt.Errorf("fasten insertReplicatedTx: requires a sealed row (non-empty hash); row %q has no hash", row.ID)
	}
	return s.insertRowExec(ctx, exec, row)
}

// Insert calls InsertOriginated. The drainer writes through it.
func (s *SQLiteStore) Insert(ctx context.Context, row Row) error {
	return s.InsertOriginated(ctx, row)
}

func (s *SQLiteStore) Query(ctx context.Context, f Filter) ([]Row, error) {
	where, args := filterToSQL(f)
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	// Cursor pagination: results are newest-first, so the next page is
	// monotonic_seq < AfterSeq. It's applied here rather than in filterToSQL
	// so CountFiltered still counts every match.
	//
	// Known limitation: seq is per origin, so on a store holding rows from
	// several origins, paging can skip or repeat rows. Fixing it needs a
	// (timestamp, seq) cursor, which would change the API.
	if f.AfterSeq > 0 {
		if where == "" {
			where = "WHERE monotonic_seq < ?"
		} else {
			where += " AND monotonic_seq < ?"
		}
		args = append(args, f.AfterSeq)
	}
	// monotonic_seq is per source_node_id, so it only breaks
	// ties between equal timestamps (#68).
	rows, err := s.db.QueryContext(ctx,
		fmt.Sprintf(`SELECT %s FROM %s %s ORDER BY timestamp DESC, monotonic_seq DESC LIMIT ? OFFSET ?`, auditCols, s.table, where),
		append(args, limit, offset)...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

// CountFiltered counts rows matching f, ignoring Limit, so a capped read
// (e.g. /correlate) can report truncation.
func (s *SQLiteStore) CountFiltered(ctx context.Context, f Filter) (int, error) {
	where, args := filterToSQL(f)
	var n int
	err := s.db.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT COUNT(*) FROM %s %s`, s.table, where), args...,
	).Scan(&n)
	return n, err
}

// Search does a case-insensitive substring match of q against detail
// (§4.1), from since, newest-first, up to limit, with no ranking. LIKE
// wildcards in q match literally.
// A non-empty tenantID scopes the query to one tenant (SQL WHERE
// tenant_id=?); the reader wires the caller's authenticated tenant here
// so a shared multi-tenant store doesn't leak substring matches across
// tenants.
func (s *SQLiteStore) Search(ctx context.Context, q, since, until, tenantID string, limit int) ([]Row, error) {
	esc := escapeLikeLiteral(strings.ToLower(q))
	conds := []string{"COALESCE(timestamp, '') >= ?", "lower(detail) LIKE ? ESCAPE '\\'"}
	args := []any{since, "%" + esc + "%"}
	if until != "" {
		conds = append(conds, "COALESCE(timestamp, '') <= ?")
		args = append(args, until)
	}
	if tenantID != "" {
		conds = append(conds, "tenant_id = ?")
		args = append(args, tenantID)
	}
	args = append(args, limit)
	sql := fmt.Sprintf(
		`SELECT %s FROM %s WHERE %s ORDER BY timestamp DESC, monotonic_seq DESC LIMIT ?`,
		auditCols, s.table, strings.Join(conds, " AND "),
	)
	rows, err := s.db.QueryContext(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

// escapeLikeLiteral escapes LIKE metacharacters (%, _, \) so they match
// as data under an ESCAPE '\' clause.
func escapeLikeLiteral(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

func (s *SQLiteStore) ListUnshipped(ctx context.Context, limit int) ([]Row, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		fmt.Sprintf(`SELECT %s FROM %s WHERE shipped_at IS NULL ORDER BY monotonic_seq ASC LIMIT ?`, auditCols, s.table),
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

// ListUnshippedOriginated returns unshipped rows this node originated, for
// (serviceID, sourceNodeID) with origin_id = id. Replicated rows are left out
// so they aren't shipped upstream again. ListUnshipped returns every
// unshipped row.
func (s *SQLiteStore) ListUnshippedOriginated(ctx context.Context, serviceID, sourceNodeID string, limit int) ([]Row, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx,
		fmt.Sprintf(`SELECT %s FROM %s WHERE shipped_at IS NULL AND service_id = ? AND source_node_id = ? AND origin_id = id ORDER BY monotonic_seq ASC LIMIT ?`, auditCols, s.table),
		serviceID, sourceNodeID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRows(rows)
}

func (s *SQLiteStore) MarkShipped(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	now := canonicalTS(time.Now())
	placeholders := make([]string, len(ids))
	args := make([]any, 0, len(ids)+1)
	args = append(args, now)
	for i, id := range ids {
		placeholders[i] = "?"
		args = append(args, id)
	}
	q := fmt.Sprintf(
		`UPDATE %s SET shipped_at=? WHERE id IN (%s)`,
		s.table, strings.Join(placeholders, ","),
	)
	_, err := s.db.ExecContext(ctx, q, args...)
	return err
}

func (s *SQLiteStore) Purge(ctx context.Context, before time.Time, respectUnshipped bool) (int, error) {
	q := fmt.Sprintf(`DELETE FROM %s WHERE timestamp < ?`, s.table)
	args := []any{canonicalTS(before)}
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

// Count returns the number of rows in the audit table. /audit/doctor uses it
// to check the store is reachable.
func (s *SQLiteStore) Count(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM %s`, s.table)).Scan(&n)
	return n, err
}

// MaxMonotonicSeq returns the highest monotonic_seq for (serviceID,
// sourceNodeID). The engine no longer uses it; the store allocates seq on
// insert. If either id is empty
// it returns the MAX over the whole table.
func (s *SQLiteStore) MaxMonotonicSeq(ctx context.Context, serviceID, sourceNodeID string) (int64, error) {
	var n sql.NullInt64
	var err error
	if serviceID != "" && sourceNodeID != "" {
		err = s.db.QueryRowContext(ctx,
			fmt.Sprintf(`SELECT MAX(monotonic_seq) FROM %s WHERE service_id = ? AND source_node_id = ?`, s.table),
			serviceID, sourceNodeID,
		).Scan(&n)
	} else {
		err = s.db.QueryRowContext(ctx, fmt.Sprintf(`SELECT MAX(monotonic_seq) FROM %s`, s.table)).Scan(&n)
	}
	if err != nil || !n.Valid {
		return 0, err
	}
	return n.Int64, nil
}

// Sources returns one entry per (source_node_id, service_id, tenant_id) in
// the audit rows, with row count and first and last timestamps, largest
// first. since and until, if set, limit the rows counted.
func (s *SQLiteStore) Sources(ctx context.Context, since, until time.Time) ([]map[string]any, error) {
	var conds []string
	var args []any
	if !since.IsZero() {
		conds = append(conds, "timestamp >= ?")
		args = append(args, canonicalTS(since))
	}
	if !until.IsZero() {
		conds = append(conds, "timestamp <= ?")
		args = append(args, canonicalTS(until))
	}
	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}
	query := fmt.Sprintf(
		"SELECT source_node_id, service_id, tenant_id, COUNT(*) AS n, "+
			"MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen "+
			"FROM %s %s GROUP BY source_node_id, service_id, tenant_id ORDER BY n DESC",
		s.table, where,
	)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var node, svc string
		var tenant, first, last sql.NullString
		var n int
		if err := rows.Scan(&node, &svc, &tenant, &n, &first, &last); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"source_node_id": node,
			"service_id":     svc,
			"tenant_id":      nullStrOrNil(tenant),
			"rows":           n,
			"first_seen":     nullStrOrNil(first),
			"last_seen":      nullStrOrNil(last),
		})
	}
	return out, rows.Err()
}

func nullStrOrNil(ns sql.NullString) any {
	if ns.Valid {
		return ns.String
	}
	return nil
}

func filterToSQL(f Filter) (string, []any) {
	var conds []string
	var args []any
	if f.RequestID != "" {
		conds = append(conds, "request_id = ?")
		args = append(args, f.RequestID)
	}
	if f.Code != "" {
		conds = append(conds, "code = ?")
		args = append(args, string(f.Code))
	}
	if f.Domain != "" {
		conds = append(conds, "domain = ?")
		args = append(args, string(f.Domain))
	}
	if f.SourceNodeID != "" {
		conds = append(conds, "source_node_id = ?")
		args = append(args, f.SourceNodeID)
	}
	if f.TenantID != "" {
		conds = append(conds, "tenant_id = ?")
		args = append(args, f.TenantID)
	}
	if f.Actor != "" {
		conds = append(conds, "actor = ?")
		args = append(args, f.Actor)
	}
	if f.Target != "" {
		conds = append(conds, "target = ?")
		args = append(args, f.Target)
	}
	if !f.Since.IsZero() {
		conds = append(conds, "timestamp >= ?")
		args = append(args, canonicalTS(f.Since))
	}
	if !f.Until.IsZero() {
		conds = append(conds, "timestamp <= ?")
		args = append(args, canonicalTS(f.Until))
	}
	// AfterSeq is applied in Query, so CountFiltered counts every match.
	if len(conds) == 0 {
		return "", args
	}
	where := "WHERE " + strings.Join(conds, " AND ")
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
		var wv, hash, prevHash, formID string
		if err := rows.Scan(
			&r.ID, &r.OriginID, &r.MonotonicSeq,
			&ts, &code, &r.Action, &sev,
			&r.ServiceID, &r.SourceNodeID, &r.TenantID,
			&r.Actor, &r.ActorKind,
			&r.Target, &r.Category, &domain,
			&r.Method, &r.RequestID, &detail, &piiFlag, &shippedAt,
			&wv, &hash, &prevHash, &formID,
			&r.DetailSalt, &r.DetailCommitment,
		); err != nil {
			return nil, err
		}
		// A timestamp or detail that doesn't parse is an error. A zero time
		// would sort to the top of every newest-first query.
		parsedTs, err := parseCanonicalTS(ts)
		if err != nil {
			return nil, fmt.Errorf("scanRows: row %q: %w", r.ID, err)
		}
		r.Timestamp = parsedTs
		r.Code = Code(code)
		r.Severity = Severity(sev)
		r.Domain = Domain(domain)
		if err := json.Unmarshal([]byte(detail), &r.Detail); err != nil {
			return nil, fmt.Errorf("scanRows: row %q detail: %w", r.ID, err)
		}
		r.PiiInDetail = piiFlag != 0
		if shippedAt != nil {
			t, err := parseCanonicalTS(*shippedAt)
			if err != nil {
				return nil, fmt.Errorf("scanRows: row %q shipped_at: %w", r.ID, err)
			}
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
//
// Skips form-"1" rows: their detail IS hashed, so redacting one changes its
// hash and cascades a re-seal down the chain. Counted and logged rather than
// skipped quietly — on a pre-form-"2" store, silence lets an operator watch
// redaction "succeed" while the personal data survives.
func (s *SQLiteStore) ListRedactionCandidates(
	ctx context.Context, before time.Time, codes []Code,
) ([]RedactionCandidate, int, error) {
	if len(codes) == 0 {
		return nil, 0, nil
	}
	args := make([]any, 0, len(codes)+1)
	args = append(args, canonicalTS(before))
	ph := ""
	for i, c := range codes {
		if i > 0 {
			ph += ","
		}
		ph += "?"
		args = append(args, string(c))
	}

	var skipped int64
	if err := s.db.QueryRowContext(ctx, fmt.Sprintf(
		"SELECT COUNT(*) FROM %s WHERE timestamp < ? AND code IN (%s) "+
			"AND canonical_form_id <> '2' AND detail <> 'null'", s.table, ph),
		args...).Scan(&skipped); err != nil {
		return nil, 0, err
	}

	rows, err := s.db.QueryContext(ctx, fmt.Sprintf(
		"SELECT id, monotonic_seq FROM %s WHERE timestamp < ? AND code IN (%s) "+
			"AND canonical_form_id = '2' AND detail <> 'null' "+
			"ORDER BY monotonic_seq", s.table, ph),
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

// RedactRows implements RedactionRepository (spec §7.1). Destroys detail and
// detail_salt on an explicit id list; the hash, prev_hash and monotonic_seq are
// untouched, so the chain still verifies. It is idempotent: a retry with the
// same ids returns the same list.
func (s *SQLiteStore) RedactRows(ctx context.Context, ids []string) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	args := make([]any, 0, len(ids))
	ph := ""
	for i, id := range ids {
		if i > 0 {
			ph += ","
		}
		ph += "?"
		args = append(args, id)
	}
	// 'null' (the JSON literal), not SQL NULL: detail is NOT NULL and dropping
	// that on SQLite needs a full table rebuild. Reads back as nil either way.
	if _, err := s.db.ExecContext(ctx, fmt.Sprintf(
		"UPDATE %s SET detail = 'null', detail_salt = '' "+
			"WHERE id IN (%s) AND canonical_form_id = '2'", s.table, ph),
		args...); err != nil {
		return nil, err
	}
	return ids, nil
}
