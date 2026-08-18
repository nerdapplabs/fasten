package fasten

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
)

// PostgresStreamStore is the Postgres-backed StreamRepository — the high-volume
// sibling of StreamStore. It carries the same schema form "1" columns/indexes
// and the same query/filter/window/completeness/purge/search semantics, so a
// stream table is portable across backends and the SQLite and Postgres paths
// agree (and match the Python SDK). Chosen where SQLite's single-writer lock is
// the bottleneck.
//
// The caller imports a Postgres driver (e.g. github.com/lib/pq) and owns the
// *sql.DB, exactly as with the audit PostgresStore. This file uses only
// database/sql, so it adds no driver dependency to the library build.
type PostgresStreamStore struct {
	db        *sql.DB
	table     string
	idxPrefix string
	schema    string

	// writeFailures: swallowed Insert errors → "store-degraded". See StreamStore.
	writeFailures atomic.Int64
}

// NewPostgresStreamStore validates the table name, ensures the schema/table and
// indexes exist, and returns a ready store. Default table "syslog".
func NewPostgresStreamStore(db *sql.DB, tableName string) (*PostgresStreamStore, error) {
	if tableName == "" {
		tableName = "syslog"
	}
	if !validPgIdentifierRe.MatchString(tableName) {
		return nil, fmt.Errorf("fasten: invalid stream table name %q", tableName)
	}
	s := &PostgresStreamStore{db: db, table: tableName, idxPrefix: tableName}
	if i := strings.LastIndex(tableName, "."); i >= 0 {
		s.schema = tableName[:i]
		s.idxPrefix = tableName[i+1:]
	}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *PostgresStreamStore) migrate() error {
	if s.schema != "" {
		if _, err := s.db.Exec("CREATE SCHEMA IF NOT EXISTS " + s.schema); err != nil {
			return err
		}
	}
	ddl := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		seq        BIGSERIAL PRIMARY KEY,
		request_id TEXT,
		timestamp  TEXT,
		level      TEXT,
		service_id TEXT,
		event      TEXT,
		method     TEXT,
		path       TEXT,
		status     INTEGER,
		payload    TEXT NOT NULL)`, s.table)
	if _, err := s.db.Exec(ddl); err != nil {
		return err
	}
	for _, idx := range []struct{ suffix, col string }{
		{"req", "request_id"}, {"ts", "timestamp"}, {"lvl", "level"}, {"svc", "service_id"},
		{"evt", "event"}, {"mth", "method"}, {"pth", "path"}, {"sts", "status"},
	} {
		q := fmt.Sprintf("CREATE INDEX IF NOT EXISTS idx_%s_%s ON %s(%s)",
			s.idxPrefix, idx.suffix, s.table, idx.col)
		if _, err := s.db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

func (s *PostgresStreamStore) Insert(row map[string]any) error {
	payload, err := json.Marshal(row)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(fmt.Sprintf(
		"INSERT INTO %s (request_id,timestamp,level,service_id,event,method,path,status,payload) "+
			"VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)", s.table),
		strOrNil(row, "request_id"), strOrNil(row, "timestamp"), strOrNil(row, "level"),
		strOrNil(row, "service_id"), strOrNil(row, "event"), strOrNil(row, "method"),
		strOrNil(row, "path"), row["status"], string(payload),
	)
	return err
}

func (s *PostgresStreamStore) NoteWriteFailure() { s.writeFailures.Add(1) }

// WriteFailures exposes the swallowed-insert count (tests only).
func (s *PostgresStreamStore) WriteFailures() int64 { return s.writeFailures.Load() }

func (s *PostgresStreamStore) Degraded() bool { return s.writeFailures.Load() > 0 }

// whereClause builds an equality + time-window WHERE with $N placeholders
// starting at argStart. status arrives as a string in the eq map but the column
// is INTEGER: compare it numerically (parse to int) so non-canonical forms like
// "007" match 7 — matching the Python SDK, which binds status as an int. (The
// old CAST(status AS TEXT) compared '7' != '007' and silently missed.)
func (s *PostgresStreamStore) whereClause(eq map[string]string, since, until string, argStart int) (string, []any, int) {
	var conds []string
	var args []any
	n := argStart
	keys := make([]string, 0, len(eq))
	for k, v := range eq {
		if v != "" && isStreamIndexed(k) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		if k == "status" {
			if iv, err := strconv.Atoi(eq[k]); err == nil {
				conds = append(conds, fmt.Sprintf("status = $%d", n))
				args = append(args, iv)
				n++
				continue
			}
			// Non-numeric status can't match an INTEGER column; keep a text
			// compare so it matches nothing rather than erroring.
			conds = append(conds, fmt.Sprintf("CAST(status AS TEXT) = $%d", n))
		} else {
			conds = append(conds, fmt.Sprintf("%s = $%d", k, n))
		}
		args = append(args, eq[k])
		n++
	}
	if since != "" {
		conds = append(conds, fmt.Sprintf("COALESCE(timestamp,'') >= $%d", n))
		args = append(args, since)
		n++
	}
	if until != "" {
		conds = append(conds, fmt.Sprintf("COALESCE(timestamp,'') <= $%d", n))
		args = append(args, until)
		n++
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}
	return where, args, n
}

func (s *PostgresStreamStore) scan(query string, args []any) ([]map[string]any, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var payload string
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(payload), &m); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *PostgresStreamStore) Query(limit int, eq map[string]string, since, until string) ([]map[string]any, error) {
	where, args, n := s.whereClause(eq, since, until, 1)
	query := fmt.Sprintf("SELECT payload FROM %s%s ORDER BY seq DESC LIMIT $%d", s.table, where, n)
	return s.scan(query, append(args, limit))
}

func (s *PostgresStreamStore) CountMatching(eq map[string]string, since, until string) (int, error) {
	where, args, _ := s.whereClause(eq, since, until, 1)
	var n int
	err := s.db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s%s", s.table, where), args...).Scan(&n)
	return n, err
}

func (s *PostgresStreamStore) Count() (int, error) {
	var n int
	err := s.db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", s.table)).Scan(&n)
	return n, err
}

func (s *PostgresStreamStore) Purge(before string) (int64, error) {
	res, err := s.db.Exec(fmt.Sprintf("DELETE FROM %s WHERE timestamp < $1", s.table), before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *PostgresStreamStore) Search(q, since, until string, limit int) ([]map[string]any, error) {
	esc := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(q)
	// ILIKE is case-insensitive, so no lower(); wildcards in q are escaped.
	// ESCAPE E'\\' (explicit escape-string) always means one backslash,
	// independent of standard_conforming_strings; plain '\' would break if a
	// deployment turned that off (FR3-4).
	conds := []string{"COALESCE(timestamp,'') >= $1", `payload ILIKE $2 ESCAPE E'\\'`}
	args := []any{since, "%" + esc + "%"}
	n := 3
	if until != "" {
		conds = append(conds, fmt.Sprintf("COALESCE(timestamp,'') <= $%d", n))
		args = append(args, until)
		n++
	}
	query := fmt.Sprintf("SELECT payload FROM %s WHERE %s ORDER BY seq DESC LIMIT $%d",
		s.table, strings.Join(conds, " AND "), n)
	return s.scan(query, append(args, limit))
}
