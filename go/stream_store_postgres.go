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

// PostgresStreamStore is a Postgres StreamRepository with the same schema and
// query semantics as the SQLite StreamStore. Use it when SQLite's single
// writer is the bottleneck.
//
// The caller imports a Postgres driver (e.g. github.com/lib/pq) and owns the
// *sql.DB; this file only uses database/sql.
type PostgresStreamStore struct {
	db        *sql.DB
	table     string
	idxPrefix string
	schema    string

	// writeFailures counts swallowed Insert errors; see StreamStore.
	writeFailures atomic.Int64
}

// NewPostgresStreamStore validates the table name, creates the schema, table
// and indexes if needed, and returns the store. tableName is required (e.g.
// "api_log" or "syslog"); there is no default, so one stream can't end up
// writing into another's table.
func NewPostgresStreamStore(db *sql.DB, tableName string) (*PostgresStreamStore, error) {
	if tableName == "" {
		return nil, fmt.Errorf("fasten: stream table name is required (was empty)")
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
	payload, err := marshalStreamPayload(row)
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

// whereClause builds an equality and time-window WHERE with $N placeholders
// starting at argStart. status is compared as an integer so "007" matches 7.
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
	// ILIKE is case-insensitive; wildcards in q are escaped. E'\\' is one
	// backslash whatever standard_conforming_strings is set to.
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
