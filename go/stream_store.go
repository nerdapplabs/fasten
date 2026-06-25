package fasten

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// StreamStore is a durable, queryable backing for one ring-buffered stream
// (api or sys). Unlike the audit store (typed Row + tamper-evident hash
// chain), stream rows are schemaless maps produced by the logging/HTTP
// shims. The full row is persisted as a JSON payload and the queryable
// fields are duplicated into indexed columns, so the reader can filter by
// request_id / time / structured fields against durable history instead of a
// bounded ring.
//
// Table per stream — api and sys never share rows. Rows return newest-first,
// byte-for-byte identical to what was pushed, so a store read is
// indistinguishable from a ring read apart from depth.
//
// The caller imports the SQLite driver and opens the *sql.DB, exactly as for
// NewSQLiteStore. SQLite-only in v1; a pluggable Postgres stream store is a
// later phase.
type StreamStore struct {
	db    *sql.DB
	table string
}

// streamIndexedFields are lifted out of the row into indexed columns for
// filtering; the rest of the row survives in `payload`.
var streamIndexedFields = []string{
	"request_id", "timestamp", "level", "service_id",
	"event", "method", "path", "status",
}

// NewStreamStore creates and migrates a per-stream table, then returns the
// store. tableName must be a plain SQL identifier (see validIdentifierRe).
func NewStreamStore(db *sql.DB, tableName string) (*StreamStore, error) {
	if tableName == "" {
		return nil, fmt.Errorf("fasten StreamStore: tableName is required")
	}
	if !validIdentifierRe.MatchString(tableName) {
		return nil, fmt.Errorf(
			"fasten StreamStore: tableName %q is not a valid SQL identifier "+
				"(must match %s)", tableName, validIdentifierRe.String())
	}
	s := &StreamStore{db: db, table: tableName}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("fasten StreamStore migrate: %w", err)
	}
	return s, nil
}

func (s *StreamStore) migrate() error {
	ddl := fmt.Sprintf(`
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS %s (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT,
    timestamp  TEXT,
    level      TEXT,
    service_id TEXT,
    event      TEXT,
    method     TEXT,
    path       TEXT,
    status     INTEGER,
    payload    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_%s_req ON %s(request_id);
CREATE INDEX IF NOT EXISTS idx_%s_ts  ON %s(timestamp);
CREATE INDEX IF NOT EXISTS idx_%s_lvl ON %s(level);
CREATE INDEX IF NOT EXISTS idx_%s_svc ON %s(service_id);
CREATE INDEX IF NOT EXISTS idx_%s_evt ON %s(event);
CREATE INDEX IF NOT EXISTS idx_%s_mth ON %s(method);
CREATE INDEX IF NOT EXISTS idx_%s_pth ON %s(path);
CREATE INDEX IF NOT EXISTS idx_%s_sts ON %s(status);
`, s.table,
		s.table, s.table, s.table, s.table, s.table, s.table, s.table, s.table,
		s.table, s.table, s.table, s.table, s.table, s.table, s.table, s.table,
	)
	_, err := s.db.Exec(ddl)
	return err
}

// Insert write-through persists a single stream row. Newest rows sort first.
func (s *StreamStore) Insert(row map[string]any) error {
	payload, err := json.Marshal(row)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		fmt.Sprintf("INSERT INTO %s "+
			"(request_id,timestamp,level,service_id,event,method,path,status,payload) "+
			"VALUES (?,?,?,?,?,?,?,?,?)", s.table),
		strOrNil(row, "request_id"), strOrNil(row, "timestamp"), strOrNil(row, "level"),
		strOrNil(row, "service_id"), strOrNil(row, "event"), strOrNil(row, "method"),
		strOrNil(row, "path"), row["status"], string(payload),
	)
	return err
}

// Query returns up to limit rows newest-first, filtered by equality on the
// given indexed columns (only columns in streamIndexedFields are honoured).
// Mirrors the ring's exact-match filter semantics so store and ring agree.
func (s *StreamStore) Query(limit int, eq map[string]string) ([]map[string]any, error) {
	var conds []string
	var args []any
	// Deterministic clause order for stable, testable SQL.
	keys := make([]string, 0, len(eq))
	for k := range eq {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if eq[k] == "" || !isStreamIndexed(k) {
			continue
		}
		conds = append(conds, fmt.Sprintf("%s = ?", k))
		args = append(args, eq[k])
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}
	args = append(args, limit)
	rows, err := s.db.Query(
		fmt.Sprintf("SELECT payload FROM %s%s ORDER BY seq DESC LIMIT ?", s.table, where),
		args...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
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

// Count returns the number of persisted rows (test/diagnostic helper).
func (s *StreamStore) Count() (int, error) {
	var n int
	err := s.db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", s.table)).Scan(&n)
	return n, err
}

func isStreamIndexed(col string) bool {
	for _, f := range streamIndexedFields {
		if f == col {
			return true
		}
	}
	return false
}

// strOrNil returns the string value at key, or nil so the column stores NULL
// rather than an empty string when the field is absent.
func strOrNil(row map[string]any, key string) any {
	if v, ok := row[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		return v
	}
	return nil
}
