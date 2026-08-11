package fasten

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
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
// reconstructed from the stored JSON payload, so a store read is equivalent
// to a ring read in content and ordering. Note JSON decoding normalises
// number types: all numbers decode to float64 (a ring read returns the
// original int), so the value is JSON-equivalent, not type-identical.
//
// Write cost: persistence is write-through — every pushed row is one
// synchronous INSERT in its own transaction, on the caller's thread. With
// WAL + synchronous=NORMAL (set by migrate; see below) a commit is a WAL
// append without a per-commit fsync, which keeps a hot api/sys stream
// viable. Even so this is a per-row disk write: for very hot streams prefer
// ring-only mode, or expect stream persistence to grow an async drainer in
// a later phase (the audit path already has one).
//
// The caller imports the SQLite driver and opens the *sql.DB, exactly as for
// NewSQLiteStore. SQLite-only in v1; a pluggable Postgres stream store is a
// later phase.
type StreamStore struct {
	db    *sql.DB
	table string

	// writeFailures counts Insert errors swallowed by the transport (the hot
	// path never blocks on the sink). Non-zero means durable history has holes,
	// so the reader degrades the stream's completeness flag from "store" to
	// "store-degraded" — otherwise the flag would assert durability for rows
	// that were silently lost. Sticky for the store's lifetime: a hole in
	// history doesn't heal when the disk recovers.
	writeFailures atomic.Int64
}

// streamIndexedFields are lifted out of the row into indexed columns for
// filtering; the rest of the row survives in `payload`.
var streamIndexedFields = []string{
	"request_id", "timestamp", "level", "service_id",
	"event", "method", "path", "status",
}

// NewStreamStore creates and migrates a per-stream table, then returns the
// store. tableName must be a plain SQL identifier (see validIdentifierRe).
//
// migrate sets PRAGMA synchronous=NORMAL, but that pragma is per-connection
// and database/sql pools connections — set it in the DSN so every pooled
// connection gets it (e.g. mattn/go-sqlite3: "file:app.db?_synchronous=NORMAL";
// modernc.org/sqlite: "file:app.db?_pragma=synchronous(NORMAL)").
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
	// synchronous=NORMAL is the standard WAL pairing: commits append to the
	// WAL without a per-commit fsync (the WAL is synced at checkpoints), which
	// matters because Insert runs one commit per pushed row. In WAL mode
	// NORMAL still guarantees database consistency after a crash; the tail of
	// unsynced commits may be lost, which is acceptable for stream rows (the
	// tamper-evident audit chain has its own store and drainer).
	ddl := fmt.Sprintf(`
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
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

// NoteWriteFailure records that a persist attempt for this store was
// swallowed. Called by the transport at the swallow point, so callers that
// handle an Insert error themselves don't mark the store degraded.
func (s *StreamStore) NoteWriteFailure() { s.writeFailures.Add(1) }

// WriteFailures returns how many persist attempts were swallowed.
func (s *StreamStore) WriteFailures() int64 { return s.writeFailures.Load() }

// Degraded reports whether durable history has known holes (at least one
// swallowed persist failure). Drives the "store-degraded" completeness flag.
func (s *StreamStore) Degraded() bool { return s.writeFailures.Load() > 0 }

// whereClause builds the shared WHERE for Query/CountMatching: equality on
// indexed columns (only streamIndexedFields are honoured) plus an optional
// [since, until] window on timestamp.
func (s *StreamStore) whereClause(eq map[string]string, since, until string) (string, []any) {
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
	// COALESCE so a NULL (timestamp-less) row sorts as "" — matching the ring,
	// which treats a missing timestamp as empty string. Without this a NULL row
	// is excluded by `<= until` in SQL but included in the ring.
	if since != "" {
		conds = append(conds, "COALESCE(timestamp, '') >= ?")
		args = append(args, since)
	}
	if until != "" {
		conds = append(conds, "COALESCE(timestamp, '') <= ?")
		args = append(args, until)
	}
	if len(conds) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// Query returns up to limit rows newest-first, filtered by equality on the
// given indexed columns plus an optional [since, until] window on timestamp.
// Mirrors the ring's exact-match filter semantics so store and ring agree.
func (s *StreamStore) Query(limit int, eq map[string]string, since, until string) ([]map[string]any, error) {
	where, args := s.whereClause(eq, since, until)
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

// CountMatching returns the total number of rows matching the same filters
// as Query, without a limit — so a capped read can report how much history
// it truncated (the /correlate totals).
func (s *StreamStore) CountMatching(eq map[string]string, since, until string) (int, error) {
	where, args := s.whereClause(eq, since, until)
	var n int
	err := s.db.QueryRow(
		fmt.Sprintf("SELECT COUNT(*) FROM %s%s", s.table, where), args...,
	).Scan(&n)
	return n, err
}

// Count returns the number of persisted rows (test/diagnostic helper).
func (s *StreamStore) Count() (int, error) {
	var n int
	err := s.db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", s.table)).Scan(&n)
	return n, err
}

// Purge deletes rows older than before (a canonical UTC ISO-8601 string) and
// returns how many were removed. Per-stream retention pruning (FR1): api/sys
// run 10-100x audit volume, so their history is trimmed by age. Unlike audit,
// stream rows have no ship/replication lifecycle, so this is an unconditional
// age-based delete backed by idx_<table>_ts.
//
// Rows with a NULL/absent timestamp are never purged (timestamp < ? is never
// true for NULL) — the age of a timestamp-less row is unknown, so it is kept
// rather than silently dropped. The comparison is lexicographic, matching the
// read window; keep before in the same canonical UTC form as stored timestamps.
func (s *StreamStore) Purge(before string) (int64, error) {
	res, err := s.db.Exec(
		fmt.Sprintf("DELETE FROM %s WHERE timestamp < ?", s.table), before,
	)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
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
