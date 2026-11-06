package fasten

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	_ "modernc.org/sqlite" // registers the "sqlite" driver used by OpenStreamStore
)

// StreamRepository is the store behind one ring-buffered stream (api or sys).
// *StreamStore (SQLite) and *PostgresStreamStore implement it.
type StreamRepository interface {
	Insert(row map[string]any) error
	Query(limit int, eq map[string]string, since, until string) ([]map[string]any, error)
	CountMatching(eq map[string]string, since, until string) (int, error)
	Count() (int, error)
	Purge(before string) (int64, error)
	Search(q, since, until string, limit int) ([]map[string]any, error)
	NoteWriteFailure()
	Degraded() bool
}

// StreamStore is a SQLite store for one stream (api or sys), one table per
// stream. Each row is stored whole as JSON, with the filterable fields
// copied into indexed columns. Rows come back newest-first, decoded from the
// JSON, so numbers come back as float64 where a ring read has the original int.
//
// Every pushed row is one INSERT on the caller's goroutine. With WAL and
// synchronous=NORMAL that avoids an fsync per row, but for very hot streams
// ring-only mode is cheaper.
type StreamStore struct {
	db    *sql.DB
	table string

	// writeFailures counts Insert errors the transport swallowed. Non-zero
	// marks the stream "store-degraded" for the life of the store, since the
	// missing rows don't come back.
	writeFailures atomic.Int64
}

// streamIndexedFields are copied into indexed columns for filtering.
var streamIndexedFields = []string{
	"request_id", "timestamp", "level", "service_id",
	"event", "method", "path", "status",
}

// OpenStreamStore opens a SQLite stream store from a DSN using the
// modernc.org/sqlite driver. WAL and synchronous=NORMAL go in the DSN so
// every pooled connection gets them, not just the one migrate runs on.
//
// A new database file is created owner-only (0600).
//
// For another driver, or an existing *sql.DB, use NewStreamStore and set the
// pragmas in your own DSN.
func OpenStreamStore(dsn, tableName string) (*StreamStore, error) {
	path, table, err := parseStreamDSN(dsn, tableName)
	if err != nil {
		return nil, err
	}
	createOwnerOnly(path)
	db, err := sql.Open("sqlite", streamPragmaDSN(path))
	if err != nil {
		return nil, fmt.Errorf("fasten StreamStore open: %w", err)
	}
	s, err := NewStreamStore(db, table)
	if err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// createOwnerOnly creates a missing database file with mode 0600, so SQLite
// does not create it with the umask. An existing file keeps its mode. If the
// file cannot be created, the driver reports the error on first use.
func createOwnerOnly(path string) {
	if strings.HasPrefix(path, "file:") {
		path = uriFilePath(path)
	} else if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	if path == "" || path == ":memory:" {
		return
	}
	// No O_EXCL: like SQLite, follow a symlink to a missing file. The mode
	// applies only when the file is created.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err == nil {
		f.Close()
	}
}

// uriFilePath returns the file path of a SQLite file: URI, or "" when the URI
// names no file to create (in-memory, read-only, another VFS, or another
// host).
func uriFilePath(uri string) string {
	rest, _, _ := strings.Cut(strings.TrimPrefix(uri, "file:"), "#")
	rest, query, _ := strings.Cut(rest, "?")
	for _, p := range strings.Split(query, "&") {
		key, value, _ := strings.Cut(p, "=")
		switch {
		case p == "mode=memory", p == "mode=ro", p == "mode=rw", key == "vfs",
			key == "immutable" && uriTrue(value):
			return ""
		}
	}
	if strings.HasPrefix(rest, "//") {
		host, tail, _ := strings.Cut(rest[2:], "/")
		if host != "" && host != "localhost" {
			return ""
		}
		rest = "/" + tail
	}
	p := uriUnescape(rest)
	// SQLite ends the path at a %00.
	if i := strings.IndexByte(p, 0); i >= 0 {
		p = p[:i]
	}
	return p
}

// uriTrue reads a URI boolean as sqlite3_uri_boolean does.
func uriTrue(v string) bool {
	if v != "" && v[0] >= '0' && v[0] <= '9' {
		digits := v[:len(v)-len(strings.TrimLeft(v, "0123456789"))]
		return strings.Trim(digits, "0") != ""
	}
	switch strings.ToLower(v) {
	case "yes", "on", "true", "full", "extra", "normal":
		return true
	}
	return false
}

// uriUnescape decodes %XX escapes as SQLite does: a '%' without two hex
// digits after it stays as it is.
func uriUnescape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// streamPragmaDSN adds the WAL and synchronous=NORMAL pragmas to a modernc
// sqlite DSN, keeping any existing query parameters.
func streamPragmaDSN(dsn string) string {
	pragmas := "_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	if strings.Contains(dsn, "?") {
		return dsn + "&" + pragmas
	}
	return dsn + "?" + pragmas
}

// parseStreamDSN returns the file path and table name for a DSN. Accepts:
//   - a bare path: "./streams.db"
//   - a sqlite URL: "sqlite:///./rel.db" (three slashes = relative),
//     "sqlite:////abs/path.db" (four = absolute)
//   - "?table=X" on a sqlite URL to override the default table
func parseStreamDSN(dsn, defaultTable string) (string, string, error) {
	table := defaultTable
	path := dsn
	if strings.HasPrefix(dsn, "sqlite:") {
		u, err := url.Parse(dsn)
		if err != nil {
			return "", "", fmt.Errorf("fasten StreamStore: invalid sqlite DSN %q: %w", dsn, err)
		}
		path = u.Path
		// Strip the one separator slash: sqlite:///rel.db gives "rel.db",
		// sqlite:////abs.db gives "/abs.db".
		if strings.HasPrefix(path, "/") {
			path = path[1:]
		}
		if t := u.Query().Get("table"); t != "" {
			table = t
		}
	} else if strings.Contains(dsn, "://") {
		// Probably a Postgres or MySQL DSN; reject it rather than treat it as
		// a file path.
		return "", "", fmt.Errorf(
			"fasten StreamStore: DSN scheme not supported for SQLite backend "+
				"(dsn=%q). Use sqlite:///./path.db or a bare filesystem path.", dsn)
	}
	if path == "" {
		return "", "", fmt.Errorf("fasten StreamStore: DSN %q has no path", dsn)
	}
	return path, table, nil
}

// NewStreamStore creates the stream table on db if needed and returns the
// store. tableName must be a plain SQL identifier (see validIdentifierRe).
//
// migrate sets synchronous=NORMAL on only one pooled connection, so set it
// in the DSN as well (mattn/go-sqlite3: "file:app.db?_synchronous=NORMAL";
// modernc.org/sqlite: "file:app.db?_pragma=synchronous(NORMAL)").
// OpenStreamStore does this for you.
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
	// With WAL, synchronous=NORMAL skips the fsync per commit. A crash can
	// lose the last few stream rows but leaves the database consistent.
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

// Insert stores one stream row.
func (s *StreamStore) Insert(row map[string]any) error {
	payload, err := marshalStreamPayload(row)
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

// NoteWriteFailure records a swallowed Insert error. The transport calls it,
// so callers that handle Insert errors themselves don't mark the store
// degraded.
func (s *StreamStore) NoteWriteFailure() { s.writeFailures.Add(1) }

// WriteFailures returns how many persist attempts were swallowed.
func (s *StreamStore) WriteFailures() int64 { return s.writeFailures.Load() }

// Degraded reports whether any Insert error was swallowed, which makes the
// stream "store-degraded".
func (s *StreamStore) Degraded() bool { return s.writeFailures.Load() > 0 }

// whereClause builds the WHERE for Query and CountMatching: equality on
// streamIndexedFields plus an optional [since, until] window.
func (s *StreamStore) whereClause(eq map[string]string, since, until string) (string, []any) {
	var conds []string
	var args []any
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
	// The ring treats a missing timestamp as "", so do the same here.
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

// Query returns up to limit rows newest-first, filtered as in whereClause.
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

// CountMatching counts rows matching the same filters as Query, without a
// limit, so a capped read can report truncation.
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

// Purge deletes rows with a timestamp before `before` (canonical form) and
// returns how many were removed. Rows without a timestamp are kept, since
// their age is unknown.
func (s *StreamStore) Purge(before string) (int64, error) {
	res, err := s.db.Exec(
		fmt.Sprintf("DELETE FROM %s WHERE timestamp < ?", s.table), before,
	)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Search does a case-insensitive substring match of q against the stored
// JSON of each row since `since` (and up to `until` if set), newest-first,
// with no ranking. LIKE wildcards in q match literally.
func (s *StreamStore) Search(q, since, until string, limit int) ([]map[string]any, error) {
	esc := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(strings.ToLower(q))
	conds := []string{"COALESCE(timestamp,'') >= ?", "lower(payload) LIKE ? ESCAPE '\\'"}
	args := []any{since, "%" + esc + "%"}
	if until != "" {
		conds = append(conds, "COALESCE(timestamp,'') <= ?")
		args = append(args, until)
	}
	args = append(args, limit)
	query := fmt.Sprintf(
		"SELECT payload FROM %s WHERE %s ORDER BY seq DESC LIMIT ?",
		s.table, strings.Join(conds, " AND "),
	)
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

// marshalStreamPayload encodes a row as JSON without escaping '<', '>' and
// '&', the way the Python SDK writes it, so a search for "<foo>" matches
// rows from either SDK.
func marshalStreamPayload(row map[string]any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(row); err != nil {
		return nil, err
	}
	// Drop the newline Encode adds.
	b := buf.Bytes()
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
	}
	return b, nil
}

func isStreamIndexed(col string) bool {
	for _, f := range streamIndexedFields {
		if f == col {
			return true
		}
	}
	return false
}

// strOrNil returns row[key], or nil if absent so the column stores NULL.
func strOrNil(row map[string]any, key string) any {
	if v, ok := row[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		return v
	}
	return nil
}
