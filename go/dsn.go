package fasten

import (
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// Store DSNs, as FASTEN_AUDIT_DSN, FASTEN_API_DSN and FASTEN_SYSLOG_DSN hold
// them. The forms are the Python SDK's:
//
//   - postgres://... or postgresql://... (the scheme in any case);
//   - sqlite:///rel.db (relative), sqlite:////abs.db (absolute), or a bare
//     path, which may also be a SQLite file: URI;
//   - ?table=name names the table, and ?wal=false turns SQLite's WAL
//     journal off.
//
// Any other scheme, and libpq's keyword form (host=db dbname=app), is an
// error. An error names the scheme at most, never the DSN, which can hold a
// password.

// dsnEnvVars are the variables Init opens stores from.
var dsnEnvVars = []string{"FASTEN_AUDIT_DSN", "FASTEN_API_DSN", "FASTEN_SYSLOG_DSN"}

var (
	dsnSchemeRe  = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9+.-]*):`)
	dsnKeywordRe = regexp.MustCompile(`^\s*[A-Za-z_]+\s*=`)
	dsnLikeEnvRe = regexp.MustCompile(`^FASTEN_\w*(DSN|DNS|URL)$`)
)

// storeDSN is a parsed store DSN.
type storeDSN struct {
	scheme string // "postgres" or "sqlite"
	conn   string // postgres: the DSN for the driver; sqlite: the file path
	table  string
	wal    bool // sqlite only
}

// parseStoreDSN parses a store DSN; defaultTable is the table when the DSN
// names none. It opens nothing and creates no file.
func parseStoreDSN(dsn, defaultTable string) (storeDSN, error) {
	if dsnKeywordRe.MatchString(dsn) {
		return storeDSN{}, errors.New("DSN in libpq keyword form not supported; " +
			"use postgres://user@host/db, sqlite:///./fasten.db or a bare filesystem path")
	}
	scheme := ""
	// A file: URI and a Windows drive letter are paths, not schemes.
	if m := dsnSchemeRe.FindStringSubmatch(dsn); m != nil && len(m[1]) > 1 && !strings.EqualFold(m[1], "file") {
		scheme = strings.ToLower(m[1])
	}
	switch scheme {
	case "postgres", "postgresql":
		return parsePostgresDSN(scheme, dsn[len(scheme)+1:], defaultTable), nil
	case "sqlite":
		u, err := url.Parse(dsn)
		if err != nil {
			// A fixed message: url.Parse's own error, even its cause, can
			// quote part of the DSN (a password read as a port or an escape).
			return storeDSN{}, errors.New("invalid sqlite DSN")
		}
		// Strip the one separator slash: sqlite:///rel.db gives "rel.db",
		// sqlite:////abs.db gives "/abs.db".
		path := strings.TrimPrefix(u.Path, "/")
		q := u.Query()
		return sqliteDSN(path, q.Get("table"), q.Get("wal"), defaultTable)
	case "":
		// table and wal are ours; any other parameter is left for the driver.
		path, query, _ := strings.Cut(dsn, "?")
		var table, wal string
		var kept []string
		for _, p := range strings.Split(query, "&") {
			if p == "" {
				continue
			}
			k, v, _ := strings.Cut(p, "=")
			switch queryUnescape(k) {
			case "table":
				if table == "" {
					table = queryUnescape(v)
				}
			case "wal":
				if wal == "" {
					wal = queryUnescape(v)
				}
			default:
				kept = append(kept, p)
			}
		}
		d, err := sqliteDSN(path, table, wal, defaultTable)
		if err == nil && len(kept) > 0 {
			d.conn += "?" + strings.Join(kept, "&")
		}
		return d, err
	default:
		return storeDSN{}, fmt.Errorf("DSN scheme %q not supported; "+
			"use sqlite:///./fasten.db, postgres://... or a bare filesystem path", scheme)
	}
}

func sqliteDSN(path, table, wal, defaultTable string) (storeDSN, error) {
	if path == "" {
		return storeDSN{}, errors.New("the SQLite DSN has no path; use sqlite:///./fasten.db or similar")
	}
	if table == "" {
		table = defaultTable
	}
	return storeDSN{scheme: "sqlite", conn: path, table: table, wal: wal != "false"}, nil
}

// parsePostgresDSN returns the DSN with its scheme in lowercase and without
// its table parameter, which the driver would refuse.
func parsePostgresDSN(scheme, rest, defaultTable string) storeDSN {
	table := ""
	base, query, hasQuery := strings.Cut(rest, "?")
	if hasQuery {
		query, fragment, hasFragment := strings.Cut(query, "#")
		var kept []string
		for _, p := range strings.Split(query, "&") {
			if p == "" {
				continue
			}
			k, v, _ := strings.Cut(p, "=")
			if queryUnescape(k) == "table" {
				if table == "" {
					table = queryUnescape(v)
				}
				continue
			}
			kept = append(kept, p)
		}
		if len(kept) > 0 {
			base += "?" + strings.Join(kept, "&")
		}
		if hasFragment {
			base += "#" + fragment
		}
	}
	if table == "" {
		table = defaultTable
	}
	return storeDSN{scheme: "postgres", conn: scheme + ":" + base, table: table}
}

// queryUnescape decodes a query key or value, or returns it as it is when
// it does not decode.
func queryUnescape(s string) string {
	if u, err := url.QueryUnescape(s); err == nil {
		return u
	}
	return s
}

// check refuses, before any store is opened, a DSN whose table name the
// store would refuse, whose SQLite directory does not exist, or whose
// Postgres driver is not registered, so a failed Init creates no file.
func (d storeDSN) check() error {
	if d.scheme == "postgres" {
		if !validPgIdentifierRe.MatchString(d.table) {
			return errors.New("the table name is not a valid SQL identifier")
		}
		if !slices.Contains(sql.Drivers(), "postgres") {
			return errors.New(`a postgres DSN needs a database/sql driver registered as "postgres", ` +
				`such as github.com/lib/pq`)
		}
		return nil
	}
	if !validIdentifierRe.MatchString(d.table) {
		return errors.New("the table name is not a valid SQL identifier")
	}
	path := d.conn
	if strings.HasPrefix(path, "file:") {
		path = uriFilePath(path)
	} else if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	if path == "" || path == ":memory:" {
		return nil
	}
	if dir := filepath.Dir(path); dir != "." {
		if fi, err := os.Stat(dir); err != nil {
			return fmt.Errorf("cannot open the sqlite store (%T)", err)
		} else if !fi.IsDir() {
			return errors.New("cannot open the sqlite store (not a directory)")
		}
	}
	return nil
}

// envStore is a store Init opened from a DSN variable.
type envStore struct {
	dsn   string
	store any // AuditRepository or StreamRepository
	db    *sql.DB
}

// openAuditStore opens the audit store for d.
func openAuditStore(d storeDSN) (*envStore, error) {
	if d.scheme == "postgres" {
		db, err := sql.Open("postgres", d.conn)
		if err != nil {
			return nil, err
		}
		s, err := NewPostgresStore(db, d.table)
		if err != nil {
			db.Close()
			return nil, err
		}
		return &envStore{store: s, db: db}, nil
	}
	createOwnerOnly(d.conn)
	db, err := sql.Open("sqlite", d.conn)
	if err != nil {
		return nil, err
	}
	if d.conn == ":memory:" {
		// Each connection to :memory: is its own database.
		db.SetMaxOpenConns(1)
	}
	s, err := newSQLiteStore(db, d.table, d.wal)
	if err != nil {
		db.Close()
		return nil, err
	}
	return &envStore{store: s, db: db}, nil
}

// openStreamStore opens the api or sys stream store for d.
func openStreamStore(d storeDSN) (*envStore, error) {
	if d.scheme == "postgres" {
		db, err := sql.Open("postgres", d.conn)
		if err != nil {
			return nil, err
		}
		s, err := NewPostgresStreamStore(db, d.table)
		if err != nil {
			db.Close()
			return nil, err
		}
		return &envStore{store: s, db: db}, nil
	}
	s, err := openSQLiteStreamStore(d)
	if err != nil {
		return nil, err
	}
	return &envStore{store: s, db: s.db}, nil
}

// errorType names the innermost error, as open failures report it: the
// driver's text can quote the user, host or database name.
func errorType(err error) string {
	for {
		u := errors.Unwrap(err)
		if u == nil {
			return fmt.Sprintf("%T", err)
		}
		err = u
	}
}

// storesFromEnv opens the stores cfg does not pass from FASTEN_AUDIT_DSN,
// FASTEN_API_DSN and FASTEN_SYSLOG_DSN, and returns cfg with them set. A
// store already opened from the same DSN is kept. Every DSN is parsed and
// checked before any store opens, and a store that opens is dropped again
// if a later one fails, so a failed call changes nothing. Stores this call
// stops using are added to e.envUnused, to close once nothing writes to
// them.
func (e *Engine) storesFromEnv(cfg Config) (Config, error) {
	type slot struct {
		name, table string
		passed      bool
	}
	slots := []slot{
		{"FASTEN_AUDIT_DSN", "audit_log", cfg.AuditStore != nil},
		{"FASTEN_API_DSN", "api_log", cfg.APIStore != nil},
		{"FASTEN_SYSLOG_DSN", "syslog", cfg.SyslogStore != nil},
	}
	next := map[string]*envStore{}
	parsed := map[string]storeDSN{}
	for _, s := range slots {
		dsn := envOr(s.name, "")
		if s.passed || dsn == "" {
			continue
		}
		if held := e.envStores[s.name]; held != nil && held.dsn == dsn {
			next[s.name] = held
			continue
		}
		d, err := parseStoreDSN(dsn, s.table)
		if err == nil {
			err = d.check()
		}
		if err != nil {
			return cfg, fmt.Errorf("fasten.Init: %s: %v", s.name, err)
		}
		parsed[s.name] = d
	}
	var opened []*envStore
	for _, s := range slots {
		d, ok := parsed[s.name]
		if !ok {
			continue
		}
		open := openStreamStore
		if s.name == "FASTEN_AUDIT_DSN" {
			open = openAuditStore
		}
		es, err := open(d)
		if err != nil {
			for _, o := range opened {
				o.db.Close()
			}
			return cfg, fmt.Errorf("fasten.Init: %s: cannot open the %s store (%s)",
				s.name, d.scheme, errorType(err))
		}
		es.dsn = envOr(s.name, "")
		opened = append(opened, es)
		next[s.name] = es
	}
	for name, held := range e.envStores {
		if next[name] != held {
			e.envUnused = append(e.envUnused, held)
		}
	}
	e.envStores = next
	if es := next["FASTEN_AUDIT_DSN"]; es != nil {
		cfg.AuditStore = es.store.(AuditRepository)
	}
	if es := next["FASTEN_API_DSN"]; es != nil {
		cfg.APIStore = es.store.(StreamRepository)
	}
	if es := next["FASTEN_SYSLOG_DSN"]; es != nil {
		cfg.SyslogStore = es.store.(StreamRepository)
	}
	return cfg, nil
}

// closeEnvStores closes the stores in e.envUnused, and with all set, every
// store opened from the environment. It returns false if a close failed.
func (e *Engine) closeEnvStores(all bool) bool {
	stores := e.envUnused
	e.envUnused = nil
	if all {
		for _, held := range e.envStores {
			stores = append(stores, held)
		}
		e.envStores = nil
	}
	ok := true
	for _, s := range stores {
		if err := s.db.Close(); err != nil {
			ok = false
			e.drainerSysLog("error", "store_close_failed", map[string]any{
				"error_type": errorType(err),
			})
		}
	}
	return ok
}

// warnedDSNEnv holds the variables already reported as env_dsn_not_read.
var warnedDSNEnv sync.Map

// warnUnreadDSNEnv reports, once per process and variable, a set FASTEN_*
// variable named like a DSN variable that Init does not read: a misspelt
// one leaves the app without the store it meant to open. The value is not
// logged.
func (e *Engine) warnUnreadDSNEnv() {
	for _, kv := range os.Environ() {
		name, value, _ := strings.Cut(kv, "=")
		if value == "" || !dsnLikeEnvRe.MatchString(name) || slices.Contains(dsnEnvVars, name) {
			continue
		}
		if _, seen := warnedDSNEnv.LoadOrStore(name, true); seen {
			continue
		}
		e.drainerSysLog("warn", "env_dsn_not_read", map[string]any{
			"variable": name,
			"reason":   "Init opens stores from " + strings.Join(dsnEnvVars, ", ") + " only",
		})
	}
}
