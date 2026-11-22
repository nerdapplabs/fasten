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
// A SQLite path is used as written, without decoding %XX escapes, and a
// #fragment is dropped, as Python's urlparse does. Any other scheme, and
// libpq's keyword form (host=db dbname=app), is an error. An error never
// quotes the DSN, which can hold a password, and names a scheme only when
// the DSN has one.

// dsnEnvVars are the variables Init opens stores from.
var dsnEnvVars = []string{"FASTEN_AUDIT_DSN", "FASTEN_API_DSN", "FASTEN_SYSLOG_DSN"}

var (
	dsnSchemeRe  = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9+.-]*):`)
	dsnKeywordRe = regexp.MustCompile(`^\s*[A-Za-z_]+\s*=`)
	dsnLikeEnvRe = regexp.MustCompile(`^FASTEN_\w*(DSN|DNS|URL)$`)
)

// sqlDrivers lists the registered database/sql drivers.
var sqlDrivers = sql.Drivers

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
		path, query := splitDSNPath(dsn[len("sqlite:"):])
		// Drop the host, then the one separator slash: sqlite:///rel.db
		// gives "rel.db", sqlite:////abs.db gives "/abs.db".
		if rest, ok := strings.CutPrefix(path, "//"); ok {
			_, tail, found := strings.Cut(rest, "/")
			path = ""
			if found {
				path = "/" + tail
			}
		}
		path = strings.TrimPrefix(path, "/")
		table, wal, _ := dsnParams(query)
		return sqliteDSN(path, table, wal, defaultTable)
	case "":
		path, query := splitDSNPath(dsn)
		// table and wal are ours; any other parameter is left for the driver.
		table, wal, kept := dsnParams(query)
		d, err := sqliteDSN(path, table, wal, defaultTable)
		if err == nil && len(kept) > 0 {
			d.conn += "?" + strings.Join(kept, "&")
		}
		return d, err
	default:
		// Text before a ':' is a scheme only when "//" follows; otherwise
		// it can be a user name or a host.
		if strings.HasPrefix(dsn[len(scheme)+1:], "//") {
			return storeDSN{}, fmt.Errorf("DSN scheme %q not supported; "+
				"use sqlite:///./fasten.db, postgres://... or a bare filesystem path", scheme)
		}
		return storeDSN{}, errors.New("DSN form not recognised; " +
			"use postgres://..., sqlite:///./fasten.db or a bare filesystem path")
	}
}

// splitDSNPath drops a #fragment and splits off the query.
func splitDSNPath(s string) (path, query string) {
	s, _, _ = strings.Cut(s, "#")
	path, query, _ = strings.Cut(s, "?")
	return path, query
}

// dsnParams returns the first non-empty table and wal parameters of a query,
// decoded, and the other parameters as they are.
func dsnParams(query string) (table, wal string, kept []string) {
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
	return table, wal, kept
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
// Postgres driver is not registered.
func (d storeDSN) check() error {
	if d.scheme == "postgres" {
		if !validPgIdentifierRe.MatchString(d.table) {
			return errors.New("the table name is not a valid SQL identifier")
		}
		if !slices.Contains(sqlDrivers(), "postgres") {
			return errors.New(`a postgres DSN needs a database/sql driver registered as "postgres", ` +
				`such as github.com/lib/pq`)
		}
		return nil
	}
	if !validIdentifierRe.MatchString(d.table) {
		return errors.New("the table name is not a valid SQL identifier")
	}
	path := sqliteFile(d.conn)
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
	name  string // the variable
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

// envSlot is a DSN variable Init uses: the store it keeps from the last
// Init, or else the DSN it opens.
type envSlot struct {
	name string
	dsn  string
	held *envStore
	d    storeDSN
}

// planEnvStores parses and checks the DSN variables for the stores cfg does
// not pass, and returns the ones that are set. It opens nothing. A store in
// held opened from the same DSN is kept.
func planEnvStores(cfg Config, held map[string]*envStore) ([]envSlot, error) {
	var slots []envSlot
	for _, s := range []struct {
		name, table string
		passed      bool
	}{
		{"FASTEN_AUDIT_DSN", "audit_log", cfg.AuditStore != nil},
		{"FASTEN_API_DSN", "api_log", cfg.APIStore != nil},
		{"FASTEN_SYSLOG_DSN", "syslog", cfg.SyslogStore != nil},
	} {
		dsn := envOr(s.name, "")
		if s.passed || dsn == "" {
			continue
		}
		if h := held[s.name]; h != nil && h.dsn == dsn {
			slots = append(slots, envSlot{name: s.name, dsn: dsn, held: h})
			continue
		}
		d, err := parseStoreDSN(dsn, s.table)
		if err == nil {
			err = d.check()
		}
		if err != nil {
			return nil, fmt.Errorf("fasten.Init: %s: %v", s.name, err)
		}
		slots = append(slots, envSlot{name: s.name, dsn: dsn, d: d})
	}
	return slots, nil
}

// hasSlot reports whether slots holds the variable name.
func hasSlot(slots []envSlot, name string) bool {
	return slices.ContainsFunc(slots, func(s envSlot) bool { return s.name == name })
}

// testHookEnvOpened, when set, is called with each store openEnvStores opens.
var testHookEnvOpened func(*envStore)

// openEnvStores opens the stores slots does not keep, and returns every
// store for slots by variable. If one fails to open, the stores this call
// opened are closed again and the database files it created are removed.
// Journal and WAL files are left alone: another connection may be using
// them.
func (e *Engine) openEnvStores(slots []envSlot) (map[string]*envStore, error) {
	next := map[string]*envStore{}
	var opened []*envStore
	var created []string
	for _, s := range slots {
		if s.held != nil {
			next[s.name] = s.held
			continue
		}
		file := ""
		if s.d.scheme == "sqlite" {
			if f := sqliteFile(s.d.conn); f != "" && f != ":memory:" {
				if _, err := os.Lstat(f); os.IsNotExist(err) {
					file = f
				}
			}
		}
		open := openStreamStore
		if s.name == "FASTEN_AUDIT_DSN" {
			open = openAuditStore
		}
		// A store that fails to open has closed its handle.
		es, err := open(s.d)
		if file != "" {
			created = append(created, file)
		}
		if err != nil {
			e.closeStores(e.out(), opened)
			for _, p := range created {
				os.Remove(p)
			}
			return nil, fmt.Errorf("fasten.Init: %s: cannot open the %s store (%s)",
				s.name, s.d.scheme, errorType(err))
		}
		es.name, es.dsn = s.name, s.dsn
		if testHookEnvOpened != nil {
			testHookEnvOpened(es)
		}
		opened = append(opened, es)
		next[s.name] = es
	}
	return next, nil
}

// unusedEnvStores returns the stores in e.envStores that next does not hold.
func (e *Engine) unusedEnvStores(next map[string]*envStore) []*envStore {
	var unused []*envStore
	for _, name := range dsnEnvVars {
		if held := e.envStores[name]; held != nil && next[name] != held {
			unused = append(unused, held)
		}
	}
	return unused
}

// releaseEnvStores stops using the stores Init opened from the environment,
// and returns them for the caller to close once nothing writes to them,
// with a channel closed once the inserts running on the audit store among
// them have returned. Later sys and api rows go to the rings only, and
// audit rows to stdout only. Stores passed in Config are kept.
func (e *Engine) releaseEnvStores() ([]*envStore, <-chan struct{}) {
	stores := e.unusedEnvStores(nil)
	held := e.envStores
	e.envStores = nil
	if len(stores) == 0 {
		return nil, insertsDone(nil)
	}
	isEnv := func(name string, store any) bool {
		h := held[name]
		return h != nil && store != nil && h.store == store
	}
	var inserts *sync.WaitGroup
	e.storeMu.Lock()
	defer e.storeMu.Unlock()
	if isEnv("FASTEN_AUDIT_DSN", e.auditStore) {
		inserts = e.auditInserts
		e.auditStore, e.auditInserts = nil, nil
	}
	if isEnv("FASTEN_API_DSN", e.apiStore) {
		e.apiStore = nil
	}
	if isEnv("FASTEN_SYSLOG_DSN", e.syslogStore) {
		e.syslogStore = nil
	}
	if x := e.xport.Load(); x != nil && (isEnv("FASTEN_API_DSN", x.APIStore) || isEnv("FASTEN_SYSLOG_DSN", x.SyslogStore)) {
		e.xport.Store(x.withStores(e.apiStore, e.syslogStore))
	}
	e.persistedStreams = persistedStreams(e.auditStore, e.apiStore, e.syslogStore)
	return stores, insertsDone(inserts)
}

// closeStores closes stores, reporting a failure to out. It returns false
// if a close failed.
func (e *Engine) closeStores(out sysOut, stores []*envStore) bool {
	ok := true
	for _, s := range stores {
		if err := s.db.Close(); err != nil {
			ok = false
			e.sysLogTo(out, "error", "store_close_failed", map[string]any{
				"variable":   s.name,
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
