package fasten

import (
	_ "embed"
	"strings"
)

// ARCH #3: canonical audit_log DDL loaded from the shared spec fragments
// at spec/audit_log.{sqlite,postgres}.sql. go:embed can't reach outside
// the module tree, so those files are mirrored (byte-identical) into
// go/internal/spec — see the README there for the mirror contract.
//
// SQLiteStore.migrate and PostgresStore.migrate render these with the
// {table} / {bare} placeholders and execute the resulting statements.
// Idempotent CREATE TABLE IF NOT EXISTS + additive-column migrations
// mean an existing database moves forward safely; a fresh database gets
// the full canonical shape.

//go:embed internal/spec/audit_log.sqlite.sql
var auditLogSqliteDDL string

//go:embed internal/spec/audit_log.postgres.sql
var auditLogPostgresDDL string

// specDeferredMarker sits inside a comment line in the .sql; the loader
// splits the spec into pre/post-migration sections at this marker so
// index statements that reference additively-added columns run after
// the migrations complete.
const specDeferredMarker = "@DEFERRED_AFTER_MIGRATIONS"

// splitDDL returns (pre, post) sections split at the deferred marker.
// If the marker is absent, everything is pre and post is empty.
func splitDDL(raw string) (string, string) {
	i := strings.Index(raw, specDeferredMarker)
	if i < 0 {
		return raw, ""
	}
	// Include the whole marker line in the "consumed" segment.
	// Find the newline after the marker to slice cleanly.
	tail := raw[i:]
	nl := strings.IndexByte(tail, '\n')
	if nl < 0 {
		return raw[:i], ""
	}
	return raw[:i], tail[nl+1:]
}

// renderDDL substitutes the placeholders in a raw spec fragment and
// returns the list of SQL statements to execute in order. Line comments
// (`-- ...`) are stripped so the spec file's header never enters the
// statement stream.
func renderDDL(raw string, replacements map[string]string) []string {
	var body strings.Builder
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(trimmed, "--") {
			continue
		}
		body.WriteString(line)
		body.WriteByte('\n')
	}
	out := body.String()
	for k, v := range replacements {
		out = strings.ReplaceAll(out, "{"+k+"}", v)
	}
	stmts := make([]string, 0, 8)
	for _, s := range strings.Split(out, ";") {
		if strings.TrimSpace(s) != "" {
			stmts = append(stmts, s)
		}
	}
	return stmts
}
