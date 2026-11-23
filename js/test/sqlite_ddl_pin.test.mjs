/**
 * The DDL SqliteStore runs on a new file, kept in spec/js-sqlite-ddl.sql.
 * The Python and Go suites build a table from that file and write to it with
 * their own stores, so a change to the JS table shows up here first. The
 * file is written when it is missing; delete it to take a new DDL.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { SqliteStore } from '../src/store/sqlite.js';

const DDL_FILE = fileURLToPath(new URL('../../spec/js-sqlite-ddl.sql', import.meta.url));

function ddlOf(path) {
    const db = new DatabaseSync(path, { readOnly: true });
    try {
        return db
            .prepare("SELECT sql FROM sqlite_master WHERE tbl_name = 'audit_log' AND sql IS NOT NULL ORDER BY type DESC, name")
            .all()
            .map((r) => `${r.sql};\n`)
            .join('');
    } finally {
        db.close();
    }
}

test('the SQLite DDL matches spec/js-sqlite-ddl.sql', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'fasten-ddl-'));
    try {
        const path = join(dir, 'audit.db');
        const store = new SqliteStore(path);
        await store.init();
        await store.close();
        const ddl = ddlOf(path);
        assert.match(ddl, /^CREATE TABLE audit_log/);
        if (!existsSync(DDL_FILE)) writeFileSync(DDL_FILE, ddl);
        assert.equal(ddl, readFileSync(DDL_FILE, 'utf8'));
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }
});
