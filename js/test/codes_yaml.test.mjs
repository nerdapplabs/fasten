/**
 * fasten JS codes-yaml tests (P1-11) — node:test, runs in node:20-alpine.
 *
 * Covers the optional yaml catalog: load(), reload() with atomic + fault-
 * tolerant semantics, programmatic-preservation across reload.
 */
import { test, before, beforeEach, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

import {
    register, metaOf, registry, codes, _yamlCodes, _resetRegistryForReload,
    _clearRustRegistry,
} from '../src/index.js';
import { _loadedPaths } from '../src/codes_yaml.js';

const FLEET_YAML = `
domain: fleet
emitter: edge-manager
codes:
  FLEET_NODE_REGISTERED:
    category: node.lifecycle
    action: registered
    severity: info
    description: Edge node claimed and registered
  FLEET_DEPLOY_FAILED:
    category: deploy
    action: failed
    severity: error
    retention_class: long
    description: Deployment failed on edge node
`;

let tmpDir;

before(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'fasten-yaml-'));
});

async function writeFile(name, contents) {
    const p = path.join(tmpDir, name);
    await fs.writeFile(p, contents, 'utf8');
    return p;
}

function resetState() {
    _clearRustRegistry();
    registry().clear();
    _yamlCodes.clear();
    _loadedPaths.length = 0;
}

describe('codes_yaml', () => {
    beforeEach(resetState);

    test('load round-trip', async () => {
        const p = await writeFile('round.yaml', FLEET_YAML);
        await codes.load(p);
        const m = metaOf('FLEET_NODE_REGISTERED');
        assert.equal(m.domain, 'fleet');
        assert.equal(m.action, 'registered');
        assert.equal(m.severity, 'info');
        assert.equal(metaOf('FLEET_DEPLOY_FAILED').severity, 'error');
        assert.equal(metaOf('FLEET_DEPLOY_FAILED').retention_class, 'long');
    });

    test('invalid severity raises', async () => {
        const p = await writeFile('badsev.yaml',
            `domain: x\ncodes:\n  BAD_CODE:\n    severity: huge\n`);
        await assert.rejects(() => codes.load(p), /severity='huge'/);
    });

    test('lowercase key raises', async () => {
        const p = await writeFile('badkey.yaml',
            `domain: x\ncodes:\n  lowercase_bad:\n    severity: info\n`);
        await assert.rejects(() => codes.load(p), /UPPER_SNAKE_CASE/);
    });

    test('reload picks up new codes', async () => {
        const p = await writeFile('reload-add.yaml', FLEET_YAML);
        await codes.load(p);
        await fs.writeFile(p, `
domain: fleet
codes:
  FLEET_NODE_REGISTERED:
    severity: info
    description: x
  FLEET_NEW_CODE:
    severity: warn
    description: x
`, 'utf8');
        await codes.reload();
        assert.ok(metaOf('FLEET_NEW_CODE'));
        assert.equal(metaOf('FLEET_NEW_CODE').severity, 'warn');
    });

    test('reload removes codes (full-file replacement)', async () => {
        const p = await writeFile('reload-rm.yaml', FLEET_YAML);
        await codes.load(p);
        assert.ok(metaOf('FLEET_DEPLOY_FAILED'));

        await fs.writeFile(p, `
domain: fleet
codes:
  FLEET_NODE_REGISTERED:
    severity: info
    description: x
`, 'utf8');
        await codes.reload();
        assert.equal(metaOf('FLEET_DEPLOY_FAILED'), undefined);
        assert.ok(metaOf('FLEET_NODE_REGISTERED'));
    });

    test('reload fault-tolerant — bad yaml leaves previous catalog active', async () => {
        const p = await writeFile('reload-bad.yaml', FLEET_YAML);
        await codes.load(p);
        const before = registry().size;

        await fs.writeFile(p, `
domain: fleet
codes:
  FLEET_NODE_REGISTERED:
    severity: completely_bogus
`, 'utf8');
        await assert.rejects(() => codes.reload());

        // Live registry untouched
        assert.equal(registry().size, before);
        assert.ok(metaOf('FLEET_NODE_REGISTERED'));
        assert.ok(metaOf('FLEET_DEPLOY_FAILED'));
    });

    test('reload preserves programmatic codes', async () => {
        const p = await writeFile('reload-prog.yaml', FLEET_YAML);
        await codes.load(p);

        // Programmatic register — different domain, not in yaml
        register('extra', {
            EXTRA_PROG_CODE: { domain: 'extra', category: 'x', action: 'x',
                                severity: 'info', description: 'x', emitter: 't' },
        });
        assert.ok(metaOf('EXTRA_PROG_CODE'));

        await fs.writeFile(p, `
domain: fleet
codes:
  FLEET_NODE_REGISTERED:
    severity: info
    description: x
`, 'utf8');
        await codes.reload();

        assert.ok(metaOf('EXTRA_PROG_CODE'));      // programmatic preserved
        assert.ok(metaOf('FLEET_NODE_REGISTERED')); // yaml reloaded
        assert.equal(metaOf('FLEET_DEPLOY_FAILED'), undefined); // yaml-removed gone
    });
});
