/**
 * Catalog YAML loader (P1-11) for fasten-js.
 *
 * Optional feature — adopters who stay on programmatic register() never
 * touch this code path. js-yaml is imported lazily inside load() / reload()
 * so it's only resolved when actually called. Adopters who don't use
 * the yaml catalog can omit js-yaml from their dependencies entirely.
 *
 * API:
 *
 *   await fasten.codes.load("fleet.codes.yaml");   // initial load
 *   await fasten.codes.reload();                    // atomic + fault-tolerant
 *
 * Reload semantics match Python:
 * - Atomic: parse + validate fully into a fresh map, then swap.
 * - Fault-tolerant: any error during reload leaves the previous catalog
 *   active. Designed for SIGHUP / live edit; bad yaml shouldn't brick prod.
 * - NOT additive: codes removed from the yaml become unknown after reload.
 *   Programmatic register() codes survive reload (tracked separately).
 */
import fs from 'node:fs/promises';

import { registry, _resetRegistryForReload, _yamlCodes } from './index.js';

const CODE_KEY_RE = /^[A-Z][A-Z0-9_]*$/;
const VALID_SEVERITIES = new Set(['debug', 'info', 'warn', 'error', 'critical']);
const VALID_RETENTION = new Set(['short', 'medium', 'long']);

// Exported (with underscore prefix to mark internal) so tests can reset
// state between cases.
export const _loadedPaths = [];

async function _loadYaml() {
    try {
        const yaml = await import('js-yaml');
        return yaml.default ?? yaml;
    } catch (e) {
        throw new Error(
            "fasten codes yaml loader requires js-yaml; install with: npm install js-yaml"
        );
    }
}

async function _buildFromPaths(paths) {
    const yaml = await _loadYaml();
    const fresh = new Map();

    for (const path of paths) {
        let text;
        try {
            text = await fs.readFile(path, 'utf8');
        } catch (e) {
            throw new Error(`fasten: reading ${path}: ${e.message}`);
        }

        let doc;
        try {
            doc = yaml.load(text) ?? {};
        } catch (e) {
            throw new Error(`fasten: parsing ${path}: ${e.message}`);
        }
        if (typeof doc !== 'object' || Array.isArray(doc)) {
            throw new Error(`fasten: ${path} — top-level must be a mapping`);
        }

        const fileDomain = doc.domain;
        if (!fileDomain || typeof fileDomain !== 'string') {
            throw new Error(`fasten: ${path} — top-level 'domain' is required (string)`);
        }
        const fileEmitter = doc.emitter ?? '';

        const codesBlock = doc.codes ?? {};
        if (typeof codesBlock !== 'object' || Array.isArray(codesBlock)) {
            throw new Error(`fasten: ${path} — 'codes' must be a mapping`);
        }

        for (const [code, raw] of Object.entries(codesBlock)) {
            if (!CODE_KEY_RE.test(code)) {
                throw new Error(
                    `fasten: ${path}:${code} — code key must be UPPER_SNAKE_CASE`
                );
            }
            if (fresh.has(code)) {
                throw new Error(`fasten: ${path}:${code} — duplicate code in yaml`);
            }
            const sev = raw?.severity ?? 'info';
            if (!VALID_SEVERITIES.has(sev)) {
                throw new Error(
                    `fasten: ${path}:${code} — severity='${sev}' is not one of ` +
                    `{${[...VALID_SEVERITIES].join(',')}}`
                );
            }
            const rc = raw?.retention_class ?? 'medium';
            if (!VALID_RETENTION.has(rc)) {
                throw new Error(
                    `fasten: ${path}:${code} — retention_class='${rc}' is not one of ` +
                    `{${[...VALID_RETENTION].join(',')}}`
                );
            }
            const codeDomain = raw?.domain ?? fileDomain;
            if (codeDomain !== fileDomain) {
                throw new Error(
                    `fasten: ${path}:${code} — domain='${codeDomain}' disagrees with ` +
                    `file-level domain='${fileDomain}'`
                );
            }
            fresh.set(code, {
                id: code,
                domain: fileDomain,
                category: raw?.category ?? '',
                action: raw?.action ?? '',
                severity: sev,
                description: raw?.description ?? '',
                emitter: raw?.emitter ?? fileEmitter,
                retention_class: rc,
                high_volume: !!raw?.high_volume,
                pii_in_detail: !!raw?.pii_in_detail,
                declared_unused: !!raw?.declared_unused,
            });
        }
    }
    return fresh;
}

/**
 * Load a yaml catalog file. Errors raise loudly (startup, restart-safe).
 * Subsequent reload() calls re-read this path along with any other
 * paths previously passed to load().
 */
export async function load(path) {
    const fresh = await _buildFromPaths([path]);
    const reg = registry();   // current catalog snapshot

    // Reject collisions with programmatic registrations.
    for (const code of fresh.keys()) {
        if (reg.has(code) && !_yamlCodes.has(code)) {
            throw new Error(
                `fasten.load: ${path}:${code} — duplicate code (already registered programmatically)`
            );
        }
    }

    // Merge into the live registry under the same internal lock register() uses.
    // (JS is single-threaded — no concurrent emit() yields mid-update.)
    for (const [code, meta] of fresh) {
        reg.set(code, meta);
        _yamlCodes.add(code);
    }

    if (!_loadedPaths.includes(path)) {
        _loadedPaths.push(path);
    }
}

/**
 * Re-read every previously-loaded path and atomically swap the registry.
 *
 * Fault-tolerant: any error during reload leaves the previous catalog
 * active and is thrown. Reload is NOT additive — codes removed from the
 * yaml become unknown after the swap.
 */
export async function reload() {
    if (_loadedPaths.length === 0) return;

    // Step 1: parse + validate fully. Any error throws here, before any
    // mutation of the live registry.
    const fresh = await _buildFromPaths([..._loadedPaths]);

    // Step 2: build new registry view (programmatic codes preserved) and
    // atomically swap. JS single-thread = no torn reads.
    const reg = registry();
    const newRegistry = new Map();
    for (const [code, meta] of reg) {
        if (!_yamlCodes.has(code)) {
            newRegistry.set(code, meta);   // programmatic — preserved
        }
    }
    for (const [code, meta] of fresh) {
        newRegistry.set(code, meta);
    }

    // Atomic swap — replaces every entry, drops yaml-removed codes.
    _resetRegistryForReload(newRegistry, new Set(fresh.keys()));
}
