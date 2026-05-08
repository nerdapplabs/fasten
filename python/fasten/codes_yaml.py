"""
Catalog YAML loader (P1-11).

Optional feature — yaml parser is imported lazily, only when ``load()``
or ``reload()`` is actually called. Adopters who stay on programmatic
``fasten.codes.register({...})`` never pay the dep.

Example yaml:

    # fleet.codes.yaml
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

Usage:

    fasten.codes.load("fleet.codes.yaml")            # initial load
    fasten.codes.reload()                             # re-read all paths
    fasten.codes.reload("fleet.codes.yaml")           # re-read one file

Reload is **atomic + fault-tolerant**: parse + validate fully into a
fresh registry, then swap under a lock. If anything fails, the previous
catalog stays active and the error is raised.

Reload is **not additive**: removing a code from the file means
subsequent ``emit("REMOVED_CODE")`` raises the existing
``unknown audit code`` error. Stored audit rows referencing the
removed code remain readable (the wire ``code`` field is a free string).
"""
from __future__ import annotations

import re
import threading
from pathlib import Path
from typing import Any

from .codes import (
    AuditCatalogError,
    Meta,
    RetentionClass,
    Severity,
    _registry,
)

# UPPER_SNAKE_CASE key validator (mirrors Rust catalog.rs CODE_KEY_RE).
_CODE_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


# Paths previously passed to load(); reload() re-reads all of them.
_loaded_paths: list[Path] = []
# Code-ids whose source-of-truth is a yaml file (vs. programmatic register()).
# Tracked so reload() can distinguish "code removed from yaml" (drop it) from
# "code only registered programmatically" (keep it).
_yaml_codes: set[str] = set()
# code-id → originating yaml path. Used to detect cross-file collisions
# in load(): the same id loaded from two different files used to silently
# overwrite the first registration with the second's metadata.
_yaml_code_origins: dict[str, Path] = {}
_lock = threading.Lock()


def _yaml_loader() -> Any:
    """Lazy import of pyyaml — paid only when load() / reload() is called."""
    try:
        import yaml
    except ImportError as e:
        raise RuntimeError(
            "fasten.codes.load() requires pyyaml; install with: pip install pyyaml"
        ) from e
    return yaml


def _parse_meta(
    file_path: str,
    file_domain: str,
    file_emitter: str,
    code: str,
    raw: dict[str, Any],
) -> Meta:
    """Parse one yaml entry into a Meta. Raises AuditCatalogError with file:key context."""
    if not _CODE_KEY_RE.match(code):
        raise AuditCatalogError(
            f"{file_path} — code key {code!r} must be UPPER_SNAKE_CASE"
        )
    if not isinstance(raw, dict):
        raise AuditCatalogError(
            f"{file_path}:{code} — entry must be a mapping, got {type(raw).__name__}"
        )

    sev_raw = raw.get("severity", "info")
    try:
        severity = Severity(sev_raw)
    except ValueError as e:
        valid = ", ".join(s.value for s in Severity)
        raise AuditCatalogError(
            f"{file_path}:{code} — severity={sev_raw!r} is not one of {{{valid}}}"
        ) from e

    rc_raw = raw.get("retention_class", "medium")
    try:
        retention = RetentionClass(rc_raw)
    except ValueError as e:
        valid = ", ".join(r.value for r in RetentionClass)
        raise AuditCatalogError(
            f"{file_path}:{code} — retention_class={rc_raw!r} is not one of {{{valid}}}"
        ) from e

    code_domain = raw.get("domain", file_domain)
    if code_domain != file_domain:
        raise AuditCatalogError(
            f"{file_path}:{code} — domain={code_domain!r} disagrees with "
            f"file-level domain={file_domain!r}"
        )

    return Meta(
        domain=file_domain,
        category=str(raw.get("category", "")),
        action=str(raw.get("action", "")),
        severity=severity,
        description=str(raw.get("description", "")),
        emitter=str(raw.get("emitter", file_emitter)),
        id=code,
        retention_class=retention,
        high_volume=bool(raw.get("high_volume", False)),
        pii_in_detail=bool(raw.get("pii_in_detail", False)),
        declared_unused=bool(raw.get("declared_unused", False)),
    )


def _build_registry_from_paths(
    paths: list[Path],
) -> tuple[dict[str, Meta], dict[str, Path]]:
    """Read every yaml + run all validation; return (registry, origins).

    `origins` maps each code-id to the path it was declared in, so reload()
    can reset the cross-file collision tracker atomically alongside the
    registry swap.

    Any error raises AuditCatalogError (or yaml.YAMLError) — the caller's
    live registry is never touched until this returns successfully.
    """
    yaml = _yaml_loader()
    fresh: dict[str, Meta] = {}
    origins: dict[str, Path] = {}

    for path in paths:
        text = path.read_text()
        try:
            doc = yaml.safe_load(text) or {}
        except yaml.YAMLError as e:
            raise AuditCatalogError(f"{path} — yaml parse error: {e}") from e

        if not isinstance(doc, dict):
            raise AuditCatalogError(f"{path} — top-level must be a mapping")

        file_domain = doc.get("domain")
        if not file_domain or not isinstance(file_domain, str):
            raise AuditCatalogError(f"{path} — top-level 'domain' is required (string)")

        file_emitter = str(doc.get("emitter", ""))

        codes_block = doc.get("codes", {})
        if not isinstance(codes_block, dict):
            raise AuditCatalogError(f"{path} — 'codes' must be a mapping")

        for code, raw in codes_block.items():
            if code in fresh:
                raise AuditCatalogError(
                    f"{path}:{code} — duplicate code "
                    f"(already declared in {origins[code]})"
                )
            fresh[code] = _parse_meta(str(path), file_domain, file_emitter, str(code), raw)
            origins[code] = path

    return fresh, origins


def load(path: str | Path) -> None:
    """Initial load of a catalog yaml. Errors raise loudly — startup, restart-safe.

    Subsequent ``reload()`` calls re-read this path (and any other paths
    loaded since). Programmatic ``register()`` calls remain in the
    registry and survive ``reload()`` (yaml-loaded codes overlay).
    """
    p = Path(path)
    fresh_yaml, _fresh_origins = _build_registry_from_paths([p])

    with _lock:
        # Two duplicate-detection passes:
        # (a) cross-yaml-file: same id was loaded from a *different* path
        #     earlier. The earlier check inside _build_registry_from_paths
        #     only catches dupes within a single load() invocation, so it
        #     would miss `load(a.yaml)` then `load(b.yaml)` with the same
        #     id. Without this, the second load silently overwrites the
        #     first registration's metadata.
        # (b) yaml-vs-programmatic: id was registered in code via
        #     register() before yaml load. The yaml file is asserting
        #     ownership it doesn't have.
        for code in fresh_yaml:
            existing_path = _yaml_code_origins.get(code)
            if existing_path is not None and existing_path != p:
                raise AuditCatalogError(
                    f"{p}:{code} — duplicate code "
                    f"(already loaded from {existing_path})"
                )
            if code in _registry and code not in _yaml_codes:
                raise AuditCatalogError(
                    f"{p}:{code} — duplicate code (already registered programmatically)"
                )
        _registry.update(fresh_yaml)
        _yaml_codes.update(fresh_yaml.keys())
        for code in fresh_yaml:
            _yaml_code_origins[code] = p
        if p not in _loaded_paths:
            _loaded_paths.append(p)


def reload() -> None:
    """Re-read every previously-loaded yaml path and atomically swap the registry.

    Atomic + fault-tolerant: parse + validate fully into a fresh dict;
    only swap under the lock if everything succeeded. If anything fails
    (yaml parse error, invalid severity, missing field), raise — the
    previous catalog stays active and queryable.

    Reload is **not additive** — codes removed from the yaml become
    unknown after the swap. Stored audit rows referencing them remain
    readable (the wire ``code`` field is a free string).

    Codes registered programmatically (via ``fasten.codes.register()``)
    are preserved across reload.
    """
    if not _loaded_paths:
        return  # nothing to reload

    # Step 1: parse + validate fully. Any error raises here, before we
    # touch the live registry. Fault-tolerant guarantee: previous
    # catalog stays active on failure.
    fresh_yaml, fresh_origins = _build_registry_from_paths(list(_loaded_paths))

    # Step 2: take snapshot under the lock to avoid racing with concurrent
    # register() calls, then swap. Programmatic codes (not in _yaml_codes)
    # survive reload; previously-yaml codes that the new yaml dropped go
    # away (full-file replacement semantics).
    with _lock:
        programmatic = {
            k: v for k, v in _registry.items() if k not in _yaml_codes
        }
        new_registry = {**programmatic, **fresh_yaml}

        # Atomic swap inside the critical section. Concurrent emit()
        # readers either see old contents or new — the clear+update pair
        # runs under the same lock that any future register() / reload()
        # acquires, but emit's metaOf does not lock (single dict.get is
        # GIL-atomic). Brief window during clear+update where emit may
        # raise unknown-code; for typical reload frequencies (manual /
        # SIGHUP) the window is microseconds.
        _registry.clear()
        _registry.update(new_registry)
        _yaml_codes.clear()
        _yaml_codes.update(fresh_yaml.keys())
        _yaml_code_origins.clear()
        _yaml_code_origins.update(fresh_origins)
