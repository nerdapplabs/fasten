"""Load audit codes from yaml files.

pyyaml is imported only when load() or reload() is called, so it is optional.

Example:

    # fleet.codes.yaml
    domain: fleet
    emitter: fleet-service
    codes:
      FLEET_NODE_REGISTERED:
        category: node.lifecycle
        action: registered
        severity: info
        description: Node claimed and registered
      FLEET_DEPLOY_FAILED:
        category: deploy
        action: failed
        severity: error
        retention_class: long
        description: Deployment failed on node

    fasten.codes.load("fleet.codes.yaml")
    fasten.codes.reload()   # re-read every loaded file

reload() parses and validates everything before replacing the catalog; on
error the old catalog stays and the error is raised. Codes removed from a file
become unknown to emit(). Stored rows with that code are still readable.
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

# Same as CODE_KEY_RE in fasten-core/src/catalog.rs.
_CODE_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


# Paths passed to load(); reload() re-reads all of them.
_loaded_paths: list[Path] = []
# Codes that came from yaml, so reload() can drop removed ones and keep codes
# added with register().
_yaml_codes: set[str] = set()
# Code id to the file it came from, to catch one id in two files.
_yaml_code_origins: dict[str, Path] = {}
_lock = threading.Lock()


def _yaml_loader() -> Any:
    """Import pyyaml, or raise RuntimeError if it is not installed."""
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
    """Parse one yaml entry into a Meta. Errors name the file and key."""
    if not _CODE_KEY_RE.match(code):
        raise AuditCatalogError(
            f"{file_path}: code key {code!r} must be UPPER_SNAKE_CASE"
        )
    if not isinstance(raw, dict):
        raise AuditCatalogError(
            f"{file_path}:{code}: entry must be a mapping, got {type(raw).__name__}"
        )

    sev_raw = raw.get("severity", "info")
    try:
        severity = Severity(sev_raw)
    except ValueError as e:
        valid = ", ".join(s.value for s in Severity)
        raise AuditCatalogError(
            f"{file_path}:{code}: severity={sev_raw!r} is not one of {{{valid}}}"
        ) from e

    rc_raw = raw.get("retention_class", "medium")
    try:
        retention = RetentionClass(rc_raw)
    except ValueError as e:
        valid = ", ".join(r.value for r in RetentionClass)
        raise AuditCatalogError(
            f"{file_path}:{code}: retention_class={rc_raw!r} is not one of {{{valid}}}"
        ) from e

    code_domain = raw.get("domain", file_domain)
    if code_domain != file_domain:
        raise AuditCatalogError(
            f"{file_path}:{code}: domain={code_domain!r} disagrees with "
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
    """Read and validate every file. Returns (codes, origins), where origins
    maps each code to its file. Raises AuditCatalogError and changes nothing
    on error."""
    yaml = _yaml_loader()
    fresh: dict[str, Meta] = {}
    origins: dict[str, Path] = {}

    for path in paths:
        text = path.read_text()
        try:
            doc = yaml.safe_load(text) or {}
        except yaml.YAMLError as e:
            raise AuditCatalogError(f"{path}: yaml parse error: {e}") from e

        if not isinstance(doc, dict):
            raise AuditCatalogError(f"{path}: top-level must be a mapping")

        file_domain = doc.get("domain")
        if not file_domain or not isinstance(file_domain, str):
            raise AuditCatalogError(f"{path}: top-level 'domain' is required (string)")

        file_emitter = str(doc.get("emitter", ""))

        codes_block = doc.get("codes", {})
        if not isinstance(codes_block, dict):
            raise AuditCatalogError(f"{path}: 'codes' must be a mapping")

        for code, raw in codes_block.items():
            if code in fresh:
                raise AuditCatalogError(
                    f"{path}:{code}: duplicate code "
                    f"(already declared in {origins[code]})"
                )
            fresh[code] = _parse_meta(str(path), file_domain, file_emitter, str(code), raw)
            origins[code] = path

    return fresh, origins


def load(path: str | Path) -> None:
    """Load a catalog yaml file and remember it for reload().

    Raises AuditCatalogError if a code is invalid, already loaded from another
    file, or already added with register().
    """
    p = Path(path)
    fresh_yaml, _fresh_origins = _build_registry_from_paths([p])

    with _lock:
        # _build_registry_from_paths only sees this one file, so check
        # against earlier files and against codes added with register().
        for code in fresh_yaml:
            existing_path = _yaml_code_origins.get(code)
            if existing_path is not None and existing_path != p:
                raise AuditCatalogError(
                    f"{p}:{code}: duplicate code "
                    f"(already loaded from {existing_path})"
                )
            if code in _registry and code not in _yaml_codes:
                raise AuditCatalogError(
                    f"{p}:{code}: duplicate code (already registered programmatically)"
                )
        _registry.update(fresh_yaml)
        _yaml_codes.update(fresh_yaml.keys())
        for code in fresh_yaml:
            _yaml_code_origins[code] = p
        if p not in _loaded_paths:
            _loaded_paths.append(p)


def reload() -> None:
    """Re-read every loaded file and replace the yaml codes.

    On any error the old catalog stays and the error is raised. Codes removed
    from the files are dropped; codes added with register() are kept.
    """
    if not _loaded_paths:
        return

    fresh_yaml, fresh_origins = _build_registry_from_paths(list(_loaded_paths))

    # _lock serialises load() and reload(); register() does not take it.
    with _lock:
        programmatic = {
            k: v for k, v in _registry.items() if k not in _yaml_codes
        }
        new_registry = {**programmatic, **fresh_yaml}

        # meta_of() reads without the lock, so an emit() running during
        # clear() and update() can briefly see an unknown code.
        _registry.clear()
        _registry.update(new_registry)
        _yaml_codes.clear()
        _yaml_codes.update(fresh_yaml.keys())
        _yaml_code_origins.clear()
        _yaml_code_origins.update(fresh_origins)
