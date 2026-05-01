"""Tests for P1-11 — `fasten.codes.load()` + `reload()` yaml catalog."""
import textwrap
from pathlib import Path

import pytest

from fasten.codes import (
    AuditCatalogError,
    Severity,
    _registry,
    load,
    registry,
    reload,
)


# pyyaml is required for these tests; skip the whole module if missing.
yaml = pytest.importorskip("yaml")


@pytest.fixture
def fasten_yaml(tmp_path: Path) -> Path:
    """Write a known-good catalog yaml and return its path."""
    p = tmp_path / "fleet.codes.yaml"
    p.write_text(textwrap.dedent("""\
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
    """))
    return p


@pytest.fixture
def clean_yaml_paths():
    """Reset yaml-load state between tests: clear loaded paths AND any
    FLEET_/EXTRA_ codes in the registry (fresh_state in conftest doesn't
    touch the catalog)."""
    from fasten.codes_yaml import _loaded_paths, _yaml_codes
    saved_paths = list(_loaded_paths)
    saved_yaml_codes = set(_yaml_codes)
    saved_registry = dict(_registry)
    _loaded_paths.clear()
    _yaml_codes.clear()
    for code in list(_registry):
        if code.startswith(("FLEET_", "EXTRA_")):
            del _registry[code]
    yield
    _loaded_paths.clear()
    _loaded_paths.extend(saved_paths)
    _yaml_codes.clear()
    _yaml_codes.update(saved_yaml_codes)
    for code in list(_registry):
        if code.startswith(("FLEET_", "EXTRA_")):
            del _registry[code]
    for k, v in saved_registry.items():
        if k not in _registry:
            _registry[k] = v


def test_load_round_trip(fasten_yaml, clean_yaml_paths):
    load(str(fasten_yaml))
    reg = registry()
    assert "FLEET_NODE_REGISTERED" in reg
    assert reg["FLEET_NODE_REGISTERED"].domain == "fleet"
    assert reg["FLEET_NODE_REGISTERED"].action == "registered"
    assert reg["FLEET_NODE_REGISTERED"].severity == Severity.INFO

    assert reg["FLEET_DEPLOY_FAILED"].severity == Severity.ERROR
    assert reg["FLEET_DEPLOY_FAILED"].retention_class.value == "long"


def test_load_invalid_severity_raises(tmp_path, clean_yaml_paths):
    p = tmp_path / "bad.codes.yaml"
    p.write_text(textwrap.dedent("""\
        domain: x
        codes:
          BAD_CODE:
            severity: huge
    """))
    with pytest.raises(AuditCatalogError, match="severity='huge'"):
        load(str(p))


def test_load_lowercase_key_raises(tmp_path, clean_yaml_paths):
    p = tmp_path / "bad.codes.yaml"
    p.write_text(textwrap.dedent("""\
        domain: x
        codes:
          lowercase_bad:
            severity: info
    """))
    with pytest.raises(AuditCatalogError, match="UPPER_SNAKE_CASE"):
        load(str(p))


def test_load_collision_with_programmatic_raises(fasten_yaml, clean_yaml_paths):
    """A code already in the programmatic registry must not be silently overwritten."""
    from fasten.codes import register, Meta
    # Pre-register one of the codes in the yaml programmatically
    if "FLEET_NODE_REGISTERED" in _registry:
        del _registry["FLEET_NODE_REGISTERED"]
    register("fleet", {
        "FLEET_NODE_REGISTERED": Meta(
            domain="fleet", category="x", action="x",
            severity=Severity.INFO, description="x", emitter="t",
        ),
    })
    with pytest.raises(AuditCatalogError, match="duplicate"):
        load(str(fasten_yaml))
    # cleanup
    del _registry["FLEET_NODE_REGISTERED"]


def test_reload_picks_up_new_codes(fasten_yaml, clean_yaml_paths):
    load(str(fasten_yaml))

    # Edit yaml — add a new code
    fasten_yaml.write_text(textwrap.dedent("""\
        domain: fleet
        codes:
          FLEET_NODE_REGISTERED:
            category: node.lifecycle
            action: registered
            severity: info
            description: x
          FLEET_NEW_CODE:
            category: x
            action: x
            severity: warn
            description: x
    """))
    reload()
    reg = registry()
    assert "FLEET_NEW_CODE" in reg
    assert reg["FLEET_NEW_CODE"].severity == Severity.WARN


def test_reload_removes_codes(fasten_yaml, clean_yaml_paths):
    """Reload is full replacement of the file — codes removed from yaml are gone."""
    load(str(fasten_yaml))
    assert "FLEET_DEPLOY_FAILED" in registry()

    fasten_yaml.write_text(textwrap.dedent("""\
        domain: fleet
        codes:
          FLEET_NODE_REGISTERED:
            category: node.lifecycle
            action: registered
            severity: info
            description: x
    """))
    reload()
    reg = registry()
    assert "FLEET_NODE_REGISTERED" in reg
    assert "FLEET_DEPLOY_FAILED" not in reg  # full replacement


def test_reload_fault_tolerant(fasten_yaml, clean_yaml_paths):
    """Bad yaml during reload must NOT break the live registry."""
    load(str(fasten_yaml))
    snapshot = dict(registry())  # known-good registry contents

    # Now corrupt the yaml (invalid severity)
    fasten_yaml.write_text(textwrap.dedent("""\
        domain: fleet
        codes:
          FLEET_NODE_REGISTERED:
            severity: completely_bogus
    """))

    with pytest.raises(AuditCatalogError):
        reload()

    # Live registry must be unchanged — previous catalog still active.
    after = registry()
    assert after == snapshot


def test_reload_preserves_programmatic_codes(fasten_yaml, clean_yaml_paths):
    """Codes registered programmatically (not in any yaml) survive reload()."""
    from fasten.codes import register, Meta
    load(str(fasten_yaml))

    # Add a code programmatically — different domain, not in yaml
    if "EXTRA_PROG_CODE" in _registry:
        del _registry["EXTRA_PROG_CODE"]
    register("extra", {
        "EXTRA_PROG_CODE": Meta(
            domain="extra", category="x", action="x",
            severity=Severity.INFO, description="x", emitter="t",
        ),
    })
    assert "EXTRA_PROG_CODE" in registry()

    # Reload yaml (modify slightly to trigger a real reload path)
    fasten_yaml.write_text(textwrap.dedent("""\
        domain: fleet
        codes:
          FLEET_NODE_REGISTERED:
            severity: info
            description: x
    """))
    reload()

    reg = registry()
    assert "EXTRA_PROG_CODE" in reg  # programmatic code preserved
    assert "FLEET_NODE_REGISTERED" in reg  # yaml code reloaded
    assert "FLEET_DEPLOY_FAILED" not in reg  # yaml code removed (full-file replacement)
    # cleanup
    del _registry["EXTRA_PROG_CODE"]


def test_reload_no_op_without_load(clean_yaml_paths):
    """reload() with no prior load() is a no-op (no-op is the right default)."""
    reload()  # must not raise
