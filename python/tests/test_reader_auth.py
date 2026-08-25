"""
P1-45 reader auth footgun reduction — pins the two contract shifts:

  1) router() with no `dependencies=` raises RuntimeError at wire time
     (no more silent public /audit on a mis-configured proxy).
  2) require_bearer() is a working, opinionated default any caller can
     hand `dependencies=[Depends(...)]` when they don't yet have an
     auth stack — 401 on missing/malformed/wrong token, 200 on match.
"""
from __future__ import annotations

import pytest

import fasten


def _init_engine():
    from fasten.store.sqlite import SQLiteStore
    fasten.init(
        service_id="svc", node_id="n",
        audit_store=SQLiteStore(":memory:"),
        audit_store_failure_strategy="raise",
    )


# ── 1) router() defaults to a hard error, not silent public /audit ────────

def test_router_without_dependencies_raises():
    pytest.importorskip("fastapi")
    from fasten.reader.router import router

    with pytest.raises(RuntimeError, match=r"dependencies=.*required"):
        router()


def test_router_with_explicit_empty_deps_is_the_opt_in_no_auth():
    pytest.importorskip("fastapi")
    from fasten.reader.router import router
    r = router(dependencies=[])
    assert r is not None


# ── 2) require_bearer() end-to-end ────────────────────────────────────────

def test_require_bearer_unset_env_raises_at_wire_time(monkeypatch):
    pytest.importorskip("fastapi")
    from fasten.reader import require_bearer

    monkeypatch.delenv("FASTEN_READER_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match=r"FASTEN_READER_TOKEN.*unset"):
        require_bearer()


def _client_with_bearer(monkeypatch, token: str):
    from fastapi import Depends, FastAPI
    from fastapi.testclient import TestClient
    from fasten.reader import require_bearer
    from fasten.reader.router import router

    _init_engine()
    monkeypatch.setenv("FASTEN_READER_TOKEN", token)
    app = FastAPI()
    app.include_router(
        router(dependencies=[Depends(require_bearer())]),
        prefix="/api/v1/logs",
    )
    return TestClient(app)


def test_require_bearer_missing_header_returns_401(monkeypatch):
    pytest.importorskip("fastapi")
    c = _client_with_bearer(monkeypatch, "s3cret")
    r = c.get("/api/v1/logs/audit")
    assert r.status_code == 401


def test_require_bearer_wrong_scheme_returns_401(monkeypatch):
    pytest.importorskip("fastapi")
    c = _client_with_bearer(monkeypatch, "s3cret")
    r = c.get("/api/v1/logs/audit", headers={"Authorization": "Basic s3cret"})
    assert r.status_code == 401


def test_require_bearer_wrong_token_returns_401(monkeypatch):
    pytest.importorskip("fastapi")
    c = _client_with_bearer(monkeypatch, "s3cret")
    r = c.get("/api/v1/logs/audit", headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401


def test_require_bearer_matching_token_passes_through(monkeypatch):
    pytest.importorskip("fastapi")
    c = _client_with_bearer(monkeypatch, "s3cret")
    r = c.get("/api/v1/logs/audit", headers={"Authorization": "Bearer s3cret"})
    assert r.status_code == 200
