"""Errors about a store DSN name no part of it."""
import pytest

from fasten.engine import _stream_store_from_dsn
from fasten.store.sqlite import SQLiteStore


def test_unsupported_stream_scheme_error_omits_dsn():
    with pytest.raises(ValueError) as e:
        _stream_store_from_dsn("postgresql+asyncpg://app:s3cret@db/audit", "sys")
    assert "s3cret" not in str(e.value)
    assert "postgresql+asyncpg" in str(e.value)


def test_sqlite_dsn_without_path_error_omits_dsn():
    with pytest.raises(ValueError) as e:
        SQLiteStore.from_dsn("sqlite://app:s3cret@")
    assert "s3cret" not in str(e.value)


@pytest.mark.parametrize("cls_path", [
    "fasten.store.postgres:PostgresStore",
    "fasten.store.stream_postgres:PostgresStreamStore",
])
def test_unparsable_postgres_dsn_error_omits_dsn(cls_path):
    pytest.importorskip("psycopg")
    import importlib
    mod, name = cls_path.split(":")
    cls = getattr(importlib.import_module(mod), name)
    with pytest.raises(ValueError) as e:
        cls("postgresql://app:pa%ss@db/audit", "audit_log")
    assert "pa%ss" not in str(e.value)
    assert str(e.value) == "fasten: invalid Postgres connection string"


_WORDS = ("admin", "s3cret", "db.internal", "user", "pw", "host", "hunter2")


@pytest.mark.parametrize("name", ["FASTEN_AUDIT_DSN", "FASTEN_API_DSN", "FASTEN_SYSLOG_DSN"])
def test_dsn_errors_name_a_scheme_only_when_the_dsn_has_one(name, monkeypatch, tmp_path):
    from fasten.engine import Engine
    monkeypatch.chdir(tmp_path)
    for var in ("FASTEN_AUDIT_DSN", "FASTEN_API_DSN", "FASTEN_SYSLOG_DSN"):
        monkeypatch.delenv(var, raising=False)
    kind, file = ("audit", "audit.db") if name == "FASTEN_AUDIT_DSN" else ("stream", "streams.db")
    for dsn in ("admin:s3cret@db.internal:5432/app", "db.internal:5432/app", "user:pw@host/db"):
        monkeypatch.setenv(name, dsn)
        with pytest.raises(ValueError) as e:
            Engine().init_config(service_id="svc", node_id="n1")
        assert str(e.value) == (
            f"fasten: {kind} DSN form not recognised. "
            f"Use postgres://..., sqlite:///./{file}, or a bare filesystem path.")
    monkeypatch.setenv(name, "mysql://u:hunter2@db/app")
    with pytest.raises(ValueError) as e:
        Engine().init_config(service_id="svc", node_id="n1")
    assert "scheme 'mysql'" in str(e.value)
    assert not any(w in str(e.value) for w in _WORDS)
    assert list(tmp_path.iterdir()) == []


def test_sqlite_forms_without_slashes_still_open(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    store = _stream_store_from_dsn("sqlite:rel.db", "syslog")
    assert store.count() == 0
    assert (tmp_path / "rel.db").exists()
