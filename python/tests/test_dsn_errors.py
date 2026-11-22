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


_VARS = (("FASTEN_AUDIT_DSN", "audit", "audit.db"),
         ("FASTEN_API_DSN", "stream", "streams.db"),
         ("FASTEN_SYSLOG_DSN", "stream", "streams.db"))


@pytest.fixture
def no_dsn_env(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    for name, _, _ in _VARS:
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize("name, kind, file", _VARS)
@pytest.mark.parametrize("dsn", ["host=db.internal user=admin password=s3cret dbname=appdb",
                                 "  dbname = appdb host=db.internal"])
def test_a_libpq_keyword_dsn_is_refused(no_dsn_env, monkeypatch, tmp_path, name, kind, file, dsn):
    from fasten.engine import Engine
    monkeypatch.setenv(name, dsn)
    with pytest.raises(ValueError) as e:
        Engine().init_config(service_id="svc", node_id="n1")
    assert str(e.value) == (
        f"fasten: {kind} DSN in libpq keyword form not supported. "
        f"Use postgres://user@host/db, sqlite:///./{file}, or a bare filesystem path.")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("name, kind, file", _VARS)
def test_an_unparseable_dsn_gets_a_fixed_message(no_dsn_env, monkeypatch, tmp_path, name, kind, file):
    import traceback
    from fasten.engine import Engine
    monkeypatch.setenv(name, "postgresql://admin:s3＠cret@db.internal/app")
    with pytest.raises(ValueError) as e:
        Engine().init_config(service_id="svc", node_id="n1")
    assert str(e.value) == (
        f"fasten: {kind} DSN could not be parsed. "
        f"Use postgres://..., sqlite:///./{file}, or a bare filesystem path.")
    assert e.value.__cause__ is None and e.value.__context__ is None
    text = "".join(traceback.format_exception(e.type, e.value, e.tb))
    assert not any(w in text for w in ("admin", "s3", "cret", "db.internal"))
    assert list(tmp_path.iterdir()) == []


def test_a_postgres_scheme_in_any_case_opens_postgres(no_dsn_env, monkeypatch, tmp_path):
    import os
    import uuid

    import fasten
    dsn = os.getenv("FASTEN_TEST_POSTGRES_DSN")
    if not dsn:
        pytest.skip("FASTEN_TEST_POSTGRES_DSN not set")
    psycopg = pytest.importorskip("psycopg")
    from fasten.emitter import _default
    from fasten.store.stream_postgres import PostgresStreamStore
    rest = dsn.split("://", 1)[1]
    sep = "&" if "?" in rest else "?"
    tables = []
    try:
        for scheme in ("Postgres", "POSTGRES"):
            audit, api = (f"dsn_case_{uuid.uuid4().hex[:10]}" for _ in range(2))
            tables += [audit, api]
            monkeypatch.setenv("FASTEN_AUDIT_DSN", f"{scheme}://{rest}{sep}table={audit}")
            fasten.init(service_id="svc", node_id="n1", audit_store_failure_strategy="raise")
            fasten.emit(code="USER_CREATED", target="u-1")
            fasten.close()
            _default.reset_for_tests()
            store = _stream_store_from_dsn(f"{scheme}://{rest}{sep}table={api}", "api_log")
            assert isinstance(store, PostgresStreamStore)
            store.insert({"level": "info", "event": "ok", "service_id": "svc",
                          "timestamp": "2026-08-01T00:00:00Z", "request_id": "r-1"})
            with psycopg.connect(dsn, autocommit=True) as conn:
                for table in (audit, api):
                    assert conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 1
        assert list(tmp_path.iterdir()) == []
    finally:
        with psycopg.connect(dsn, autocommit=True) as conn:
            for table in tables:
                conn.execute(f"DROP TABLE IF EXISTS {table}")


@pytest.mark.parametrize("form, file, table, journal", [
    ("rel.db", "cwd/rel.db", "audit_log", "wal"),
    ("{}/abs.db", "abs.db", "audit_log", "wal"),
    ("./a:b.db", "cwd/a:b.db", "audit_log", "wal"),
    ("sqlite:rel.db", "cwd/rel.db", "audit_log", "wal"),
    ("sqlite:///rel.db", "cwd/rel.db", "audit_log", "wal"),
    ("sqlite:///{}/abs.db", "abs.db", "audit_log", "wal"),
    ("sqlite:///t.db?table=my_audit", "cwd/t.db", "my_audit", "wal"),
    ("rel.db?table=my_audit", "cwd/rel.db", "my_audit", "wal"),
    ("sqlite:///w.db?wal=false", "cwd/w.db", "audit_log", "delete"),
])
def test_sqlite_audit_dsn_forms_still_open(no_dsn_env, monkeypatch, tmp_path,
                                           form, file, table, journal):
    import sqlite3

    import fasten
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    monkeypatch.setenv("FASTEN_AUDIT_DSN", form.format(tmp_path))
    fasten.init(service_id="svc", node_id="n1", audit_store_failure_strategy="raise")
    fasten.emit(code="USER_CREATED", target="u-1")
    fasten.close()
    db = tmp_path / file
    made = {p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*") if p.is_file()}
    assert {m for m in made if not m.endswith(("-wal", "-shm"))} == {file}
    conn = sqlite3.connect(db)
    assert conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0] == 1
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == journal
