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
