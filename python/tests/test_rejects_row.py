"""Which store errors mean the row itself was refused, and which mean the
connection was lost."""
import sqlite3

from fasten.engine import _rejects_row
from fasten.store.postgres import _connection_lost


class _PgError(Exception):
    """A psycopg-style error: the server's SQLSTATE is in ``sqlstate``."""

    def __init__(self, sqlstate):
        super().__init__(sqlstate)
        self.sqlstate = sqlstate


def test_rejecting_sqlstate_classes():
    for code in ("22021", "23505", "42703", "54000"):
        assert _rejects_row(_PgError(code)), code
    for code in ("08006", "40001", "53300", "57P01", None):
        assert not _rejects_row(_PgError(code)), code


def test_dbapi_data_and_integrity_errors_reject():
    assert _rejects_row(sqlite3.IntegrityError("UNIQUE constraint failed"))
    assert _rejects_row(sqlite3.DataError("bad"))
    assert not _rejects_row(sqlite3.OperationalError("database is locked"))
    assert not _rejects_row(RuntimeError("down"))


def test_connection_lost_only_for_connection_errors():
    # No SQLSTATE: the server never answered.
    assert _connection_lost(_PgError(None))
    assert _connection_lost(_PgError("08006"))
    assert _connection_lost(_PgError("57P01"))
    # The server answered over a working connection.
    assert not _connection_lost(_PgError("54000"))
    assert not _connection_lost(_PgError("22021"))
