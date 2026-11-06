"""New SQLite store files are created 0600; existing files keep their mode."""
import contextlib
import os
import sqlite3
import stat
import sys

import pytest

from fasten.store.sqlite import SQLiteStore
from fasten.store.stream import StreamStore

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")


@pytest.fixture
def umask_022():
    old = os.umask(0o022)
    yield
    os.umask(old)


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def _open_audit(path):
    s = SQLiteStore(str(path))
    s.query(limit=1)
    return s


def _open_stream(path):
    s = StreamStore(str(path), "api_stream")
    s.insert({"request_id": "r1", "event": "e"})
    return s


@pytest.mark.parametrize("open_store", [_open_audit, _open_stream])
def test_new_store_file_is_0600(tmp_path, umask_022, open_store):
    path = tmp_path / "store.db"
    open_store(path)
    assert _mode(path) == 0o600


@pytest.mark.parametrize("open_store", [_open_audit, _open_stream])
def test_existing_store_file_keeps_mode(tmp_path, umask_022, open_store):
    path = tmp_path / "store.db"
    path.touch()
    os.chmod(path, 0o644)
    open_store(path)
    assert _mode(path) == 0o644


@pytest.mark.parametrize("open_store", [_open_audit, _open_stream])
def test_wal_file_is_0600(tmp_path, umask_022, open_store):
    path = tmp_path / "store.db"
    store = open_store(path)
    wal = tmp_path / "store.db-wal"
    assert wal.exists()
    assert _mode(wal) == 0o600
    del store


@pytest.mark.parametrize("store_cls", [SQLiteStore, StreamStore])
def test_pathlib_path_is_0600(tmp_path, umask_022, store_cls):
    path = tmp_path / "store.db"
    store_cls(path, "t")
    assert _mode(path) == 0o600


def test_file_uri_is_0600(tmp_path, umask_022):
    path = tmp_path / "my store.db"
    StreamStore("file://" + str(path).replace(" ", "%20") + "?cache=private", "t")
    assert _mode(path) == 0o600


def test_read_only_file_uri_creates_nothing(tmp_path, umask_022):
    path = tmp_path / "store.db"
    with pytest.raises(sqlite3.OperationalError):
        StreamStore(f"file:{path}?mode=ro", "t")
    assert not path.exists()


@pytest.mark.parametrize("param", ["immutable=1", "vfs=memdb"])
def test_file_uri_without_a_file_to_create_creates_nothing(tmp_path, umask_022, param):
    path = tmp_path / "store.db"
    with contextlib.suppress(sqlite3.Error):
        StreamStore(f"file:{path}?{param}", "t")
    # Some SQLite versions create an empty file for immutable=1 themselves,
    # with the umask; fasten must not create one 0600 first.
    assert not path.exists() or (param == "immutable=1" and _mode(path) == 0o644)


def test_file_uri_keeps_an_invalid_escape(tmp_path, umask_022):
    StreamStore(f"file:{tmp_path}/a%zzb.db", "t")
    assert _mode(tmp_path / "a%zzb.db") == 0o600
