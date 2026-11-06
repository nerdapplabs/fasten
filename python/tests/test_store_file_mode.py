"""New SQLite store files are created 0600; existing files keep their mode."""
import os
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
