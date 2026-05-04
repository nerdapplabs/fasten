"""SQLiteStore: insert, query, list_unshipped, mark_shipped, purge."""
import threading
from datetime import datetime, timezone, timedelta
import pytest
from fasten.store.sqlite import SQLiteStore
from fasten.attrs import AuditRow
from fasten.context import mint_id


def make_row(**overrides):
    defaults = dict(
        id=f"evt-{'a' * 20}",
        origin_id=f"evt-{'a' * 20}",
        monotonic_seq=1,
        timestamp=datetime.now(timezone.utc),
        code="USER_CREATED",
        action="create",
        severity="info",
        service_id="svc",
        source_node_id="node-1",
        actor="system",
        actor_kind="service",
        target="u-1",
        category="account",
        domain="user",
        method="sdk",
        request_id=mint_id(),
        detail={"email": "a@b.com"},
    )
    defaults.update(overrides)
    return AuditRow(**defaults)


@pytest.fixture
def store():
    return SQLiteStore(":memory:")


def test_insert_and_query_by_request_id(store):
    row = make_row(id="evt-" + "b" * 20, origin_id="evt-" + "b" * 20, request_id="abc123def456")
    store.insert(row)
    results = store.query(request_id="abc123def456")
    assert len(results) == 1
    assert results[0].id == row.id
    assert results[0].code == "USER_CREATED"


def test_insert_idempotent(store):
    row = make_row()
    store.insert(row)
    store.insert(row)  # duplicate — INSERT OR IGNORE
    assert len(store.query()) == 1


def test_list_unshipped(store):
    row = make_row()
    store.insert(row)
    unshipped = store.list_unshipped(limit=10)
    assert len(unshipped) == 1
    assert unshipped[0].id == row.id


def test_mark_shipped(store):
    row = make_row()
    store.insert(row)
    store.mark_shipped([row.id])
    assert store.list_unshipped(limit=10) == []


def test_purge_respects_unshipped(store):
    row = make_row(timestamp=datetime.now(timezone.utc) - timedelta(days=31))
    store.insert(row)
    deleted = store.purge(before=datetime.now(timezone.utc), respect_unshipped=True)
    assert deleted == 0
    assert len(store.query()) == 1


def test_purge_shipped(store):
    row = make_row(timestamp=datetime.now(timezone.utc) - timedelta(days=31))
    store.insert(row)
    store.mark_shipped([row.id])
    deleted = store.purge(before=datetime.now(timezone.utc), respect_unshipped=True)
    assert deleted == 1


def test_query_by_code(store):
    store.insert(make_row(id="evt-" + "c" * 20, origin_id="evt-" + "c" * 20, code="USER_CREATED"))
    store.insert(make_row(id="evt-" + "d" * 20, origin_id="evt-" + "d" * 20, code="USER_DELETED"))
    results = store.query(code="USER_CREATED")
    assert all(r.code == "USER_CREATED" for r in results)


def test_query_naive_datetime_normalised_to_utc(tmp_path):
    """REVIEW #16: a naive datetime passed to since/until must compare
    correctly against the UTC-aware ISO strings stored on disk.

    Earlier `since.isoformat()` on a naive datetime produced a string
    without offset, so lexicographic compare against
    '2026-01-01T...+00:00' silently misorders.
    """
    s = SQLiteStore(str(tmp_path / "naive.db"))
    aware_now = datetime.now(timezone.utc)
    s.insert(make_row(timestamp=aware_now))
    # Same instant, but naive. After the fix, since=naive matches.
    naive_now = aware_now.replace(tzinfo=None)
    earlier_naive = naive_now - timedelta(seconds=10)
    later_naive = naive_now + timedelta(seconds=10)
    assert len(s.query(since=earlier_naive, until=later_naive)) == 1
    # Symmetric: aware boundary still works.
    assert len(s.query(
        since=aware_now - timedelta(seconds=10),
        until=aware_now + timedelta(seconds=10),
    )) == 1


def test_per_thread_connection(tmp_path):
    """REVIEW #15: file-backed store opens one connection per thread.

    Earlier the store shared a single connection via
    check_same_thread=False, which silenced the safety assertion but
    left the underlying sqlite3 cursor protocol unsafe under
    concurrent drainer + reader access.
    """
    s = SQLiteStore(str(tmp_path / "perthread.db"))

    seen_conns: set[int] = set()
    barrier = threading.Barrier(4)

    def worker(idx: int):
        barrier.wait()
        # Each worker triggers a connection open by doing one read.
        s.query(limit=1)
        seen_conns.add(id(s._connect()))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # Four worker threads → at least four distinct connection objects.
    assert len(seen_conns) >= 4


def test_memory_store_serialises_compound_ops(tmp_path):
    """`:memory:` falls back to single connection + RLock; compound ops
    from multiple threads must complete without sqlite cursor errors."""
    s = SQLiteStore(":memory:")
    errors: list[Exception] = []

    def writer(start: int):
        try:
            for i in range(20):
                idx = start + i
                rid = f"evt-{idx:020x}"
                s.insert(make_row(id=rid, origin_id=rid))
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=writer, args=(i * 100,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert len(s.query(limit=200)) == 80
