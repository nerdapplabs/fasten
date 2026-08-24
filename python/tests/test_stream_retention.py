"""Per-stream retention pruning (FR1).

StreamStore.purge trims history by age so a persisted api/sys stream does not
grow without bound. A timestamp-less row has unknown age and is kept, not
silently dropped.
"""
from fasten.store.stream import StreamStore


def test_purge_removes_rows_older_than_cutoff():
    store = StreamStore(":memory:", table="ret")
    store.insert({"request_id": "old", "timestamp": "2026-01-01T00:00:00Z", "event": "a"})
    store.insert({"request_id": "new", "timestamp": "2026-08-01T00:00:00Z", "event": "b"})
    store.insert({"request_id": "nots", "timestamp": None, "event": "c"})  # no timestamp

    removed = store.purge(before="2026-06-01T00:00:00Z")
    assert removed == 1  # only the January row is older than the cutoff

    ids = {r["request_id"] for r in store.query()}
    assert ids == {"new", "nots"}  # old purged; newer + timestamp-less kept


def test_purge_none_when_all_newer():
    store = StreamStore(":memory:", table="ret2")
    store.insert({"request_id": "x", "timestamp": "2026-08-10T00:00:00Z"})
    assert store.purge(before="2026-01-01T00:00:00Z") == 0
    assert len(store.query()) == 1


def test_purge_keeps_null_timestamp_row():
    store = StreamStore(":memory:", table="ret3")
    store.insert({"request_id": "nots", "event": "c"})  # timestamp key absent
    assert store.purge(before="2099-01-01T00:00:00Z") == 0  # NULL age unknown → kept
    assert len(store.query()) == 1


def test_retention_prunes_persisted_reads_end_to_end():
    """Functional: rows written through the transport persist to the stream
    store; purging old history removes them from subsequent reads served from
    that store (the reader path, not just the store in isolation)."""
    import fasten
    from fasten.store.sqlite import SQLiteStore

    syslog_store = StreamStore(":memory:", table="syslog")
    fasten.init(
        service_id="svc", node_id="node",
        audit_store=SQLiteStore(":memory:"),
        syslog_store=syslog_store,
        audit_store_failure_strategy="raise",
    )
    t = fasten.transport()
    t.push_syslog({"level": "info", "event": "old",
                   "timestamp": "2026-01-01T00:00:00Z", "request_id": "r1"})
    t.push_syslog({"level": "info", "event": "new",
                   "timestamp": "2026-08-01T00:00:00Z", "request_id": "r2"})
    assert len(t.query_syslog()) == 2  # both readable from the store

    removed = syslog_store.purge(before="2026-06-01T00:00:00Z")
    assert removed == 1

    events = {r["event"] for r in t.query_syslog()}
    assert events == {"new"}  # the read now reflects the pruned history
