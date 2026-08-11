"""Ring and store window a timestamp-less row identically.

An explicit ``timestamp: None`` (or a missing timestamp) must be treated the
same by RingBuffer and StreamStore under a since/until window: the store
coalesces a NULL timestamp to ``''``, and the ring must match rather than
comparing the literal string ``"None"`` (which sorts above real ISO
timestamps).
"""
from fasten.store.ring import RingBuffer
from fasten.store.stream import StreamStore


def _both_with_none_timestamp():
    ring = RingBuffer(maxlen=10)
    store = StreamStore(":memory:", table="win")
    for sink in (ring.push, store.insert):
        sink({"request_id": "r-none", "timestamp": None, "event": "x"})
        sink({"request_id": "r-real", "timestamp": "2026-08-11T00:00:00Z", "event": "y"})
    return ring, store


def test_none_timestamp_excluded_by_since_in_both():
    ring, store = _both_with_none_timestamp()
    since = "2026-01-01T00:00:00Z"
    ring_ids = {r["request_id"] for r in ring.query(since=since)}
    store_ids = {r["request_id"] for r in store.query(since=since)}
    assert ring_ids == store_ids == {"r-real"}  # the None-timestamp row is dropped by both


def test_none_timestamp_kept_by_until_in_both():
    ring, store = _both_with_none_timestamp()
    until = "2027-01-01T00:00:00Z"
    ring_ids = {r["request_id"] for r in ring.query(until=until)}
    store_ids = {r["request_id"] for r in store.query(until=until)}
    assert ring_ids == store_ids == {"r-none", "r-real"}  # '' <= until, so both kept


def test_none_timestamp_consistent_without_window():
    ring, store = _both_with_none_timestamp()
    ring_ids = {r["request_id"] for r in ring.query()}
    store_ids = {r["request_id"] for r in store.query()}
    assert ring_ids == store_ids == {"r-none", "r-real"}
