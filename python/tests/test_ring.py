"""RingBuffer: capacity, push order, query filters, thread-safety."""
import threading
import pytest
from fasten.store.ring import RingBuffer
from fasten.transport.stdout import StdoutTransport


def test_push_and_len():
    rb = RingBuffer(maxlen=10)
    for i in range(5):
        rb.push({"n": i})
    assert len(rb) == 5


def test_eviction_at_capacity():
    rb = RingBuffer(maxlen=3)
    for i in range(5):
        rb.push({"n": i})
    assert len(rb) == 3
    results = rb.query(limit=10)
    # most-recent first (appendleft)
    assert results[0]["n"] == 4
    assert results[1]["n"] == 3
    assert results[2]["n"] == 2


def test_query_limit():
    rb = RingBuffer(maxlen=100)
    for i in range(20):
        rb.push({"n": i})
    assert len(rb.query(limit=5)) == 5


def test_query_filter_level():
    rb = RingBuffer()
    rb.push({"level": "info", "msg": "a"})
    rb.push({"level": "error", "msg": "b"})
    rb.push({"level": "info", "msg": "c"})
    results = rb.query(level="info")
    assert all(r["level"] == "info" for r in results)
    assert len(results) == 2


def test_query_filter_request_id():
    rb = RingBuffer()
    rb.push({"request_id": "abc", "msg": "x"})
    rb.push({"request_id": "xyz", "msg": "y"})
    results = rb.query(request_id="abc")
    assert len(results) == 1
    assert results[0]["msg"] == "x"


def test_query_filter_method():
    rb = RingBuffer()
    rb.push({"method": "GET", "path": "/health"})
    rb.push({"method": "POST", "path": "/api/users"})
    results = rb.query(method="post")
    assert len(results) == 1
    assert results[0]["path"] == "/api/users"


def test_query_filter_path_substring():
    rb = RingBuffer()
    rb.push({"method": "GET", "path": "/api/users/42"})
    rb.push({"method": "GET", "path": "/health"})
    results = rb.query(path="/api")
    assert len(results) == 1
    assert "users" in results[0]["path"]


def test_empty_query_returns_all():
    rb = RingBuffer()
    rb.push({"msg": "a"})
    rb.push({"msg": "b"})
    assert len(rb.query()) == 2


def test_thread_safe_concurrent_push():
    rb = RingBuffer(maxlen=1000)
    threads = [
        threading.Thread(target=lambda: [rb.push({"n": i}) for i in range(100)])
        for _ in range(10)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(rb) == 1000


# ── StdoutTransport integration ────────────────────────────────────────────

def test_push_syslog_no_stdout(capsys):
    transport = StdoutTransport()
    transport.push_syslog({"level": "info", "event": "silent"})
    captured = capsys.readouterr()
    assert captured.out == ""
    results = transport.query_syslog()
    assert results[0]["event"] == "silent"


def test_push_api_no_stdout(capsys):
    transport = StdoutTransport()
    transport.push_api({"method": "GET", "path": "/health", "status": 200})
    captured = capsys.readouterr()
    assert captured.out == ""
    results = transport.query_api(method="GET")
    assert len(results) == 1


def test_write_syslog_emits_stdout(capsys):
    import json
    transport = StdoutTransport()
    transport.write_syslog({"level": "info", "event": "boot"})
    captured = capsys.readouterr()
    obj = json.loads(captured.out.strip())
    assert obj["shape"] == "sys"
    assert obj["event"] == "boot"


def test_syslog_and_api_rings_independent():
    transport = StdoutTransport()
    transport.push_syslog({"level": "info", "event": "sys_event"})
    transport.push_api({"method": "POST", "path": "/x"})
    assert len(transport.query_syslog()) == 1
    assert len(transport.query_api()) == 1
    assert transport.query_syslog()[0].get("event") == "sys_event"
