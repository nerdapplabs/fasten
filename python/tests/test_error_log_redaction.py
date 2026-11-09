"""Exception log lines carry the type and frames, and a redacted message."""
import logging
import threading
import time
from datetime import timedelta

import fasten

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0.c2lnbmF0dXJl"
HERE = __file__.rsplit("/", 1)[-1]


def _raise(exc):
    raise exc


def _wait_for(cond, timeout=5.0):
    deadline = time.monotonic() + timeout
    while not cond() and time.monotonic() < deadline:
        time.sleep(0.005)
    assert cond()


class _BadStr(Exception):
    def __str__(self):
        raise RuntimeError(f"no text: {JWT}")


def _assert_redacted(text, type_name):
    assert JWT not in text
    assert type_name in text
    assert f"{HERE}:" in text


def test_describe_error_redacts_the_message():
    from fasten.redact import describe_error

    try:
        _raise(ValueError(f"insert failed: bearer {JWT}"))
    except ValueError as e:
        text = describe_error(e)
    _assert_redacted(text, "ValueError")
    assert " in _raise" in text


def test_describe_error_drops_the_message_without_the_core(monkeypatch):
    from fasten import core_ffi
    from fasten.redact import describe_error

    def _no_core(*_a, **_k):
        raise OSError("libfasten_core not found")

    monkeypatch.setattr(core_ffi, "get_lib", _no_core)
    try:
        _raise(ValueError("password hunter2"))
    except ValueError as e:
        text = describe_error(e)
    assert "hunter2" not in text
    assert text.startswith("ValueError: ")
    assert f"{HERE}:" in text


def test_describe_error_survives_a_raising_str():
    from fasten.redact import describe_error

    try:
        _raise(_BadStr())
    except _BadStr as e:
        text = describe_error(e)
    assert text.startswith("_BadStr: <str failed>")
    assert f"{HERE}:" in text


def test_describe_error_names_the_chain():
    from fasten.redact import describe_error

    try:
        try:
            _raise(KeyError(f"bearer {JWT}"))
        except KeyError as inner:
            raise ValueError("insert failed") from inner
    except ValueError as e:
        text = describe_error(e)
    assert "ValueError: insert failed" in text
    assert "caused by:\nKeyError: " in text
    assert JWT not in text


def test_describe_error_stops_on_a_cycle():
    from fasten.redact import describe_error

    a, b = ValueError("a"), ValueError("b")
    a.__context__, b.__context__ = b, a
    text = describe_error(a)
    assert text.count("ValueError:") == 2
    assert not text.endswith(":")
    assert "chain cut" not in text


def test_describe_error_says_where_the_chain_is_cut():
    from fasten.redact import describe_error

    excs = [ValueError(f"e{i}") for i in range(8)]
    for outer, inner in zip(excs, excs[1:]):
        outer.__cause__ = inner
    text = describe_error(excs[0])
    assert text.count("ValueError:") == 5
    assert text.endswith("  ... (chain cut at 5)")


def test_describe_error_skips_a_suppressed_context():
    from fasten.redact import describe_error

    try:
        try:
            _raise(KeyError("inner"))
        except KeyError:
            raise ValueError("outer") from None
    except ValueError as e:
        text = describe_error(e)
    assert "ValueError: outer" in text
    assert "KeyError" not in text
    assert "during handling of" not in text


def test_redacted_json_survives_deep_nesting():
    from fasten.redact import redacted_json

    assert redacted_json("[" * 100_000 + "]" * 100_000) == "<not json>"


class _DataError(Exception):
    """Named like the DB-API error, so the drainer dead-letters at once."""


_DataError.__name__ = "DataError"


class _FailingStore:
    def insert(self, row):
        _raise(_DataError(f"bad row: bearer {JWT}"))

    def allocate_and_insert_originated(self, row):
        _raise(_DataError(f"bad row: bearer {JWT}"))

    def count(self, **_):
        return 0

    def max_monotonic_seq(self, service_id=None, source_node_id=None):
        return 0


def test_insert_failure_log_is_redacted(caplog):
    fasten.init(service_id="svc", node_id="n", audit_store=_FailingStore(),
                audit_store_failure_strategy="queue")
    with caplog.at_level(logging.ERROR, logger="fasten"):
        fasten.emit(code="USER_CREATED", target="u-1")
        _wait_for(lambda: "insert_cb failed" in caplog.text)
    _assert_redacted(caplog.text, "DataError")


def test_drainer_store_call_failure_log_is_redacted(caplog, monkeypatch):
    from fasten.emitter import _default

    fasten.init(service_id="svc", node_id="n", audit_store=_FailingStore(),
                audit_store_failure_strategy="queue",
                extra_value_redact_patterns=[("acct", r"acct-\d+", "[acct]")])

    def _fail(*_a, **_k):
        _raise(RuntimeError("sys write failed: acct-12345"))

    monkeypatch.setattr(_default, "_drainer_sys_log", _fail)
    with caplog.at_level(logging.ERROR, logger="fasten"):
        fasten.emit(code="USER_CREATED", target="u-1")
        _wait_for(lambda: "drainer store call failed" in caplog.text)
    assert "acct-12345" not in caplog.text
    assert "RuntimeError: [acct]" in caplog.text


def test_drainer_store_thread_survives_a_raising_str(caplog, monkeypatch):
    from fasten.emitter import _default

    fasten.init(service_id="svc", node_id="n", audit_store=_FailingStore(),
                audit_store_failure_strategy="queue")
    d = _default._drainer
    monkeypatch.setattr(_default, "_drainer_sys_log", lambda *a, **k: _raise(_BadStr()))
    results = []

    def _calls():
        results.append(d.call_on_worker(lambda: _raise(_BadStr())))
        results.append(d.call_on_worker(lambda: 0))

    with caplog.at_level(logging.ERROR, logger="fasten"):
        # On a thread: if the store thread died, the calls never return.
        t = threading.Thread(target=_calls, daemon=True)
        t.start()
        t.join(timeout=5.0)
    assert results == [1, 0]
    assert "_BadStr: <str failed>" in caplog.text


def test_drainer_sys_event_failure_log_is_redacted(caplog, monkeypatch):
    from fasten.emitter import _default

    fasten.init(service_id="svc", node_id="n", audit_store=_FailingStore(),
                audit_store_failure_strategy="queue")
    d = _default._drainer
    monkeypatch.setattr(_default, "_drainer_sys_log",
                        lambda *a, **k: _raise(RuntimeError(f"sys write failed: bearer {JWT}")))
    event = f'{{"level": "error", "event": "audit_drain_failed", "error": "bearer {JWT}"}}'
    with caplog.at_level(logging.ERROR, logger="fasten"):
        d.sys_callback(event.encode(), None)
    assert "drainer sys event failed: {" in caplog.text
    assert "audit_drain_failed" in caplog.text
    _assert_redacted(caplog.text, "RuntimeError")


class _PurgeFails:
    def __init__(self, exc):
        self.exc, self.calls = exc, 0

    def purge(self, before):
        self.calls += 1
        _raise(self.exc)


def _run_purger(store, done, interval=timedelta(seconds=60), **kw):
    from fasten.retention import start_purger

    stop = threading.Event()
    t = start_purger(store=store, stream="api", retention=timedelta(days=1),
                     check_interval=interval, stop_event=stop, **kw)
    try:
        _wait_for(done)
    finally:
        stop.set()
        t.join(timeout=1.0)


def test_retention_failure_log_is_redacted(caplog):
    store = _PurgeFails(ValueError(f"purge failed: bearer {JWT}"))
    with caplog.at_level(logging.WARNING, logger="fasten.retention"):
        _run_purger(store, lambda: "api/age-purge failed" in caplog.text)
    _assert_redacted(caplog.text, "ValueError")


def test_retention_on_error_failure_log_is_redacted(caplog):
    def _on_error(_label, _e):
        _raise(RuntimeError(f"on_error failed: bearer {JWT}"))

    store = _PurgeFails(ValueError("x"))
    with caplog.at_level(logging.WARNING, logger="fasten.retention"):
        _run_purger(store, lambda: "on_error callback raised" in caplog.text,
                    on_error=_on_error)
    _assert_redacted(caplog.text, "RuntimeError")


def test_retention_uses_the_given_redactor(caplog):
    from fasten.redact import Redactor

    store = _PurgeFails(ValueError("purge failed: acct-12345"))
    redactor = Redactor(extra_value_patterns=[("acct", r"acct-\d+", "[acct]")])
    with caplog.at_level(logging.WARNING, logger="fasten.retention"):
        _run_purger(store, lambda: "api/age-purge failed" in caplog.text, redactor=redactor)
    assert "acct-12345" not in caplog.text
    assert "[acct]" in caplog.text


def test_retention_keeps_running_after_a_raising_str(caplog):
    store = _PurgeFails(_BadStr())
    with caplog.at_level(logging.WARNING, logger="fasten.retention"):
        _run_purger(store, lambda: store.calls >= 2, interval=timedelta(milliseconds=10))
    assert "_BadStr: <str failed>" in caplog.text


def test_retiring_drainer_logs_with_its_own_redactor(caplog, monkeypatch):
    from fasten.emitter import _default

    fasten.init(service_id="svc", node_id="n", audit_store=_FailingStore(),
                audit_store_failure_strategy="queue",
                extra_value_redact_patterns=[("acct", r"acct-\d+", "[acct]")])
    old = _default._drainer
    fasten.init(service_id="svc", node_id="n", audit_store=_FailingStore(),
                audit_store_failure_strategy="queue")
    assert _default._drainer is not old
    monkeypatch.setattr(_default, "_drainer_sys_log",
                        lambda *a, **k: _raise(RuntimeError("sys write failed: acct-12345")))
    event = '{"level": "error", "event": "audit_drain_failed", "error": "acct-67890"}'
    with caplog.at_level(logging.ERROR, logger="fasten"):
        old.sys_callback(event.encode(), None)
    assert "drainer sys event failed" in caplog.text
    assert "acct-12345" not in caplog.text
    assert "acct-67890" not in caplog.text
