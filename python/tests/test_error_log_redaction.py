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
        fasten.flush(timeout=2.0)
    assert "insert_cb failed" in caplog.text
    _assert_redacted(caplog.text, "DataError")


def test_drainer_store_call_failure_log_is_redacted(caplog, monkeypatch):
    from fasten.emitter import _default

    fasten.init(service_id="svc", node_id="n", audit_store=_FailingStore(),
                audit_store_failure_strategy="queue")

    def _fail(*_a, **_k):
        _raise(RuntimeError(f"sys write failed: bearer {JWT}"))

    monkeypatch.setattr(_default, "_drainer_sys_log", _fail)
    with caplog.at_level(logging.ERROR, logger="fasten"):
        fasten.emit(code="USER_CREATED", target="u-1")
        fasten.flush(timeout=2.0)
        time.sleep(0.1)
    assert "drainer store call failed" in caplog.text
    _assert_redacted(caplog.text, "RuntimeError")


def test_drainer_sys_event_failure_log_is_redacted(caplog, monkeypatch):
    from fasten.engine import _QueueDrainer

    orig = _QueueDrainer.call_on_worker

    def _call(self, fn, *args):
        if fn.__name__ == "_sys_event":
            _raise(RuntimeError(f"sys write failed: bearer {JWT}"))
        return orig(self, fn, *args)

    monkeypatch.setattr(_QueueDrainer, "call_on_worker", _call)
    fasten.init(service_id="svc", node_id="n", audit_store=_FailingStore(),
                audit_store_failure_strategy="queue")
    with caplog.at_level(logging.ERROR, logger="fasten"):
        fasten.emit(code="USER_CREATED", target="u-1")
        fasten.flush(timeout=2.0)
        time.sleep(0.1)
    assert "drainer sys event failed: {" in caplog.text
    assert "audit_drain_dead_letter" in caplog.text
    _assert_redacted(caplog.text, "RuntimeError")


class _PurgeFails:
    def purge(self, before):
        _raise(ValueError(f"purge failed: bearer {JWT}"))


def _run_purger(**kw):
    from fasten.retention import start_purger

    stop = threading.Event()
    t = start_purger(store=_PurgeFails(), stream="api", retention=timedelta(days=1),
                     check_interval=timedelta(seconds=60), stop_event=stop, **kw)
    time.sleep(0.2)
    stop.set()
    t.join(timeout=1.0)


def test_retention_failure_log_is_redacted(caplog):
    with caplog.at_level(logging.WARNING, logger="fasten.retention"):
        _run_purger()
    assert "api/age-purge failed" in caplog.text
    _assert_redacted(caplog.text, "ValueError")


def test_retention_on_error_failure_log_is_redacted(caplog):
    def _on_error(_label, _e):
        _raise(RuntimeError(f"on_error failed: bearer {JWT}"))

    with caplog.at_level(logging.WARNING, logger="fasten.retention"):
        _run_purger(on_error=_on_error)
    assert "on_error callback raised" in caplog.text
    _assert_redacted(caplog.text, "RuntimeError")
