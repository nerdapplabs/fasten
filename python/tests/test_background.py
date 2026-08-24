"""§8.1 background-work correlation — fasten.background / fasten.go.

Work outside a request must still be correlatable: a bg- sentinel is minted when
no request_id is active, otherwise the active id is inherited.
"""
import fasten
from fasten.context import current_request_id, request_id_kind, with_request_id
from fasten.store.sqlite import SQLiteStore
from fasten.store.stream import StreamStore


def _init():
    fasten.init(service_id="svc", node_id="node")


def test_background_mints_bg_when_no_context():
    _init()
    with fasten.background() as rid:
        assert request_id_kind(rid) == "bg"
        assert current_request_id() == rid


def test_background_inherits_active_request_id():
    _init()
    with with_request_id("req-real123"):
        with fasten.background() as rid:
            assert rid == "req-real123"  # inherit, never override a real id


def test_background_kind_sched():
    _init()
    with fasten.background(kind="sched") as rid:
        assert request_id_kind(rid) == "sched"


def test_go_runs_under_bg_context():
    _init()
    seen: dict[str, str] = {}
    t = fasten.go(lambda: seen.setdefault("rid", current_request_id() or ""))
    t.join(timeout=2)
    assert request_id_kind(seen["rid"]) == "bg"


def test_go_inherits_parent_request_id():
    _init()
    seen: dict[str, str] = {}
    with with_request_id("req-parent99"):
        t = fasten.go(lambda: seen.setdefault("rid", current_request_id() or ""))
    t.join(timeout=2)
    assert seen["rid"] == "req-parent99"  # captured at call time, used in the thread


def test_background_sys_log_is_correlatable_end_to_end():
    syslog_store = StreamStore(":memory:", table="syslog")
    fasten.init(
        service_id="svc", node_id="node",
        audit_store=SQLiteStore(":memory:"),
        syslog_store=syslog_store,
        audit_store_failure_strategy="raise",
    )
    with fasten.background() as rid:
        fasten.log.info("worker.tick")

    rows = syslog_store.query(request_id=rid)
    assert len(rows) == 1 and rows[0]["event"] == "worker.tick"
    assert request_id_kind(rid) == "bg"  # recoverable via /correlate?request_id=bg-...
