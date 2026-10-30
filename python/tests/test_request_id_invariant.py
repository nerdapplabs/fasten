"""Every persisted sys row carries a request_id (spec §8.7).

Runs boot, a request, a background tick and shutdown, and checks that every
stored sys row has a real request_id or a sentinel. The Go suite runs the same
scenario (TestRequestIDInvariant_EveryPersistedSysRow).
"""
import fasten
from fasten.context import request_id_kind, with_request_id
from fasten.store.sqlite import SQLiteStore
from fasten.store.stream import StreamStore


def test_every_persisted_sys_row_has_request_id():
    syslog_store = StreamStore(":memory:", table="syslog")
    fasten.init(
        service_id="svc", node_id="node",
        audit_store=SQLiteStore(":memory:"),
        syslog_store=syslog_store,
        audit_store_failure_strategy="raise",
    )

    fasten.log.info("boot.init")                    # boot: before the first request
    with with_request_id("req-abc123def"):
        fasten.log.info("handling")                 # first request: real context
    fasten.log.info("bg.tick")                      # background tick: no context
    fasten.log.info("shutdown")                     # shutdown: no context

    rows = syslog_store.query(limit=100)
    assert len(rows) == 4
    for r in rows:
        assert r.get("request_id"), f"persisted sys row missing request_id: {r}"

    kind = {r["event"]: request_id_kind(r["request_id"]) for r in rows}
    assert kind["boot.init"] == "boot"     # boot-window sentinel
    assert kind["handling"] == "request"   # real correlation id
    assert kind["bg.tick"] == "orphan"     # no context, after boot
    assert kind["shutdown"] == "orphan"
