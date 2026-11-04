"""Chain checkpoints (spec §9): verify_chain checked against a node's
published latest seq and hash detects a cut-off tail and a full re-seal."""
import dataclasses
import http.server
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from fasten.attrs import AuditRow
from fasten.canonical_ts import parse_canonical
from fasten.chain import seal, verify_chain
from fasten.checkpoints import (
    Checkpoint,
    FileCheckpointSink,
    HttpCheckpointSink,
    load_checkpoints,
    publish_checkpoints,
    take_checkpoints,
)
from fasten.store.sqlite import SQLiteStore

DSN = os.environ.get("FASTEN_TEST_POSTGRES_DSN")
VECTORS = Path(__file__).resolve().parents[2] / "spec" / "checkpoint-vectors.json"


def _row(seq: int, *, node: str = "node-1", target: str = "u/1") -> AuditRow:
    rid = f"evt-{node}-{seq}-{target}"
    return AuditRow(
        id=rid, origin_id=rid, monotonic_seq=seq,
        timestamp=datetime(2026, 6, 15, 10, 30, seq % 60, tzinfo=timezone.utc),
        code="USER_CREATED", action="create", severity="info",
        service_id="svc", source_node_id=node, tenant_id=None,
        actor="a", actor_kind="user", target=target,
        category="account", domain="user", method="sdk",
        request_id=f"req-{seq}", detail={"k": "v"},
    )


def _chain(seqs, *, node: str = "node-1", prev: str = "genesis", **kw) -> list[AuditRow]:
    out = []
    for seq in seqs:
        row = seal(prev, _row(seq, node=node, **kw))
        prev = row.hash
        out.append(row)
    return out


def _cp(row: AuditRow) -> Checkpoint:
    return Checkpoint(source_node_id=row.source_node_id, monotonic_seq=row.monotonic_seq,
                      hash=row.hash, anchored_at="2026-06-15T11:00:00.000000Z")


# verify_chain against checkpoints, no store

def test_a_chain_matching_its_checkpoint_verifies():
    rows = _chain(range(1, 6))
    assert verify_chain(rows, checkpoints=[_cp(rows[-1])]).ok


def test_an_older_checkpoint_inside_the_chain_verifies():
    rows = _chain(range(1, 6))
    assert verify_chain(rows, checkpoints=[_cp(rows[1]), _cp(rows[-1])]).ok


def test_a_cut_off_tail_breaks_after_the_last_row():
    rows = _chain(range(1, 11))
    result = verify_chain(rows[:6], checkpoints=[_cp(rows[-1])])
    assert verify_chain(rows[:6]).ok
    assert not result.ok and result.first_break_at == 7
    assert result.reason == "node 'node-1': chain ends at seq 6 before checkpoint at seq 10"


def test_a_resealed_chain_fails_against_the_earlier_checkpoint():
    rows = _chain(range(1, 6))
    resealed = _chain(range(1, 6), target="u/2")
    assert verify_chain(resealed).ok
    result = verify_chain(resealed, checkpoints=[_cp(rows[-1])])
    assert not result.ok and result.first_break_at == 5
    assert result.reason == f"row {resealed[-1].id}: hash differs from checkpoint at seq 5"


def test_a_checkpoint_older_than_the_oldest_row_is_skipped():
    rows = _chain(range(1, 11))
    assert verify_chain(rows[4:], checkpoints=[_cp(rows[1]), _cp(rows[-1])]).ok


def test_a_missing_checkpointed_row_inside_the_chain_breaks_there():
    # Rows 1-2 unsealed, the chain starts at 5 after a purged head, and the
    # checkpointed seq 3 is gone from between them.
    legacy = [dataclasses.replace(_row(s), hash="", prev_hash="") for s in (1, 2)]
    sealed = _chain(range(3, 8))
    result = verify_chain(legacy + sealed[2:], checkpoints=[_cp(sealed[0])])
    assert verify_chain(legacy + sealed[2:]).ok
    assert not result.ok and result.first_break_at == 3
    assert result.reason == "node 'node-1': no row at checkpointed seq 3"


def test_a_checkpoint_for_a_node_not_in_the_rows_is_skipped():
    other = _chain(range(1, 4), node="node-2")
    assert verify_chain(_chain(range(1, 4)), checkpoints=[_cp(other[-1])]).ok


def test_the_lowest_break_across_nodes_is_reported():
    a, b = _chain(range(1, 11), node="node-a"), _chain(range(1, 11), node="node-b")
    rows = a[:8] + b[:3]
    result = verify_chain(rows, checkpoints=[_cp(a[-1]), _cp(b[-1])])
    assert not result.ok and result.first_break_at == 4
    assert result.reason == "node 'node-b': chain ends at seq 3 before checkpoint at seq 10"


def test_a_chain_break_below_a_checkpoint_break_wins():
    rows = _chain(range(1, 11))
    cut = rows[:6]
    cut[1] = dataclasses.replace(cut[1], target="u/edited")
    result = verify_chain(cut, checkpoints=[_cp(rows[-1])])
    assert result.first_break_at == 2 and "hash mismatch" in result.reason


# sinks

def test_file_sink_round_trip(tmp_path):
    path = tmp_path / "checkpoints.jsonl"
    sink = FileCheckpointSink(path)
    first = [_cp(r) for r in _chain(range(1, 3))]
    second = [_cp(_chain(range(1, 2), node="node-2")[0])]
    sink.publish(first)
    sink.publish(second)
    sink.publish([])
    assert load_checkpoints(path) == first + second
    line = json.loads(path.read_text().splitlines()[0])
    assert set(line) == {"source_node_id", "monotonic_seq", "hash", "anchored_at"}


def test_load_rejects_a_line_that_is_not_a_checkpoint(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text('{"source_node_id": "n", "monotonic_seq": "1", "hash": "h", '
                    '"anchored_at": "t"}\n')
    with pytest.raises(ValueError):
        load_checkpoints(path)


class _Server:
    def __init__(self, status: int):
        self.bodies: list = []
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers["Content-Length"])
                outer.bodies.append((self.headers["Content-Type"],
                                     json.loads(self.rfile.read(n))))
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/checkpoints"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server(request):
    s = _Server(request.param)
    yield s
    s.close()


@pytest.mark.parametrize("server", [204], indirect=True)
def test_http_sink_posts_a_json_array(server):
    cps = [_cp(r) for r in _chain(range(1, 3))]
    HttpCheckpointSink(server.url, timeout=5).publish(cps)
    assert server.bodies == [("application/json", [c.to_dict() for c in cps])]


@pytest.mark.parametrize("server", [500], indirect=True)
def test_http_sink_raises_on_an_error_status(server):
    with pytest.raises(OSError):
        HttpCheckpointSink(server.url, timeout=5).publish([_cp(_chain([1])[0])])


def test_http_sink_refuses_other_schemes():
    with pytest.raises(ValueError):
        HttpCheckpointSink("file:///etc/passwd")


# stores

def _sqlite(tmp_path):
    store = SQLiteStore(str(tmp_path / "audit.db"))

    def run(sql, params):
        conn = store._connect()
        conn.execute(sql.replace("%s", "?"), params)
        conn.commit()
    return store, run, lambda: None


def _postgres():
    if not DSN:
        pytest.skip("set FASTEN_TEST_POSTGRES_DSN")
    from fasten.store.postgres import PostgresStore
    table = f"checkpoints_{uuid.uuid4().hex[:12]}"
    store = PostgresStore(DSN, table=table)

    def run(sql, params):
        def _go(conn):
            conn.execute(sql, params)
            conn.commit()
        store._execute_with_retry(_go)
    return store, run, lambda: run(f"DROP TABLE IF EXISTS {table}", ())


@pytest.fixture(params=["sqlite", "postgres"])
def store(request, tmp_path):
    s, run, drop = _sqlite(tmp_path) if request.param == "sqlite" else _postgres()
    s.run_sql = run
    yield s
    drop()


def _emit(store, n, *, node="node-1", target="u/1"):
    return [store.allocate_and_insert_originated(
        dataclasses.replace(_row(i, node=node, target=target), monotonic_seq=0))
        for i in range(1, n + 1)]


def _rows(store, node="node-1"):
    return store.chain_tail(node, 1000)


def test_store_chain_matches_its_published_checkpoint(store, tmp_path):
    _emit(store, 4)
    path = tmp_path / "cp.jsonl"
    [cp] = publish_checkpoints(store, FileCheckpointSink(path))
    assert cp.monotonic_seq == 4 and parse_canonical(cp.anchored_at)
    assert verify_chain(_rows(store), checkpoints=load_checkpoints(path)).ok


def test_store_with_rows_deleted_from_the_end_fails_its_checkpoint(store):
    _emit(store, 8)
    cps = take_checkpoints(store)
    store.run_sql(f"DELETE FROM {store._table} WHERE monotonic_seq > %s", (5,))
    rows = _rows(store)
    assert verify_chain(rows).ok
    result = verify_chain(rows, checkpoints=cps)
    assert not result.ok and result.first_break_at == 6
    assert result.reason == "node 'node-1': chain ends at seq 5 before checkpoint at seq 8"


def test_store_resealed_from_genesis_fails_its_checkpoint(store):
    _emit(store, 5)
    cps = take_checkpoints(store)
    store.run_sql(f"DELETE FROM {store._table}", ())
    _emit(store, 6, target="u/rewritten")
    rows = _rows(store)
    assert verify_chain(rows).ok
    result = verify_chain(rows, checkpoints=cps)
    assert not result.ok and result.first_break_at == 5
    assert "hash differs from checkpoint at seq 5" in result.reason


def test_take_checkpoints_uses_the_latest_sealed_row_per_node(store):
    a = _emit(store, 3, node="node-a")
    b = _emit(store, 2, node="node-b")
    unsealed = dataclasses.replace(_row(4, node="node-a", target="u/x"), hash="", prev_hash="")
    store.insert_originated(unsealed)
    only = dataclasses.replace(_row(1, node="node-c"), hash="", prev_hash="")
    store.insert_originated(only)
    cps = take_checkpoints(store)
    assert [(c.source_node_id, c.monotonic_seq, c.hash) for c in cps] == [
        ("node-a", 3, a[-1].hash), ("node-b", 2, b[-1].hash)]
    assert len({c.anchored_at for c in cps}) == 1


def test_take_checkpoints_on_an_empty_store(store):
    assert take_checkpoints(store) == []


# cross-SDK vectors, also run by Go

def _vector_rows(raw):
    out = []
    for d in raw:
        d = dict(d)
        for field in ("timestamp", "shipped_at"):
            if isinstance(d.get(field), str):
                d[field] = parse_canonical(d[field])
        out.append(AuditRow(**{k: d[k] for k in AuditRow.__dataclass_fields__ if k in d}))
    return out


def test_checkpoint_vectors():
    cases = json.loads(VECTORS.read_text())["cases"]
    assert len(cases) >= 8
    for case in cases:
        result = verify_chain(_vector_rows(case["rows"]),
                              checkpoints=[Checkpoint.from_dict(c) for c in case["checkpoints"]])
        want = case["expected"]
        got = {"ok": result.ok, "first_break_at": result.first_break_at,
               "reason": result.reason}
        assert got == want, case["label"]


def test_committed_checkpoint_vectors_are_current():
    import subprocess
    import sys
    repo = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, str(repo / "scripts" / "gen_checkpoint_vectors.py"), "--check"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
