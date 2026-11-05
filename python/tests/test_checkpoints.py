"""Chain checkpoints (spec §9): verify_chain checked against a node's
published latest seq and hash detects a cut-off tail and a full re-seal."""
import dataclasses
import http.server
import json
import logging
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
    checkpoints_since,
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


def test_a_checkpoint_below_the_oldest_row_fails_a_whole_chain_verify():
    rows = _chain(range(1, 11))
    cps = [_cp(rows[1]), _cp(rows[-1])]
    result = verify_chain(rows[4:], checkpoints=cps)
    assert not result.ok and result.first_break_at == 5
    assert result.reason == "node 'node-1': rows start at seq 5, after the checkpoint at seq 2"
    assert verify_chain(rows[4:], checkpoints=cps, partial=True).ok


def test_rows_resealed_above_an_old_checkpoint_fail_after_the_next_publish():
    # Every row deleted and edited copies re-sealed from seq 21, then the
    # next publish checkpoints the new tip. The checkpoint at 20 still fails.
    rows = _chain(range(1, 21))
    resealed = _chain(range(21, 31), target="u/2")
    cps = [_cp(rows[-1]), _cp(resealed[-1])]
    assert verify_chain(resealed).ok
    result = verify_chain(resealed, checkpoints=cps)
    assert not result.ok and result.first_break_at == 21
    assert result.reason == "node 'node-1': rows start at seq 21, after the checkpoint at seq 20"
    assert verify_chain(resealed, checkpoints=cps, partial=True).ok


def test_a_purge_verifies_with_the_checkpoints_since_it():
    rows = _chain(range(1, 11))
    cps = [_cp_at(rows[1], "2026-06-15T11:00:00.000000Z"),
           _cp_at(rows[-1], "2026-06-15T12:00:00.000000Z")]
    assert not verify_chain(rows[4:], checkpoints=cps).ok
    kept = checkpoints_since(cps, datetime(2026, 6, 15, 12, tzinfo=timezone.utc))
    assert verify_chain(rows[4:], checkpoints=kept).ok


def test_a_chain_resealed_above_the_newest_checkpoint_fails():
    rows = _chain(range(1, 11))
    resealed = _chain(range(11, 21), target="u/2")
    assert verify_chain(resealed).ok
    result = verify_chain(resealed, checkpoints=[_cp(rows[4]), _cp(rows[-1])])
    assert not result.ok and result.first_break_at == 11
    assert result.reason == ("node 'node-1': rows start at seq 11, "
                             "after the checkpoint at seq 5")


def test_a_checkpointed_node_with_no_rows_fails():
    one, two = _chain(range(1, 4)), _chain(range(1, 6), node="node-2")
    result = verify_chain(one, checkpoints=[_cp(one[-1]), _cp(two[1]), _cp(two[-1])])
    assert not result.ok and result.first_break_at == 5
    assert result.reason == "node 'node-2': no rows, but checkpointed at seq 5"
    result = verify_chain([], checkpoints=[_cp(two[-1])])
    assert not result.ok and result.first_break_at == 5 and result.total_rows == 0


def test_partial_skips_checkpoints_outside_the_rows():
    rows = _chain(range(1, 11))
    other = _chain(range(1, 4), node="node-2")
    resealed = _chain(range(11, 21), target="u/2")
    cps = [_cp(rows[-1]), _cp(other[-1])]
    assert verify_chain(resealed, checkpoints=cps, partial=True).ok
    assert verify_chain([], checkpoints=cps, partial=True).ok
    assert verify_chain(rows[4:], checkpoints=cps, partial=True).ok
    # An older page: the checkpoint above it says nothing about rows 3 to 6.
    assert verify_chain(rows[2:6], checkpoints=cps, partial=True).ok
    # The whole chain cut off at 6 is still caught.
    result = verify_chain(rows[:6], checkpoints=cps[:1])
    assert result.first_break_at == 7
    assert result.reason == "node 'node-1': chain ends at seq 6 before checkpoint at seq 10"


def test_a_missing_checkpointed_row_inside_the_chain_breaks_there():
    # Rows 1-2 unsealed, the chain starts at 5 after a purged head, and the
    # checkpointed seq 3 is gone from between them.
    legacy = [dataclasses.replace(_row(s), hash="", prev_hash="") for s in (1, 2)]
    sealed = _chain(range(3, 8))
    result = verify_chain(legacy + sealed[2:], checkpoints=[_cp(sealed[0])])
    assert verify_chain(legacy + sealed[2:]).ok
    assert not result.ok and result.first_break_at == 3
    assert result.reason == "node 'node-1': no row at checkpointed seq 3"


def test_partial_skips_a_checkpoint_for_a_node_not_in_the_rows():
    other = _chain(range(1, 4), node="node-2")
    assert verify_chain(_chain(range(1, 4)), checkpoints=[_cp(other[-1])], partial=True).ok


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


def _cp_at(row: AuditRow, at: str) -> Checkpoint:
    return dataclasses.replace(_cp(row), anchored_at=at)


def test_checkpoints_since_drops_a_fully_purged_nodes_checkpoints():
    # node-2's rows were all purged at 12:00; node-1 was checkpointed again after.
    one, two = _chain(range(1, 6)), _chain(range(1, 4), node="node-2")
    cps = [_cp_at(one[2], "2026-06-15T11:00:00.000000Z"),
           _cp_at(two[-1], "2026-06-15T11:59:00.000000Z"),
           _cp_at(one[-1], "2026-06-15T12:00:00.000000Z")]
    assert not verify_chain(one, checkpoints=cps).ok
    kept = checkpoints_since(cps, datetime(2026, 6, 15, 12, tzinfo=timezone.utc))
    assert kept == [cps[2]]
    assert verify_chain(one, checkpoints=kept).ok


def test_checkpoints_since_keeps_a_recent_checkpoint_of_a_node_with_no_rows():
    one, two = _chain(range(1, 6)), _chain(range(1, 4), node="node-2")
    cps = [_cp_at(two[-1], "2026-06-15T12:30:00.000000Z"),
           _cp_at(one[-1], "2026-06-15T12:30:00.000000Z")]
    kept = checkpoints_since(cps, datetime(2026, 6, 15, 12))
    assert kept == cps
    result = verify_chain(one, checkpoints=kept)
    assert not result.ok and result.reason == "node 'node-2': no rows, but checkpointed at seq 3"


def test_checkpoints_since_rejects_a_non_canonical_anchored_at():
    with pytest.raises(ValueError):
        checkpoints_since([_cp_at(_chain([1])[0], "2026-06-15T12:30:00Z")],
                          datetime(2026, 6, 15, tzinfo=timezone.utc))


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


@pytest.mark.parametrize("line", [
    '{"source_node_id": "n", "monotonic_seq": 1, "hash": "h", "anchored_at": "t", "x": 1}',
    '{"source_node_id": "n", "Monotonic_Seq": 1, "hash": "h", "anchored_at": "t"}',
    '{"source_node_id": null, "monotonic_seq": 1, "hash": "h", "anchored_at": "t"}',
    '[]',
])
def test_load_rejects_other_keys_and_values(tmp_path, line):
    path = tmp_path / "bad.jsonl"
    path.write_text(line + "\n")
    with pytest.raises(ValueError):
        load_checkpoints(path)


def test_load_skips_an_unfinished_last_line(tmp_path, caplog):
    cps = [_cp(r) for r in _chain(range(1, 3))]
    path = tmp_path / "cp.jsonl"
    FileCheckpointSink(path).publish(cps)
    with open(path, "a") as f:
        f.write('{"source_node_id": "node-1", "monot')
    with caplog.at_level(logging.WARNING, logger="fasten.checkpoints"):
        assert load_checkpoints(path) == cps
    assert "unfinished last line" in caplog.text


def test_load_reads_a_complete_last_line_without_a_newline(tmp_path):
    cps = [_cp(r) for r in _chain(range(1, 3))]
    path = tmp_path / "cp.jsonl"
    path.write_text("\n".join(json.dumps(c.to_dict()) for c in cps))
    assert load_checkpoints(path) == cps


def test_load_rejects_an_unfinished_line_before_the_last(tmp_path):
    cp = json.dumps(_cp(_chain([1])[0]).to_dict())
    path = tmp_path / "cp.jsonl"
    path.write_text('{"source_node_id": "node-1", "monot\n' + cp + "\n")
    with pytest.raises(ValueError):
        load_checkpoints(path)


def test_publish_drops_an_unfinished_last_line_first(tmp_path, caplog):
    first = [_cp(r) for r in _chain(range(1, 3))]
    second = [_cp(_chain([1], node="node-2")[0])]
    path = tmp_path / "cp.jsonl"
    sink = FileCheckpointSink(path)
    sink.publish(first)
    with open(path, "a") as f:
        f.write('{"source_node_id": "node-1", "monot')
    sink.publish(second)
    with caplog.at_level(logging.WARNING, logger="fasten.checkpoints"):
        assert load_checkpoints(path) == first + second
    assert caplog.text == ""


def test_publish_over_a_file_with_only_an_unfinished_line(tmp_path):
    cps = [_cp(_chain([1])[0])]
    path = tmp_path / "cp.jsonl"
    path.write_text('{"source_node_id": "node-1", "monot')
    FileCheckpointSink(path).publish(cps)
    assert load_checkpoints(path) == cps
    assert path.read_text().count("\n") == 1


def test_publish_keeps_a_complete_last_line_without_a_newline(tmp_path):
    first = [_cp(r) for r in _chain(range(1, 3))]
    second = [_cp(_chain([1], node="node-2")[0])]
    path = tmp_path / "cp.jsonl"
    path.write_text("\n".join(json.dumps(c.to_dict()) for c in first))
    FileCheckpointSink(path).publish(second)
    assert load_checkpoints(path) == first + second


class _Server:
    def __init__(self, status: int):
        self.bodies: list = []
        self.auth: list = []
        self.gets = 0
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers["Content-Length"])
                outer.bodies.append((self.headers["Content-Type"],
                                     json.loads(self.rfile.read(n))))
                outer.auth.append(self.headers.get("Authorization"))
                self.send_response(status)
                if 300 <= status < 400:
                    self.send_header("Location", "/elsewhere")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self):
                outer.gets += 1
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/checkpoints"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        if self.thread.is_alive():
            self.httpd.shutdown()
            self.httpd.server_close()
            self.thread.join()


@pytest.fixture
def server(request):
    s = _Server(request.param)
    s.status = request.param
    yield s
    s.close()


@pytest.mark.parametrize("server", [204], indirect=True)
def test_http_sink_posts_a_json_array(server):
    cps = [_cp(r) for r in _chain(range(1, 3))]
    HttpCheckpointSink(server.url, timeout=5).publish(cps)
    assert server.bodies == [("application/json", [c.to_dict() for c in cps])]


@pytest.mark.parametrize("server", [204], indirect=True)
def test_http_sink_sends_userinfo_as_basic_auth(server):
    host = server.url.removeprefix("http://")
    cps = [_cp(_chain([1])[0])]
    HttpCheckpointSink(f"http://user:p%40ss@{host}", timeout=5).publish(cps)
    HttpCheckpointSink(server.url, timeout=5).publish(cps)
    assert server.auth == ["Basic dXNlcjpwQHNz", None]  # user:p@ss
    assert len(server.bodies) == 2


@pytest.mark.parametrize("server", [500], indirect=True)
def test_http_sink_raises_on_an_error_status(server):
    with pytest.raises(OSError):
        HttpCheckpointSink(server.url, timeout=5).publish([_cp(_chain([1])[0])])


@pytest.mark.parametrize("server", [301, 302, 303, 307], indirect=True)
def test_http_sink_fails_on_a_redirect(server):
    with pytest.raises(OSError, match=f"HTTP {server.status}"):
        HttpCheckpointSink(server.url, timeout=5).publish([_cp(_chain([1])[0])])
    assert len(server.bodies) == 1 and server.gets == 0


@pytest.mark.parametrize("server", [500], indirect=True)
def test_http_sink_errors_leave_out_userinfo_and_query(server):
    cps = [_cp(_chain([1])[0])]
    with pytest.raises(OSError) as err:
        HttpCheckpointSink(f"{server.url}?token=tok-456", timeout=5).publish(cps)
    assert str(err.value) == f"checkpoint sink {server.url}: HTTP 500"
    host = server.url.removeprefix("http://")
    with pytest.raises(OSError) as err:
        HttpCheckpointSink(f"http://user:pw-123@{host}?token=tok-456", timeout=5).publish(cps)
    assert str(err.value) == f"checkpoint sink {server.url}: HTTP 500"
    assert err.value.__cause__ is None
    server.close()
    with pytest.raises(OSError) as err:
        HttpCheckpointSink(f"http://user:pw-123@{host}?token=tok-456", timeout=5).publish(cps)
    assert str(err.value).startswith(f"checkpoint sink {server.url}: ")
    assert "pw-123" not in str(err.value) and "tok-456" not in str(err.value)
    with pytest.raises(ValueError) as verr:
        HttpCheckpointSink("ftp://user:pw-123@example.com/x?token=tok-456")
    assert str(verr.value).endswith("ftp://example.com/x")


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
                              checkpoints=[Checkpoint.from_dict(c) for c in case["checkpoints"]],
                              partial=case["partial"])
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
