"""Chain checkpoints (spec chain-replication.md §9).

A checkpoint records a node's latest sealed row: its seq and hash. Published
somewhere the store's operator cannot rewrite, it lets ``verify_chain`` detect
a chain cut short at the end, or re-sealed from genesis:

    from fasten.checkpoints import FileCheckpointSink, load_checkpoints, publish_checkpoints
    publish_checkpoints(store, FileCheckpointSink("/mnt/worm/checkpoints.jsonl"))
    ...
    verify_chain(rows, checkpoints=load_checkpoints("/mnt/worm/checkpoints.jsonl"))

``rows`` there must be the whole chain; pass ``partial=True`` to verify a page
or one node.
"""
from __future__ import annotations

import dataclasses
import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import TYPE_CHECKING, Any, Protocol

from .canonical_ts import canonical_now

if TYPE_CHECKING:
    from .attrs import AuditRow

_log = logging.getLogger(__name__)
_FIELDS = frozenset(("source_node_id", "monotonic_seq", "hash", "anchored_at"))

__all__ = [
    "Checkpoint",
    "CheckpointSink",
    "CheckpointStore",
    "FileCheckpointSink",
    "HttpCheckpointSink",
    "load_checkpoints",
    "publish_checkpoints",
    "take_checkpoints",
]


@dataclasses.dataclass(frozen=True)
class Checkpoint:
    """A node's latest sealed row at ``anchored_at`` (canonical UTC time)."""
    source_node_id: str
    monotonic_seq: int
    hash: str
    anchored_at: str

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Checkpoint":
        if not isinstance(d, dict) or set(d) != _FIELDS:
            raise ValueError(f"not a checkpoint: {d!r}")
        node, seq, h, at = (d[k] for k in
                            ("source_node_id", "monotonic_seq", "hash", "anchored_at"))
        if (not isinstance(node, str) or not isinstance(h, str) or not isinstance(at, str)
                or not isinstance(seq, int) or isinstance(seq, bool)):
            raise ValueError(f"not a checkpoint: {d!r}")
        return cls(source_node_id=node, monotonic_seq=seq, hash=h, anchored_at=at)


class CheckpointSink(Protocol):
    """Where checkpoints are published."""

    def publish(self, checkpoints: list[Checkpoint]) -> None: ...


class FileCheckpointSink:
    """Appends one JSON line per checkpoint to ``path`` and fsyncs it."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = path

    def publish(self, checkpoints: list[Checkpoint]) -> None:
        if not checkpoints:
            return
        lines = "".join(json.dumps(cp.to_dict(), sort_keys=True) + "\n" for cp in checkpoints)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(lines)
            f.flush()
            os.fsync(f.fileno())


def _redact_url(url: str) -> str:
    """``url`` as scheme://host[:port]/path, for error messages: no userinfo,
    query or fragment."""
    parts = urllib.parse.urlsplit(url)
    return f"{parts.scheme}://{parts.netloc.rpartition('@')[2]}{parts.path}"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # urllib would follow a 301-303 on POST as a GET without the body.
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class HttpCheckpointSink:
    """POSTs the checkpoints as one JSON array to ``url``. Raises OSError
    unless the response is 2xx; redirects are not followed. Errors name the
    url without userinfo or query."""

    def __init__(self, url: str, timeout: float = 10.0) -> None:
        if not url.startswith(("http://", "https://")):
            raise ValueError(f"checkpoint sink url must be http or https: {_redact_url(url)}")
        self.url = url
        self.timeout = timeout
        self._opener = urllib.request.build_opener(_NoRedirect)

    def publish(self, checkpoints: list[Checkpoint]) -> None:
        if not checkpoints:
            return
        body = json.dumps([cp.to_dict() for cp in checkpoints]).encode()
        req = urllib.request.Request(
            self.url, data=body, method="POST",
            headers={"Content-Type": "application/json"},
        )
        where = _redact_url(self.url)
        # The errors are raised from None: HTTPError carries the full url.
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                status = resp.status
        except urllib.error.HTTPError as e:
            e.close()
            raise OSError(f"checkpoint sink {where}: HTTP {e.code}") from None
        except urllib.error.URLError as e:
            raise OSError(f"checkpoint sink {where}: {e.reason}") from None
        if not 200 <= status < 300:
            raise OSError(f"checkpoint sink {where}: HTTP {status}")


class CheckpointStore(Protocol):
    """What take_checkpoints reads: each node's sealed row with the highest
    monotonic_seq, by node id. SQLiteStore and PostgresStore implement it."""

    def chain_tips(self) -> "list[AuditRow]": ...


def take_checkpoints(store: CheckpointStore) -> list[Checkpoint]:
    """One checkpoint per node in ``store`` with a sealed row, by node id.
    ``store.chain_tips()`` (SQLiteStore, PostgresStore) gives each node's
    latest sealed row."""
    now = canonical_now()
    out: list[Checkpoint] = []
    for tip in store.chain_tips():
        if out and out[-1].source_node_id == tip.source_node_id:
            continue  # two rows at one seq; verify_chain reports that
        out.append(Checkpoint(source_node_id=tip.source_node_id,
                              monotonic_seq=tip.monotonic_seq, hash=tip.hash, anchored_at=now))
    return out


def publish_checkpoints(store: CheckpointStore, sink: CheckpointSink) -> list[Checkpoint]:
    """Take checkpoints of ``store``, publish them to ``sink`` and return them."""
    checkpoints = take_checkpoints(store)
    sink.publish(checkpoints)
    return checkpoints


def load_checkpoints(path: str | os.PathLike[str]) -> list[Checkpoint]:
    """Read back a file written by FileCheckpointSink. Blank lines are skipped.

    A line that is not a checkpoint raises ValueError, except an unfinished
    last line (no trailing newline, not valid JSON), as a crash mid-append
    leaves it: that one is skipped with a warning on the ``fasten.checkpoints``
    logger. Go returns ErrPartialLastLine for it."""
    with open(path, encoding="utf-8") as f:
        lines = f.read().split("\n")
    # The text after the last newline; empty when the file ends with one.
    last = lines.pop()
    out = [Checkpoint.from_dict(json.loads(line)) for line in lines if line.strip()]
    if last.strip():
        try:
            d = json.loads(last)
        except json.JSONDecodeError:
            _log.warning("%s: skipped an unfinished last line", path)
            return out
        out.append(Checkpoint.from_dict(d))
    return out
