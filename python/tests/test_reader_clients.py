"""`fasten tail`, the TUI and `fasten dump`: reader auth and catalog loading."""
from __future__ import annotations

import textwrap
import urllib.error
import urllib.request

import pytest

from fasten import cli
from fasten.cli import _tail
from fasten.tui import app as tui


class _Resp:
    def __init__(self, body: bytes = b'{"rows": [{"id": "r1"}]}') -> None:
        self._body = body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_Resp":
        return self

    def __exit__(self, *_a: object) -> bool:
        return False


def _reader(monkeypatch, status: int = 200) -> dict:
    """Stand in for the reader: record the Authorization header, answer
    with one row or with an HTTP error."""
    seen: dict = {}

    def urlopen(req, timeout=None):
        seen["auth"] = req.get_header("Authorization")
        if status != 200:
            raise urllib.error.HTTPError(req.full_url, status, "error", None, None)
        return _Resp()

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    return seen


def test_tail_sends_the_token_as_bearer(monkeypatch):
    seen = _reader(monkeypatch)
    rows = _tail._fetch("http://r/logs", "audit", None, None, 10, token="t1")
    assert seen["auth"] == "Bearer t1"
    assert rows == [{"id": "r1"}]


def test_tail_names_the_token_on_401(monkeypatch, capsys):
    _reader(monkeypatch, status=401)
    assert _tail._fetch("http://r/logs", "audit", None, None, 10, token=None) == []
    err = capsys.readouterr().err
    assert "HTTP 401" in err and "FASTEN_READER_TOKEN" in err
    assert "unreachable" not in err


def test_tail_reads_the_token_from_the_env(monkeypatch):
    seen: dict = {}

    def fetch(*_a, token=None, **_k):
        seen["token"] = token
        raise KeyboardInterrupt

    monkeypatch.setenv("FASTEN_READER_TOKEN", "envtok")
    monkeypatch.setattr(_tail, "_fetch", fetch)
    assert _tail.run("http://r/logs", "audit") == 0
    assert seen["token"] == "envtok"


def test_tui_sends_the_token_and_reports_401(monkeypatch):
    monkeypatch.setattr(tui, "_token", "t2")
    monkeypatch.setattr(tui, "_errors", {})
    seen = _reader(monkeypatch, status=401)
    assert tui._fetch("http://r/logs", "audit", None, 5) == []
    assert seen["auth"] == "Bearer t2"
    assert "HTTP 401" in tui._errors["audit"]

    _reader(monkeypatch)
    assert tui._fetch("http://r/logs", "audit", None, 5) == [{"id": "r1"}]
    assert tui._errors == {}


@pytest.fixture
def catalog(tmp_path, monkeypatch):
    """A catalog file, with the registry and yaml state restored after."""
    pytest.importorskip("yaml")
    from fasten import codes_yaml
    from fasten.codes import _registry

    for name in ("_loaded_paths", "_yaml_codes", "_yaml_code_origins"):
        saved = getattr(codes_yaml, name)
        monkeypatch.setattr(codes_yaml, name, type(saved)(saved))
    saved_registry = dict(_registry)
    p = tmp_path / "dumptest.codes.yaml"
    p.write_text(textwrap.dedent("""\
        domain: dumptest
        emitter: dumptest-service
        codes:
          DUMPTEST_DONE:
            category: job
            action: done
            severity: warn
            description: Job finished
    """))
    yield p
    _registry.clear()
    _registry.update(saved_registry)


def test_dump_prints_the_catalog_codes(catalog, capsys):
    assert cli.main(["dump", "--catalog", str(catalog)]) == 0
    assert "DUMPTEST_DONE,dumptest,warn" in capsys.readouterr().out.splitlines()


def test_dump_fails_with_no_codes(monkeypatch, capsys):
    monkeypatch.setattr(cli, "dump_codes", lambda: "")
    assert cli.main(["dump"]) == 1
    assert "--catalog" in capsys.readouterr().err
