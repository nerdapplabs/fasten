"""fasten doctor CLI output."""
import pytest

from fasten.cli import _doctor


@pytest.fixture
def doctor_env(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FASTEN_SERVICE_ID", "svc")
    monkeypatch.setenv("FASTEN_NODE_ID", "node")
    monkeypatch.delenv("FASTEN_AUDIT_DSN", raising=False)
    monkeypatch.delenv("FASTEN_API_DSN", raising=False)


def _run(capsys):
    _doctor.run(as_json=False)
    _doctor.run(as_json=True)
    return capsys.readouterr().out


@pytest.mark.parametrize("dsn", [
    "postgresql://app:s3cret@127.0.0.1:1/audit",
    "postgresql://app:s%40cret@127.0.0.1:1/audit",
    "postgresql://app:s3cret@h1:1,h2:2/audit?sslpassword=s3cret",
    "postgresql://app:s3#cret@127.0.0.1:1/audit",
    "postgresql://app:s3@cret@127.0.0.1:1/audit",
])
def test_postgres_dsn_password_is_never_printed(doctor_env, monkeypatch, capsys, tmp_path, dsn):
    monkeypatch.setenv("FASTEN_AUDIT_DSN", dsn)
    monkeypatch.setenv("FASTEN_API_DSN", dsn)
    out = _run(capsys)
    assert not any(p in out for p in ("s3cret", "s@cret", "s3#cret", "cret@"))
    assert "postgres" in out
    assert list(tmp_path.iterdir()) == []  # a postgres DSN never creates a SQLite file


def test_uppercase_scheme_is_described_as_init_opens_it(doctor_env, monkeypatch, capsys):
    monkeypatch.setenv("FASTEN_AUDIT_DSN", "POSTGRES://app:s3cret@h")
    out = _run(capsys)
    assert "sqlite (path hidden" in out and "s3cret" not in out


def test_sqlite_path_with_credentials_is_not_printed(doctor_env, monkeypatch, capsys):
    monkeypatch.setenv("FASTEN_AUDIT_DSN", "Postgresql://app:ab/cdEFGH@db")
    out = _run(capsys)
    assert "cdEFGH" not in out and "sqlite (path hidden" in out


def test_api_dsn_uppercase_scheme_is_postgres(doctor_env, monkeypatch, capsys):
    monkeypatch.setenv("FASTEN_API_DSN", "POSTGRES://app:s3cret@127.0.0.1:1/api")
    out = _run(capsys)
    assert "api_dsn       postgres" in out and "s3cret" not in out


def test_sqlite_dsn_shows_its_path(doctor_env, monkeypatch, capsys):
    monkeypatch.setenv("FASTEN_AUDIT_DSN", "sqlite:///./audit.db")
    out = _run(capsys)
    assert "sqlite /./audit.db (connected" in out


def test_error_hides_details_that_contain_the_password(doctor_env, monkeypatch, capsys):
    dsn = "postgresql://app:s3cret@db"
    monkeypatch.setenv("FASTEN_AUDIT_DSN", dsn)
    monkeypatch.setattr("fasten.engine._store_from_dsn",
                        lambda d: (_ for _ in ()).throw(ValueError(f"bad dsn {d!r}")))
    out = _run(capsys)
    assert "s3cret" not in out
    assert "ValueError (details hidden" in out


@pytest.mark.parametrize("dsn, shown", [
    ("mysql://app:ab\\cdEFGH@127.0.0.1:1/db", "ab\\\\cdEFGH"),
    ("postgresql://db/a?password=s3cret%20PW", "s3cret+PW"),
])
def test_error_hides_escaped_and_query_passwords(doctor_env, monkeypatch, capsys, dsn, shown):
    monkeypatch.setenv("FASTEN_AUDIT_DSN", dsn)
    monkeypatch.setattr("fasten.engine._store_from_dsn",
                        lambda d: (_ for _ in ()).throw(ValueError(f"bad {shown}")))
    out = _run(capsys)
    assert "cdEFGH" not in out and "s3cret" not in out


def test_error_keeps_details_without_the_password(doctor_env, monkeypatch, capsys):
    monkeypatch.setenv("FASTEN_AUDIT_DSN", "postgresql://app:s3cret@db/audit")
    monkeypatch.setattr("fasten.engine._store_from_dsn",
                        lambda d: (_ for _ in ()).throw(OSError("connection refused")))
    out = _run(capsys)
    assert "OSError: connection refused" in out
