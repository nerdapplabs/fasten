"""Redactor: default patterns, deep dicts, lists, extra keys, replacement."""
import sys

import pytest
from fasten.redact import Redactor


@pytest.fixture
def r():
    return Redactor()


def test_api_key_redacted(r):
    assert r.redact({"api_key": "secret"}) == {"api_key": "***"}


def test_password_redacted(r):
    assert r.redact({"password": "hunter2"}) == {"password": "***"}


def test_token_redacted(r):
    assert r.redact({"token": "tok"}) == {"token": "***"}


def test_safe_key_preserved(r):
    assert r.redact({"user_id": "u-42"}) == {"user_id": "u-42"}


def test_case_insensitive(r):
    assert r.redact({"API_KEY": "x"})["API_KEY"] == "***"
    assert r.redact({"Password": "x"})["Password"] == "***"


def test_nested_dict_redacted(r):
    detail = {"outer": {"token": "xyz", "safe": "ok"}}
    result = r.redact(detail)
    assert result["outer"]["token"] == "***"
    assert result["outer"]["safe"] == "ok"


def test_list_of_dicts_redacted(r):
    detail = {"items": [{"api_key": "x"}, {"name": "y"}]}
    result = r.redact(detail)
    assert result["items"][0]["api_key"] == "***"
    assert result["items"][1]["name"] == "y"


def test_extra_keys(r):
    r2 = Redactor(extra_keys=["my_custom_secret"])
    result = r2.redact({"my_custom_secret": "val", "safe": "ok"})
    assert result["my_custom_secret"] == "***"
    assert result["safe"] == "ok"


def test_custom_replacement():
    r2 = Redactor(replacement="<hidden>")
    assert r2.redact({"password": "x"}) == {"password": "<hidden>"}


def test_apikey_no_separator(r):
    assert r.redact({"apikey": "x"})["apikey"] == "***"
    assert r.redact({"api-key": "x"})["api-key"] == "***"


def test_init_honours_env_replacement(monkeypatch, mem_store):
    """FASTEN_REDACT_REPLACEMENT applies when init() gets no redact_replacement."""
    monkeypatch.setenv("FASTEN_SERVICE_ID", "svc")
    monkeypatch.setenv("FASTEN_NODE_ID", "node")
    monkeypatch.setenv("FASTEN_REDACT_REPLACEMENT", "<HIDDEN>")
    import fasten
    fasten.init(audit_store=mem_store, audit_store_failure_strategy="raise")
    assert fasten.redactor().redact({"password": "x"}) == {"password": "<HIDDEN>"}


def test_init_explicit_replacement_overrides_env(monkeypatch, mem_store):
    """An explicit kwarg wins over the env var."""
    monkeypatch.setenv("FASTEN_SERVICE_ID", "svc")
    monkeypatch.setenv("FASTEN_NODE_ID", "node")
    monkeypatch.setenv("FASTEN_REDACT_REPLACEMENT", "<env>")
    import fasten
    fasten.init(
        audit_store=mem_store,
        audit_store_failure_strategy="raise",
        redact_replacement="<kwarg>",
    )
    assert fasten.redactor().redact({"password": "x"}) == {"password": "<kwarg>"}


def test_redact_tolerates_non_string_keys(r):
    """int and tuple keys (e.g. a lookup table under detail) are kept as is."""
    detail = {
        1: "first",
        (2, 3): "tuple-keyed",
        "api_key": "should-redact",
        "nested": {42: "still-fine", "token": "secret"},
    }
    out = r.redact(detail)
    assert out[1] == "first"
    assert out[(2, 3)] == "tuple-keyed"
    assert out["api_key"] == "***"
    assert out["nested"][42] == "still-fine"
    assert out["nested"]["token"] == "***"


def test_structlog_processor_tolerates_non_string_keys():
    """Same guard for the structlog processor path."""
    r2 = Redactor()
    proc = r2.as_structlog_processor()
    event = {1: "ok", "api_key": "leak", "nested": {"password": "x"}}
    out = proc(None, "info", dict(event))
    assert out[1] == "ok"
    assert out["api_key"] == "***"
    assert out["nested"]["password"] == "***"


# Value-shape redaction

def test_jwt_in_value_redacted(r):
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1LTQyIn0.abc123def456ghi789"
    assert r.redact({"notes": jwt}) == {"notes": "***JWT***"}


def test_jwt_in_nested_value_redacted(r):
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1LTQyIn0.abc123def456ghi789"
    out = r.redact({"meta": {"comment": jwt}})
    assert out["meta"]["comment"] == "***JWT***"


def test_pem_private_key_redacted(r):
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
    assert r.redact({"paste": pem}) == {"paste": "***PRIVATE_KEY***"}


def test_ec_private_key_redacted(r):
    pem = "-----BEGIN EC PRIVATE KEY-----\ndata\n-----END EC PRIVATE KEY-----"
    assert r.redact({"key_data": pem}) == {"key_data": "***PRIVATE_KEY***"}


def test_aws_access_key_redacted(r):
    assert r.redact({"meta": "AKIAIOSFODNN7EXAMPLE"}) == {"meta": "***AWS_KEY***"}


def test_aws_asia_key_redacted(r):
    assert r.redact({"meta": "ASIAIOSFODNN7EXAMPLE"}) == {"meta": "***AWS_KEY***"}


def test_gh_token_redacted(r):
    tok = "ghp_" + "A" * 36
    # A key containing "token" would match a key pattern, so use a neutral key.
    assert r.redact({"raw_value": tok}) == {"raw_value": "***GH_TOKEN***"}


def test_cc_luhn_valid_redacted(r):
    # Visa test card, passes Luhn
    assert r.redact({"notes": "4111111111111111"}) == {"notes": "***CC***"}


def test_cc_luhn_invalid_not_redacted(r):
    # Same length but fails Luhn
    assert r.redact({"notes": "4111111111111112"}) == {"notes": "4111111111111112"}


def test_random_order_number_not_redacted(r):
    # 16-digit order number that fails Luhn should not be redacted
    assert r.redact({"order_id": "1234567890123456"}) == {"order_id": "1234567890123456"}


def test_key_pattern_still_wins(r):
    # The key match runs first, so the value becomes *** rather than ***JWT***.
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1LTQyIn0.sig"
    assert r.redact({"api_key": jwt}) == {"api_key": "***"}


def test_extra_value_pattern(r):
    r2 = Redactor(extra_value_patterns=[("MY_SECRET", r"MY_SECRET_[A-Z0-9]{8}", "***MY***")])
    assert r2.redact({"info": "see MY_SECRET_ABCD1234 here"}) == {"info": "***MY***"}


def test_structlog_processor_redacts_jwt_value():
    r2 = Redactor()
    proc = r2.as_structlog_processor()
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1LTQyIn0.abc123def456ghi789"
    out = proc(None, "info", {"event": "test", "comment": jwt})
    assert out["comment"] == "***JWT***"
    assert out["event"] == "test"  # structlog internal not touched


def test_value_redact_list_of_strings(r):
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1LTQyIn0.abc"
    # A key containing "token" would redact the whole list, so use a neutral key.
    out = r.redact({"messages": [jwt, "safe-string"]})
    assert out["messages"][0] == "***JWT***"
    assert out["messages"][1] == "safe-string"


# Key-name and value-shape edge cases

def test_three_level_deep_nesting_redacted(r):
    detail = {"l1": {"l2": {"l3": {"token": "deep-secret", "ok": "visible"}}}}
    out = r.redact(detail)
    assert out["l1"]["l2"]["l3"]["token"] == "***"
    assert out["l1"]["l2"]["l3"]["ok"] == "visible"


def test_authorization_header_redacted(r):
    assert r.redact({"authorization": "Bearer tok-xyz"}) == {"authorization": "***"}


def test_user_password_wrapper_key_redacted(r):
    assert r.redact({"user_password": "hunter2"}) == {"user_password": "***"}


def test_mixed_case_api_key_variants(r):
    assert r.redact({"ApiKey": "x"})["ApiKey"] == "***"
    assert r.redact({"API_KEY": "x"})["API_KEY"] == "***"
    assert r.redact({"api-key": "x"})["api-key"] == "***"


def test_secret_key_substring_in_stacktrace_not_matched(r):
    trace = "RuntimeError: timeout at module.py:42\n  File 'web.py' line 7"
    out = r.redact({"stacktrace": trace})
    assert out["stacktrace"] == trace


def test_stripe_live_key_redacted(r):
    key = "sk_live_" + "A" * 24
    assert r.redact({"payment_ref": key}) == {"payment_ref": "***STRIPE_KEY***"}


def test_openai_key_redacted(r):
    key = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"
    assert r.redact({"llm_ref": key}) == {"llm_ref": "***OPENAI_KEY***"}


def test_openai_org_key_redacted(r):
    key = "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklm"
    assert r.redact({"llm_ref": key}) == {"llm_ref": "***OPENAI_KEY***"}


def test_stripe_key_pattern_wins_if_key_also_matches(r):
    key = "sk_live_" + "B" * 24
    # A key such as "secret" would match a key pattern first, so use a neutral key.
    assert r.redact({"payment": key}) == {"payment": "***STRIPE_KEY***"}


def test_safe_16digit_non_luhn_not_cc(r):
    assert r.redact({"order": "1234567890123456"}) == {"order": "1234567890123456"}


def test_with_extra_keys_keeps_base_rules():
    base = Redactor(replacement="[x]",
                    extra_value_patterns=[("my", r"MY_SECRET_\w+", "***MY***")])
    r2 = base.with_extra_keys(["ssn"])
    assert r2.redact({"ssn": "1", "api_key": "k", "batch": 7}) == {
        "ssn": "[x]", "api_key": "[x]", "batch": 7}
    assert r2.redact({"info": "MY_SECRET_ABCD"}) == {"info": "***MY***"}
    assert base.with_extra_keys(None) is base


def test_structlog_event_survives_an_oversize_payload():
    proc = Redactor(extra_keys=["big"]).as_structlog_processor()
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1LTQyIn0.abc123def456ghi789"
    out = proc(None, "info", {"event": "big_event", "blob": "x" * 70000})
    assert out["event"] == "big_event" and out["_truncated"] is True
    assert "blob" not in out
    out = proc(None, "info", {"event": f"bearer {jwt}"})
    assert out["event"] == "***JWT***"


# ---- libfasten_core can't be loaded ----

@pytest.fixture
def no_core(monkeypatch):
    from fasten import core_ffi, redact

    def _no_core(*_a, **_k):
        raise OSError("libfasten_core not found")

    monkeypatch.setattr(core_ffi, "get_lib", _no_core)
    monkeypatch.setattr(redact, "_warned_no_core", False)


@pytest.mark.parametrize("redactor", [Redactor(), Redactor(extra_keys=["email"])],
                         ids=["default", "extra-keys"])
@pytest.mark.parametrize("value", [{"note": "hello"}, ["hello"], "hello", {1: "hello"}],
                         ids=["dict", "list", "str", "non-string-key"])
def test_redact_raises_without_the_core(no_core, redactor, value):
    """It used to return the unredactable marker, as it does for bad input,
    so a missing library looked like a redaction."""
    with pytest.raises(OSError, match="libfasten_core not found"):
        redactor.redact(value)


def test_structlog_processor_warns_once_without_the_core(no_core, capsys):
    """A log call must not raise, so the values are dropped and stderr says
    why, once."""
    proc = Redactor().as_structlog_processor()
    for _ in range(2):
        out = proc(None, "info", {"event": "login", "password": "hunter2", "level": "info"})
        assert out["event"] == "<unredactable>"
        assert out["_redact_failed"] is True
        assert out["level"] == "info"
        assert "hunter2" not in str(out)
    err = capsys.readouterr().err
    assert err.count("libfasten_core not found") == 1
    assert "<unredactable>" in err


def test_bad_input_is_still_the_marker_not_an_error(r):
    deep: dict = {}
    cur = deep
    for _ in range(200):
        cur["k"] = {}
        cur = cur["k"]
    assert r.redact(deep) == {"_redact_failed": True, "_summary": "<unredactable>"}


def test_log_redaction_does_not_raise_without_stderr(no_core, monkeypatch):
    """sys.stderr is None under pythonw and some service managers."""
    monkeypatch.setattr(sys, "stderr", None)
    out = Redactor()._redact_for_log({"password": "hunter2"})
    assert out == {"_redact_failed": True, "_summary": "<unredactable>"}


def test_stdout_transport_log_rows_do_not_raise_without_the_core(no_core, capsys):
    from fasten.transport.stdout import StdoutTransport

    transport = StdoutTransport(service_id="svc")
    transport.push_syslog({"event": "login", "password": "hunter2"})
    transport.write_api({"path": "/login", "password": "hunter2"})
    captured = capsys.readouterr()
    assert "hunter2" not in captured.out
    assert "_redact_failed" in captured.out
    assert captured.err.count("libfasten_core not found") == 1


def test_bad_value_pattern_is_refused_when_configured():
    """A pattern the core cannot compile is refused where it is configured,
    naming it, instead of turning every detail into the unredactable marker."""
    with pytest.raises(ValueError, match=r"extra_value_redact_patterns: .*\(\["):
        Redactor(extra_value_patterns=[("ok", r"OK_\d+", "X"), ("bad", "([", "Y")])


def test_rejected_reinit_keeps_the_running_config():
    """A bad pattern on re-init raises before anything changes, so the
    engine keeps the redactor it had."""
    from fasten.engine import Engine
    e = Engine()
    e.init(service_id="svc", node_id="n1", extra_redact_keys=["field_x"])
    try:
        before = e._redactor
        with pytest.raises(ValueError):
            e.init(service_id="svc", node_id="n1",
                   extra_value_redact_patterns=[("bad", "([", "Y")])
        assert e._redactor is before
        assert before.redact({"field_x": "v"}) == {"field_x": "***"}
    finally:
        e.close()


def test_bad_value_pattern_is_refused_before_a_dsn_store_opens(tmp_path, monkeypatch):
    """init_config opens DSN stores; a pattern refused after that would leave
    a connection nothing closes. It is checked first, so no store is opened."""
    from fasten.engine import Engine
    db = tmp_path / "audit.db"
    monkeypatch.setenv("FASTEN_AUDIT_DSN", str(db))
    with pytest.raises(ValueError, match="extra_value_redact_patterns"):
        Engine().init_config(service_id="svc", node_id="n1",
                             extra_value_redact_patterns=[("bad", "([", "Y")])
    assert not db.exists()


# Values json.dumps cannot encode as they are

def test_custom_value_pattern_applies_under_a_tuple_key():
    r2 = Redactor(extra_value_patterns=[("acct", r"acct-\d+", "[acct]")])
    out = r2.redact({(1, 2): "acct-1234", "note": "see acct-99"})
    # A match replaces the whole value, as on the plain JSON path.
    assert out == {(1, 2): "[acct]", "note": "[acct]"}


def test_custom_replacement_applies_under_an_int_key():
    r2 = Redactor(replacement="<x>")
    out = r2.redact({1: {"password": "hunter2"}, "api_key": "k"})
    assert out[1] == {"password": "<x>"}
    assert out["api_key"] == "<x>"


def test_datetime_value_is_converted_and_redacted(r):
    import datetime as dt
    when = dt.datetime(2026, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc)
    out = r.redact({"at": when, "password": when})
    assert out == {"at": str(when), "password": "***"}


def test_value_with_a_secret_in_its_str_is_redacted(r):
    class Note:
        def __str__(self) -> str:
            return "card 4111111111111111"

    out = r.redact({"note": Note(), 7: Note()})
    assert out == {"note": "***CC***", 7: "***CC***"}


def test_size_cap_applies_under_a_tuple_key(monkeypatch, r):
    monkeypatch.setenv("FASTEN_MAX_DETAIL_BYTES", "64")
    out = r.redact({(1, 2): "x" * 200})
    assert out["_truncated"] is True


def test_circular_value_becomes_the_unredactable_marker(r):
    loop: dict = {}
    loop["self"] = loop
    assert r.redact(loop) == {"_redact_failed": True, "_summary": "<unredactable>"}


def test_log_field_with_a_datetime_is_written(initialized):
    import datetime as dt
    import fasten
    fasten.log.info("tick", at=dt.datetime(2026, 1, 2, tzinfo=dt.timezone.utc), token="t")
    rows = [r for r in fasten.transport().query_syslog(limit=100) if r.get("event") == "tick"]
    assert len(rows) == 1
    assert rows[0]["token"] == "***"
    assert rows[0]["at"].startswith("2026-01-02")


class _StrFails:
    def __str__(self) -> str:
        raise RuntimeError("no str")


def test_value_whose_str_raises_does_not_raise(r):
    assert r.redact({1: "ok", "password": _StrFails()}) == {1: "ok", "password": "***"}
    assert r.redact({"note": _StrFails()}) == {"note": "<str failed>"}


def test_very_deep_nesting_becomes_the_unredactable_marker(r):
    deep: dict = {}
    cur = deep
    for _ in range(5000):
        cur["a"] = {}
        cur = cur["a"]
    assert r.redact(deep) == {"_redact_failed": True, "_summary": "<unredactable>"}
