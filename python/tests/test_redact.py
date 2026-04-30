"""Redactor: default patterns, deep dicts, lists, extra keys, replacement."""
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
