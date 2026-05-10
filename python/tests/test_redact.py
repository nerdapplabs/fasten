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


def test_init_honours_env_replacement(monkeypatch, mem_store):
    """FASTEN_REDACT_REPLACEMENT applied when init() is called env-only.

    Regression: the prior signature defaulted ``redact_replacement="***"``
    so the truthy default short-circuited the env-var read. Adopters
    setting only the env var saw "***" with no signal that the override
    was ignored.
    """
    monkeypatch.setenv("FASTEN_SERVICE_ID", "svc")
    monkeypatch.setenv("FASTEN_NODE_ID", "node")
    monkeypatch.setenv("FASTEN_REDACT_REPLACEMENT", "<HIDDEN>")
    import fasten
    fasten.init(audit_store=mem_store, audit_store_failure_strategy="raise")
    assert fasten.redactor().redact({"password": "x"}) == {"password": "<HIDDEN>"}


def test_init_explicit_replacement_overrides_env(monkeypatch, mem_store):
    """Explicit kwarg wins over env var (standard precedence)."""
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
    """REVIEW #17: int / tuple keys must not crash re.search.

    Adopters occasionally pass dicts whose keys aren't strings (e.g.
    int-keyed lookup tables placed under detail). Earlier the redactor
    would TypeError on the first non-str key and abort the whole emit.
    """
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


# ── P1-24: value-shape redaction ─────────────────────────────────────────────

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
    # "token_data" contains "token" → key-pattern fires; use neutral key for value-shape test
    assert r.redact({"raw_value": tok}) == {"raw_value": "***GH_TOKEN***"}


def test_cc_luhn_valid_redacted(r):
    # Visa test card — passes Luhn
    assert r.redact({"notes": "4111111111111111"}) == {"notes": "***CC***"}


def test_cc_luhn_invalid_not_redacted(r):
    # Same length but fails Luhn — must NOT be treated as a CC
    assert r.redact({"notes": "4111111111111112"}) == {"notes": "4111111111111112"}


def test_random_order_number_not_redacted(r):
    # 16-digit order number that fails Luhn should not be redacted
    assert r.redact({"order_id": "1234567890123456"}) == {"order_id": "1234567890123456"}


def test_key_pattern_still_wins(r):
    # A field named `api_key` whose VALUE is a JWT — key redactor fires first,
    # value is replaced with *** (not ***JWT***).
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
    # "tokens" contains "token" → key-pattern fires on the whole list; use a neutral key
    out = r.redact({"messages": [jwt, "safe-string"]})
    assert out["messages"][0] == "***JWT***"
    assert out["messages"][1] == "safe-string"


# ── P1-3: adversarial key-name + value-shape tests ───────────────────────────

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
    assert out["stacktrace"] == trace  # safe key → not redacted by key-pattern


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
    # "secret" is in _REDACT_PATTERNS so "sk_live..." key would match; use neutral key
    assert r.redact({"payment": key}) == {"payment": "***STRIPE_KEY***"}


def test_safe_16digit_non_luhn_not_cc(r):
    assert r.redact({"order": "1234567890123456"}) == {"order": "1234567890123456"}
