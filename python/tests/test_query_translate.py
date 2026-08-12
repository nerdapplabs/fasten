"""NL / smart-box → structured chips (§3.7, §6.3).

The translator maps query text to the three reader primitives — structured
filters, a correlation request_id, and the bounded q= — and never invents a
filter the store doesn't support.
"""
from fasten.query import Chips, RuleTranslator, Translator, translate


def test_structured_field_chip():
    c = translate("target:r-901")
    assert c.filters == {"target": "r-901"}
    assert c.request_id is None and c.q is None


def test_composed_structured_filters():
    c = translate("level:error status:502 method:POST")
    assert c.filters == {"level": "error", "status": "502", "method": "POST"}


def test_quoted_text_becomes_q():
    c = translate('"connection reset by peer"')
    assert c.q == "connection reset by peer"
    assert c.filters == {} and c.request_id is None


def test_bare_hex_is_correlation_id():
    c = translate("3a7b1c9d0e2f")  # 12 hex → request_id pivot
    assert c.request_id == "3a7b1c9d0e2f"
    assert c.q is None


def test_sentinel_id_is_correlation_id():
    c = translate("boot-auth-svc-1a2b3c4d5e6f")
    assert c.request_id == "boot-auth-svc-1a2b3c4d5e6f"


def test_explicit_request_id_field():
    c = translate("request_id:abc123def456")
    assert c.request_id == "abc123def456"
    assert c.filters == {}


def test_unknown_field_is_search_text_not_a_filter():
    # The store has no 'colour' filter — must not fabricate one.
    c = translate("colour:blue")
    assert c.filters == {}
    assert c.q == "colour:blue"


def test_ask_prefix_stripped_and_parsed():
    c = translate("ask: target:r-901 refund failed")
    assert c.filters == {"target": "r-901"}
    assert c.q == "refund failed"  # bare words fall through to bounded search


def test_mixed_field_and_free_text():
    c = translate('status:502 "gateway timeout"')
    assert c.filters == {"status": "502"}
    assert c.q == "gateway timeout"


def test_default_is_a_translator_protocol_impl():
    assert isinstance(RuleTranslator(), Translator)


def test_chips_defaults_are_independent():
    a = Chips()
    a.filters["x"] = "1"
    b = Chips()
    assert b.filters == {}  # no shared mutable default
