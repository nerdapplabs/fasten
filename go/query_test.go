package fasten

import (
	"reflect"
	"testing"
)

// NL / smart-box → structured chips (§3.7, §6.3). Parity with the Python
// test_query_translate.py contract.

func TestTranslate_StructuredFieldChip(t *testing.T) {
	c := TranslateQuery("target:r-901")
	if !reflect.DeepEqual(c.Filters, map[string]string{"target": "r-901"}) {
		t.Errorf("filters=%v", c.Filters)
	}
	if c.RequestID != "" || c.Q != "" {
		t.Errorf("expected only a filter, got %+v", c)
	}
}

func TestTranslate_ComposedFilters(t *testing.T) {
	c := TranslateQuery("level:error status:502 method:POST")
	want := map[string]string{"level": "error", "status": "502", "method": "POST"}
	if !reflect.DeepEqual(c.Filters, want) {
		t.Errorf("filters=%v, want %v", c.Filters, want)
	}
}

func TestTranslate_QuotedBecomesQ(t *testing.T) {
	c := TranslateQuery(`"connection reset by peer"`)
	if c.Q != "connection reset by peer" {
		t.Errorf("q=%q", c.Q)
	}
	if len(c.Filters) != 0 || c.RequestID != "" {
		t.Errorf("expected only q, got %+v", c)
	}
}

func TestTranslate_BareHexIsRequestID(t *testing.T) {
	c := TranslateQuery("3a7b1c9d0e2f")
	if c.RequestID != "3a7b1c9d0e2f" || c.Q != "" {
		t.Errorf("got %+v", c)
	}
}

func TestTranslate_SentinelIsRequestID(t *testing.T) {
	c := TranslateQuery("boot-auth-svc-1a2b3c4d5e6f")
	if c.RequestID != "boot-auth-svc-1a2b3c4d5e6f" {
		t.Errorf("got %+v", c)
	}
}

func TestTranslate_ExplicitRequestIDField(t *testing.T) {
	c := TranslateQuery("request_id:abc123def456")
	if c.RequestID != "abc123def456" || len(c.Filters) != 0 {
		t.Errorf("got %+v", c)
	}
}

func TestTranslate_UnknownFieldIsSearchText(t *testing.T) {
	c := TranslateQuery("colour:blue") // no such filter — must not fabricate one
	if len(c.Filters) != 0 || c.Q != "colour:blue" {
		t.Errorf("got %+v", c)
	}
}

func TestTranslate_AskPrefixStripped(t *testing.T) {
	c := TranslateQuery("ask: target:r-901 refund failed")
	if !reflect.DeepEqual(c.Filters, map[string]string{"target": "r-901"}) || c.Q != "refund failed" {
		t.Errorf("got %+v", c)
	}
}

func TestTranslate_MixedFieldAndFreeText(t *testing.T) {
	c := TranslateQuery(`status:502 "gateway timeout"`)
	if !reflect.DeepEqual(c.Filters, map[string]string{"status": "502"}) || c.Q != "gateway timeout" {
		t.Errorf("got %+v", c)
	}
}

func TestTranslate_SatisfiesTranslatorInterface(t *testing.T) {
	var _ Translator = RuleTranslator{}
}
