package detectors

import (
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func newResponseTextValueContext(id string) *dsctx.RequestContext {
	ctx := dsctx.New(id, dsctx.DefaultParseLimits())
	ctx.Response = &dsctx.ResponseContext{}
	return ctx
}

func TestResponseBodyXMLValuesAndAttributes(t *testing.T) {
	ctx := newResponseTextValueContext("response-xml-values")
	body := []byte(`<?xml version="1.0"?><root><contact phone="13912345678">13800138000</contact></root>`)
	scanner := NewResponseBodyValueScanner(ctx, responsePhoneValueRules(t), dsctx.DefaultParseLimits())
	if reason := scanner.ScanXML(body); reason != "" {
		t.Fatalf("valid XML must be fully inspected: %s", reason)
	}
	matches := ctx.CopyMatches()
	if len(matches) != 2 {
		t.Fatalf("XML text and attribute must both match: %+v", matches)
	}
	assertResponseValueMatch(t, matches[0], "root.contact.@phone", "phone")
	assertResponseValueMatch(t, matches[1], "root.contact", "phone")
	assertNoResponseValuePlaintext(t, ctx, "13800138000", "13912345678")
}

func TestResponseBodyXMLRejectionAndBudgets(t *testing.T) {
	t.Run("DTD", func(t *testing.T) {
		ctx := newResponseTextValueContext("response-xml-dtd")
		scanner := NewResponseBodyValueScanner(ctx, responsePhoneValueRules(t), dsctx.DefaultParseLimits())
		body := []byte(`<!DOCTYPE root [<!ENTITY payload "13800138000">]><root><contact>&payload;</contact></root>`)
		if reason := scanner.ScanXML(body); reason != "DTD_FORBIDDEN" {
			t.Fatalf("DTD reason = %q", reason)
		}
		if ctx.MatchCount() != 0 {
			t.Fatalf("DTD must not be inspected: %+v", ctx.CopyMatches())
		}
	})

	t.Run("invalid UTF8", func(t *testing.T) {
		ctx := newResponseTextValueContext("response-xml-utf8")
		scanner := NewResponseBodyValueScanner(ctx, responsePhoneValueRules(t), dsctx.DefaultParseLimits())
		if reason := scanner.ScanXML([]byte{0xff, '<', 'r', '>'}); reason != "INVALID_UTF8" {
			t.Fatalf("invalid UTF8 reason = %q", reason)
		}
	})

	t.Run("depth", func(t *testing.T) {
		ctx := newResponseTextValueContext("response-xml-depth")
		limits := dsctx.DefaultParseLimits()
		limits.MaxXMLDepth = 1
		scanner := NewResponseBodyValueScanner(ctx, responsePhoneValueRules(t), limits)
		if reason := scanner.ScanXML([]byte(`<root><contact>13800138000</contact></root>`)); reason != "XML_DEPTH_EXCEEDED" {
			t.Fatalf("depth reason = %q", reason)
		}
		if ctx.MatchCount() != 0 {
			t.Fatalf("over-depth value must not be inspected: %+v", ctx.CopyMatches())
		}
	})

	t.Run("field budget", func(t *testing.T) {
		ctx := newResponseTextValueContext("response-xml-fields")
		limits := dsctx.DefaultParseLimits()
		limits.MaxFieldCount = 2
		scanner := NewResponseBodyValueScanner(ctx, responsePhoneValueRules(t), limits)
		if reason := scanner.ScanXML([]byte(`<root><contact>13800138000</contact></root>`)); reason != "FIELD_BUDGET_EXCEEDED" {
			t.Fatalf("field budget reason = %q", reason)
		}
	})

	t.Run("scan budget", func(t *testing.T) {
		ctx := newResponseTextValueContext("response-xml-scans")
		var body strings.Builder
		body.WriteString("<root>")
		for i := 0; i < maxSensitiveValueScans+1; i++ {
			body.WriteString("<v>ordinary</v>")
		}
		body.WriteString("<v>13800138000</v></root>")
		scanner := NewResponseBodyValueScanner(ctx, responsePhoneValueRules(t), dsctx.DefaultParseLimits())
		if reason := scanner.ScanXML([]byte(body.String())); reason != "SCAN_BUDGET_EXCEEDED" {
			t.Fatalf("scan budget reason = %q", reason)
		}
		if ctx.MatchCount() != 0 {
			t.Fatalf("value after scan budget must not match: %+v", ctx.CopyMatches())
		}
	})
}

func TestResponseBodyTextUsesLineLabels(t *testing.T) {
	ctx := newResponseTextValueContext("response-text-lines")
	scanner := NewResponseBodyValueScanner(ctx, responsePhoneValueRules(t), dsctx.DefaultParseLimits())
	if reason := scanner.ScanText([]byte("ordinary\r\n13800138000\n13912345678"), "text."); reason != "" {
		t.Fatalf("text scan reason = %q", reason)
	}
	matches := ctx.CopyMatches()
	if len(matches) != 2 {
		t.Fatalf("line hits = %d, want 2: %+v", len(matches), matches)
	}
	assertResponseValueMatch(t, matches[0], "text.line[2]", "phone")
	assertResponseValueMatch(t, matches[1], "text.line[3]", "phone")
	assertNoResponseValuePlaintext(t, ctx, "13800138000", "13912345678")
}

func TestResponseBodySSEJSONPrefixAndSharedScanner(t *testing.T) {
	ctx := newResponseTextValueContext("response-sse-json")
	scanner := NewResponseBodyValueScanner(ctx, responsePhoneValueRules(t), dsctx.DefaultParseLimits())
	if reason := scanner.ScanJSON([]byte(`{"contact":"13800138000"}`), "sse.event[2].data"); reason != "" {
		t.Fatalf("JSON event scan reason = %q", reason)
	}
	if reason := scanner.ScanText([]byte("13912345678"), "sse.event[3].data."); reason != "" {
		t.Fatalf("text event scan reason = %q", reason)
	}
	matches := ctx.CopyMatches()
	if len(matches) != 2 {
		t.Fatalf("shared scanner hits = %+v", matches)
	}
	assertResponseValueMatch(t, matches[0], "sse.event[2].data.contact", "phone")
	assertResponseValueMatch(t, matches[1], "sse.event[3].data.line[1]", "phone")
	assertNoResponseValuePlaintext(t, ctx, "13800138000", "13912345678")
}

func TestNoteResponseBodyValueUncheckedContract(t *testing.T) {
	ctx := newResponseTextValueContext("response-unchecked")
	NoteResponseBodyValueUnchecked(ctx, "XML", "response_body", "DTD_FORBIDDEN")
	matches := ctx.CopyMatches()
	if len(matches) != 1 {
		t.Fatalf("unchecked detail missing: %+v", matches)
	}
	m := matches[0]
	if m.RuleID != "sensitive.response_body_unchecked" || m.Category != "INFO" || m.ScoreDelta != 0 {
		t.Fatalf("unchecked attributes: %+v", m)
	}
	want := map[string]string{
		"field": "response_body", "format": "XML", "location": "response_body",
		"direction": "RESPONSE", "completion": "partial", "skip_reason": "DTD_FORBIDDEN",
	}
	for key, value := range want {
		if m.Evidence[key] != value {
			t.Fatalf("evidence[%s] = %q, want %q", key, m.Evidence[key], value)
		}
	}
	if !HasResponseBodySensitiveLocation([]SensitiveValueRule{{Locations: []string{"response_body"}}}) ||
		HasResponseBodySensitiveLocation([]SensitiveValueRule{{Locations: []string{"json"}}}) {
		t.Fatal("response_body location detection mismatch")
	}
}
