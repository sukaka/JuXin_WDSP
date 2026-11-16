package pipeline

import (
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
)

func TestProcessResponseXMLAndTextSensitiveValues(t *testing.T) {
	for _, tc := range []struct {
		name        string
		contentType string
		body        string
		field       string
	}{
		{name: "XML", contentType: "application/xml", body: `<root><contact>13800138000</contact></root>`, field: "root.contact"},
		{name: "XML suffix", contentType: "application/atom+xml", body: `<feed><phone>13800138000</phone></feed>`, field: "feed.phone"},
		{name: "plain text", contentType: "text/plain; charset=utf-8", body: "ordinary\n13800138000", field: "text.line[2]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := dsctx.New("response-text-value", dsctx.DefaultParseLimits())
			act, err := ProcessResponse(ctx, ResponseInput{
				Status: 200, ContentType: tc.contentType, Body: []byte(tc.body), BodySize: int64(len(tc.body)),
			}, ResponseConfig{Mode: decision.ModeProtect, SensitiveValueRules: responseBodySensitivePipelineRules()})
			if err != nil {
				t.Fatal(err)
			}
			if act != dsctx.ActionObserve {
				t.Fatalf("value observation must not block: %s", act)
			}
			var hits int
			for _, match := range ctx.CopyMatches() {
				if match.RuleID != "sensitive.response_value" {
					continue
				}
				hits++
				if match.Evidence["field"] != tc.field || match.Evidence["location"] != "response_body" {
					t.Fatalf("unexpected value evidence: %+v", match.Evidence)
				}
				for _, value := range match.Evidence {
					if strings.Contains(value, "13800138000") {
						t.Fatalf("plaintext leaked: %+v", match.Evidence)
					}
				}
			}
			if hits != 1 {
				t.Fatalf("hits = %d, want 1: %+v", hits, ctx.CopyMatches())
			}
		})
	}
}

func TestProcessResponseXMLUncheckedReason(t *testing.T) {
	body := []byte(`<!DOCTYPE root><root><contact>13800138000</contact></root>`)
	ctx := dsctx.New("response-xml-dtd", dsctx.DefaultParseLimits())
	act, err := ProcessResponse(ctx, ResponseInput{
		Status: 200, ContentType: "application/xml", Body: body, BodySize: int64(len(body)),
	}, ResponseConfig{Mode: decision.ModeProtect, SensitiveValueRules: responseBodySensitivePipelineRules()})
	if err != nil {
		t.Fatal(err)
	}
	if act == dsctx.ActionBlock {
		t.Fatal("unchecked XML must not block")
	}
	for _, match := range ctx.CopyMatches() {
		if match.RuleID == "sensitive.response_value" {
			t.Fatalf("DTD must not be scanned: %+v", match)
		}
		if match.RuleID == "sensitive.response_body_unchecked" {
			if match.Evidence["completion"] != "partial" || match.Evidence["skip_reason"] != "DTD_FORBIDDEN" || match.Evidence["format"] != "XML" {
				t.Fatalf("bad unchecked evidence: %+v", match.Evidence)
			}
			return
		}
	}
	t.Fatalf("unchecked detail missing: %+v", ctx.CopyMatches())
}

func TestProcessResponsePreservesStreamedSensitiveFields(t *testing.T) {
	ctx := dsctx.New("response-stream-fields", dsctx.DefaultParseLimits())
	ctx.Response = &dsctx.ResponseContext{Streamed: true, SensitiveFields: []dsctx.SensitiveFieldHit{
		{Path: "sse.event[2].data.contact", DataType: "phone"},
	}}
	_, err := ProcessResponse(ctx, ResponseInput{Status: 200, ContentType: "text/event-stream", Streamed: true}, ResponseConfig{
		Mode: decision.ModeProtect, SensitiveValueRules: responseBodySensitivePipelineRules(),
	})
	if err != nil {
		t.Fatal(err)
	}
	rc := ctx.GetResponse()
	if rc == nil || rc.Status != 200 || !rc.Streamed || len(rc.SensitiveFields) != 1 {
		t.Fatalf("stream response fields were not preserved: %+v", rc)
	}
	if rc.SensitiveFields[0].Path != "sse.event[2].data.contact" || rc.SensitiveFields[0].DataType != "phone" {
		t.Fatalf("wrong preserved fields: %+v", rc.SensitiveFields)
	}
}
