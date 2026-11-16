package pipeline

import (
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func TestProcessUploadXMLSensitiveContent(t *testing.T) {
	res, err := Process(fileCompUploadReq(t, "contacts.xml", `<contacts><contact><phone>13800138000</phone></contact></contacts>`), Config{
		Enabled: true, Mode: "PROTECT", SensitiveValueRules: fileSensitivePipelineRules(),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, match := range res.Context.CopyMatches() {
		if match.RuleID == "file.sensitive_content" {
			found = true
			if match.Evidence["field"] != "contacts.contact.phone" || match.Evidence["scope"] != "XML_DOCUMENT" {
				t.Fatalf("unexpected XML upload evidence: %+v", match)
			}
			for _, value := range match.Evidence {
				if strings.Contains(value, "13800138000") {
					t.Fatalf("XML value leaked: %+v", match.Evidence)
				}
			}
		}
	}
	if !found {
		t.Fatalf("structured XML upload not detected: %+v", res.Context.CopyMatches())
	}
	observations := parser.BuildUploadFileObservations(res.Parsed.MultipartParts)
	if len(observations) != 1 || len(observations[0].SensitiveTypes) != 1 || observations[0].SensitiveTypes[0] != "phone" {
		t.Fatalf("XML asset labels missing: %+v", observations)
	}
}

func TestProcessResponseXMLSensitiveContent(t *testing.T) {
	ctx := dsctx.New("download-xml", dsctx.DefaultParseLimits())
	act, err := ProcessResponse(ctx, ResponseInput{
		Status: 200, ContentType: "application/xml", ContentDisposition: `attachment; filename="contacts.xml"`,
		Body: []byte(`<contacts><contact><phone>13800138000</phone></contact></contacts>`), BodySize: 64,
	}, ResponseConfig{Mode: "PROTECT", SensitiveValueRules: fileSensitivePipelineRules()})
	if err != nil {
		t.Fatal(err)
	}
	if act == dsctx.ActionBlock {
		t.Fatalf("structured XML observation must not block: %+v", ctx.CopyMatches())
	}
	observation := ctx.GetResponse().FileObservation
	if observation == nil || len(observation.SensitiveTypes) != 1 || observation.SensitiveTypes[0] != "phone" {
		t.Fatalf("XML download labels missing: %+v", observation)
	}
}
