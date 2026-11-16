package pipeline

import (
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func TestProcessUploadJSONSensitiveContent(t *testing.T) {
	res, err := Process(fileCompUploadReq(t, "contacts.json", `{"contacts":[{"phone":"13800138000"}]}`), Config{
		Enabled: true, Mode: "PROTECT", SensitiveValueRules: fileSensitivePipelineRules(),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, match := range res.Context.CopyMatches() {
		if match.RuleID == "file.sensitive_content" {
			found = true
			if match.Evidence["field"] != "contacts[].phone" || match.Evidence["scope"] != "JSON_DOCUMENT" {
				t.Fatalf("unexpected JSON upload evidence: %+v", match)
			}
			for _, value := range match.Evidence {
				if strings.Contains(value, "13800138000") {
					t.Fatalf("JSON value leaked: %+v", match.Evidence)
				}
			}
		}
	}
	if !found {
		t.Fatalf("structured JSON upload not detected: %+v", res.Context.CopyMatches())
	}
	observations := parser.BuildUploadFileObservations(res.Parsed.MultipartParts)
	if len(observations) != 1 || len(observations[0].SensitiveTypes) != 1 || observations[0].SensitiveTypes[0] != "phone" {
		t.Fatalf("JSON asset labels missing: %+v", observations)
	}
}

func TestProcessResponseJSONSensitiveContent(t *testing.T) {
	ctx := dsctx.New("download-json", dsctx.DefaultParseLimits())
	act, err := ProcessResponse(ctx, ResponseInput{
		Status: 200, ContentType: "application/json", ContentDisposition: `attachment; filename="contacts.json"`,
		Body: []byte(`{"contacts":[{"phone":"13800138000"}]}`), BodySize: 38,
	}, ResponseConfig{Mode: "PROTECT", SensitiveValueRules: fileSensitivePipelineRules()})
	if err != nil {
		t.Fatal(err)
	}
	if act == dsctx.ActionBlock {
		t.Fatalf("structured JSON observation must not block: %+v", ctx.CopyMatches())
	}
	observation := ctx.GetResponse().FileObservation
	if observation == nil || len(observation.SensitiveTypes) != 1 || observation.SensitiveTypes[0] != "phone" {
		t.Fatalf("JSON download labels missing: %+v", observation)
	}
}
