package pipeline

import (
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func fileSensitivePipelineRules() []detectors.SensitiveValueRule {
	return []detectors.SensitiveValueRule{{DataType: "phone", Regex: `^1[3-9]\d{9}$`, Locations: []string{"file"}, Level: "SENSITIVE"}}
}

func TestProcessUploadFileSensitiveContent(t *testing.T) {
	res, err := Process(fileCompUploadReq(t, "contacts.csv", "name,phone\nAlex,13800138000\n"), Config{
		Enabled: true, Mode: "PROTECT", SensitiveValueRules: fileSensitivePipelineRules(),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.FinalAction == dsctx.ActionBlock {
		t.Fatalf("sensitive content observation must not block: %+v", res.Context.CopyMatches())
	}
	found := false
	for _, match := range res.Context.CopyMatches() {
		if match.RuleID == "file.sensitive_content" {
			found = true
			if match.Evidence["data_type"] != "phone" || match.Evidence["direction"] != "UPLOAD" {
				t.Fatalf("unexpected evidence: %+v", match)
			}
			for _, value := range match.Evidence {
				if strings.Contains(value, "13800138000") {
					t.Fatalf("phone number leaked: %+v", match.Evidence)
				}
			}
		}
	}
	if !found {
		t.Fatalf("sensitive file content not detected: %+v", res.Context.CopyMatches())
	}
	observations := parser.BuildUploadFileObservations(res.Parsed.MultipartParts)
	if len(observations) != 1 || len(observations[0].SensitiveTypes) != 1 || observations[0].SensitiveTypes[0] != "phone" {
		t.Fatalf("file asset types missing: %+v", observations)
	}
}

func TestProcessResponseFileSensitiveContent(t *testing.T) {
	ctx := dsctx.New("download-sensitive", dsctx.DefaultParseLimits())
	act, err := ProcessResponse(ctx, ResponseInput{
		Status: 200, ContentType: "text/csv", ContentDisposition: `attachment; filename="contacts.csv"`,
		Body: []byte("name,phone\nAlex,13800138000\n"), BodySize: 32,
	}, ResponseConfig{Mode: "PROTECT", SensitiveValueRules: fileSensitivePipelineRules()})
	if err != nil {
		t.Fatal(err)
	}
	if act == dsctx.ActionBlock {
		t.Fatalf("sensitive content observation must not block: %+v", ctx.CopyMatches())
	}
	observation := ctx.GetResponse().FileObservation
	if observation == nil || len(observation.SensitiveTypes) != 1 || observation.SensitiveTypes[0] != "phone" {
		t.Fatalf("download asset types missing: %+v", observation)
	}
	found := false
	for _, match := range ctx.CopyMatches() {
		if match.RuleID == "file.sensitive_content" {
			found = true
			for _, value := range match.Evidence {
				if strings.Contains(value, "13800138000") {
					t.Fatalf("phone number leaked: %+v", match.Evidence)
				}
			}
		}
	}
	if !found {
		t.Fatalf("download sensitive content not detected: %+v", ctx.CopyMatches())
	}
}
