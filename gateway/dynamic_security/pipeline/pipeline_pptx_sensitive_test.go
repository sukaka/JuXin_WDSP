package pipeline

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func testPipelinePPTX(t *testing.T, text string) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for name, content := range map[string]string{
		"ppt/presentation.xml":  `<p:presentation/>`,
		"ppt/slides/slide1.xml": `<p:sld><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>` + text + `</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>`,
	} {
		part, err := writer.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestProcessUploadPPTXSensitiveContent(t *testing.T) {
	body := testPipelinePPTX(t, "13800138000")
	if len(body) >= 512 {
		t.Fatalf("minimal PPTX must exercise complete-prefix inspection: %d", len(body))
	}
	res, err := Process(fileCompUploadReq(t, "contacts.pptx", string(body)), Config{
		Enabled: true, Mode: "PROTECT", SensitiveValueRules: fileSensitivePipelineRules(),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, match := range res.Context.CopyMatches() {
		if match.RuleID == "file.sensitive_content" {
			found = true
			if match.Evidence["scope"] != "PPTX_SLIDES" || match.Evidence["field"] != "slide1!p1" {
				t.Fatalf("unexpected PPTX evidence: %+v", match)
			}
			for _, value := range match.Evidence {
				if strings.Contains(value, "13800138000") {
					t.Fatalf("PPTX value leaked: %+v", match.Evidence)
				}
			}
		}
	}
	if !found {
		t.Fatalf("PPTX content not detected: %+v", res.Context.CopyMatches())
	}
	observations := parser.BuildUploadFileObservations(res.Parsed.MultipartParts)
	if len(observations) != 1 || len(observations[0].SensitiveTypes) != 1 || observations[0].SensitiveTypes[0] != "phone" {
		t.Fatalf("PPTX asset labels missing: %+v", observations)
	}
}

func TestProcessResponsePPTXSensitiveContent(t *testing.T) {
	ctx := dsctx.New("download-pptx", dsctx.DefaultParseLimits())
	act, err := ProcessResponse(ctx, ResponseInput{
		Status: 200, ContentType: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
		ContentDisposition: `attachment; filename="contacts.pptx"`,
		Body:               testPipelinePPTX(t, "13800138000"), BodySize: 512,
	}, ResponseConfig{Mode: "PROTECT", SensitiveValueRules: fileSensitivePipelineRules()})
	if err != nil {
		t.Fatal(err)
	}
	if act == dsctx.ActionBlock {
		t.Fatalf("PPTX observation must not block: %+v", ctx.CopyMatches())
	}
	observation := ctx.GetResponse().FileObservation
	if observation == nil || len(observation.SensitiveTypes) != 1 || observation.SensitiveTypes[0] != "phone" {
		t.Fatalf("PPTX download labels missing: %+v", observation)
	}
}
