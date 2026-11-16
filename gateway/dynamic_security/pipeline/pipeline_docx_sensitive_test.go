package pipeline

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func testPipelineDOCX(t *testing.T, text string) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for name, content := range map[string]string{
		"word/document.xml":   `<w:document><w:body><w:p><w:r><w:t>` + text + `</w:t></w:r></w:p></w:body></w:document>`,
		"[Content_Types].xml": "<Types/>",
		"_rels/.rels":         "<Relationships/>",
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

func TestProcessUploadDOCXSensitiveContent(t *testing.T) {
	res, err := Process(fileCompUploadReq(t, "contacts.docx", string(testPipelineDOCX(t, "13800138000"))), Config{
		Enabled: true, Mode: "PROTECT", SensitiveValueRules: fileSensitivePipelineRules(),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, match := range res.Context.CopyMatches() {
		if match.RuleID == "file.sensitive_content" {
			found = true
			if match.Evidence["scope"] != "DOCX_MAIN_DOCUMENT" {
				t.Fatalf("unexpected DOCX coverage: %+v", match)
			}
			for _, value := range match.Evidence {
				if strings.Contains(value, "13800138000") {
					t.Fatalf("DOCX value leaked: %+v", match.Evidence)
				}
			}
		}
	}
	if !found {
		t.Fatalf("DOCX content not detected: %+v", res.Context.CopyMatches())
	}
	observations := parser.BuildUploadFileObservations(res.Parsed.MultipartParts)
	if len(observations) != 1 || len(observations[0].SensitiveTypes) != 1 || observations[0].SensitiveTypes[0] != "phone" {
		t.Fatalf("DOCX asset labels missing: %+v", observations)
	}
}

func TestProcessResponseDOCXSensitiveContent(t *testing.T) {
	ctx := dsctx.New("download-docx", dsctx.DefaultParseLimits())
	act, err := ProcessResponse(ctx, ResponseInput{
		Status: 200, ContentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		ContentDisposition: `attachment; filename="contacts.docx"`,
		Body:               testPipelineDOCX(t, "13800138000"), BodySize: 512,
	}, ResponseConfig{Mode: "PROTECT", SensitiveValueRules: fileSensitivePipelineRules()})
	if err != nil {
		t.Fatal(err)
	}
	if act == dsctx.ActionBlock {
		t.Fatalf("DOCX observation must not block: %+v", ctx.CopyMatches())
	}
	observation := ctx.GetResponse().FileObservation
	if observation == nil || len(observation.SensitiveTypes) != 1 || observation.SensitiveTypes[0] != "phone" {
		t.Fatalf("DOCX download labels missing: %+v", observation)
	}
}
