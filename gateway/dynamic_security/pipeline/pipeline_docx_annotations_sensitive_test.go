package pipeline

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func testPipelineDOCXComment(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for name, content := range map[string]string{
		"word/document.xml": `<w:document><w:body/></w:document>`,
		"word/comments.xml": `<w:comments><w:comment><w:p><w:r><w:t>13800138000</w:t></w:r></w:p></w:comment></w:comments>`,
	} {
		part, err := writer.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(part, content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestProcessUploadDOCXCommentSensitiveContent(t *testing.T) {
	body := testPipelineDOCXComment(t)
	if len(body) >= 512 {
		t.Fatalf("small DOCX comment fixture must fit the upload prefix: %d", len(body))
	}
	res, err := Process(fileCompUploadReq(t, "review.docx", string(body)), Config{Enabled: true, Mode: "PROTECT", SensitiveValueRules: fileSensitivePipelineRules()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	matches := res.Context.CopyMatches()
	if len(matches) != 1 || matches[0].Evidence["scope"] != "DOCX_ANNOTATIONS" || matches[0].Evidence["source_part"] != "word/comments.xml" {
		t.Fatalf("unexpected DOCX comment evidence: %+v", matches)
	}
	for _, value := range matches[0].Evidence {
		if strings.Contains(value, "13800138000") {
			t.Fatalf("DOCX comment value leaked: %+v", matches[0].Evidence)
		}
	}
	observations := parser.BuildUploadFileObservations(res.Parsed.MultipartParts)
	if len(observations) != 1 || len(observations[0].SensitiveTypes) != 1 || observations[0].SensitiveTypes[0] != "phone" {
		t.Fatalf("DOCX comment upload labels missing: %+v", observations)
	}
}

func TestProcessResponseDOCXCommentSensitiveContent(t *testing.T) {
	ctx := dsctx.New("download-docx-comment", dsctx.DefaultParseLimits())
	act, err := ProcessResponse(ctx, ResponseInput{
		Status: 200, ContentType: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		ContentDisposition: `attachment; filename="review.docx"`,
		Body:               testPipelineDOCXComment(t), BodySize: 512,
	}, ResponseConfig{Mode: "PROTECT", SensitiveValueRules: fileSensitivePipelineRules()})
	if err != nil {
		t.Fatal(err)
	}
	if act == dsctx.ActionBlock {
		t.Fatalf("DOCX comment observation must not block: %+v", ctx.CopyMatches())
	}
	observation := ctx.GetResponse().FileObservation
	if observation == nil || len(observation.SensitiveTypes) != 1 || observation.SensitiveTypes[0] != "phone" {
		t.Fatalf("DOCX comment download labels missing: %+v", observation)
	}
}
