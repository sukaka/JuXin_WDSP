package pipeline

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func testPipelineXLSX(t *testing.T, value string) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for name, content := range map[string]string{
		"xl/workbook.xml":          `<workbook><sheets><sheet name="C" sheetId="1" r:id="rId1"/></sheets></workbook>`,
		"xl/worksheets/sheet1.xml": `<worksheet><c r="A1" t="inlineStr"><is><t>` + value + `</t></is></c></worksheet>`,
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

func TestProcessUploadXLSXSensitiveContent(t *testing.T) {
	res, err := Process(fileCompUploadReq(t, "contacts.xlsx", string(testPipelineXLSX(t, "13800138000"))), Config{
		Enabled: true, Mode: "PROTECT", SensitiveValueRules: fileSensitivePipelineRules(),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, match := range res.Context.CopyMatches() {
		if match.RuleID == "file.sensitive_content" {
			found = true
			if match.Evidence["scope"] != "XLSX_WORKSHEETS" || match.Evidence["field"] != "C!A1" {
				t.Fatalf("unexpected XLSX evidence: %+v", match)
			}
			for _, value := range match.Evidence {
				if strings.Contains(value, "13800138000") {
					t.Fatalf("XLSX value leaked: %+v", match.Evidence)
				}
			}
		}
	}
	if !found {
		t.Fatalf("XLSX content not detected: %+v", res.Context.CopyMatches())
	}
	observations := parser.BuildUploadFileObservations(res.Parsed.MultipartParts)
	if len(observations) != 1 || len(observations[0].SensitiveTypes) != 1 || observations[0].SensitiveTypes[0] != "phone" {
		t.Fatalf("XLSX asset labels missing: %+v", observations)
	}
}

func TestProcessResponseXLSXSensitiveContent(t *testing.T) {
	ctx := dsctx.New("download-xlsx", dsctx.DefaultParseLimits())
	act, err := ProcessResponse(ctx, ResponseInput{
		Status: 200, ContentType: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		ContentDisposition: `attachment; filename="contacts.xlsx"`,
		Body:               testPipelineXLSX(t, "13800138000"), BodySize: 512,
	}, ResponseConfig{Mode: "PROTECT", SensitiveValueRules: fileSensitivePipelineRules()})
	if err != nil {
		t.Fatal(err)
	}
	if act == dsctx.ActionBlock {
		t.Fatalf("XLSX observation must not block: %+v", ctx.CopyMatches())
	}
	observation := ctx.GetResponse().FileObservation
	if observation == nil || len(observation.SensitiveTypes) != 1 || observation.SensitiveTypes[0] != "phone" {
		t.Fatalf("XLSX download labels missing: %+v", observation)
	}
}
