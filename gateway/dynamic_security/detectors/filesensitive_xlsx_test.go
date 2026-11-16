package detectors

import (
	"bytes"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func testXLSXWorkbook(t *testing.T, shared, worksheet string) []byte {
	t.Helper()
	return testDOCXPackage(t, []testOOXMLEntry{
		{name: "xl/workbook.xml", body: []byte(`<workbook><sheets><sheet name="Contacts" sheetId="1" r:id="rId1"/></sheets></workbook>`)},
		{name: "xl/_rels/workbook.xml.rels", body: []byte(`<Relationships><Relationship Id="rId1" Target="worksheets/sheet1.xml"/></Relationships>`)},
		{name: "xl/sharedStrings.xml", body: []byte(shared)},
		{name: "xl/worksheets/sheet1.xml", body: []byte(worksheet)},
	})
}

func testXLSXMinimal(t *testing.T, value string) []byte {
	t.Helper()
	return testDOCXPackage(t, []testOOXMLEntry{
		{name: "xl/workbook.xml", body: []byte(`<workbook><sheets><sheet name="C" sheetId="1" r:id="rId1"/></sheets></workbook>`)},
		{name: "xl/worksheets/sheet1.xml", body: []byte(`<worksheet><c r="A1" t="inlineStr"><is><t>` + value + `</t></is></c></worksheet>`)},
	})
}

func TestXLSXSharedStrings(t *testing.T) {
	shared := `<sst><si><t>13800138000</t></si><si><r><t>alex@</t></r><r><t>example.test</t></r></si></sst>`
	worksheet := `<worksheet><sheetData><row><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c></row></sheetData></worksheet>`
	obs := &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "contacts.xlsx", Extension: "xlsx", MIME: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}
	ctx := dsctx.New("xlsx", dsctx.DefaultParseLimits())
	CheckFileSensitiveContent(ctx, obs, testXLSXWorkbook(t, shared, worksheet), true, false, fileSensitiveTestRules(t))
	matches := ctx.CopyMatches()
	if len(matches) != 2 || strings.Join(obs.SensitiveTypes, ",") != "email,phone" {
		t.Fatalf("unexpected XLSX matches=%+v types=%v", matches, obs.SensitiveTypes)
	}
	fields := map[string]bool{}
	for _, match := range matches {
		if match.Evidence["scope"] != "XLSX_WORKSHEETS" {
			t.Fatalf("unexpected XLSX scope: %+v", match)
		}
		fields[match.Evidence["field"]] = true
		for _, value := range match.Evidence {
			if strings.Contains(value, "13800138000") || strings.Contains(value, "alex@example.test") {
				t.Fatalf("XLSX value leaked: %+v", match.Evidence)
			}
		}
	}
	if !fields["Contacts!A1"] || !fields["Contacts!B1"] {
		t.Fatalf("XLSX cell paths missing: %+v", fields)
	}
}

func TestXLSXInlineAndNormalCells(t *testing.T) {
	obs := &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "inline.xlsx", Extension: "xlsx", MIME: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}
	ctx := dsctx.New("inline", dsctx.DefaultParseLimits())
	CheckFileSensitiveContent(ctx, obs, testXLSXWorkbook(t, `<sst/>`, `<worksheet><c r="A1" t="inlineStr"><is><t>13800138000</t></is></c></worksheet>`), true, false, fileSensitiveTestRules(t))
	matches := ctx.CopyMatches()
	if len(matches) != 1 || matches[0].Evidence["field"] != "Contacts!A1" {
		t.Fatalf("inline cell not detected: %+v", matches)
	}

	ctx = dsctx.New("normal-xlsx", dsctx.DefaultParseLimits())
	CheckFileSensitiveContent(ctx, obs, testXLSXWorkbook(t, `<sst/>`, `<worksheet><c r="A1"><v>42</v></c></worksheet>`), true, false, fileSensitiveTestRules(t))
	if ctx.MatchCount() != 0 {
		t.Fatalf("normal worksheet must not alert: %+v", ctx.CopyMatches())
	}
}

func TestXLSXRejectsTruncatedAndInvalidReferences(t *testing.T) {
	obs := &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "bad.xlsx", Extension: "xlsx", MIME: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}
	ctx := dsctx.New("truncated-xlsx", dsctx.DefaultParseLimits())
	CheckFileSensitiveContent(ctx, obs, testXLSXWorkbook(t, `<sst/>`, `<worksheet/>`), false, false, fileSensitiveTestRules(t))
	matches := ctx.CopyMatches()
	if len(matches) != 1 || matches[0].Evidence["reason"] != "TRUNCATED_OOXML" {
		t.Fatalf("truncated workbook must disclose: %+v", matches)
	}

	ctx = dsctx.New("bad-reference", dsctx.DefaultParseLimits())
	CheckFileSensitiveContent(ctx, obs, testXLSXWorkbook(t, `<sst/>`, `<worksheet><c r="A1" t="s"><v>99</v></c></worksheet>`), true, false, fileSensitiveTestRules(t))
	matches = ctx.CopyMatches()
	if len(matches) != 1 || matches[0].Evidence["reason"] != "XLSX_INVALID_REFERENCE" {
		t.Fatalf("out-of-range string index must be disclosed: %+v", matches)
	}
}

func TestXLSXRejectsEncryptedAndMissingWorkbook(t *testing.T) {
	body := testXLSXWorkbook(t, `<sst/>`, `<worksheet/>`)
	index := bytes.LastIndex(body, []byte("xl/workbook.xml"))
	if index < 38 {
		t.Fatal("workbook central directory entry not found")
	}
	body[6] |= 1
	body[index-38] |= 1
	obs := &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "protected.xlsx", Extension: "xlsx", MIME: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}
	ctx := dsctx.New("encrypted-xlsx", dsctx.DefaultParseLimits())
	CheckFileSensitiveContent(ctx, obs, body, true, false, fileSensitiveTestRules(t))
	matches := ctx.CopyMatches()
	if len(matches) != 1 || matches[0].Evidence["reason"] != "ENCRYPTED_OOXML" {
		t.Fatalf("encrypted workbook must not be parsed: %+v", matches)
	}

	ctx = dsctx.New("missing-workbook", dsctx.DefaultParseLimits())
	CheckFileSensitiveContent(ctx, obs, testDOCXPackage(t, []testOOXMLEntry{{name: "xl/worksheets/sheet1.xml", body: []byte(`<worksheet/>`)}}), true, false, fileSensitiveTestRules(t))
	matches = ctx.CopyMatches()
	if len(matches) != 1 || matches[0].Evidence["reason"] != "XLSX_WORKBOOK_MISSING" {
		t.Fatalf("missing workbook must disclose: %+v", matches)
	}
}

func TestUploadXLSXSensitiveContent(t *testing.T) {
	body := testXLSXMinimal(t, "13800138000")
	if len(body) >= 512 {
		t.Fatalf("minimal XLSX must exercise complete-prefix inspection: %d", len(body))
	}
	parts := uploadContentParts(t, "contacts.xlsx", body, dsctx.DefaultParseLimits())
	ctx := dsctx.New("upload-xlsx", dsctx.DefaultParseLimits())
	CheckUploadFileSensitiveContent(ctx, parts, false, fileSensitiveTestRules(t))
	observations := parser.BuildUploadFileObservations(parts)
	if len(observations) != 1 || len(observations[0].SensitiveTypes) != 1 || observations[0].SensitiveTypes[0] != "phone" {
		t.Fatalf("XLSX upload labels missing: %+v", observations)
	}
	for _, match := range ctx.CopyMatches() {
		if match.Evidence["field"] != "C!A1" {
			t.Fatalf("XLSX cell path missing: %+v", match)
		}
		for _, value := range match.Evidence {
			if strings.Contains(value, "13800138000") {
				t.Fatalf("XLSX upload value leaked: %+v", match.Evidence)
			}
		}
	}
}
