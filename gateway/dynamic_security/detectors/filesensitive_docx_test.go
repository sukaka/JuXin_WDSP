package detectors

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

type testOOXMLEntry struct {
	name string
	body []byte
}

func testDOCXPackage(t *testing.T, entries []testOOXMLEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: zip.Store}
		part, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func testDOCX(t *testing.T, document string) []byte {
	return testDOCXPackage(t, []testOOXMLEntry{
		{name: "word/document.xml", body: []byte(document)},
		{name: "[Content_Types].xml", body: []byte("<Types/>")},
		{name: "_rels/.rels", body: []byte("<Relationships/>")},
	})
}

func TestDOCXSensitiveContent(t *testing.T) {
	body := testDOCX(t, `<w:document><w:body><w:p><w:r><w:t>13800138000</w:t></w:r><w:r><w:t>alex@example.test</w:t></w:r></w:p></w:body></w:document>`)
	obs := &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "contacts.docx", Extension: "docx", MIME: "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}
	ctx := dsctx.New("docx", dsctx.DefaultParseLimits())
	CheckFileSensitiveContent(ctx, obs, body, true, false, fileSensitiveTestRules(t))
	matches := ctx.CopyMatches()
	if len(matches) != 2 || strings.Join(obs.SensitiveTypes, ",") != "email,phone" {
		t.Fatalf("unexpected DOCX result: %+v types=%v", matches, obs.SensitiveTypes)
	}
	for _, match := range matches {
		if match.Evidence["scope"] != "DOCX_MAIN_DOCUMENT" || match.Evidence["field"] != "document.body.p.r.t" {
			t.Fatalf("unexpected DOCX evidence: %+v", match)
		}
		for _, value := range match.Evidence {
			if strings.Contains(value, "13800138000") || strings.Contains(value, "alex@example.test") {
				t.Fatalf("DOCX value leaked: %+v", match.Evidence)
			}
		}
	}
}

func TestDOCXNormalAndTruncated(t *testing.T) {
	obs := &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "status.docx", Extension: "docx", MIME: "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}
	ctx := dsctx.New("normal-docx", dsctx.DefaultParseLimits())
	CheckFileSensitiveContent(ctx, obs, testDOCX(t, `<w:document><w:body><w:p><w:r><w:t>ordinary text</w:t></w:r></w:p></w:body></w:document>`), true, false, fileSensitiveTestRules(t))
	if ctx.MatchCount() != 0 || len(obs.SensitiveTypes) != 0 {
		t.Fatalf("normal DOCX must not alert: %+v types=%v", ctx.CopyMatches(), obs.SensitiveTypes)
	}

	ctx = dsctx.New("truncated-docx", dsctx.DefaultParseLimits())
	CheckFileSensitiveContent(ctx, obs, testDOCX(t, `<w:document><w:body><w:p><w:r><w:t>13800138000</w:t></w:r></w:p></w:body></w:document>`), false, false, fileSensitiveTestRules(t))
	matches := ctx.CopyMatches()
	if len(matches) != 1 || matches[0].RuleID != "file.sensitive_content_not_inspected" || matches[0].Evidence["reason"] != "TRUNCATED_OOXML" {
		t.Fatalf("truncated DOCX must disclose missing inspection: %+v", matches)
	}
}

func TestDOCXRejectsEncryptedAndInvalidPackages(t *testing.T) {
	body := testDOCX(t, `<w:document><w:body><w:p><w:r><w:t>13800138000</w:t></w:r></w:p></w:body></w:document>`)
	index := bytes.LastIndex(body, []byte("word/document.xml"))
	if index < 38 {
		t.Fatal("central directory entry not found")
	}
	body[6] |= 1
	body[index-38] |= 1
	for name, testCase := range map[string]struct {
		body []byte
		want string
	}{
		"encrypted": {body: body, want: "ENCRYPTED_OOXML"},
		"invalid":   {body: []byte("not a zip"), want: "INVALID_OOXML"},
		"missing":   {body: testDOCXPackage(t, []testOOXMLEntry{{name: "[Content_Types].xml", body: []byte("<Types/>")}}), want: "OOXML_DOCUMENT_MISSING"},
		"bad_xml":   {body: testDOCX(t, `<phone>13800138000`), want: "INVALID_XML"},
	} {
		t.Run(name, func(t *testing.T) {
			obs := &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "contacts.docx", Extension: "docx", MIME: "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}
			ctx := dsctx.New(name, dsctx.DefaultParseLimits())
			CheckFileSensitiveContent(ctx, obs, testCase.body, true, false, fileSensitiveTestRules(t))
			matches := ctx.CopyMatches()
			if len(matches) != 1 || matches[0].RuleID != "file.sensitive_content_not_inspected" || matches[0].Evidence["reason"] != testCase.want {
				t.Fatalf("unexpected package disclosure: %+v", matches)
			}
		})
	}
}

func TestDOCXRejectsExcessPartsAndLargeDocument(t *testing.T) {
	entries := make([]testOOXMLEntry, 65)
	for i := range entries {
		entries[i] = testOOXMLEntry{name: "word/document.xml", body: []byte("x")}
	}
	obs := &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "large.docx", Extension: "docx", MIME: "application/vnd.openxmlformats-officedocument.wordprocessingml.document"}
	ctx := dsctx.New("parts", dsctx.DefaultParseLimits())
	CheckFileSensitiveContent(ctx, obs, testDOCXPackage(t, entries), true, false, fileSensitiveTestRules(t))
	matches := ctx.CopyMatches()
	if len(matches) != 1 || matches[0].Evidence["reason"] != "OOXML_TOO_MANY_PARTS" {
		t.Fatalf("part cap must be disclosed: %+v", matches)
	}

	body := testDOCX(t, `<w:document><w:body><w:p><w:r><w:t>ordinary</w:t></w:r></w:p></w:body></w:document>`)
	index := bytes.LastIndex(body, []byte("word/document.xml"))
	if index < 22 {
		t.Fatal("central directory entry not found")
	}
	binary.LittleEndian.PutUint32(body[index-22:index-18], uint32(maxOOXMLDocumentBytes+1))
	ctx = dsctx.New("large-document", dsctx.DefaultParseLimits())
	CheckFileSensitiveContent(ctx, obs, body, true, false, fileSensitiveTestRules(t))
	matches = ctx.CopyMatches()
	if len(matches) != 1 || matches[0].Evidence["reason"] != "OOXML_DOCUMENT_TOO_LARGE" {
		t.Fatalf("document size cap must be disclosed: %+v", matches)
	}
}

func TestUploadDOCXSensitiveContent(t *testing.T) {
	body := testDOCX(t, `<w:document><w:body><w:p><w:r><w:t>13800138000</w:t></w:r></w:p></w:body></w:document>`)
	if len(body) >= 512 {
		t.Fatalf("small DOCX fixture must exercise complete-prefix inspection: %d", len(body))
	}
	parts := uploadContentParts(t, "contacts.docx", body, dsctx.DefaultParseLimits())
	ctx := dsctx.New("upload-docx", dsctx.DefaultParseLimits())
	CheckUploadFileSensitiveContent(ctx, parts, false, fileSensitiveTestRules(t))
	observations := parser.BuildUploadFileObservations(parts)
	if len(observations) != 1 || len(observations[0].SensitiveTypes) != 1 || observations[0].SensitiveTypes[0] != "phone" {
		t.Fatalf("DOCX upload labels missing: %+v", observations)
	}
	for _, match := range ctx.CopyMatches() {
		for _, value := range match.Evidence {
			if strings.Contains(value, "13800138000") {
				t.Fatalf("DOCX upload value leaked: %+v", match.Evidence)
			}
		}
	}
}
