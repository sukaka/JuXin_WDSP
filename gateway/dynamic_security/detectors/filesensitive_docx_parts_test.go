package detectors

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func TestDOCXHeaderFooterSensitiveContent(t *testing.T) {
	body := testDOCXPackage(t, []testOOXMLEntry{
		{name: "word/document.xml", body: []byte(`<w:document><w:body><w:p><w:r><w:t>alex@example.test</w:t></w:r></w:p></w:body></w:document>`)},
		{name: "word/header1.xml", body: []byte(`<w:hdr><w:p><w:r><w:t>13800138000</w:t></w:r></w:p></w:hdr>`)},
		{name: "word/footer1.xml", body: []byte(`<w:ftr><w:p><w:r><w:t>13900139000</w:t></w:r></w:p></w:ftr>`)},
	})
	obs := &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "report.docx", Extension: "docx"}
	ctx := dsctx.New("docx-header-footer", dsctx.DefaultParseLimits())
	CheckFileSensitiveContent(ctx, obs, body, true, false, fileSensitiveTestRules(t))
	matches := ctx.CopyMatches()
	if len(matches) != 3 || strings.Join(obs.SensitiveTypes, ",") != "email,phone" {
		t.Fatalf("unexpected DOCX parts result: %+v types=%v", matches, obs.SensitiveTypes)
	}
	sources := map[string]map[string]string{}
	for _, match := range matches {
		sources[match.Evidence["source_part"]] = match.Evidence
		for _, value := range match.Evidence {
			if strings.Contains(value, "alex@example.test") || strings.Contains(value, "13800138000") || strings.Contains(value, "13900139000") || strings.Contains(value, "13700137000") {
				t.Fatalf("DOCX part value leaked: %+v", match.Evidence)
			}
		}
	}
	for source, field := range map[string]string{
		"word/document.xml": "document.body.p.r.t",
		"word/header1.xml":  "hdr.p.r.t",
		"word/footer1.xml":  "ftr.p.r.t",
	} {
		evidence := sources[source]
		if evidence == nil || evidence["field"] != field {
			t.Fatalf("DOCX source evidence missing for %s: %+v", source, sources)
		}
		wantScope := "DOCX_HEADER_FOOTER"
		if source == "word/document.xml" {
			wantScope = "DOCX_MAIN_DOCUMENT"
		}
		if evidence["scope"] != wantScope {
			t.Fatalf("unexpected DOCX source scope: %+v", evidence)
		}
	}
}

func TestDOCXHeaderOnlyUpload(t *testing.T) {
	body := testDOCXPackage(t, []testOOXMLEntry{
		{name: "word/document.xml", body: []byte(`<w:document><w:body/></w:document>`)},
		{name: "word/header1.xml", body: []byte(`<w:hdr><w:p><w:r><w:t>13800138000</w:t></w:r></w:p></w:hdr>`)},
	})
	if len(body) >= 512 {
		t.Fatalf("small DOCX header fixture must fit the upload prefix: %d", len(body))
	}
	parts := uploadContentParts(t, "report.docx", body, dsctx.DefaultParseLimits())
	ctx := dsctx.New("docx-header-upload", dsctx.DefaultParseLimits())
	CheckUploadFileSensitiveContent(ctx, parts, false, fileSensitiveTestRules(t))
	observations := parser.BuildUploadFileObservations(parts)
	if len(observations) != 1 || len(observations[0].SensitiveTypes) != 1 || observations[0].SensitiveTypes[0] != "phone" {
		t.Fatalf("DOCX header upload labels missing: %+v", observations)
	}
	matches := ctx.CopyMatches()
	if len(matches) != 1 || matches[0].Evidence["scope"] != "DOCX_HEADER_FOOTER" || matches[0].Evidence["source_part"] != "word/header1.xml" || matches[0].Evidence["field"] != "hdr.p.r.t" {
		t.Fatalf("unexpected DOCX header upload event: %+v", matches)
	}
}

func TestDOCXRejectsInvalidAndDuplicateHeader(t *testing.T) {
	for name, testCase := range map[string]struct {
		entries []testOOXMLEntry
		want    string
	}{
		"invalid_header": {
			entries: []testOOXMLEntry{{name: "word/document.xml", body: []byte(`<w:document><w:body><w:p><w:r><w:t>13800138000</w:t></w:r></w:p></w:body></w:document>`)}, {name: "word/header1.xml", body: []byte(`<w:hdr><w:p>`)}},
			want:    "INVALID_XML",
		},
		"duplicate_header": {
			entries: []testOOXMLEntry{{name: "word/document.xml", body: []byte(`<w:document/>`)}, {name: "word/header1.xml", body: []byte(`<w:hdr/>`)}, {name: "word/header1.xml", body: []byte(`<w:hdr/>`)}},
			want:    "DOCX_DUPLICATE_PART",
		},
		"duplicate_main": {
			entries: []testOOXMLEntry{{name: "word/document.xml", body: []byte(`<w:document/>`)}, {name: "word/document.xml", body: []byte(`<w:document/>`)}},
			want:    "DOCX_DUPLICATE_PART",
		},
	} {
		t.Run(name, func(t *testing.T) {
			obs := &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "invalid.docx", Extension: "docx"}
			ctx := dsctx.New(name, dsctx.DefaultParseLimits())
			CheckFileSensitiveContent(ctx, obs, testDOCXPackage(t, testCase.entries), true, false, fileSensitiveTestRules(t))
			matches := ctx.CopyMatches()
			if len(matches) != 1 || matches[0].RuleID != "file.sensitive_content_not_inspected" || matches[0].Evidence["reason"] != testCase.want {
				t.Fatalf("unexpected DOCX part disclosure: %+v", matches)
			}
			if len(obs.SensitiveTypes) != 0 {
				t.Fatalf("invalid DOCX parts must not publish partial labels: %+v", obs.SensitiveTypes)
			}
		})
	}
}

func TestDOCXRejectsAggregateTextBudget(t *testing.T) {
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for _, name := range []string{"word/document.xml", "word/header1.xml", "word/footer1.xml"} {
		part, err := writer.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(part, `<w:document><w:p><w:r><w:t>`); err != nil {
			t.Fatal(err)
		}
		if _, err := io.CopyN(part, strings.NewReader(strings.Repeat(" ", 6<<20)), 6<<20); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(part, `</w:t></w:r></w:p></w:document>`); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if buf.Len() > 1<<20 {
		t.Fatalf("compressed DOCX budget fixture is unexpectedly large: %d", buf.Len())
	}
	obs := &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "large.docx", Extension: "docx"}
	ctx := dsctx.New("docx-aggregate-budget", dsctx.DefaultParseLimits())
	CheckFileSensitiveContent(ctx, obs, buf.Bytes(), true, false, fileSensitiveTestRules(t))
	matches := ctx.CopyMatches()
	if len(matches) != 1 || matches[0].RuleID != "file.sensitive_content_not_inspected" || matches[0].Evidence["reason"] != "DOCX_CONTENT_TOO_LARGE" {
		t.Fatalf("aggregate DOCX text budget must be disclosed: %+v", matches)
	}
}

func TestDOCXHeaderFooterPartSelection(t *testing.T) {
	for name, want := range map[string]bool{
		"word/header1.xml":        true,
		"word/footer12.xml":       true,
		"word/header0.xml":        false,
		"word/header-1.xml":       false,
		"word/header01.xml":       false,
		"word/header1.xml.rels":   false,
		"word/headerx.xml":        false,
		"word/comments.xml":       false,
		"../word/header1.xml":     false,
		"word/notes/footnote.xml": false,
	} {
		if got := isDOCXHeaderFooterPart(name); got != want {
			t.Errorf("isDOCXHeaderFooterPart(%q) = %v, want %v", name, got, want)
		}
	}
}
