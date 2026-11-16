package detectors

import (
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func TestDOCXAnnotationsSensitiveContent(t *testing.T) {
	body := testDOCXPackage(t, []testOOXMLEntry{
		{name: "word/document.xml", body: []byte(`<w:document><w:body><w:p><w:r><w:t>ordinary report</w:t></w:r></w:p></w:body></w:document>`)},
		{name: "word/comments.xml", body: []byte(`<w:comments><w:comment><w:p><w:r><w:t>13800138000</w:t></w:r></w:p></w:comment></w:comments>`)},
		{name: "word/footnotes.xml", body: []byte(`<w:footnotes><w:footnote><w:p><w:r><w:t>alex@example.test</w:t></w:r></w:p></w:footnote></w:footnotes>`)},
		{name: "word/endnotes.xml", body: []byte(`<w:endnotes><w:endnote><w:p><w:r><w:t>13900139000</w:t></w:r></w:p></w:endnote></w:endnotes>`)},
	})
	obs := &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "review.docx", Extension: "docx"}
	ctx := dsctx.New("docx-annotations", dsctx.DefaultParseLimits())
	CheckFileSensitiveContent(ctx, obs, body, true, false, fileSensitiveTestRules(t))
	matches := ctx.CopyMatches()
	if len(matches) != 3 || strings.Join(obs.SensitiveTypes, ",") != "email,phone" {
		t.Fatalf("unexpected DOCX annotation result: %+v types=%v", matches, obs.SensitiveTypes)
	}
	sources := map[string]map[string]string{}
	for _, match := range matches {
		if match.Evidence["scope"] != "DOCX_ANNOTATIONS" {
			t.Fatalf("unexpected annotation scope: %+v", match.Evidence)
		}
		sources[match.Evidence["source_part"]] = match.Evidence
		for _, value := range match.Evidence {
			if strings.Contains(value, "13800138000") || strings.Contains(value, "alex@example.test") || strings.Contains(value, "13900139000") {
				t.Fatalf("DOCX annotation value leaked: %+v", match.Evidence)
			}
		}
	}
	for source, field := range map[string]string{
		"word/comments.xml":  "comments.comment.p.r.t",
		"word/footnotes.xml": "footnotes.footnote.p.r.t",
		"word/endnotes.xml":  "endnotes.endnote.p.r.t",
	} {
		if sources[source] == nil || sources[source]["field"] != field {
			t.Fatalf("annotation source missing for %s: %+v", source, sources)
		}
	}
}

func TestDOCXCommentOnlyUpload(t *testing.T) {
	body := testDOCXPackage(t, []testOOXMLEntry{
		{name: "word/document.xml", body: []byte(`<w:document><w:body/></w:document>`)},
		{name: "word/comments.xml", body: []byte(`<w:comments><w:comment><w:p><w:r><w:t>13800138000</w:t></w:r></w:p></w:comment></w:comments>`)},
	})
	if len(body) >= 512 {
		t.Fatalf("small DOCX comment fixture must fit the upload prefix: %d", len(body))
	}
	parts := uploadContentParts(t, "review.docx", body, dsctx.DefaultParseLimits())
	ctx := dsctx.New("docx-comment-upload", dsctx.DefaultParseLimits())
	CheckUploadFileSensitiveContent(ctx, parts, false, fileSensitiveTestRules(t))
	observations := parser.BuildUploadFileObservations(parts)
	if len(observations) != 1 || len(observations[0].SensitiveTypes) != 1 || observations[0].SensitiveTypes[0] != "phone" {
		t.Fatalf("DOCX comment upload labels missing: %+v", observations)
	}
	matches := ctx.CopyMatches()
	if len(matches) != 1 || matches[0].Evidence["scope"] != "DOCX_ANNOTATIONS" || matches[0].Evidence["source_part"] != "word/comments.xml" || matches[0].Evidence["field"] != "comments.comment.p.r.t" {
		t.Fatalf("unexpected DOCX comment upload event: %+v", matches)
	}
}

func TestDOCXRejectsInvalidAndDuplicateAnnotations(t *testing.T) {
	for name, testCase := range map[string]struct {
		entries []testOOXMLEntry
		want    string
	}{
		"invalid_comment": {
			entries: []testOOXMLEntry{{name: "word/document.xml", body: []byte(`<w:document><w:body><w:p><w:r><w:t>13800138000</w:t></w:r></w:p></w:body></w:document>`)}, {name: "word/comments.xml", body: []byte(`<w:comments><w:comment>`)}},
			want:    "INVALID_XML",
		},
		"duplicate_footnotes": {
			entries: []testOOXMLEntry{{name: "word/document.xml", body: []byte(`<w:document/>`)}, {name: "word/footnotes.xml", body: []byte(`<w:footnotes/>`)}, {name: "word/footnotes.xml", body: []byte(`<w:footnotes/>`)}},
			want:    "DOCX_DUPLICATE_PART",
		},
	} {
		t.Run(name, func(t *testing.T) {
			obs := &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "invalid.docx", Extension: "docx"}
			ctx := dsctx.New(name, dsctx.DefaultParseLimits())
			CheckFileSensitiveContent(ctx, obs, testDOCXPackage(t, testCase.entries), true, false, fileSensitiveTestRules(t))
			matches := ctx.CopyMatches()
			if len(matches) != 1 || matches[0].RuleID != "file.sensitive_content_not_inspected" || matches[0].Evidence["reason"] != testCase.want {
				t.Fatalf("unexpected DOCX annotation disclosure: %+v", matches)
			}
			if len(obs.SensitiveTypes) != 0 {
				t.Fatalf("invalid DOCX annotations must not publish partial labels: %+v", obs.SensitiveTypes)
			}
		})
	}
}

func TestDOCXAnnotationPartSelection(t *testing.T) {
	for name, want := range map[string]bool{
		"word/comments.xml":         true,
		"word/footnotes.xml":        true,
		"word/endnotes.xml":         true,
		"word/commentsExtended.xml": false,
		"word/comments1.xml":        false,
		"word/people.xml":           false,
		"word/header1.xml":          false,
		"../word/comments.xml":      false,
	} {
		if got := isDOCXAnnotationPart(name); got != want {
			t.Errorf("isDOCXAnnotationPart(%q) = %v, want %v", name, got, want)
		}
	}
}
