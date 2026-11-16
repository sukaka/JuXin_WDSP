package detectors

import (
	"bytes"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func testPPTX(t *testing.T, slide string) []byte {
	t.Helper()
	return testDOCXPackage(t, []testOOXMLEntry{
		{name: "ppt/presentation.xml", body: []byte(`<p:presentation/>`)},
		{name: "ppt/slides/slide1.xml", body: []byte(slide)},
	})
}

func TestPPTXRichTextSlides(t *testing.T) {
	body := testDOCXPackage(t, []testOOXMLEntry{
		{name: "ppt/presentation.xml", body: []byte(`<p:presentation/>`)},
		{name: "ppt/slides/slide2.xml", body: []byte(`<p:sld><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>13800138000</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>`)},
		{name: "ppt/slides/slide1.xml", body: []byte(`<p:sld><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>alex@</a:t></a:r><a:r><a:t>example.test</a:t></a:r></a:p><a:p><a:r><a:t>ordinary roadmap</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>`)},
	})
	obs := &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "contacts.pptx", Extension: "pptx", MIME: "application/vnd.openxmlformats-officedocument.presentationml.presentation"}
	ctx := dsctx.New("pptx", dsctx.DefaultParseLimits())
	CheckFileSensitiveContent(ctx, obs, body, true, false, fileSensitiveTestRules(t))
	matches := ctx.CopyMatches()
	if len(matches) != 2 || strings.Join(obs.SensitiveTypes, ",") != "email,phone" {
		t.Fatalf("unexpected PPTX matches=%+v types=%v", matches, obs.SensitiveTypes)
	}
	fields := map[string]bool{}
	for _, match := range matches {
		if match.Evidence["scope"] != "PPTX_SLIDES" {
			t.Fatalf("unexpected PPTX scope: %+v", match)
		}
		fields[match.Evidence["field"]] = true
		for _, value := range match.Evidence {
			if strings.Contains(value, "13800138000") || strings.Contains(value, "alex@example.test") || strings.Contains(value, "13900139000") {
				t.Fatalf("PPTX value leaked: %+v", match.Evidence)
			}
		}
	}
	if !fields["slide1!p1"] || !fields["slide2!p1"] {
		t.Fatalf("PPTX paragraph paths missing: %+v", fields)
	}
}

func TestPPTXNormalAndTruncated(t *testing.T) {
	obs := &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "roadmap.pptx", Extension: "pptx", MIME: "application/vnd.openxmlformats-officedocument.presentationml.presentation"}
	ctx := dsctx.New("normal-pptx", dsctx.DefaultParseLimits())
	CheckFileSensitiveContent(ctx, obs, testPPTX(t, `<p:sld><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>quarterly roadmap</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>`), true, false, fileSensitiveTestRules(t))
	if ctx.MatchCount() != 0 || len(obs.SensitiveTypes) != 0 {
		t.Fatalf("normal PPTX must not alert: %+v types=%v", ctx.CopyMatches(), obs.SensitiveTypes)
	}

	ctx = dsctx.New("truncated-pptx", dsctx.DefaultParseLimits())
	CheckFileSensitiveContent(ctx, obs, testPPTX(t, `<p:sld/>`), false, false, fileSensitiveTestRules(t))
	matches := ctx.CopyMatches()
	if len(matches) != 1 || matches[0].RuleID != "file.sensitive_content_not_inspected" || matches[0].Evidence["reason"] != "TRUNCATED_OOXML" {
		t.Fatalf("truncated PPTX must disclose missing inspection: %+v", matches)
	}
}

func TestPPTXRejectsInvalidPackages(t *testing.T) {
	encrypted := testPPTX(t, `<p:sld/>`)
	index := bytes.LastIndex(encrypted, []byte("ppt/presentation.xml"))
	if index < 38 {
		t.Fatal("presentation central directory entry not found")
	}
	encrypted[6] |= 1
	encrypted[index-38] |= 1
	for name, testCase := range map[string]struct {
		body []byte
		want string
	}{
		"encrypted":        {body: encrypted, want: "ENCRYPTED_OOXML"},
		"invalid_zip":      {body: []byte("not a zip"), want: "INVALID_OOXML"},
		"missing_root":     {body: testDOCXPackage(t, []testOOXMLEntry{{name: "ppt/slides/slide1.xml", body: []byte(`<p:sld/>`)}}), want: "PPTX_PRESENTATION_MISSING"},
		"notes_only":       {body: testDOCXPackage(t, []testOOXMLEntry{{name: "ppt/presentation.xml", body: []byte(`<p:presentation/>`)}, {name: "ppt/notesSlides/notesSlide1.xml", body: []byte(`<p:notes/>`)}}), want: "PPTX_SLIDE_MISSING"},
		"invalid_slide":    {body: testPPTX(t, `<p:sld><a:p><a:t>13800138000`), want: "INVALID_PPTX_XML"},
		"wrong_root":       {body: testPPTX(t, `<word:document/>`), want: "INVALID_PPTX_XML"},
		"slide_directive":  {body: testPPTX(t, `<!DOCTYPE p:sld><p:sld/>`), want: "PPTX_UNSUPPORTED_DIRECTIVE"},
		"root_directive":   {body: testDOCXPackage(t, []testOOXMLEntry{{name: "ppt/presentation.xml", body: []byte(`<!DOCTYPE p:presentation><p:presentation/>`)}, {name: "ppt/slides/slide1.xml", body: []byte(`<p:sld/>`)}}), want: "PPTX_UNSUPPORTED_DIRECTIVE"},
		"duplicate_slides": {body: testDOCXPackage(t, []testOOXMLEntry{{name: "ppt/presentation.xml", body: []byte(`<p:presentation/>`)}, {name: "ppt/slides/slide1.xml", body: []byte(`<p:sld/>`)}, {name: "ppt/slides/slide1.xml", body: []byte(`<p:sld/>`)}}), want: "PPTX_DUPLICATE_SLIDE"},
	} {
		t.Run(name, func(t *testing.T) {
			obs := &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "invalid.pptx", Extension: "pptx", MIME: "application/vnd.openxmlformats-officedocument.presentationml.presentation"}
			ctx := dsctx.New(name, dsctx.DefaultParseLimits())
			CheckFileSensitiveContent(ctx, obs, testCase.body, true, false, fileSensitiveTestRules(t))
			matches := ctx.CopyMatches()
			if len(matches) != 1 || matches[0].RuleID != "file.sensitive_content_not_inspected" || matches[0].Evidence["reason"] != testCase.want {
				t.Fatalf("unexpected package disclosure: %+v", matches)
			}
		})
	}
}

func TestUploadPPTXSensitiveContent(t *testing.T) {
	body := testPPTX(t, `<p:sld><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>13800138000</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>`)
	if len(body) >= 512 {
		t.Fatalf("minimal PPTX must exercise complete-prefix inspection: %d", len(body))
	}
	parts := uploadContentParts(t, "contacts.pptx", body, dsctx.DefaultParseLimits())
	ctx := dsctx.New("upload-pptx", dsctx.DefaultParseLimits())
	CheckUploadFileSensitiveContent(ctx, parts, false, fileSensitiveTestRules(t))
	observations := parser.BuildUploadFileObservations(parts)
	if len(observations) != 1 || len(observations[0].SensitiveTypes) != 1 || observations[0].SensitiveTypes[0] != "phone" {
		t.Fatalf("PPTX upload labels missing: %+v", observations)
	}
	matches := ctx.CopyMatches()
	if len(matches) != 1 || matches[0].Evidence["field"] != "slide1!p1" {
		t.Fatalf("PPTX paragraph path missing: %+v", matches)
	}
	for _, value := range matches[0].Evidence {
		if strings.Contains(value, "13800138000") {
			t.Fatalf("PPTX upload value leaked: %+v", matches[0].Evidence)
		}
	}
}
