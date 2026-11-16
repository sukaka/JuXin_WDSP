package detectors

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"io"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func TestPPTXNotesSensitiveContent(t *testing.T) {
	body := testDOCXPackage(t, []testOOXMLEntry{
		{name: "ppt/presentation.xml", body: []byte(`<p:presentation/>`)},
		{name: "ppt/slides/slide1.xml", body: []byte(`<p:sld><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>13800138000</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:sld>`)},
		{name: "ppt/notesSlides/notesSlide1.xml", body: []byte(`<p:notes><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>alex@</a:t></a:r><a:r><a:t>example.test</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:notes>`)},
		{name: "ppt/notesSlides/notesSlide2.xml", body: []byte(`<p:notes><p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>13900139000</a:t></a:r></a:p></p:txBody></p:sp></p:spTree></p:cSld></p:notes>`)},
	})
	obs := &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "briefing.pptx", Extension: "pptx"}
	ctx := dsctx.New("pptx-notes", dsctx.DefaultParseLimits())
	CheckFileSensitiveContent(ctx, obs, body, true, false, fileSensitiveTestRules(t))
	matches := ctx.CopyMatches()
	if len(matches) != 3 || strings.Join(obs.SensitiveTypes, ",") != "email,phone" {
		t.Fatalf("unexpected PPTX notes result: %+v types=%v", matches, obs.SensitiveTypes)
	}
	mainFound := false
	noteFields := map[string]string{}
	for _, match := range matches {
		if match.Evidence["scope"] == "PPTX_SLIDES" {
			mainFound = match.Evidence["field"] == "slide1!p1"
		}
		if match.Evidence["scope"] == "PPTX_NOTES" {
			noteFields[match.Evidence["source_part"]] = match.Evidence["field"]
		}
		for _, value := range match.Evidence {
			if strings.Contains(value, "13800138000") || strings.Contains(value, "alex@example.test") || strings.Contains(value, "13900139000") {
				t.Fatalf("PPTX notes value leaked: %+v", match.Evidence)
			}
		}
	}
	if !mainFound || noteFields["ppt/notesSlides/notesSlide1.xml"] != "notesSlide1!p1" || noteFields["ppt/notesSlides/notesSlide2.xml"] != "notesSlide2!p1" {
		t.Fatalf("unexpected PPTX notes evidence: %+v", matches)
	}
}

func TestPPTXNotesOnlyUpload(t *testing.T) {
	body := testPPTXNotesUpload(t, "~")
	if len(body) >= 512 {
		t.Fatalf("compressed PPTX notes fixture must fit the upload prefix: %d", len(body))
	}
	rules, err := CompileSensitiveValueRules([]SensitiveValueRule{{DataType: "marker", Regex: `^~$`, Locations: []string{"file"}, Level: "SENSITIVE"}})
	if err != nil {
		t.Fatal(err)
	}
	parts := uploadContentParts(t, "briefing.pptx", body, dsctx.DefaultParseLimits())
	ctx := dsctx.New("pptx-notes-upload", dsctx.DefaultParseLimits())
	CheckUploadFileSensitiveContent(ctx, parts, false, rules)
	observations := parser.BuildUploadFileObservations(parts)
	if len(observations) != 1 || len(observations[0].SensitiveTypes) != 1 || observations[0].SensitiveTypes[0] != "marker" {
		t.Fatalf("PPTX notes upload labels missing: %+v", observations)
	}
	matches := ctx.CopyMatches()
	if len(matches) != 1 || matches[0].Evidence["data_type"] != "marker" || matches[0].Evidence["scope"] != "PPTX_NOTES" || matches[0].Evidence["source_part"] != "ppt/notesSlides/notesSlide1.xml" || matches[0].Evidence["field"] != "notesSlide1!p1" {
		t.Fatalf("unexpected PPTX notes upload event: %+v", matches)
	}
}

func TestPPTXRejectsInvalidAndDuplicateNotes(t *testing.T) {
	for name, testCase := range map[string]struct {
		entries []testOOXMLEntry
		want    string
	}{
		"wrong_root": {
			entries: []testOOXMLEntry{{name: "ppt/presentation.xml", body: []byte(`<p:presentation/>`)}, {name: "ppt/slides/slide1.xml", body: []byte(`<p:sld><a:p><a:r><a:t>13800138000</a:t></a:r></a:p></p:sld>`)}, {name: "ppt/notesSlides/notesSlide1.xml", body: []byte(`<p:sld/>`)}},
			want:    "INVALID_PPTX_XML",
		},
		"invalid_xml": {
			entries: []testOOXMLEntry{{name: "ppt/presentation.xml", body: []byte(`<p:presentation/>`)}, {name: "ppt/slides/slide1.xml", body: []byte(`<p:sld/>`)}, {name: "ppt/notesSlides/notesSlide1.xml", body: []byte(`<p:notes><a:p>`)}},
			want:    "INVALID_PPTX_XML",
		},
		"duplicate_notes": {
			entries: []testOOXMLEntry{{name: "ppt/presentation.xml", body: []byte(`<p:presentation/>`)}, {name: "ppt/slides/slide1.xml", body: []byte(`<p:sld/>`)}, {name: "ppt/notesSlides/notesSlide1.xml", body: []byte(`<p:notes/>`)}, {name: "ppt/notesSlides/notesSlide1.xml", body: []byte(`<p:notes/>`)}},
			want:    "PPTX_DUPLICATE_NOTES_SLIDE",
		},
	} {
		t.Run(name, func(t *testing.T) {
			obs := &dsctx.FileObservation{Direction: "DOWNLOAD", FileName: "invalid.pptx", Extension: "pptx"}
			ctx := dsctx.New(name, dsctx.DefaultParseLimits())
			CheckFileSensitiveContent(ctx, obs, testDOCXPackage(t, testCase.entries), true, false, fileSensitiveTestRules(t))
			matches := ctx.CopyMatches()
			if len(matches) != 1 || matches[0].RuleID != "file.sensitive_content_not_inspected" || matches[0].Evidence["reason"] != testCase.want {
				t.Fatalf("unexpected PPTX notes disclosure: %+v", matches)
			}
			if len(obs.SensitiveTypes) != 0 {
				t.Fatalf("invalid PPTX notes must not publish partial labels: %+v", obs.SensitiveTypes)
			}
		})
	}
}

func TestPPTXNotesPartSelection(t *testing.T) {
	for name, want := range map[string]int{
		"ppt/notesSlides/notesSlide1.xml":       1,
		"ppt/notesSlides/notesSlide12.xml":      12,
		"ppt/notesSlides/notesSlide0.xml":       0,
		"ppt/notesSlides/notesSlide-1.xml":      0,
		"ppt/notesSlides/notesSlide01.xml":      0,
		"ppt/notesSlides/notesSlideX.xml":       0,
		"ppt/slides/slide1.xml":                 0,
		"ppt/notesSlides/_rels/notesSlide1.xml": 0,
		"ppt/notesSlides/notesSlide1.xml.rels":  0,
	} {
		if got, ok := pptxNotesSlideIndex(name); !ok && want != 0 || got != want {
			t.Errorf("pptxNotesSlideIndex(%q) = %d, %v, want %d", name, got, ok, want)
		}
	}
}

func testPPTXNotesUpload(t *testing.T, marker string) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	writer.RegisterCompressor(zip.Deflate, func(w io.Writer) (io.WriteCloser, error) {
		return flate.NewWriter(w, flate.BestCompression)
	})
	for _, entry := range []testOOXMLEntry{
		{name: "ppt/presentation.xml", body: []byte(`<presentation/>`)},
		{name: "ppt/slides/slide1.xml", body: []byte(`<sld/>`)},
		{name: "ppt/notesSlides/notesSlide1.xml", body: []byte(`<notes><p><t>` + marker + `</t></p></notes>`)},
	} {
		part, err := writer.CreateHeader(&zip.FileHeader{Name: entry.name, Method: zip.Deflate})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(part, string(entry.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
