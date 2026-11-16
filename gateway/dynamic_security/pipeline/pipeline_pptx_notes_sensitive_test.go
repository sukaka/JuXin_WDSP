package pipeline

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"io"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func testPipelinePPTXNotes(t *testing.T, marker string) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	writer.RegisterCompressor(zip.Deflate, func(w io.Writer) (io.WriteCloser, error) {
		return flate.NewWriter(w, flate.BestCompression)
	})
	for _, entry := range []struct{ name, body string }{
		{"ppt/presentation.xml", `<presentation/>`},
		{"ppt/slides/slide1.xml", `<sld/>`},
		{"ppt/notesSlides/notesSlide1.xml", `<notes><p><t>` + marker + `</t></p></notes>`},
	} {
		part, err := writer.CreateHeader(&zip.FileHeader{Name: entry.name, Method: zip.Deflate})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(part, entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestProcessUploadPPTXNotesSensitiveContent(t *testing.T) {
	body := testPipelinePPTXNotes(t, "~")
	if len(body) >= 512 {
		t.Fatalf("small PPTX notes fixture must fit the upload prefix: %d", len(body))
	}
	res, err := Process(fileCompUploadReq(t, "briefing.pptx", string(body)), Config{
		Enabled: true, Mode: "PROTECT",
		SensitiveValueRules: []detectors.SensitiveValueRule{{DataType: "marker", Regex: `^~$`, Locations: []string{"file"}, Level: "SENSITIVE"}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	matches := res.Context.CopyMatches()
	if len(matches) != 1 || matches[0].Evidence["data_type"] != "marker" || matches[0].Evidence["scope"] != "PPTX_NOTES" || matches[0].Evidence["source_part"] != "ppt/notesSlides/notesSlide1.xml" || matches[0].Evidence["field"] != "notesSlide1!p1" {
		t.Fatalf("unexpected PPTX notes evidence: %+v", matches)
	}
	for _, value := range matches[0].Evidence {
		if strings.Contains(value, "~") {
			t.Fatalf("PPTX notes marker leaked: %+v", matches[0].Evidence)
		}
	}
	observations := parser.BuildUploadFileObservations(res.Parsed.MultipartParts)
	if len(observations) != 1 || len(observations[0].SensitiveTypes) != 1 || observations[0].SensitiveTypes[0] != "marker" {
		t.Fatalf("PPTX notes upload labels missing: %+v", observations)
	}
}

func TestProcessResponsePPTXNotesSensitiveContent(t *testing.T) {
	ctx := dsctx.New("download-pptx-notes", dsctx.DefaultParseLimits())
	act, err := ProcessResponse(ctx, ResponseInput{
		Status: 200, ContentType: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
		ContentDisposition: `attachment; filename="briefing.pptx"`,
		Body:               testPipelinePPTXNotes(t, "13800138000"), BodySize: 512,
	}, ResponseConfig{Mode: "PROTECT", SensitiveValueRules: fileSensitivePipelineRules()})
	if err != nil {
		t.Fatal(err)
	}
	if act == dsctx.ActionBlock {
		t.Fatalf("PPTX notes observation must not block: %+v", ctx.CopyMatches())
	}
	observation := ctx.GetResponse().FileObservation
	if observation == nil || len(observation.SensitiveTypes) != 1 || observation.SensitiveTypes[0] != "phone" {
		t.Fatalf("PPTX notes download labels missing: %+v", observation)
	}
}
