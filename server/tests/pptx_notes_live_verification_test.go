package tests

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"io"
	"testing"
)

func TestPPTXNotesSensitiveContentLiveGateway(t *testing.T) {
	testOOXMLSensitiveContentLiveGateway(t, liveOOXMLFormat{
		Extension: "pptx", MIME: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
		Filename: "speaker-notes.pptx", Marker: "~", RuleRegex: `^~$`, Field: "notesSlide1!p1", Scope: "PPTX_NOTES",
		SourcePart: "ppt/notesSlides/notesSlide1.xml", Port: 18091, Fixture: pptxNotesLiveFixture,
	})
}

func pptxNotesLiveFixture(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	writer.RegisterCompressor(zip.Deflate, func(w io.Writer) (io.WriteCloser, error) {
		return flate.NewWriter(w, flate.BestCompression)
	})
	for _, entry := range []struct{ name, body string }{
		{"ppt/presentation.xml", `<presentation/>`},
		{"ppt/slides/slide1.xml", `<sld/>`},
		{"ppt/notesSlides/notesSlide1.xml", `<notes><p><t>~</t></p></notes>`},
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
