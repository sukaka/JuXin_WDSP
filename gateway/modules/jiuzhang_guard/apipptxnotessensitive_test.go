package jiuzhang_guard

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testGuardPPTXNotes(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for name, content := range map[string]string{
		"ppt/presentation.xml":            `<p:presentation/>`,
		"ppt/slides/slide1.xml":           `<p:sld/>`,
		"ppt/notesSlides/notesSlide1.xml": `<p:notes><a:p><a:r><a:t>13800138000</a:t></a:r></a:p></p:notes>`,
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

func TestServeNextDownloadPPTXNotesSensitiveContent(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	g.APISensitiveValueRules = fileSensitiveGuardRules()
	body := testGuardPPTXNotes(t)
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.presentationml.presentation")
		w.Header().Set("Content-Disposition", `attachment; filename="briefing.pptx"`)
		_, _ = w.Write(body)
		return nil
	})
	rr := httptest.NewRecorder()
	if err := g.serveNext(rr, wmDownloadRequest("req-pptx-notes-download"), next); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rr.Body.Bytes(), body) {
		t.Fatal("PPTX notes observation must preserve the original package")
	}
	records := readAPIRecords(t, logPath)
	if len(records) != 1 {
		t.Fatalf("want one event, got %d", len(records))
	}
	assertSensitiveFileEvent(t, records[0].Details, "DOWNLOAD")
	if len(records[0].FileObservations) != 1 || len(records[0].FileObservations[0].SensitiveTypes) != 1 || records[0].FileObservations[0].SensitiveTypes[0] != "phone" {
		t.Fatalf("PPTX notes download labels missing: %+v", records[0].FileObservations)
	}
	found := false
	for _, detail := range records[0].Details {
		if detail.RuleID == "file.sensitive_content" && detail.Evidence["source_part"] == "ppt/notesSlides/notesSlide1.xml" && detail.Evidence["scope"] == "PPTX_NOTES" && detail.Evidence["field"] == "notesSlide1!p1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("PPTX notes source evidence missing: %+v", records[0].Details)
	}
}
