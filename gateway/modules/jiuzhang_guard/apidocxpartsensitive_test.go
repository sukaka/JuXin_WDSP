package jiuzhang_guard

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testGuardDOCXHeader(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for name, content := range map[string]string{
		"word/document.xml": `<w:document><w:body/></w:document>`,
		"word/header1.xml":  `<w:hdr><w:p><w:r><w:t>13800138000</w:t></w:r></w:p></w:hdr>`,
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

func TestServeNextDownloadDOCXHeaderSensitiveContent(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	g.APISensitiveValueRules = fileSensitiveGuardRules()
	body := testGuardDOCXHeader(t)
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
		w.Header().Set("Content-Disposition", `attachment; filename="report.docx"`)
		_, _ = w.Write(body)
		return nil
	})
	rr := httptest.NewRecorder()
	if err := g.serveNext(rr, wmDownloadRequest("req-docx-header-download"), next); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rr.Body.Bytes(), body) {
		t.Fatal("DOCX header observation must preserve the original package")
	}
	records := readAPIRecords(t, logPath)
	if len(records) != 1 {
		t.Fatalf("want one event, got %d", len(records))
	}
	assertSensitiveFileEvent(t, records[0].Details, "DOWNLOAD")
	if len(records[0].FileObservations) != 1 || len(records[0].FileObservations[0].SensitiveTypes) != 1 || records[0].FileObservations[0].SensitiveTypes[0] != "phone" {
		t.Fatalf("DOCX header download labels missing: %+v", records[0].FileObservations)
	}
	found := false
	for _, detail := range records[0].Details {
		if detail.RuleID == "file.sensitive_content" && detail.Evidence["source_part"] == "word/header1.xml" && detail.Evidence["scope"] == "DOCX_HEADER_FOOTER" {
			found = true
		}
	}
	if !found {
		t.Fatalf("DOCX header source evidence missing: %+v", records[0].Details)
	}
}
