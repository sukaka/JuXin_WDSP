package jiuzhang_guard

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testGuardXLSX(t *testing.T, text string) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for name, content := range map[string]string{
		"xl/workbook.xml":          `<workbook><sheets><sheet name="C" sheetId="1" r:id="rId1"/></sheets></workbook>`,
		"xl/worksheets/sheet1.xml": `<worksheet><c r="A1" t="inlineStr"><is><t>` + text + `</t></is></c></worksheet>`,
	} {
		part, err := writer.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestServeNextUploadXLSXSensitiveContent(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	g.APISensitiveValueRules = fileSensitiveGuardRules()
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
		return nil
	})
	req := fileCompUploadRequest("req-xlsx-upload", "contacts.xlsx", string(testGuardXLSX(t, "13800138000")))
	req.URL.Path = "/api/v1/files/upload"
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatal(err)
	}
	records := readAPIRecords(t, logPath)
	if len(records) != 1 {
		t.Fatalf("want one event, got %d", len(records))
	}
	assertSensitiveFileEvent(t, records[0].Details, "UPLOAD")
	if len(records[0].FileObservations) != 1 || len(records[0].FileObservations[0].SensitiveTypes) != 1 || records[0].FileObservations[0].SensitiveTypes[0] != "phone" {
		t.Fatalf("XLSX upload labels missing: %+v", records[0].FileObservations)
	}
}

func TestServeNextDownloadXLSXSensitiveContent(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	g.APISensitiveValueRules = fileSensitiveGuardRules()
	body := testGuardXLSX(t, "13800138000")
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
		w.Header().Set("Content-Disposition", `attachment; filename="contacts.xlsx"`)
		_, _ = w.Write(body)
		return nil
	})
	rr := httptest.NewRecorder()
	if err := g.serveNext(rr, wmDownloadRequest("req-xlsx-download"), next); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rr.Body.Bytes(), body) {
		t.Fatal("XLSX observation must preserve the original package")
	}
	records := readAPIRecords(t, logPath)
	if len(records) != 1 {
		t.Fatalf("want one event, got %d", len(records))
	}
	assertSensitiveFileEvent(t, records[0].Details, "DOWNLOAD")
	if len(records[0].FileObservations) != 1 || len(records[0].FileObservations[0].SensitiveTypes) != 1 || records[0].FileObservations[0].SensitiveTypes[0] != "phone" {
		t.Fatalf("XLSX download labels missing: %+v", records[0].FileObservations)
	}
}
