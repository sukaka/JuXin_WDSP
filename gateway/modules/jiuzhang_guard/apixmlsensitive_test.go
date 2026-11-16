package jiuzhang_guard

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServeNextUploadXMLSensitiveContent(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	g.APISensitiveValueRules = fileSensitiveGuardRules()
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
		return nil
	})
	req := fileCompUploadRequest("req-xml-upload", "contacts.xml", `<contacts><contact><phone>13800138000</phone></contact></contacts>`)
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
		t.Fatalf("XML upload labels missing: %+v", records[0].FileObservations)
	}
}

func TestServeNextDownloadXMLSensitiveContent(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	g.APISensitiveValueRules = fileSensitiveGuardRules()
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("Content-Disposition", `attachment; filename="contacts.xml"`)
		_, _ = io.WriteString(w, `<contacts><contact><phone>13800138000</phone></contact></contacts>`)
		return nil
	})
	if err := g.serveNext(httptest.NewRecorder(), wmDownloadRequest("req-xml-download"), next); err != nil {
		t.Fatal(err)
	}
	records := readAPIRecords(t, logPath)
	if len(records) != 1 {
		t.Fatalf("want one event, got %d", len(records))
	}
	assertSensitiveFileEvent(t, records[0].Details, "DOWNLOAD")
	if len(records[0].FileObservations) != 1 || len(records[0].FileObservations[0].SensitiveTypes) != 1 || records[0].FileObservations[0].SensitiveTypes[0] != "phone" {
		t.Fatalf("XML download labels missing: %+v", records[0].FileObservations)
	}
}
