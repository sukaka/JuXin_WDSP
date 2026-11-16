package jiuzhang_guard

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServeNextUploadJSONSensitiveContent(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	g.APISensitiveValueRules = fileSensitiveGuardRules()
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
		return nil
	})
	req := fileCompUploadRequest("req-json-upload", "contacts.json", `{"contacts":[{"phone":"13800138000"}]}`)
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
		t.Fatalf("JSON upload labels missing: %+v", records[0].FileObservations)
	}
}

func TestServeNextDownloadJSONSensitiveContent(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	g.APISensitiveValueRules = fileSensitiveGuardRules()
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="contacts.json"`)
		_, _ = io.WriteString(w, `{"contacts":[{"phone":"13800138000"}]}`)
		return nil
	})
	if err := g.serveNext(httptest.NewRecorder(), wmDownloadRequest("req-json-download"), next); err != nil {
		t.Fatal(err)
	}
	records := readAPIRecords(t, logPath)
	if len(records) != 1 {
		t.Fatalf("want one event, got %d", len(records))
	}
	assertSensitiveFileEvent(t, records[0].Details, "DOWNLOAD")
	if len(records[0].FileObservations) != 1 || len(records[0].FileObservations[0].SensitiveTypes) != 1 || records[0].FileObservations[0].SensitiveTypes[0] != "phone" {
		t.Fatalf("JSON download labels missing: %+v", records[0].FileObservations)
	}
}
