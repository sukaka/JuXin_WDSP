package jiuzhang_guard

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

func fileSensitiveGuardRules() []detectors.SensitiveValueRule {
	return []detectors.SensitiveValueRule{{DataType: "phone", Regex: `^1[3-9]\d{9}$`, Locations: []string{"file"}, Level: "SENSITIVE"}}
}

func TestServeNextUploadFileSensitiveContent(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	g.APISensitiveValueRules = fileSensitiveGuardRules()
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
		return nil
	})
	req := fileCompUploadRequest("req-sensitive-upload", "contacts.csv", "name,phone\nAlex,13800138000\n")
	req.URL.Path = "/api/v1/files/upload"
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatal(err)
	}
	records := readAPIRecords(t, logPath)
	if len(records) != 1 {
		t.Fatalf("want one event, got %d", len(records))
	}
	if !records[0].IsAPI {
		t.Fatal("file asset observations require API traffic")
	}
	assertSensitiveFileEvent(t, records[0].Details, "UPLOAD")
	if len(records[0].FileObservations) != 1 || len(records[0].FileObservations[0].SensitiveTypes) != 1 || records[0].FileObservations[0].SensitiveTypes[0] != "phone" {
		t.Fatalf("upload asset types missing: %+v", records[0].FileObservations)
	}
}

func TestServeNextDownloadFileSensitiveContent(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	g.APISensitiveValueRules = fileSensitiveGuardRules()
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", `attachment; filename="contacts.csv"`)
		_, _ = io.WriteString(w, "name,phone\nAlex,13800138000\n")
		return nil
	})
	rr := httptest.NewRecorder()
	if err := g.serveNext(rr, wmDownloadRequest("req-sensitive-download"), next); err != nil {
		t.Fatal(err)
	}
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "13800138000") {
		t.Fatalf("observation must preserve the original response: %d", rr.Code)
	}
	records := readAPIRecords(t, logPath)
	if len(records) != 1 {
		t.Fatalf("want one event, got %d", len(records))
	}
	assertSensitiveFileEvent(t, records[0].Details, "DOWNLOAD")
	if len(records[0].FileObservations) != 1 || len(records[0].FileObservations[0].SensitiveTypes) != 1 || records[0].FileObservations[0].SensitiveTypes[0] != "phone" {
		t.Fatalf("download asset types missing: %+v", records[0].FileObservations)
	}
}

func assertSensitiveFileEvent(t *testing.T, details []dsctx.DetectorMatch, direction string) {
	t.Helper()
	found := false
	for _, detail := range details {
		if detail.RuleID != "file.sensitive_content" {
			continue
		}
		found = true
		if detail.Category != "OBSERVE" || detail.Evidence["data_type"] != "phone" || detail.Evidence["direction"] != direction {
			t.Fatalf("unexpected sensitive-file event: %+v", detail)
		}
		for _, value := range detail.Evidence {
			if strings.Contains(value, "13800138000") {
				t.Fatalf("event leaked a phone number: %+v", detail.Evidence)
			}
		}
	}
	if !found {
		t.Fatalf("sensitive content event missing: %+v", details)
	}
}
