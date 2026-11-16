package jiuzhang_guard

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

func TestServeNextUploadFileContentTypeMismatchObserves(t *testing.T) {
	g, logPath := newFileComplianceTestGuard(t, "PROTECT", []detectors.FileComplianceRule{{Direction: "UPLOAD", Match: "MIME", Value: "image/", Action: "OBSERVE"}})
	originCalls := 0
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		originCalls++
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
		return nil
	})
	req := fileCompUploadRequest("req-upload-content-1", "avatar.png", "MZ-FAKE-UPLOAD-CONTENT")
	rr := httptest.NewRecorder()
	if err := g.serveNext(rr, req, next); err != nil {
		t.Fatal(err)
	}
	if originCalls != 1 || rr.Code != http.StatusOK {
		t.Fatalf("observation must pass upload through: calls=%d status=%d", originCalls, rr.Code)
	}
	records := readAPIRecords(t, logPath)
	if len(records) != 1 {
		t.Fatalf("want one API event, got %d", len(records))
	}
	found := false
	for _, detail := range records[0].Details {
		if detail.RuleID != "file.content_type_mismatch" {
			continue
		}
		found = true
		if detail.Category != "OBSERVE" || detail.Evidence["direction"] != "UPLOAD" || detail.Evidence["detected_type"] != "windows_executable" {
			t.Fatalf("unexpected upload event: %+v", detail)
		}
		for _, value := range detail.Evidence {
			if strings.Contains(value, "FAKE-UPLOAD-CONTENT") {
				t.Fatalf("upload event leaked body: %+v", detail.Evidence)
			}
		}
	}
	if !found {
		t.Fatalf("upload signature event missing: %+v", records[0].Details)
	}
}
