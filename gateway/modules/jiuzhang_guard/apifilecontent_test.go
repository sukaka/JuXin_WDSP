package jiuzhang_guard

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

func TestServeNextFileContentTypeMismatchObserves(t *testing.T) {
	g, logPath := newFileComplianceTestGuard(t, "PROTECT", []detectors.FileComplianceRule{{Direction: "DOWNLOAD", Match: "MIME", Value: "image/", Action: "OBSERVE"}})
	const payload = "MZ-FAKE-EXECUTABLE-PAYLOAD"
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Content-Disposition", `attachment; filename="portrait.png"`)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, payload)
		return nil
	})
	rr := httptest.NewRecorder()
	if err := g.serveNext(rr, wmDownloadRequest("req-file-content-1"), next); err != nil {
		t.Fatal(err)
	}
	if rr.Code != http.StatusOK || rr.Body.String() != payload {
		t.Fatalf("observation must preserve the response: status=%d body=%q", rr.Code, rr.Body.String())
	}
	records := readAPIRecords(t, logPath)
	if len(records) != 1 {
		t.Fatalf("want one event, got %d", len(records))
	}
	found := false
	for _, detail := range records[0].Details {
		if detail.RuleID != "file.content_type_mismatch" {
			continue
		}
		found = true
		if detail.Category != "OBSERVE" || detail.Evidence["detected_type"] != "windows_executable" || detail.Evidence["declared_class"] != "image" {
			t.Fatalf("unexpected event: %+v", detail)
		}
		for _, value := range detail.Evidence {
			if strings.Contains(value, "FAKE-EXECUTABLE-PAYLOAD") {
				t.Fatalf("event leaked file content: %+v", detail.Evidence)
			}
		}
	}
	if !found {
		t.Fatalf("content-type event missing: %+v", records[0].Details)
	}
}

func TestServeNextFileContentSpillDisclosesNoInspection(t *testing.T) {
	g, logPath := newFileComplianceTestGuard(t, "PROTECT", []detectors.FileComplianceRule{{Direction: "DOWNLOAD", Match: "MIME", Value: "image/", Action: "OBSERVE"}})
	g.APIResponseCaptureMaxBytes = 16
	payload := "MZ" + strings.Repeat("X", 4096)
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Content-Disposition", `attachment; filename="portrait.png"`)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, payload)
		return nil
	})
	rr := httptest.NewRecorder()
	if err := g.serveNext(rr, wmDownloadRequest("req-file-content-2"), next); err != nil {
		t.Fatal(err)
	}
	if rr.Code != http.StatusOK || rr.Body.String() != payload {
		t.Fatalf("spilled response must remain intact: status=%d len=%d", rr.Code, rr.Body.Len())
	}
	found := false
	for _, record := range readAPIRecords(t, logPath) {
		for _, detail := range record.Details {
			if detail.RuleID == "file.content_not_inspected" {
				found = true
				if detail.Evidence["reason"] != "STREAMED" {
					t.Fatalf("unexpected inspection disclosure: %+v", detail)
				}
			}
			if detail.RuleID == "file.content_type_mismatch" {
				t.Fatalf("unavailable body must not produce a mismatch: %+v", detail)
			}
		}
	}
	if !found {
		t.Fatal("spilled response must disclose that content was not inspected")
	}
}
