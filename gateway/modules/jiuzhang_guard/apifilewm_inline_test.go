package jiuzhang_guard

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/response"
)

func inlineHTMLWatermarkGuard(t *testing.T, include bool) (*Guard, string) {
	t.Helper()
	g, logPath := newAPITestGuard(t, "OBSERVE", nil)
	cfg, err := response.NewFileWatermarkConfig(true, "trace ip={ip}", []string{"text/html"}, "")
	if err != nil {
		t.Fatal(err)
	}
	cfg.IncludeInlineHTML = include
	g.apiFileWatermark = cfg
	return g, logPath
}

func TestServeNextInlineHTMLWatermark(t *testing.T) {
	g, logPath := inlineHTMLWatermarkGuard(t, true)
	const payload = `<html><body>report</body></html>`
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, payload)
		return nil
	})
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, wmDownloadRequest("req-inline-html-watermark"), next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	body, _ := io.ReadAll(rec.Result().Body)
	want := payload + "\n<!-- trace ip=203.0.113.9 -->"
	if string(body) != want {
		t.Fatalf("inline html body=%q want %q", body, want)
	}
	if got := rec.Header().Get("Content-Length"); got != strconv.Itoa(len(body)) {
		t.Fatalf("content-length=%s want %d", got, len(body))
	}
	records := readAPIRecords(t, logPath)
	if len(records) != 1 {
		t.Fatalf("events=%d", len(records))
	}
	found := false
	for _, detail := range records[0].Details {
		if detail.RuleID != "file.watermark_applied" {
			continue
		}
		found = true
		if detail.Evidence["delivery"] != "INLINE_HTML" || detail.Evidence["mime"] != "text/html" ||
			detail.Category != "INFO" || strings.Contains(detail.Evidence["mime"], "trace ip=") {
			t.Fatalf("inline watermark detail=%+v", detail)
		}
	}
	if !found {
		t.Fatalf("inline watermark detail missing: %+v", records[0].Details)
	}
}

func TestServeNextInlineHTMLWatermarkDefaultOff(t *testing.T) {
	g, _ := inlineHTMLWatermarkGuard(t, false)
	const payload = `<html><body>unchanged</body></html>`
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, payload)
		return nil
	})
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, wmDownloadRequest("req-inline-html-off"), next); err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(rec.Result().Body)
	if string(body) != payload {
		t.Fatalf("default-off inline html changed: %q", body)
	}
}

func TestServeNextInlineHTMLWatermarkDownloadCompatibility(t *testing.T) {
	g, logPath := inlineHTMLWatermarkGuard(t, true)
	const payload = `<html><body>download</body></html>`
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Disposition", `attachment; filename="report.html"`)
		_, _ = io.WriteString(w, payload)
		return nil
	})
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, wmDownloadRequest("req-inline-html-download"), next); err != nil {
		t.Fatal(err)
	}
	if body, _ := io.ReadAll(rec.Result().Body); !strings.Contains(string(body), "<!-- trace ip=") {
		t.Fatalf("download watermark missing: %q", body)
	}
	records := readAPIRecords(t, logPath)
	for _, detail := range records[0].Details {
		if detail.RuleID == "file.watermark_applied" && detail.Evidence["delivery"] != "DOWNLOAD" {
			t.Fatalf("download delivery changed: %+v", detail)
		}
	}
}

func TestServeNextInlineHTMLWatermarkSkipsUnsafeShapes(t *testing.T) {
	for _, tc := range []struct {
		name         string
		contentType  string
		status       int
		encoding     string
		contentRange string
		disposition  string
		oversize     bool
	}{
		{"non-html", "text/plain", http.StatusOK, "", "", "", false},
		{"error-status", "text/html", http.StatusInternalServerError, "", "", "", false},
		{"compressed", "text/html", http.StatusOK, "gzip", "", "", false},
		{"partial", "text/html", http.StatusPartialContent, "", "bytes 0-10/100", "", false},
		{"sse", "text/event-stream", http.StatusOK, "", "", "", false},
		{"existing-download-without-observation", "text/plain", http.StatusOK, "", "", `attachment; filename="plain.txt"`, false},
		{"overflow", "text/html", http.StatusOK, "", "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, _ := inlineHTMLWatermarkGuard(t, true)
			if tc.oversize {
				g.APIResponseCaptureMaxBytes = 64
			}
			payload := `<html><body>original</body></html>`
			if tc.oversize {
				payload = strings.Repeat("x", 128)
			}
			next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.Header().Set("Content-Type", tc.contentType)
				if tc.encoding != "" {
					w.Header().Set("Content-Encoding", tc.encoding)
				}
				if tc.contentRange != "" {
					w.Header().Set("Content-Range", tc.contentRange)
				}
				if tc.disposition != "" {
					w.Header().Set("Content-Disposition", tc.disposition)
				}
				if tc.status != 0 {
					w.WriteHeader(tc.status)
				}
				_, _ = io.WriteString(w, payload)
				return nil
			})
			rec := httptest.NewRecorder()
			if err := g.serveNext(rec, wmDownloadRequest("req-inline-html-skip-"+tc.name), next); err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(rec.Result().Body)
			if string(body) != payload {
				t.Fatalf("unsafe shape must remain unchanged: %q", body)
			}
		})
	}
}
