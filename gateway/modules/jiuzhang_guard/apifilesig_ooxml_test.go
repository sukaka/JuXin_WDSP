package jiuzhang_guard

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/response"
)

func testGuardOOXMLSignaturePackage(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	writer := zip.NewWriter(&buf)
	for _, entry := range []struct{ name, body string }{
		{"[Content_Types].xml", `<Types/>`},
		{"_rels/.rels", `<Relationships/>`},
		{"word/document.xml", `<document><text>ordinary content</text></document>`},
	} {
		part, err := writer.CreateHeader(&zip.FileHeader{Name: entry.name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write([]byte(entry.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.SetComment("legacy-comment"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestServeNextFileSignatureOOXMLDownload(t *testing.T) {
	g, logPath := newFileSignatureTestGuard(t, "OBSERVE", "k2026")
	original := testGuardOOXMLSignaturePackage(t)
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
		w.Header().Set("Content-Disposition", `attachment; filename="report.docx"`)
		_, _ = w.Write(original)
		return nil
	})
	rr := httptest.NewRecorder()
	if err := g.serveNext(rr, wmDownloadRequest("req-ooxml-signature"), next); err != nil {
		t.Fatal(err)
	}
	if rr.Code != http.StatusOK || bytes.Equal(rr.Body.Bytes(), original) {
		t.Fatalf("OOXML signature was not embedded: HTTP %d", rr.Code)
	}
	if got := rr.Header().Get("Content-Length"); got != strconv.Itoa(rr.Body.Len()) {
		t.Fatalf("Content-Length = %q, want %d", got, rr.Body.Len())
	}
	if _, err := zip.NewReader(bytes.NewReader(rr.Body.Bytes()), int64(rr.Body.Len())); err != nil {
		t.Fatalf("signed OOXML is not a valid ZIP: %v", err)
	}
	recovered, token, signed, err := response.RecoverOOXMLSignedContent(rr.Body.Bytes())
	if err != nil || !signed || token == "" || !bytes.Equal(recovered, original) {
		t.Fatalf("signed content does not recover the original: signed=%v err=%v", signed, err)
	}
	records := readAPIRecords(t, logPath)
	if len(records) != 1 {
		t.Fatalf("want one API event, got %d", len(records))
	}
	if len(records[0].FileObservations) != 1 || records[0].FileObservations[0].ContentSHA256 != response.FileContentSHA256(rr.Body.Bytes()) {
		t.Fatalf("file fingerprint must cover the final signed content: %+v", records[0].FileObservations)
	}
	found := false
	for _, detail := range records[0].Details {
		if detail.RuleID != "file.signature_embedded" {
			continue
		}
		found = true
		if detail.Evidence["kid"] != "k2026" || detail.Evidence["filename"] != "report.docx" {
			t.Fatalf("unexpected signature evidence: %+v", detail.Evidence)
		}
		for _, value := range detail.Evidence {
			if strings.Contains(value, sigE2EKeyHex) || strings.Contains(value, token) {
				t.Fatalf("signature evidence leaks key material or token: %+v", detail.Evidence)
			}
		}
	}
	if !found {
		t.Fatalf("file.signature_embedded missing: %+v", records[0].Details)
	}
}

func TestServeNextFileSignatureOOXMLFailurePassesThrough(t *testing.T) {
	g, logPath := newFileSignatureTestGuard(t, "OBSERVE", "k2026")
	original := []byte("not-a-zip")
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
		w.Header().Set("Content-Disposition", `attachment; filename="report.docx"`)
		_, _ = w.Write(original)
		return nil
	})
	rr := httptest.NewRecorder()
	if err := g.serveNext(rr, wmDownloadRequest("req-ooxml-signature-invalid"), next); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rr.Body.Bytes(), original) {
		t.Fatal("invalid OOXML must pass through unchanged")
	}
	for _, detail := range readAPIRecords(t, logPath)[0].Details {
		if detail.RuleID == "file.signature_embedded" {
			t.Fatal("failed signature must not be reported as embedded")
		}
	}
}
