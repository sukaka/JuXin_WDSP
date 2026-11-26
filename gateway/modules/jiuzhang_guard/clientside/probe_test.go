package clientside

import (
	"crypto/sha512"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestServeProbeScript_HeadersSRIAndPrivacyBoundary(t *testing.T) {
	// 1. Verify precomputed SHA-384 SRI matches exact ProbeScriptJS bytes.
	sum := sha512.Sum384([]byte(ProbeScriptJS))
	wantSRI := "sha384-" + base64.StdEncoding.EncodeToString(sum[:])
	if ProbeScriptSRI != wantSRI {
		t.Fatalf("ProbeScriptSRI mismatch:\ngot:  %q\nwant: %q", ProbeScriptSRI, wantSRI)
	}
	tag := ProbeScriptTag()
	wantTag := `<script src="/_wdsp/cs/v1/probe.js" integrity="` + wantSRI + `" defer></script>`
	if tag != wantTag {
		t.Fatalf("ProbeScriptTag = %q, want %q", tag, wantTag)
	}

	// 2. Privacy & security audit: probe MUST monitor MutationObserver/fetch/XHR/sendBeacon
	//    and NEVER touch cookies, input values, passwords, FormData, or web storage.
	requiredTokens := []string{"MutationObserver", "window.fetch", "XMLHttpRequest", "sendBeacon", "/_wdsp/csp/v1/report"}
	for _, tok := range requiredTokens {
		if !strings.Contains(ProbeScriptJS, tok) {
			t.Errorf("probe JS missing required monitor %q", tok)
		}
	}
	forbiddenTokens := []string{"cookie", "password", ".value", "FormData", "localStorage", "sessionStorage"}
	lowerJS := strings.ToLower(ProbeScriptJS)
	for _, bad := range forbiddenTokens {
		if strings.Contains(lowerJS, strings.ToLower(bad)) {
			t.Errorf("probe JS MUST NEVER reference sensitive token %q", bad)
		}
	}

	// 3. GET /_wdsp/cs/v1/probe.js -> 200 with exact headers and body.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://shop.example.com/_wdsp/cs/v1/probe.js", nil)
	status := ServeProbeScript(rec, req)
	if status != http.StatusOK || rec.Code != http.StatusOK {
		t.Fatalf("GET probe.js status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/javascript; charset=utf-8" {
		t.Fatalf("Content-Type = %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=300" {
		t.Fatalf("Cache-Control = %q", cc)
	}
	if cl := rec.Header().Get("Content-Length"); cl != strconv.Itoa(len(ProbeScriptJS)) {
		t.Fatalf("Content-Length = %q, want %d", cl, len(ProbeScriptJS))
	}
	if rec.Body.String() != ProbeScriptJS {
		t.Fatal("GET probe.js body mismatch")
	}

	// 4. HEAD -> 200 empty body.
	recHead := httptest.NewRecorder()
	reqHead := httptest.NewRequest(http.MethodHead, "https://shop.example.com/_wdsp/cs/v1/probe.js", nil)
	if st := ServeProbeScript(recHead, reqHead); st != http.StatusOK || recHead.Body.Len() != 0 {
		t.Fatalf("HEAD probe.js got status=%d bodyLen=%d", st, recHead.Body.Len())
	}

	// 5. POST -> 405.
	recPost := httptest.NewRecorder()
	reqPost := httptest.NewRequest(http.MethodPost, "https://shop.example.com/_wdsp/cs/v1/probe.js", nil)
	if st := ServeProbeScript(recPost, reqPost); st != http.StatusMethodNotAllowed || recPost.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST probe.js expected 405 Allow GET,HEAD, got status=%d allow=%q", st, recPost.Header().Get("Allow"))
	}
}
