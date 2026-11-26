package clientside

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func sha256SRI(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}

func TestScanAndRewriteHTML_ExternalInlineSRITamperAndStripping(t *testing.T) {
	pinnedSRI := "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
	wrongSRI := "sha384-WRONGHASHWRONGHASHWRONGHASHWRONGHASHWRONGHASHWRONGHASHWRONGHASH=="
	blockedInlineJS := "evilSteal();"
	blockedInlineHash := sha256SRI(blockedInlineJS)
	okInlineJS := "window.appReady=true;"
	okInlineHash := sha256SRI(okInlineJS)

	pol := &Policy{
		SchemaVersion:            1,
		ApplicationID:            "app-1",
		Mode:                     ModeProtect,
		Version:                  4,
		CSPMode:                  CSPModeEnforce,
		SensitivePaths:           []string{"/checkout"},
		ProbeEnabled:             true,
		StripUnauthorizedScripts: true,
		AllowedScriptOrigins:     []string{"'self'", "https://trusted.cdn.example"},
		AuthorizedScripts: []AuthorizedScript{
			{
				ScriptURL:  "https://pinned.cdn.example/sdk.js",
				ScriptType: ScriptTypeExternal,
				SRIHash:    pinnedSRI,
				Status:     ScriptStatusAuthorized,
			},
			{
				ScriptURL:  "https://trusted.cdn.example/blocked.js",
				ScriptType: ScriptTypeExternal,
				Status:     ScriptStatusBlocked,
			},
			{
				ScriptURL:  "inline:" + blockedInlineHash,
				ScriptType: ScriptTypeInlineHash,
				SRIHash:    blockedInlineHash,
				Status:     ScriptStatusBlocked,
			},
		},
	}

	eng, err := NewEngine(pol, EngineOptions{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	inputHTML := `<!doctype html><html><head><title>Checkout</title>` +
		`<!-- <script src="https://commented.evil.example/ignored.js"></script> -->` +
		`<script src="/static/app.js?v=1"></script>` +
		`<script src="https://trusted.cdn.example/ok.js"></script>` +
		`<script src="https://pinned.cdn.example/sdk.js" integrity="` + pinnedSRI + `"></script>` +
		`<script src="https://pinned.cdn.example/sdk.js?v=2" integrity="` + wrongSRI + `"></script>` +
		`<script src="https://trusted.cdn.example/blocked.js"></script>` +
		`<script src="https://magecart.evil.example/skim.js?secret=4111"></script>` +
		`<script type="application/ld+json">{"@type":"Product"}</script>` +
		`<script>` + okInlineJS + `</script>` +
		`<script>` + blockedInlineJS + `</script>` +
		`</head><body><h1>Pay</h1></body></html>`

	res := eng.ScanAndRewriteHTML([]byte(inputHTML), ScanContext{
		Scheme:      "https",
		Host:        "shop.example.com",
		PagePath:    "/checkout",
		InjectProbe: true,
	})

	if !res.Modified || !res.ProbeInjected {
		t.Fatalf("expected modified=true probeInjected=true, got %+v", res)
	}
	if res.StrippedCount != 4 {
		t.Fatalf("expected 4 stripped scripts (tampered sdk, blocked external, unauthorized evil, blocked inline), got %d", res.StrippedCount)
	}

	out := string(res.Body)
	// Kept scripts & data blocks & comments
	if !strings.Contains(out, `src="/static/app.js?v=1"`) {
		t.Errorf("same-origin script should be preserved: %s", out)
	}
	if !strings.Contains(out, `src="https://trusted.cdn.example/ok.js"`) {
		t.Errorf("allowed-origin script should be preserved: %s", out)
	}
	if !strings.Contains(out, `integrity="`+pinnedSRI+`"`) {
		t.Errorf("matching-SRI pinned script should be preserved: %s", out)
	}
	if !strings.Contains(out, `type="application/ld+json"`) {
		t.Errorf("JSON-LD data block should be preserved: %s", out)
	}
	if !strings.Contains(out, okInlineJS) {
		t.Errorf("non-blocked inline script should be preserved: %s", out)
	}
	if !strings.Contains(out, `<!-- <script src="https://commented.evil.example/ignored.js"></script> -->`) {
		t.Errorf("HTML comment must be preserved untouched: %s", out)
	}

	// Stripped scripts
	for _, bad := range []string{wrongSRI, "blocked.js", "magecart.evil.example", blockedInlineJS} {
		if strings.Contains(out, bad) {
			t.Errorf("expected %q to be stripped from HTML, got: %s", bad, out)
		}
	}

	// Probe injected right before </head>
	probeIdx := strings.Index(out, ProbeScriptTag())
	headCloseIdx := strings.Index(out, "</head>")
	if probeIdx < 0 || headCloseIdx < 0 || probeIdx > headCloseIdx {
		t.Errorf("expected probe script injected before </head>: probeIdx=%d headCloseIdx=%d", probeIdx, headCloseIdx)
	}

	// Verify findings: no secret query string leaked, proper types and actions.
	var foundTampered, foundUnauthEvil, foundBlockedExt, foundBlockedInline, foundInlineObs bool
	for _, f := range res.Findings {
		if strings.Contains(f.ScriptURL, "secret=") {
			t.Fatalf("query string must be stripped from script_url: %+v", f)
		}
		if strings.Contains(f.ScriptURL, "commented.evil.example") {
			t.Fatalf("HTML comment must not trigger script finding: %+v", f)
		}
		switch {
		case f.ViolationType == ViolationScriptTampered && f.ScriptURL == "https://pinned.cdn.example/sdk.js":
			foundTampered = true
			if f.ExpectedSRI != pinnedSRI || f.ObservedSRI != wrongSRI || f.ActionTaken != ActionStripped || f.Reason != "SRI_MISMATCH" {
				t.Errorf("unexpected tampered finding: %+v", f)
			}
		case f.ViolationType == ViolationUnauthorizedScript && f.ScriptURL == "https://magecart.evil.example/skim.js":
			foundUnauthEvil = true
			if f.ActionTaken != ActionStripped || f.ScriptOrigin != "https://magecart.evil.example" {
				t.Errorf("unexpected unauthorized finding: %+v", f)
			}
		case f.ViolationType == ViolationUnauthorizedScript && f.ScriptURL == "https://trusted.cdn.example/blocked.js":
			foundBlockedExt = true
			if f.Reason != "SCRIPT_EXPLICITLY_BLOCKED" || f.ActionTaken != ActionStripped {
				t.Errorf("unexpected blocked external finding: %+v", f)
			}
		case f.ViolationType == ViolationUnauthorizedScript && f.ObservedSRI == blockedInlineHash:
			foundBlockedInline = true
			if f.ScriptType != ScriptTypeInlineHash || f.ActionTaken != ActionStripped {
				t.Errorf("unexpected blocked inline finding: %+v", f)
			}
		case f.ViolationType == ViolationScriptObserved && f.ObservedSRI == okInlineHash:
			foundInlineObs = true
			if f.ScriptType != ScriptTypeInlineHash || f.ScriptURL != "inline:"+okInlineHash {
				t.Errorf("unexpected inline observed finding: %+v", f)
			}
		}
	}
	if !foundTampered || !foundUnauthEvil || !foundBlockedExt || !foundBlockedInline || !foundInlineObs {
		t.Fatalf("missing expected findings: tampered=%v unauthEvil=%v blockedExt=%v blockedInline=%v inlineObs=%v; all=%+v",
			foundTampered, foundUnauthEvil, foundBlockedExt, foundBlockedInline, foundInlineObs, res.Findings)
	}
}

func TestScanAndRewriteHTML_ObserveDoesNotStripAndBodyFallbackProbe(t *testing.T) {
	eng, err := NewEngine(&Policy{
		SchemaVersion:            1,
		Mode:                     ModeObserve,
		CSPMode:                  CSPModeReportOnly,
		SensitivePaths:           []string{"/pay"},
		ProbeEnabled:             true,
		StripUnauthorizedScripts: true, // MUST NOT strip in OBSERVE mode!
		AllowedScriptOrigins:     []string{"'self'"},
	}, EngineOptions{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// No </head> tag -> probe falls back to before </body>.
	htmlDoc := `<html><body><script>var s="</head>";</script><script src="https://evil.example/x.js"></script><p>Pay</p></body></html>`
	res := eng.ScanAndRewriteHTML([]byte(htmlDoc), ScanContext{
		Scheme:      "https",
		Host:        "shop.example.com",
		PagePath:    "/pay",
		InjectProbe: true,
	})
	out := string(res.Body)
	if res.StrippedCount != 0 {
		t.Fatalf("OBSERVE mode must never strip scripts, stripped=%d", res.StrippedCount)
	}
	if !strings.Contains(out, `https://evil.example/x.js`) {
		t.Fatalf("OBSERVE mode must preserve script tag: %s", out)
	}
	if !res.ProbeInjected {
		t.Fatal("expected probe injected before </body>")
	}
	probeIdx := strings.Index(out, ProbeScriptTag())
	bodyCloseIdx := strings.Index(out, "</body>")
	if probeIdx < 0 || bodyCloseIdx < 0 || probeIdx > bodyCloseIdx {
		t.Fatalf("probe must be injected before </body> (not inside JS string </head>): %s", out)
	}
	// Ensure JS string "</head>" inside inline script was not split!
	if !strings.Contains(out, `var s="</head>";`) {
		t.Fatalf("inline JS string containing </head> was corrupted: %s", out)
	}
}

func TestScriptDedupCache_TTLAndBoundedLRU(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	c := newScriptDedupCache(60*time.Second, 3)

	if !c.ShouldEmit("https://a.com/1.js", "", now) {
		t.Fatal("first sight must emit")
	}
	if c.ShouldEmit("https://a.com/1.js", "", now.Add(30*time.Second)) {
		t.Fatal("duplicate within 60s must be deduped")
	}
	if !c.ShouldEmit("https://a.com/1.js", "sha384-NEW", now.Add(30*time.Second)) {
		t.Fatal("different SRI hash must emit")
	}
	if !c.ShouldEmit("https://a.com/1.js", "", now.Add(61*time.Second)) {
		t.Fatal("expired TTL must emit again")
	}

	// Fill past maxEntries=3 and verify strict bound & LRU eviction.
	c.ShouldEmit("https://a.com/2.js", "", now.Add(62*time.Second))
	c.ShouldEmit("https://a.com/3.js", "", now.Add(63*time.Second))
	c.ShouldEmit("https://a.com/4.js", "", now.Add(64*time.Second))
	if c.Len() > 3 {
		t.Fatalf("dedup cache exceeded maxEntries: got %d", c.Len())
	}

	// Concurrent race check.
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				c.ShouldEmit(fmt.Sprintf("https://cdn.example/%d-%d.js", id, i%10), "", now.Add(time.Duration(i)*time.Second))
			}
		}(g)
	}
	wg.Wait()
	if c.Len() > 3 {
		t.Fatalf("dedup cache exceeded bound after concurrent writes: %d", c.Len())
	}
}

func TestHTMLResponseWrapper_BoundedUncompressedCompressedStreamingOversized(t *testing.T) {
	eng, err := NewEngine(&Policy{
		SchemaVersion:            1,
		Mode:                     ModeProtect,
		CSPMode:                  CSPModeEnforce,
		SensitivePaths:           []string{"/checkout"},
		ProbeEnabled:             true,
		StripUnauthorizedScripts: true,
		AllowedScriptOrigins:     []string{"'self'"},
	}, EngineOptions{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	t.Run("2xx_uncompressed_strips_updates_content_length_and_sets_csp", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://shop.example.com/checkout", nil)
		var findings []ScanFinding
		w := eng.NewHTMLResponseWrapper(rec, req, "/checkout", func(fs []ScanFinding) {
			findings = append(findings, fs...)
		})
		raw := `<html><head></head><body><script src="https://evil.example/skim.js"></script><p>ok</p></body></html>`
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(raw))
		w.Finish(false)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if rec.Header().Get(HeaderCSP) == "" {
			t.Fatal("expected Content-Security-Policy header set")
		}
		gotBody := rec.Body.String()
		if strings.Contains(gotBody, "evil.example") {
			t.Fatalf("unauthorized script not stripped: %s", gotBody)
		}
		if !strings.Contains(gotBody, ProbeScriptPath) {
			t.Fatalf("probe script not injected: %s", gotBody)
		}
		if cl := rec.Header().Get("Content-Length"); cl != strconv.Itoa(len(gotBody)) {
			t.Fatalf("Content-Length = %q, want %d", cl, len(gotBody))
		}
		if len(findings) == 0 {
			t.Fatal("expected scan findings")
		}
	})

	t.Run("gzip_compressed_passthrough_untouched_with_csp", func(t *testing.T) {
		var gzBuf bytes.Buffer
		gz := gzip.NewWriter(&gzBuf)
		_, _ = gz.Write([]byte(`<html><head></head><body><script src="https://evil.example/skim.js"></script></body></html>`))
		_ = gz.Close()

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://shop.example.com/checkout", nil)
		calledFindings := false
		w := eng.NewHTMLResponseWrapper(rec, req, "/checkout", func(fs []ScanFinding) {
			calledFindings = true
		})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(gzBuf.Bytes())
		w.Finish(false)

		if calledFindings {
			t.Fatal("compressed HTML must NOT produce scan findings")
		}
		if !bytes.Equal(rec.Body.Bytes(), gzBuf.Bytes()) {
			t.Fatal("compressed HTML body must pass through byte-for-byte untouched")
		}
		if rec.Header().Get(HeaderCSP) == "" {
			t.Fatal("compressed 2xx HTML should still receive CSP header")
		}
	})

	t.Run("streaming_flush_passthrough_untouched", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://shop.example.com/checkout", nil)
		calledFindings := false
		w := eng.NewHTMLResponseWrapper(rec, req, "/checkout", func(fs []ScanFinding) {
			calledFindings = true
		})
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><head></head><body>`))
		w.Flush()
		_, _ = w.Write([]byte(`<script src="https://evil.example/stream.js"></script></body></html>`))
		w.Finish(false)

		if calledFindings {
			t.Fatal("streaming response after Flush must pass through without false scan claims")
		}
		if !strings.Contains(rec.Body.String(), "evil.example/stream.js") {
			t.Fatal("streaming body must pass through untouched")
		}
	})

	t.Run("oversized_over_1MiB_passthrough_untouched", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://shop.example.com/checkout", nil)
		calledFindings := false
		w := eng.NewHTMLResponseWrapper(rec, req, "/checkout", func(fs []ScanFinding) {
			calledFindings = true
		})
		bigBody := `<html><head></head><body><script src="https://evil.example/big.js"></script>` +
			strings.Repeat("x", MaxHTMLScanBytes) + `</body></html>`
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(bigBody))
		w.Finish(false)

		if calledFindings {
			t.Fatal("oversized >1MiB HTML must pass through without false scan claims")
		}
		if rec.Body.Len() != len(bigBody) {
			t.Fatalf("oversized body truncated or modified: got %d, want %d", rec.Body.Len(), len(bigBody))
		}
		if rec.Header().Get(HeaderCSP) == "" {
			t.Fatal("oversized 2xx HTML should still receive CSP header")
		}
	})

	t.Run("non_html_and_non_2xx_passthrough", func(t *testing.T) {
		recJSON := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "https://shop.example.com/checkout", nil)
		w := eng.NewHTMLResponseWrapper(recJSON, req, "/checkout", func(fs []ScanFinding) {
			t.Fatal("JSON response must not be scanned")
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"html":"<script src='https://evil.example/a.js'></script>"}`))
		w.Finish(false)
		if recJSON.Header().Get(HeaderCSP) != "" {
			t.Fatal("non-HTML response must not get CSP header")
		}

		rec404 := httptest.NewRecorder()
		w404 := eng.NewHTMLResponseWrapper(rec404, req, "/checkout", func(fs []ScanFinding) {
			t.Fatal("404 HTML must not be scanned")
		})
		w404.Header().Set("Content-Type", "text/html")
		w404.WriteHeader(http.StatusNotFound)
		_, _ = w404.Write([]byte(`<html><body>not found</body></html>`))
		w404.Finish(false)
		if rec404.Header().Get(HeaderCSP) != "" {
			t.Fatal("non-2xx HTML must not get CSP header")
		}
	})
}
