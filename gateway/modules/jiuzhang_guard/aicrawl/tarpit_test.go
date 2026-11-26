package aicrawl

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLabyrinth_SignVerifyAndDeterministicOfflineRender(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	lab := NewLabyrinth(LabyrinthConfig{
		Key:            key,
		MaxDepth:       3,
		MaxConcurrency: 16,
		Delay:          0,
	})

	p0 := lab.SignPath("Example.COM", "0123456789abcdef", 0)
	if !strings.HasPrefix(p0, LabyrinthReservedNamespace+"p/0/0123456789abcdef/") {
		t.Fatalf("unexpected signed path: %s", p0)
	}
	seed, depth, ok := lab.VerifyPath("example.com", p0)
	if !ok || seed != "0123456789abcdef" || depth != 0 {
		t.Fatalf("VerifyPath failed: seed=%q depth=%d ok=%v", seed, depth, ok)
	}
	// Wrong host MUST fail MAC check.
	if _, _, ok := lab.VerifyPath("other.com", p0); ok {
		t.Fatal("VerifyPath must reject mismatched host")
	}
	// Tampered signature MUST fail MAC check.
	tampered := p0[:len(p0)-1] + "0"
	if tampered == p0 {
		tampered = p0[:len(p0)-1] + "1"
	}
	if _, _, ok := lab.VerifyPath("example.com", tampered); ok {
		t.Fatal("VerifyPath must reject tampered signature")
	}
	// Depth > maxDepth MUST fail.
	overDepth := lab.SignPath("example.com", "0123456789abcdef", 4)
	if _, _, ok := lab.VerifyPath("example.com", overDepth); ok {
		t.Fatal("VerifyPath must reject depth > maxDepth")
	}

	// Deterministic offline render: identical inputs yield identical HTML, zero external links/assets.
	html1 := lab.RenderPage("example.com", "0123456789abcdef", 0)
	html2 := lab.RenderPage("example.com", "0123456789abcdef", 0)
	if html1 != html2 {
		t.Fatal("RenderPage must be deterministic")
	}
	if strings.Contains(html1, "http://") || strings.Contains(html1, "https://") || strings.Contains(html1, "<script") {
		t.Fatalf("RenderPage must not reference external URLs or scripts: %s", html1)
	}
	if !strings.Contains(html1, `rel="nofollow noopener"`) {
		t.Fatalf("RenderPage links must carry rel=nofollow noopener: %s", html1)
	}

	// Extract signed next-hop link from depth=0 page and verify it points to depth=1.
	re := regexp.MustCompile(`href="(/_wdsp/labyrinth/v1/p/[^"]+)"`)
	matches := re.FindAllStringSubmatch(html1, -1)
	if len(matches) != labyrinthLinksPerPage {
		t.Fatalf("expected %d next-hop links at depth=0, got %d", labyrinthLinksPerPage, len(matches))
	}
	for _, m := range matches {
		_, d, valid := lab.VerifyPath("example.com", m[1])
		if !valid || d != 1 {
			t.Fatalf("invalid next-hop link %q (depth=%d valid=%v)", m[1], d, valid)
		}
	}

	// At maxDepth, ZERO next-hop links are emitted.
	terminal := lab.RenderPage("example.com", "0123456789abcdef", 3)
	if re.MatchString(terminal) {
		t.Fatalf("max_depth page must not emit further links: %s", terminal)
	}
}

func TestLabyrinth_BoundedConcurrencyAndContextCancel(t *testing.T) {
	key := make([]byte, 32)
	lab := NewLabyrinth(LabyrinthConfig{
		Key:            key,
		MaxDepth:       2,
		MaxConcurrency: 2,
		Delay:          80 * time.Millisecond,
	})
	signed := lab.SignPath("example.com", "abcdef0123456789", 0)

	var okCount, satCount atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest(http.MethodGet, "https://example.com"+signed, nil)
			rec := httptest.NewRecorder()
			tr := lab.ServeLabyrinthRequest(rec, r, signed, "ai-train=no")
			if tr.Status == http.StatusOK {
				okCount.Add(1)
			} else if tr.Status == http.StatusTooManyRequests && tr.Saturated {
				satCount.Add(1)
			}
		}()
	}
	wg.Wait()
	if okCount.Load() != 2 || satCount.Load() != 4 {
		t.Fatalf("bounded semaphore violated: ok=%d saturated=%d", okCount.Load(), satCount.Load())
	}

	// Context cancellation releases semaphore promptly without waiting full delay.
	slowLab := NewLabyrinth(LabyrinthConfig{
		Key:            key,
		MaxDepth:       2,
		MaxConcurrency: 1,
		Delay:          5 * time.Second,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	r := httptest.NewRequest(http.MethodGet, "https://example.com"+signed, nil).WithContext(ctx)
	rec := httptest.NewRecorder()
	start := time.Now()
	tr := slowLab.ServeLabyrinthRequest(rec, r, signed, "")
	if !tr.Canceled || time.Since(start) > time.Second {
		t.Fatalf("expected prompt cancellation, got tr=%+v elapsed=%v", tr, time.Since(start))
	}
	// Semaphore slot MUST be freed.
	if len(slowLab.sem) != 0 {
		t.Fatalf("semaphore leaked: len=%d", len(slowLab.sem))
	}
}

func TestTrapLinkInjectorWriter(t *testing.T) {
	key := make([]byte, 32)
	lab := NewLabyrinth(LabyrinthConfig{Key: key, MaxDepth: 3, MaxConcurrency: 8})

	// 1. Uncompressed 200 text/html injects invisible link before </body>.
	rec := httptest.NewRecorder()
	iw := lab.NewTrapLinkInjectorWriter(rec, "example.com", "/blog")
	iw.Header().Set("Content-Type", "text/html; charset=utf-8")
	iw.WriteHeader(http.StatusOK)
	_, _ = iw.Write([]byte("<html><body><h1>Hello</h1></body></html>"))
	iw.Finish(false)

	body := rec.Body.String()
	if !strings.Contains(body, `aria-hidden="true"`) ||
		!strings.Contains(body, `display:none`) ||
		!strings.Contains(body, `rel="nofollow noopener"`) ||
		!strings.Contains(body, LabyrinthReservedNamespace+"p/0/") {
		t.Fatalf("expected invisible trap link injected before </body>, got: %s", body)
	}
	if !strings.HasSuffix(body, "</body></html>") {
		t.Fatalf("trap link must be injected before </body>, got: %s", body)
	}

	// 2. Non-HTML (application/json) is passed through untouched.
	recJSON := httptest.NewRecorder()
	iwJSON := lab.NewTrapLinkInjectorWriter(recJSON, "example.com", "/api")
	iwJSON.Header().Set("Content-Type", "application/json")
	iwJSON.WriteHeader(http.StatusOK)
	_, _ = iwJSON.Write([]byte(`{"html":"</body>"}`))
	iwJSON.Finish(false)
	if recJSON.Body.String() != `{"html":"</body>"}` {
		t.Fatalf("JSON response must not be modified: %s", recJSON.Body.String())
	}

	// 3. Compressed HTML (Content-Encoding: gzip) is passed through untouched.
	recGzip := httptest.NewRecorder()
	iwGzip := lab.NewTrapLinkInjectorWriter(recGzip, "example.com", "/blog")
	iwGzip.Header().Set("Content-Type", "text/html")
	iwGzip.Header().Set("Content-Encoding", "gzip")
	iwGzip.WriteHeader(http.StatusOK)
	_, _ = iwGzip.Write([]byte("raw-gzip-bytes</body>"))
	iwGzip.Finish(false)
	if recGzip.Body.String() != "raw-gzip-bytes</body>" {
		t.Fatalf("compressed response must not be corrupted: %s", recGzip.Body.String())
	}

	// 4. Terminated/skipInject=true writes original body untouched.
	recTerm := httptest.NewRecorder()
	iwTerm := lab.NewTrapLinkInjectorWriter(recTerm, "example.com", "/blog")
	iwTerm.Header().Set("Content-Type", "text/html")
	iwTerm.WriteHeader(http.StatusOK)
	_, _ = iwTerm.Write([]byte("<html><body>block</body></html>"))
	iwTerm.Finish(true)
	if strings.Contains(recTerm.Body.String(), LabyrinthReservedNamespace) {
		t.Fatalf("skipInject=true must not inject trap link: %s", recTerm.Body.String())
	}
}
