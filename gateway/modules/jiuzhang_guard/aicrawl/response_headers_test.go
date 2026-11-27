package aicrawl

import (
	"bufio"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteHTTP402_JSONAndHTML(t *testing.T) {
	cfg := HTTP402Config{
		Message:       "AI access requires license <tag>",
		PriceHint:     "$0.002/request",
		ContactURL:    "https://billing.example.com/ai",
		ReceiptHeader: "X-Payment-Receipt",
	}
	sig := "ai-train=no, search=yes, ai-input=no"

	// 1. JSON Accept
	rJSON := httptest.NewRequest(http.MethodGet, "https://example.com/article", nil)
	rJSON.Header.Set("Accept", "application/json")
	recJSON := httptest.NewRecorder()
	WriteHTTP402(recJSON, rJSON, cfg, sig, "req-402-json")

	if recJSON.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402", recJSON.Code)
	}
	if got := recJSON.Header().Get(ContentSignalHeader); got != sig {
		t.Fatalf("Content-Signal = %q, want %q", got, sig)
	}
	if got := recJSON.Header().Get("X-Payment-Price"); got != cfg.PriceHint {
		t.Fatalf("X-Payment-Price = %q", got)
	}
	if got := recJSON.Header().Get("Link"); !strings.Contains(got, cfg.ContactURL) {
		t.Fatalf("Link header missing contact_url: %q", got)
	}
	var payload map[string]string
	if err := json.Unmarshal(recJSON.Body.Bytes(), &payload); err != nil {
		t.Fatalf("JSON decode failed: %v", err)
	}
	if payload["error"] != "payment_required" || payload["price_hint"] != cfg.PriceHint || payload["receipt_header"] != cfg.ReceiptHeader {
		t.Fatalf("unexpected 402 JSON payload: %+v", payload)
	}

	// 2. HTML Accept (verifies HTML escaping!)
	rHTML := httptest.NewRequest(http.MethodGet, "https://example.com/article", nil)
	rHTML.Header.Set("Accept", "text/html")
	recHTML := httptest.NewRecorder()
	WriteHTTP402(recHTML, rHTML, cfg, sig, "req-402-html")

	if recHTML.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402", recHTML.Code)
	}
	if !strings.Contains(recHTML.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("Content-Type = %q", recHTML.Header().Get("Content-Type"))
	}
	if strings.Contains(recHTML.Body.String(), "<tag>") || !strings.Contains(recHTML.Body.String(), "&lt;tag&gt;") {
		t.Fatalf("HTML message not escaped: %s", recHTML.Body.String())
	}
}

func TestContentSignalWriter(t *testing.T) {
	rec := httptest.NewRecorder()
	cw := NewContentSignalWriter(rec, "ai-train=no, search=yes")
	cw.WriteHeader(http.StatusOK)
	_, _ = cw.Write([]byte("ok"))

	if got := rec.Header().Get(ContentSignalHeader); got != "ai-train=no, search=yes" {
		t.Fatalf("Content-Signal = %q", got)
	}
}

type wsTestWriter struct {
	header   http.Header
	codes    []int
	flushed  int
	hijacked bool
	writes   int
}

func (w *wsTestWriter) Header() http.Header         { return w.header }
func (w *wsTestWriter) WriteHeader(code int)        { w.codes = append(w.codes, code) }
func (w *wsTestWriter) Write(p []byte) (int, error) { w.writes++; return len(p), nil }
func (w *wsTestWriter) Flush()                      { w.flushed++ }
func (w *wsTestWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.hijacked = true
	c1, c2 := net.Pipe()
	_ = c2.Close()
	return c1, bufio.NewReadWriter(bufio.NewReader(c1), bufio.NewWriter(c1)), nil
}

type unwrapOnlyWriter struct{ http.ResponseWriter }

func (u *unwrapOnlyWriter) Unwrap() http.ResponseWriter { return u.ResponseWriter }

func TestContentSignalWriter_1xx101AndHijack(t *testing.T) {
	t.Run("provisional 103 does not lock wroteHeader", func(t *testing.T) {
		root := &wsTestWriter{header: make(http.Header)}
		cw := NewContentSignalWriter(root, "ai-train=no")
		cw.WriteHeader(http.StatusEarlyHints)
		if cw.wroteHeader {
			t.Fatal("103 must not lock wroteHeader")
		}
		cw.Header().Del(ContentSignalHeader)
		cw.WriteHeader(http.StatusOK)
		if got := root.Header().Get(ContentSignalHeader); got != "ai-train=no" {
			t.Fatalf("Content-Signal missing after provisional 103: %q", got)
		}
		if len(root.codes) != 2 || root.codes[0] != http.StatusEarlyHints || root.codes[1] != http.StatusOK {
			t.Fatalf("codes = %v, want [103 200]", root.codes)
		}
	})

	t.Run("101 forwards immediately and Hijack/Flush work via Unwrap-only wrapper", func(t *testing.T) {
		root := &wsTestWriter{header: make(http.Header)}
		outer := &unwrapOnlyWriter{ResponseWriter: root}
		cw := NewContentSignalWriter(outer, "ai-train=no")
		cw.WriteHeader(http.StatusSwitchingProtocols)
		if !cw.wroteHeader {
			t.Fatal("101 must lock wroteHeader")
		}
		if len(root.codes) != 1 || root.codes[0] != http.StatusSwitchingProtocols {
			t.Fatalf("codes = %v, want [101]", root.codes)
		}
		cw.Flush()
		if root.flushed != 1 {
			t.Fatalf("flushed = %d, want 1", root.flushed)
		}
		conn, _, err := cw.Hijack()
		if err != nil {
			t.Fatalf("Hijack failed: %v", err)
		}
		_ = conn.Close()
		if !root.hijacked {
			t.Fatal("root not hijacked")
		}
		cw.Flush()
		if root.flushed != 1 {
			t.Fatalf("Flush after hijack must be a no-op, flushed=%d", root.flushed)
		}
	})
}

func TestTrapLinkInjectorWriter_101AndHijack(t *testing.T) {
	lab := NewLabyrinth(LabyrinthConfig{Key: []byte("0123456789abcdef0123456789abcdef")})
	root := &wsTestWriter{header: make(http.Header)}
	outer := &unwrapOnlyWriter{ResponseWriter: root}
	tw := lab.NewTrapLinkInjectorWriter(outer, "example.com", "/ws")

	tw.WriteHeader(http.StatusEarlyHints)
	if tw.status != 0 {
		t.Fatalf("103 must be provisional, got status=%d", tw.status)
	}
	tw.WriteHeader(http.StatusSwitchingProtocols)
	if len(root.codes) != 2 || root.codes[0] != http.StatusEarlyHints || root.codes[1] != http.StatusSwitchingProtocols {
		t.Fatalf("101 must forward immediately: codes=%v", root.codes)
	}
	tw.Flush()
	if root.flushed != 1 {
		t.Fatalf("flushed = %d, want 1", root.flushed)
	}
	conn, _, err := tw.Hijack()
	if err != nil {
		t.Fatalf("Hijack failed: %v", err)
	}
	_ = conn.Close()
	if !root.hijacked {
		t.Fatal("root not hijacked")
	}
	tw.Finish(false)
	tw.Flush()
	if root.writes != 0 || root.flushed != 1 {
		t.Fatalf("Finish/Flush after Hijack must not touch conn: writes=%d flushed=%d", root.writes, root.flushed)
	}
}
