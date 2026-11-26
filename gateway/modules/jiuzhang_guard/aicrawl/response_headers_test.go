package aicrawl

import (
	"encoding/json"
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
