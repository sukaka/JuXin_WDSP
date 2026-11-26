// response_headers.go Content-Signal 响应头包装器与 HTTP 402 / BLOCK / RATE_LIMIT 响应渲染。
package aicrawl

import (
	"bufio"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// ContentSignalHeader 标准化内容信号响应头名（如 ai-train=no, search=yes, ai-input=no）。
const ContentSignalHeader = "Content-Signal"

// ContentSignalWriter 轻量响应头包装器：在首次 WriteHeader 前确保 Content-Signal 响应头生效。
type ContentSignalWriter struct {
	base          http.ResponseWriter
	contentSignal string
	wroteHeader   bool
}

// NewContentSignalWriter 构造 Content-Signal 响应头包装器。
func NewContentSignalWriter(base http.ResponseWriter, contentSignal string) *ContentSignalWriter {
	trimmed := strings.TrimSpace(contentSignal)
	if trimmed != "" {
		base.Header().Set(ContentSignalHeader, trimmed)
	}
	return &ContentSignalWriter{base: base, contentSignal: trimmed}
}

func (w *ContentSignalWriter) Header() http.Header { return w.base.Header() }

func (w *ContentSignalWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.wroteHeader = true
		if w.contentSignal != "" {
			w.base.Header().Set(ContentSignalHeader, w.contentSignal)
		}
	}
	w.base.WriteHeader(code)
}

func (w *ContentSignalWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.base.Write(p)
}

func (w *ContentSignalWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if f, ok := w.base.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *ContentSignalWriter) Unwrap() http.ResponseWriter { return w.base }

func (w *ContentSignalWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.base.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying writer does not support hijacking")
	}
	return h.Hijack()
}

type http402Payload struct {
	Error         string `json:"error"`
	Message       string `json:"message"`
	PriceHint     string `json:"price_hint,omitempty"`
	ContactURL    string `json:"contact_url,omitempty"`
	ReceiptHeader string `json:"receipt_header,omitempty"`
	RequestID     string `json:"request_id,omitempty"`
}

// WriteHTTP402 按 Accept 头输出 HTTP 402 Payment Required（JSON 或转义 HTML）并附带 Content-Signal 头。
func WriteHTTP402(w http.ResponseWriter, r *http.Request, cfg HTTP402Config, contentSignal, requestID string) {
	msg := strings.TrimSpace(cfg.Message)
	if msg == "" {
		msg = DefaultHTTP402Message
	}
	if contentSignal != "" {
		w.Header().Set(ContentSignalHeader, contentSignal)
	}
	w.Header().Set("Cache-Control", "no-store")
	if requestID != "" {
		w.Header().Set("X-Jiuzhang-Request-ID", requestID)
	}
	if cfg.PriceHint != "" {
		w.Header().Set("X-Payment-Price", cfg.PriceHint)
	}
	if cfg.ReceiptHeader != "" {
		w.Header().Set("X-Payment-Receipt-Header", cfg.ReceiptHeader)
	}
	if cfg.ContactURL != "" {
		w.Header().Set("Link", "<"+cfg.ContactURL+">; rel=\"payment\"")
	}

	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusPaymentRequired)
		body, _ := json.Marshal(http402Payload{
			Error:         "payment_required",
			Message:       msg,
			PriceHint:     cfg.PriceHint,
			ContactURL:    cfg.ContactURL,
			ReceiptHeader: cfg.ReceiptHeader,
			RequestID:     requestID,
		})
		_, _ = w.Write(body)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusPaymentRequired)
	var sb strings.Builder
	sb.WriteString(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>402 Payment Required</title></head><body><h1>402 Payment Required</h1><p>`)
	sb.WriteString(html.EscapeString(msg))
	sb.WriteString(`</p>`)
	if cfg.PriceHint != "" {
		sb.WriteString(`<p>Price: `)
		sb.WriteString(html.EscapeString(cfg.PriceHint))
		sb.WriteString(`</p>`)
	}
	if cfg.ContactURL != "" {
		escapedURL := html.EscapeString(cfg.ContactURL)
		sb.WriteString(`<p>Licensing &amp; Contact: <a href="`)
		sb.WriteString(escapedURL)
		sb.WriteString(`" rel="nofollow noopener">`)
		sb.WriteString(escapedURL)
		sb.WriteString(`</a></p>`)
	}
	if cfg.ReceiptHeader != "" {
		sb.WriteString(`<p>Receipt Header: <code>`)
		sb.WriteString(html.EscapeString(cfg.ReceiptHeader))
		sb.WriteString(`</code></p>`)
	}
	if requestID != "" {
		sb.WriteString(`<p>Request ID: `)
		sb.WriteString(html.EscapeString(requestID))
		sb.WriteString(`</p>`)
	}
	sb.WriteString(`</body></html>`)
	_, _ = w.Write([]byte(sb.String()))
}

// WriteBlock 输出 AI 爬虫策略 403 阻断响应（JSON 或转义 HTML）并附带 Content-Signal 头。
func WriteBlock(w http.ResponseWriter, r *http.Request, contentSignal, requestID, message string) {
	if strings.TrimSpace(message) == "" {
		message = "Automated AI crawler access is forbidden by site policy."
	}
	if contentSignal != "" {
		w.Header().Set(ContentSignalHeader, contentSignal)
	}
	w.Header().Set("Cache-Control", "no-store")
	if requestID != "" {
		w.Header().Set("X-Jiuzhang-Request-ID", requestID)
	}
	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		body, _ := json.Marshal(map[string]string{
			"error":      "ai_crawl_blocked",
			"message":    message,
			"request_id": requestID,
		})
		_, _ = w.Write(body)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>403 Forbidden</title></head><body><h1>403 Forbidden</h1><p>%s</p><p>Request ID: %s</p></body></html>`,
		html.EscapeString(message), html.EscapeString(requestID))
}

// WriteRateLimit 输出 AI 爬虫策略 429 限速响应并附带 Retry-After 与 Content-Signal 头。
func WriteRateLimit(w http.ResponseWriter, r *http.Request, retryAfterSec int, contentSignal, requestID string) {
	if retryAfterSec <= 0 {
		retryAfterSec = 1
	}
	if contentSignal != "" {
		w.Header().Set(ContentSignalHeader, contentSignal)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Retry-After", strconv.Itoa(retryAfterSec))
	if requestID != "" {
		w.Header().Set("X-Jiuzhang-Request-ID", requestID)
	}
	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusTooManyRequests)
		body, _ := json.Marshal(map[string]string{
			"error":      "ai_crawl_rate_limited",
			"message":    "AI crawler rate limit exceeded.",
			"request_id": requestID,
		})
		_, _ = w.Write(body)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusTooManyRequests)
	fmt.Fprintf(w, `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>429 Too Many Requests</title></head><body><h1>429 Too Many Requests</h1><p>AI crawler rate limit exceeded.</p><p>Request ID: %s</p></body></html>`,
		html.EscapeString(requestID))
}

func wantsJSON(r *http.Request) bool {
	if r == nil {
		return false
	}
	accept := strings.ToLower(r.Header.Get("Accept"))
	return strings.Contains(accept, "application/json")
}
