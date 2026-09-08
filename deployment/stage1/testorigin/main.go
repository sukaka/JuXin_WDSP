// 九章阶段1测试源站
// 仅用于网关 POC 验证，不承担任何管理功能，不得与管理后端混用。
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

const maxBodyRead = 1 << 20 // 最多读取 1MB 请求体用于摘要

type echoResponse struct {
	Service      string            `json:"service"`
	Method       string            `json:"method"`
	Path         string            `json:"path"`
	Query        string            `json:"query"`
	Proto        string            `json:"proto"`
	RequestID    string            `json:"request_id"`
	ClientIP     string            `json:"client_ip"`
	Headers      map[string]string `json:"headers"`
	BodySHA256   string            `json:"body_sha256"`
	BodyPreview  string            `json:"body_preview,omitempty"`
	BodySize     int               `json:"body_size"`
	ContentType  string            `json:"content_type,omitempty"`
	ReceivedAt   string            `json:"received_at"`
	UpstreamMark string            `json:"upstream_mark"`
}

// OriginMarkHeader 受控源站标记契约（P1-04 回归对账）：源站对每个到达请求
// 回写该响应头，证明请求真实到达源站（HTTP 状态不能替代源站到达证据）。
const OriginMarkHeader = "X-Wdsp-Origin-Mark"

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// 摘要化请求头：不回显敏感值，只记录存在性和长度
func summarizeHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	sensitive := map[string]bool{
		"authorization": true, "cookie": true, "set-cookie": true,
		"proxy-authorization": true,
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		lk := strings.ToLower(k)
		if sensitive[lk] {
			out[k] = fmt.Sprintf("masked(len=%d)", len(strings.Join(h[k], ",")))
			continue
		}
		vals := h[k]
		joined := strings.Join(vals, "; ")
		if len(joined) > 256 {
			joined = joined[:256] + "...(truncated)"
		}
		out[k] = joined
	}
	return out
}

func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		return host[:i]
	}
	return host
}

func buildEcho(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(io.LimitReader(r.Body, maxBodyRead))
	}
	sum := sha256.Sum256(body)
	preview := string(body)
	if len(preview) > 512 {
		preview = preview[:512] + "...(truncated)"
	}
	resp := echoResponse{
		Service:      "jiuzhang-test-origin",
		Method:       r.Method,
		Path:         r.URL.Path,
		Query:        r.URL.RawQuery,
		Proto:        r.Proto,
		RequestID:    r.Header.Get("X-Request-Id"),
		ClientIP:     clientIP(r),
		Headers:      summarizeHeaders(r.Header),
		BodySHA256:   hex.EncodeToString(sum[:]),
		BodySize:     len(body),
		ContentType:  r.Header.Get("Content-Type"),
		ReceivedAt:   time.Now().UTC().Format(time.RFC3339),
		UpstreamMark: "REACHED_ORIGIN",
	}
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/json") || strings.HasPrefix(ct, "application/x-www-form-urlencoded") || strings.HasPrefix(ct, "text/") {
		resp.BodyPreview = preview
	}
	writeJSON(w, http.StatusOK, resp)
}

func main() {
	addr := os.Getenv("ORIGIN_ADDR")
	if addr == "" {
		addr = ":8081"
	}
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"service":      "jiuzhang-test-origin",
			"status":       "ok",
			"upstream_mark": "REACHED_ORIGIN",
			"request_id":   r.Header.Get("X-Request-Id"),
			"time":         time.Now().UTC().Format(time.RFC3339),
		})
	})
	// P1-04 回归语料路径（仅追加注册，其余未知路径保持 404 语义不变）：
	// 正常/攻击样本的业务路径全部回显 echo，由响应头 X-Wdsp-Origin-Mark
	// 承担源站到达对账；不改动既有 /cc/* 等未知路径的 404 行为。
	for _, p := range []string{
		"/search", "/download", "/ping", "/form", "/submit", "/articles",
		"/api/fetch", "/api/xml", "/api/v1/tenants/t001/projects/p002/items",
	} {
		mux.HandleFunc(p, buildEcho)
	}
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "healthy"})
	})
	mux.HandleFunc("/echo", buildEcho)
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		buildEcho(w, r)
	})
	mux.HandleFunc("/api/json", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		buildEcho(w, r)
	})
	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		buildEcho(w, r)
	})

	srv := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 受控源站标记：任何到达源站的请求（含 404）均回写，供回归对账
			w.Header().Set(OriginMarkHeader, "jiuzhang-test-origin")
			mux.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("jiuzhang-test-origin listening on %s", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("test origin error: %v", err)
	}
}
