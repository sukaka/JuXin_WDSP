package jiuzhang_guard

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/encode"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/encode/gzip"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/encode/zstd"
	"github.com/klauspost/compress/zstd"
)

// TestGatewayResponseCompressionWithCaddyEncode 验证与 gatewayconfig.buildEncodeHandler
// 完全一致的 Caddy encode JSON 配置在真实 Caddy v2.11.4 运行时中的行为：
//   - zstd 与 gzip 协商压缩及解压逐字节一致、附带 Vary: Accept-Encoding；
//   - 源站已压缩响应原样透传、不二次压缩；
//   - SSE（text/event-stream）与小响应（<=512B）跳过压缩；
//   - 放在 jiuzhang_guard 外侧时，guard 仍看到未压缩明文响应，之后由 encode 压缩返回客户端。
func TestGatewayResponseCompressionWithCaddyEncode(t *testing.T) {
	rawCfg := `{
		"encodings": {"zstd": {}, "gzip": {}},
		"prefer": ["zstd", "gzip"],
		"minimum_length": 512,
		"match": {
			"headers": {
				"Content-Type": [
					"application/atom+xml*",
					"application/eot*",
					"application/font*",
					"application/geo+json*",
					"application/graphql+json*",
					"application/graphql-response+json*",
					"application/javascript*",
					"application/json*",
					"application/ld+json*",
					"application/manifest+json*",
					"application/opentype*",
					"application/otf*",
					"application/rss+xml*",
					"application/truetype*",
					"application/ttf*",
					"application/vnd.api+json*",
					"application/vnd.ms-fontobject*",
					"application/wasm*",
					"application/x-httpd-cgi*",
					"application/x-javascript*",
					"application/x-opentype*",
					"application/x-otf*",
					"application/x-perl*",
					"application/x-protobuf*",
					"application/x-ttf*",
					"application/xhtml+xml*",
					"application/xml*",
					"font/ttf*",
					"font/otf*",
					"image/svg+xml*",
					"image/vnd.microsoft.icon*",
					"image/x-icon*",
					"multipart/bag*",
					"multipart/mixed*",
					"text/cache-manifest*",
					"text/calendar*",
					"text/css*",
					"text/csv*",
					"text/html*",
					"text/javascript*",
					"text/markdown*",
					"text/plain*",
					"text/vcard*",
					"text/vtt*",
					"text/x-component*",
					"text/x-cross-domain-policy*",
					"text/xml*"
				]
			}
		}
	}`

	var enc encode.Encode
	if err := json.Unmarshal([]byte(rawCfg), &enc); err != nil {
		t.Fatalf("unmarshal encode config: %v", err)
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	defer cancel()
	if err := enc.Provision(ctx); err != nil {
		t.Fatalf("provision encode: %v", err)
	}
	if err := enc.Validate(); err != nil {
		t.Fatalf("validate encode: %v", err)
	}

	largeJSON := `{"items":[` + strings.Repeat(`{"name":"jiuzhang-wdsp-compression-payload","ok":true},`, 24) + `{"end":true}]}`
	if len(largeJSON) <= 512 {
		t.Fatalf("test payload too small: %d", len(largeJSON))
	}

	// 1. zstd 优先协商（Accept-Encoding: gzip, zstd）
	t.Run("prefers zstd and preserves plaintext inside guard", func(t *testing.T) {
		sawPlainInside := false
		inner := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			// 模拟位于 encode 内侧的 jiuzhang_guard / waf：观察源站明文
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Add("Vary", "User-Agent")
			if w.Header().Get("Content-Encoding") == "" {
				sawPlainInside = true
			}
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(largeJSON))
			return err
		})
		req := httptest.NewRequest(http.MethodGet, "http://app.example.com/api/data", nil)
		req.Header.Set("Accept-Encoding", "gzip, zstd")
		rec := httptest.NewRecorder()
		if err := enc.ServeHTTP(rec, req, inner); err != nil {
			t.Fatalf("ServeHTTP: %v", err)
		}
		if !sawPlainInside {
			t.Fatal("inner handler did not observe uncompressed response")
		}
		if got := rec.Header().Get("Content-Encoding"); got != "zstd" {
			t.Fatalf("Content-Encoding = %q, want zstd", got)
		}
		varyAll := strings.Join(rec.Header().Values("Vary"), ", ")
		if !strings.Contains(varyAll, "Accept-Encoding") || !strings.Contains(varyAll, "User-Agent") {
			t.Fatalf("Vary = %q, want both User-Agent and Accept-Encoding", varyAll)
		}
		dec, err := zstd.NewReader(bytes.NewReader(rec.Body.Bytes()))
		if err != nil {
			t.Fatalf("zstd reader: %v", err)
		}
		defer dec.Close()
		plain, err := io.ReadAll(dec)
		if err != nil {
			t.Fatalf("zstd decode: %v", err)
		}
		if string(plain) != largeJSON {
			t.Fatalf("decoded body mismatch: got %d bytes, want %d", len(plain), len(largeJSON))
		}
		if rec.Body.Len() >= len(largeJSON) {
			t.Fatalf("compressed size %d should be smaller than plain %d", rec.Body.Len(), len(largeJSON))
		}
	})

	// 2. gzip 回退协商（Accept-Encoding: gzip）
	t.Run("compresses with gzip when client only accepts gzip", func(t *testing.T) {
		inner := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("<html><body>" + strings.Repeat("<p>jiuzhang</p>", 60) + "</body></html>"))
			return err
		})
		req := httptest.NewRequest(http.MethodGet, "http://app.example.com/", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		rec := httptest.NewRecorder()
		if err := enc.ServeHTTP(rec, req, inner); err != nil {
			t.Fatalf("ServeHTTP: %v", err)
		}
		if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
			t.Fatalf("Content-Encoding = %q, want gzip", got)
		}
		gr, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
		if err != nil {
			t.Fatalf("gzip reader: %v", err)
		}
		defer gr.Close()
		plain, err := io.ReadAll(gr)
		if err != nil {
			t.Fatalf("gzip decode: %v", err)
		}
		if !strings.Contains(string(plain), "<p>jiuzhang</p>") {
			t.Fatalf("unexpected gzip plain body: %q", string(plain[:64]))
		}
	})

	// 3. 源站已压缩响应不二次压缩
	t.Run("skips already compressed upstream response", func(t *testing.T) {
		var preCompressed bytes.Buffer
		gw := gzip.NewWriter(&preCompressed)
		_, _ = gw.Write([]byte(largeJSON))
		_ = gw.Close()
		upstreamBytes := preCompressed.Bytes()

		inner := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Encoding", "gzip")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write(upstreamBytes)
			return err
		})
		req := httptest.NewRequest(http.MethodGet, "http://app.example.com/api/precompressed", nil)
		req.Header.Set("Accept-Encoding", "zstd, gzip")
		rec := httptest.NewRecorder()
		if err := enc.ServeHTTP(rec, req, inner); err != nil {
			t.Fatalf("ServeHTTP: %v", err)
		}
		if got := rec.Header().Get("Content-Encoding"); got != "gzip" {
			t.Fatalf("Content-Encoding = %q, want original gzip", got)
		}
		if !bytes.Equal(rec.Body.Bytes(), upstreamBytes) {
			t.Fatal("already compressed response was modified")
		}
	})

	// 4. SSE text/event-stream 不被压缩
	t.Run("skips SSE text/event-stream", func(t *testing.T) {
		ssePayload := strings.Repeat("data: {\"token\":\"hello\"}\n\n", 40)
		inner := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(ssePayload))
			return err
		})
		req := httptest.NewRequest(http.MethodGet, "http://app.example.com/sse", nil)
		req.Header.Set("Accept-Encoding", "zstd, gzip")
		rec := httptest.NewRecorder()
		if err := enc.ServeHTTP(rec, req, inner); err != nil {
			t.Fatalf("ServeHTTP: %v", err)
		}
		if got := rec.Header().Get("Content-Encoding"); got != "" {
			t.Fatalf("SSE should not be compressed, got Content-Encoding=%q", got)
		}
		if rec.Body.String() != ssePayload {
			t.Fatal("SSE payload altered")
		}
	})

	// 5. 小响应（<=512B）跳过压缩
	t.Run("skips small response under 512 bytes", func(t *testing.T) {
		small := `{"ok":true}`
		inner := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(small))
			return err
		})
		req := httptest.NewRequest(http.MethodGet, "http://app.example.com/health", nil)
		req.Header.Set("Accept-Encoding", "zstd, gzip")
		rec := httptest.NewRecorder()
		if err := enc.ServeHTTP(rec, req, inner); err != nil {
			t.Fatalf("ServeHTTP: %v", err)
		}
		if got := rec.Header().Get("Content-Encoding"); got != "" {
			t.Fatalf("small payload should not be compressed, got Content-Encoding=%q", got)
		}
		if rec.Body.String() != small {
			t.Fatalf("body = %q, want %q", rec.Body.String(), small)
		}
	})
}
