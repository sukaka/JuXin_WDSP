package jiuzhang_guard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/headers"
	_ "github.com/caddyserver/caddy/v2/modules/caddyhttp/standard"
)

func TestACMEHTTP01_FileLookupAndPassThrough(t *testing.T) {
	dir := t.TempDir()
	token := "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-"
	keyAuth := token + ".thumbprint_value_123456"
	if err := os.WriteFile(filepath.Join(dir, token), []byte(keyAuth+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	h := &ACMEHTTP01{ChallengeDir: dir}
	calledNext := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		calledNext = true
		w.WriteHeader(http.StatusTeapot)
		return nil
	})

	// 1. 命中文件：200 OK text/plain，不进入 next
	req := httptest.NewRequest(http.MethodGet, ACMEHTTP01PathPrefix+token, nil)
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if calledNext {
		t.Fatal("hit challenge should not call next")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != keyAuth {
		t.Fatalf("body=%q, want %q", got, keyAuth)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type=%q, want text/plain", ct)
	}

	// 2. HEAD 请求同样 200 无正文
	recHead := httptest.NewRecorder()
	if err := h.ServeHTTP(recHead, httptest.NewRequest(http.MethodHead, ACMEHTTP01PathPrefix+token, nil), next); err != nil {
		t.Fatalf("HEAD ServeHTTP: %v", err)
	}
	if recHead.Code != http.StatusOK || recHead.Body.Len() != 0 {
		t.Fatalf("HEAD status=%d body=%q", recHead.Code, recHead.Body.String())
	}

	// 3. 未命中 token 透传 next
	calledNext = false
	recMiss := httptest.NewRecorder()
	if err := h.ServeHTTP(recMiss, httptest.NewRequest(http.MethodGet, ACMEHTTP01PathPrefix+"NonExistentToken1234567890", nil), next); err != nil {
		t.Fatalf("miss ServeHTTP: %v", err)
	}
	if !calledNext || recMiss.Code != http.StatusTeapot {
		t.Fatalf("miss should fall through to next; calledNext=%v code=%d", calledNext, recMiss.Code)
	}

	// 4. 非法路径穿越 token 拒绝读文件并透传
	for _, bad := range []string{"../etc/passwd", "short", "has/slash/inside12345", "bad space token 123456"} {
		calledNext = false
		recBad := httptest.NewRecorder()
		badReq := (&http.Request{Method: http.MethodGet, URL: &url.URL{Path: ACMEHTTP01PathPrefix + bad}}).WithContext(context.Background())
		if err := h.ServeHTTP(recBad, badReq, next); err != nil {
			t.Fatalf("bad token %q: %v", bad, err)
		}
		if !calledNext || recBad.Code != http.StatusTeapot {
			t.Fatalf("bad token %q must fall through; calledNext=%v code=%d", bad, calledNext, recBad.Code)
		}
	}

	// 5. 符号链接文件拒绝读取
	outsideFile := filepath.Join(t.TempDir(), "secret")
	_ = os.WriteFile(outsideFile, []byte("secret-value"), 0o600)
	symToken := "SymlinkToken1234567890ABCD"
	if err := os.Symlink(outsideFile, filepath.Join(dir, symToken)); err == nil {
		calledNext = false
		recSym := httptest.NewRecorder()
		_ = h.ServeHTTP(recSym, httptest.NewRequest(http.MethodGet, ACMEHTTP01PathPrefix+symToken, nil), next)
		if !calledNext || recSym.Code != http.StatusTeapot {
			t.Fatalf("symlink token must not be served; calledNext=%v code=%d", calledNext, recSym.Code)
		}
	}

	// 6. POST 方法不拦截
	calledNext = false
	recPost := httptest.NewRecorder()
	_ = h.ServeHTTP(recPost, httptest.NewRequest(http.MethodPost, ACMEHTTP01PathPrefix+token, nil), next)
	if !calledNext {
		t.Fatal("POST must fall through to next")
	}
}

func TestACMEHTTP01_ValkeyPrimaryAndFallback(t *testing.T) {
	dir := t.TempDir()
	tokenValkey := "ValkeyHitToken1234567890AB"
	tokenFallback := "FallbackToken1234567890ABC"
	if err := os.WriteFile(filepath.Join(dir, tokenFallback), []byte("file-key-auth"), 0o644); err != nil {
		t.Fatal(err)
	}

	h := &ACMEHTTP01{
		ChallengeDir: dir,
		lookupFunc: func(_ context.Context, token string) (string, bool, error) {
			if token == tokenValkey {
				return "valkey-key-auth", true, nil
			}
			if token == tokenFallback {
				return "", false, errors.New("valkey timeout")
			}
			return "", false, nil
		},
	}
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusNotFound)
		return nil
	})

	// Valkey 命中
	rec1 := httptest.NewRecorder()
	if err := h.ServeHTTP(rec1, httptest.NewRequest(http.MethodGet, ACMEHTTP01PathPrefix+tokenValkey, nil), next); err != nil {
		t.Fatal(err)
	}
	if rec1.Code != http.StatusOK || rec1.Body.String() != "valkey-key-auth" {
		t.Fatalf("valkey hit failed: status=%d body=%q", rec1.Code, rec1.Body.String())
	}

	// Valkey 异常时平滑回退本地目录
	rec2 := httptest.NewRecorder()
	if err := h.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, ACMEHTTP01PathPrefix+tokenFallback, nil), next); err != nil {
		t.Fatal(err)
	}
	if rec2.Code != http.StatusOK || rec2.Body.String() != "file-key-auth" {
		t.Fatalf("file fallback failed: status=%d body=%q", rec2.Code, rec2.Body.String())
	}
}

func TestACMEHTTP01_CaddyIntegrationPrecedesRedirect(t *testing.T) {
	dir := t.TempDir()
	token := "RealCaddyACMEToken12345678"
	keyAuth := token + ".caddyThumbprint999"
	if err := os.WriteFile(filepath.Join(dir, token), []byte(keyAuth), 0o644); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cfg := map[string]any{
		"admin": map[string]any{"disabled": true},
		"apps": map[string]any{
			"http": map[string]any{
				"servers": map[string]any{
					"srv0": map[string]any{
						"listen":          []string{addr},
						"automatic_https": map[string]any{"disable": true},
						"routes": []any{
							map[string]any{
								"match": []any{map[string]any{"path": []string{"/.well-known/acme-challenge/*"}}},
								"handle": []any{
									map[string]any{
										"handler":       "jiuzhang_acme_http01",
										"challenge_dir": dir,
									},
								},
							},
							map[string]any{
								"match": []any{map[string]any{"host": []string{"shop.example.com"}}},
								"handle": []any{
									map[string]any{
										"handler":     "static_response",
										"status_code": 308,
										"headers":     map[string]any{"Location": []string{"https://{http.request.host}{http.request.uri}"}},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := caddy.Load(raw, true); err != nil {
		t.Fatalf("caddy.Load failed: %v", err)
	}
	t.Cleanup(func() { _ = caddy.Stop() })

	client := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// 1. 挑战路径优先于 308 跳转，返回 200 + keyAuth
	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s%s%s", addr, ACMEHTTP01PathPrefix, token), nil)
	req.Host = "shop.example.com"
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("challenge request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != keyAuth {
		t.Fatalf("challenge status=%d body=%q, want 200 %q", resp.StatusCode, string(body), keyAuth)
	}

	// 2. 普通路径仍正常 308 跳转 HTTPS
	req2, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/hello", addr), nil)
	req2.Host = "shop.example.com"
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("normal request failed: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusPermanentRedirect {
		t.Fatalf("normal path status=%d, want 308", resp2.StatusCode)
	}
}
