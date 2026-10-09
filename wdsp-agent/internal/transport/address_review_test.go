// 代码审查回归测试（批次5-A）：
// MED-19 控制面地址非 https 拒绝（仅 loopback http 例外，防 Bearer credential
// 明文传输并固化进 agent.json）。
package transport

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestNewRejectsPlainHTTPNonLoopback(t *testing.T) {
	for _, bad := range []string{
		"http://192.168.1.10:8080",
		"http://10.0.0.5",
		"http://wdsp.internal.example.com",
		"http://0.0.0.0:8080",
	} {
		if _, err := New(bad, false, "test"); err == nil {
			t.Fatalf("非 loopback 的 http 地址应拒绝: %q", bad)
		} else if !strings.Contains(err.Error(), "https") {
			t.Fatalf("错误信息应指向 https 要求: %v", err)
		}
	}
}

func TestHTTPSRedirectToHTTPIsRejectedBeforeCredentialsAreForwarded(t *testing.T) {
	var insecureRequests atomic.Int32
	var insecureAuthorization atomic.Bool
	insecure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		insecureRequests.Add(1)
		insecureAuthorization.Store(r.Header.Get("Authorization") != "")
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(insecure.Close)

	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, insecure.URL+"/redirected", http.StatusFound)
	}))
	t.Cleanup(secure.Close)

	client, err := New(secure.URL, true, "test")
	if err != nil {
		t.Fatal(err)
	}
	client.SetCredential("test-credential")
	_, _, err = client.do(context.Background(), http.MethodGet, "/control", nil, true, "", nil)
	if err == nil || !strings.Contains(err.Error(), "HTTPS 降级重定向") {
		t.Fatalf("HTTPS 到 HTTP 重定向应被拒绝: %v", err)
	}
	if insecureRequests.Load() != 0 || insecureAuthorization.Load() {
		t.Fatalf("不安全目标不应收到请求或凭据: requests=%d authorization=%t", insecureRequests.Load(), insecureAuthorization.Load())
	}
}

func TestNewAllowsHTTPSAndLoopbackHTTP(t *testing.T) {
	for _, ok := range []string{
		"https://wdsp.example.com:8443",
		"http://127.0.0.1:8080",
		"http://[::1]:8080",
		"http://localhost:8080",
	} {
		c, err := New(ok, false, "test")
		if err != nil {
			t.Fatalf("%q 应允许: %v", ok, err)
		}
		if c == nil {
			t.Fatalf("%q 客户端为 nil", ok)
		}
	}
}
