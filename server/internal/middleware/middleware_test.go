package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
)

func TestSameOrigin(t *testing.T) {
	cases := []struct {
		origin string
		host   string
		want   bool
	}{
		{"http://localhost:5173", "localhost:5173", true},
		{"https://waf.example.com", "waf.example.com", true},
		{"http://evil.com", "waf.example.com", false},
		{"https://waf.example.com/path", "waf.example.com", true},
		{"http://waf.example.com.evil.com", "waf.example.com", false},
		// 默认端口归一：省略端口与显式默认端口等价
		{"https://waf.example.com", "waf.example.com:443", true},
		{"https://waf.example.com:443", "waf.example.com", true},
		{"https://waf.example.com:443", "waf.example.com:443", true},
		{"http://waf.example.com", "waf.example.com:80", true},
		{"http://waf.example.com:80", "waf.example.com", true},
		// scheme 默认端口不匹配对端显式默认端口
		{"https://waf.example.com", "waf.example.com:80", false},
		{"http://waf.example.com", "waf.example.com:443", false},
		{"http://waf.example.com:80", "waf.example.com:443", false},
		// 非默认端口必须精确匹配
		{"https://waf.example.com:8443", "waf.example.com:8443", true},
		{"https://waf.example.com:8443", "waf.example.com", false},
		{"https://waf.example.com", "waf.example.com:8443", false},
		{"https://waf.example.com:8443", "waf.example.com:443", false},
		// 畸形 Origin 一律拒绝
		{"https://", "waf.example.com", false},
		{"https:///path", "waf.example.com", false},
		{"://waf.example.com", "waf.example.com", false},
		{"javascript://waf.example.com", "waf.example.com", false},
		{"ftp://waf.example.com", "waf.example.com", false},
		{"HTTPS://WAF.EXAMPLE.COM:443", "waf.example.com", true},
	}
	for _, c := range cases {
		if got := sameOrigin(c.origin, c.host); got != c.want {
			t.Errorf("sameOrigin(%q, %q) = %v, want %v", c.origin, c.host, got, c.want)
		}
	}
}

func TestClientIPTrustsForwardedChainOnlyFromConfiguredProxy(t *testing.T) {
	resolver, err := ClientIP([]string{"172.16.0.0/12"})
	if err != nil {
		t.Fatalf("ClientIP() error = %v", err)
	}
	handler := resolver(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Resolved-IP", RemoteIP(r))
		w.Header().Set("Connection-IP", ConnectionIP(r))
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "172.18.0.2:43210"
	req.Header.Set("X-Forwarded-For", "198.51.100.7, 172.18.0.3")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Resolved-IP"); got != "198.51.100.7" {
		t.Fatalf("resolved IP = %q, want client IP", got)
	}
	if got := rec.Header().Get("Connection-IP"); got != "172.18.0.2" {
		t.Fatalf("connection IP = %q, want direct peer", got)
	}
}

func TestClientIPRejectsSpoofedForwardedHeaderFromUntrustedPeer(t *testing.T) {
	resolver, err := ClientIP([]string{"172.16.0.0/12"})
	if err != nil {
		t.Fatalf("ClientIP() error = %v", err)
	}
	handler := resolver(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Resolved-IP", RemoteIP(r))
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:43210"
	req.Header.Set("X-Forwarded-For", "198.51.100.7")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Resolved-IP"); got != "203.0.113.9" {
		t.Fatalf("resolved IP = %q, want direct untrusted peer", got)
	}
}

func TestClientIPFallsBackOnMalformedForwardedChain(t *testing.T) {
	resolver, err := ClientIP([]string{"172.16.0.0/12"})
	if err != nil {
		t.Fatalf("ClientIP() error = %v", err)
	}
	handler := resolver(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Resolved-IP", RemoteIP(r))
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "[2001:db8::10]:43210"
	req.Header.Set("X-Forwarded-For", "198.51.100.7, not-an-ip")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Resolved-IP"); got != "2001:db8::10" {
		t.Fatalf("resolved IP = %q, want direct IPv6 peer", got)
	}
}

func TestSanitizeClientRequestID(t *testing.T) {
	cases := []struct {
		in   string
		want bool // 是否被采纳
	}{
		{"abc-123_DEF", true},
		{"", false},
		{"valid-uuid-1234", true},
		{"with space", false},
		{"with\nnewline", false},
		{"with\"quote", false},
		{string(make([]byte, 100)), false}, // 超长且含空字节
	}
	for _, c := range cases {
		got := sanitizeClientRequestID(c.in)
		if c.want && got != c.in {
			t.Errorf("sanitizeClientRequestID(%q) rejected valid id", c.in)
		}
		if !c.want && got != "" {
			t.Errorf("sanitizeClientRequestID(%q) = %q, want rejected", c.in, got)
		}
	}
}

func TestRequirePermission(t *testing.T) {
	handler := RequirePermission("users.read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// 无 Principal → 401
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("no principal status = %d, want 401", rec.Code)
	}

	// 有权限 → 200
	p := &authz.Principal{
		UserID:   uuid.New(),
		Username: "admin",
		PermsSet: map[string]bool{"users.read": true},
	}
	req2 := httptest.NewRequest(http.MethodGet, "/x", nil)
	req2 = req2.WithContext(authz.WithPrincipal(req2.Context(), p))
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Errorf("with permission status = %d, want 200", rec2.Code)
	}

	// 无权限 → 403
	p2 := &authz.Principal{
		UserID:   uuid.New(),
		Username: "sec",
		PermsSet: map[string]bool{"profile.read": true},
	}
	req3 := httptest.NewRequest(http.MethodGet, "/x", nil)
	req3 = req3.WithContext(authz.WithPrincipal(req3.Context(), p2))
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusForbidden {
		t.Errorf("without permission status = %d, want 403", rec3.Code)
	}
}

func TestCSRFProtectSafeMethods(t *testing.T) {
	called := false
	handler := CSRFProtect(func(r *http.Request, token string) bool {
		return false // 总是校验失败
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	// GET 安全方法应放行（不校验CSRF）
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusOK {
		t.Errorf("GET should pass through, called=%v status=%d", called, rec.Code)
	}

	// POST 应校验失败
	called = false
	req2 := httptest.NewRequest(http.MethodPost, "/x", nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if called || rec2.Code != http.StatusForbidden {
		t.Errorf("POST should be blocked, called=%v status=%d", called, rec2.Code)
	}
}

func TestCSRFProtectValidToken(t *testing.T) {
	handler := CSRFProtect(func(r *http.Request, token string) bool {
		return token == "valid-token"
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.Header.Set("X-CSRF-Token", "valid-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("valid csrf status = %d, want 200", rec.Code)
	}
}

func TestCSRFProtectOriginDefaultPortNormalization(t *testing.T) {
	handler := CSRFProtect(func(r *http.Request, token string) bool {
		return token == "valid-token"
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	cases := []struct {
		name   string
		origin string
		host   string
		want   int
	}{
		{"Origin无端口Host显式443", "https://waf.example.com", "waf.example.com:443", http.StatusOK},
		{"Origin显式443Host无端口", "https://waf.example.com:443", "waf.example.com", http.StatusOK},
		{"http默认端口等价", "http://waf.example.com", "waf.example.com:80", http.StatusOK},
		{"默认端口交叉不匹配", "http://waf.example.com", "waf.example.com:443", http.StatusForbidden},
		{"非默认端口精确匹配", "https://waf.example.com:8443", "waf.example.com:8443", http.StatusOK},
		{"非默认端口不匹配", "https://waf.example.com:8443", "waf.example.com", http.StatusForbidden},
		{"畸形Origin拒绝", "javascript://waf.example.com", "waf.example.com", http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/x", nil)
			req.Host = c.host
			req.Header.Set("Origin", c.origin)
			req.Header.Set("X-CSRF-Token", "valid-token")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != c.want {
				t.Errorf("Origin %q Host %q status = %d, want %d", c.origin, c.host, rec.Code, c.want)
			}
		})
	}
}
