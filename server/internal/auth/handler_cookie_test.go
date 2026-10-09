package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionCookieSecureByScheme(t *testing.T) {
	h := &Handler{secure: true}
	expires := time.Now().Add(time.Hour)

	// 纯 HTTP（离线包默认控制台形态）：不得带 Secure——带 Secure 的 Cookie
	// 会被浏览器静默丢弃，登录态无法保持
	rec := httptest.NewRecorder()
	rHTTP := httptest.NewRequest(http.MethodPost, "http://192.0.2.1:8080/api/v1/auth/login", nil)
	h.setSessionCookie(rec, rHTTP, "sess-1", expires)
	if c := rec.Result().Cookies(); len(c) != 1 || c[0].Secure {
		t.Fatalf("plain http must not set Secure cookie: %+v", c)
	}

	// 前置反代声明 https：带 Secure
	rec = httptest.NewRecorder()
	rProxy := httptest.NewRequest(http.MethodPost, "http://internal/api/v1/auth/login", nil)
	rProxy.Header.Set("X-Forwarded-Proto", "https")
	h.setSessionCookie(rec, rProxy, "sess-1", expires)
	if c := rec.Result().Cookies(); len(c) != 1 || !c[0].Secure {
		t.Fatalf("https via proxy must set Secure cookie: %+v", c)
	}

	// 直连 TLS：带 Secure（httptest 对 https 目标会置非空 TLS）
	rec = httptest.NewRecorder()
	rTLS := httptest.NewRequest(http.MethodPost, "https://example.com/api/v1/auth/login", nil)
	h.setSessionCookie(rec, rTLS, "sess-1", expires)
	if c := rec.Result().Cookies(); len(c) != 1 || !c[0].Secure {
		t.Fatalf("direct tls must set Secure cookie: %+v", c)
	}

	// secure=false（dev）：任何协议都不带 Secure
	h2 := &Handler{secure: false}
	rec = httptest.NewRecorder()
	h2.setSessionCookie(rec, rTLS, "sess-1", expires)
	if c := rec.Result().Cookies(); len(c) != 1 || c[0].Secure {
		t.Fatalf("secure=false must never set Secure: %+v", c)
	}
}
