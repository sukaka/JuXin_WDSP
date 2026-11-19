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

	// M-S2: COOKIE_SECURE=true（h.secure=true）时无条件设置 Secure=true，
	// 不得因明文 HTTP 或缺失/伪造 X-Forwarded-Proto 而降级去除 Secure 属性。
	rec := httptest.NewRecorder()
	rHTTP := httptest.NewRequest(http.MethodPost, "http://192.0.2.1:8080/api/v1/auth/login", nil)
	h.setSessionCookie(rec, rHTTP, "sess-1", expires)
	if c := rec.Result().Cookies(); len(c) != 1 || !c[0].Secure {
		t.Fatalf("secure=true must unconditionally set Secure cookie even on plain http: %+v", c)
	}

	// 伪造 X-Forwarded-Proto: http 也不得去除 Secure
	rec = httptest.NewRecorder()
	rDowngrade := httptest.NewRequest(http.MethodPost, "http://internal/api/v1/auth/login", nil)
	rDowngrade.Header.Set("X-Forwarded-Proto", "http")
	h.setSessionCookie(rec, rDowngrade, "sess-1", expires)
	if c := rec.Result().Cookies(); len(c) != 1 || !c[0].Secure {
		t.Fatalf("secure=true must ignore X-Forwarded-Proto downgrade: %+v", c)
	}

	// clearSessionCookie 同步遵循 h.secure
	rec = httptest.NewRecorder()
	h.clearSessionCookie(rec, rHTTP)
	if c := rec.Result().Cookies(); len(c) != 1 || !c[0].Secure || c[0].MaxAge != -1 {
		t.Fatalf("clearSessionCookie with secure=true must set Secure=true and MaxAge=-1: %+v", c)
	}

	// 直连 TLS：带 Secure
	rec = httptest.NewRecorder()
	rTLS := httptest.NewRequest(http.MethodPost, "https://example.com/api/v1/auth/login", nil)
	h.setSessionCookie(rec, rTLS, "sess-1", expires)
	if c := rec.Result().Cookies(); len(c) != 1 || !c[0].Secure {
		t.Fatalf("direct tls must set Secure cookie: %+v", c)
	}

	// secure=false（dev）：不带 Secure
	h2 := &Handler{secure: false}
	rec = httptest.NewRecorder()
	h2.setSessionCookie(rec, rTLS, "sess-1", expires)
	if c := rec.Result().Cookies(); len(c) != 1 || c[0].Secure {
		t.Fatalf("secure=false must never set Secure: %+v", c)
	}
}
