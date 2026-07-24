package jiuzhang_guard

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// staticHandler 模拟源站固定响应（Location 可空）。
type staticHandler struct {
	location string
	status   int
}

func (h staticHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	if h.location != "" {
		w.Header().Set("Location", h.location)
	}
	w.WriteHeader(h.status)
	return nil
}

// 302 改写：绝对 Location 显式端口 != 目标 → 改写为目标端口（保留 scheme/host/query）。
func TestRedirectPortRewriteDifferentPort(t *testing.T) {
	g := newTestGuard(t, Guard{AppID: "app1", RedirectPortRewrite: 443})
	rec := httptest.NewRecorder()
	h := staticHandler{location: "http://upstream.local:8080/login?next=%2Fhome", status: 302}
	if err := g.ServeHTTP(rec, req("203.0.113.142:1", nil), h); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 302 {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "http://upstream.local:443/login?next=%2Fhome" {
		t.Fatalf("location should be rewritten to port 443: %q", got)
	}
}

// 302 改写：目标为 80 时剥离显式端口。
func TestRedirectPortRewritePort80Stripped(t *testing.T) {
	g := newTestGuard(t, Guard{AppID: "app1", RedirectPortRewrite: 80})
	rec := httptest.NewRecorder()
	h := staticHandler{location: "http://upstream.local:8080/a/b?x=1", status: 302}
	if err := g.ServeHTTP(rec, req("203.0.113.143:1", nil), h); err != nil {
		t.Fatal(err)
	}
	if got := rec.Header().Get("Location"); got != "http://upstream.local/a/b?x=1" {
		t.Fatalf("port should be stripped for target 80: %q", got)
	}
}

// 302 改写：相对路径 Location 不动。
func TestRedirectPortRewriteRelativeUntouched(t *testing.T) {
	g := newTestGuard(t, Guard{AppID: "app1", RedirectPortRewrite: 443})
	rec := httptest.NewRecorder()
	h := staticHandler{location: "/login?next=%2Fhome", status: 302}
	if err := g.ServeHTTP(rec, req("203.0.113.144:1", nil), h); err != nil {
		t.Fatal(err)
	}
	if got := rec.Header().Get("Location"); got != "/login?next=%2Fhome" {
		t.Fatalf("relative location must stay unchanged: %q", got)
	}
}

// 302 改写：无 Location 的响应不动。
func TestRedirectPortRewriteNoLocationUntouched(t *testing.T) {
	g := newTestGuard(t, Guard{AppID: "app1", RedirectPortRewrite: 443})
	rec := httptest.NewRecorder()
	h := staticHandler{status: 200}
	if err := g.ServeHTTP(rec, req("203.0.113.145:1", nil), h); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "" {
		t.Fatalf("no location should be added: %q", got)
	}
}

// 关闭（redirect_port_rewrite=0）：Location 原样透传，零行为变化。
func TestRedirectPortRewriteDisabledZeroEffect(t *testing.T) {
	g := newTestGuard(t, Guard{AppID: "app1"})
	rec := httptest.NewRecorder()
	h := staticHandler{location: "http://upstream.local:8080/login", status: 302}
	if err := g.ServeHTTP(rec, req("203.0.113.146:1", nil), h); err != nil {
		t.Fatal(err)
	}
	if got := rec.Header().Get("Location"); got != "http://upstream.local:8080/login" {
		t.Fatalf("disabled rewrite must pass location through: %q", got)
	}
}
