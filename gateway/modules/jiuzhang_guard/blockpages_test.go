package jiuzhang_guard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestBlockPageHandlerProvisionValidation(t *testing.T) {
	bad := []struct {
		name string
		h    *BlockPageHandler
	}{
		{
			"invalid_scene",
			&BlockPageHandler{Global: map[string]*blockPageItemJSON{"UNKNOWN": {HTML: "<p>x</p>"}}},
		},
		{
			"empty_html",
			&BlockPageHandler{Global: map[string]*blockPageItemJSON{blockSceneWAF: {HTML: "   "}}},
		},
		{
			"oversize_html",
			&BlockPageHandler{Global: map[string]*blockPageItemJSON{blockSceneWAF: {HTML: strings.Repeat("a", maxBlockPageHTMLBytes+1)}}},
		},
		{
			"bad_status",
			&BlockPageHandler{Global: map[string]*blockPageItemJSON{blockSceneWAF: {HTML: "<p>x</p>", StatusCode: 200}}},
		},
		{
			"bad_json_code",
			&BlockPageHandler{Global: map[string]*blockPageItemJSON{blockSceneWAF: {HTML: "<p>x</p>", JSONCode: "bad code!"}}},
		},
		{
			"sanitized_empty",
			&BlockPageHandler{Global: map[string]*blockPageItemJSON{blockSceneWAF: {HTML: "<script>alert(1)</script>"}}},
		},
	}
	for _, tc := range bad {
		if err := tc.h.Provision(caddy.Context{}); err == nil {
			t.Errorf("%s: expected fail-closed provision error", tc.name)
		}
	}
}

func TestBlockPageHandlerPrioritySanitizeAndFallback(t *testing.T) {
	h := &BlockPageHandler{
		Global: map[string]*blockPageItemJSON{
			blockSceneDefault: {
				PageID:  "g-def",
				Version: 1,
				HTML:    `<html><head><style>body{background:#111;}</style></head><body><h1>全局默认</h1><p>{{request_id}} {{client_ip}} {{domain}} {{path}} {{scene_label}}</p><script>alert(1)</script></body></html>`,
			},
			blockSceneWAF: {
				PageID:      "g-waf",
				Version:     2,
				HTML:        `<html><body><h1 onclick="alert(1)">全局WAF v2</h1><p>{{status_code}} {{app_code}}</p></body></html>`,
				JSONCode:    "global_waf_v2",
				JSONMessage: "WAF 拦截",
			},
		},
		Apps: map[string]map[string]*blockPageItemJSON{
			"shop": {
				blockSceneDefault: {
					PageID:     "s-def",
					Version:    3,
					StatusCode: 451,
					HTML:       `<html><body><h1>商城自定义默认 v3</h1><p>{{status_code}} {{domain}}</p></body></html>`,
				},
			},
		},
		HostToAppCode: map[string]string{
			"shop.example.com": "shop",
		},
	}
	if err := h.Provision(caddy.Context{}); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	makeErrReq := func(host, path, appCode, scene, ip, reqID string, status int) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "https://"+host+path, nil)
		r.Host = host
		r.Header.Set("X-Request-Id", reqID)
		vars := map[string]any{}
		ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, vars)
		ctx = context.WithValue(ctx, caddyhttp.ErrorCtxKey, caddyhttp.Error(status, errors.New("blocked")))
		r = r.WithContext(ctx)
		if appCode != "" {
			setBlockPageContext(r, appCode, "app-1", ip, reqID)
		}
		if scene != "" {
			setBlockPageScene(r, scene)
		}
		return r
	}

	fallbackCalled := false
	fallback := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		fallbackCalled = true
		w.WriteHeader(http.StatusBadGateway)
		return nil
	})

	// 1. 502 错误不接管，透明透传给 next
	rec := httptest.NewRecorder()
	if err := h.ServeHTTP(rec, makeErrReq("portal.example.com", "/", "portal", "", "1.2.3.4", "req-502", http.StatusBadGateway), fallback); err != nil {
		t.Fatal(err)
	}
	if !fallbackCalled || rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 to fall through, called=%v status=%d", fallbackCalled, rec.Code)
	}

	// 2. portal + ACCESS_CONTROL 403 -> 回退全局 DEFAULT，并验证 <script> 已剥离、路径 XSS 被转义
	fallbackCalled = false
	rec = httptest.NewRecorder()
	req := makeErrReq("portal.example.com", `/q?x=<script>alert(1)</script>`, "portal", blockSceneAccessControl, "198.51.100.7", "req-ac-1", http.StatusForbidden)
	if err := h.ServeHTTP(rec, req, fallback); err != nil {
		t.Fatal(err)
	}
	if fallbackCalled {
		t.Fatal("should not call fallback when global DEFAULT matched")
	}
	body := rec.Body.String()
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want 403", rec.Code)
	}
	if strings.Contains(body, "<script>") {
		t.Fatalf("script tag survived in rendered HTML: %s", body)
	}
	for _, want := range []string{"background:#111", "全局默认", "req-ac-1", "198.51.100.7", "portal.example.com", "访问控制拦截"} {
		if !strings.Contains(body, want) {
			t.Fatalf("rendered body missing %q:\n%s", want, body)
		}
	}

	// 3. portal + WAF 403 + Accept: application/json -> 全局 WAF JSON 响应
	rec = httptest.NewRecorder()
	req = makeErrReq("portal.example.com", "/login", "portal", blockSceneWAF, "198.51.100.8", "req-waf-json", http.StatusForbidden)
	req.Header.Set("Accept", "application/json")
	if err := h.ServeHTTP(rec, req, fallback); err != nil {
		t.Fatal(err)
	}
	var jb map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &jb); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	if jb["error"] != "global_waf_v2" || jb["message"] != "WAF 拦截" || jb["request_id"] != "req-waf-json" {
		t.Fatalf("unexpected JSON body: %v", jb)
	}

	// 4. shop（无 guard 写入 app_code，走 host_to_app_code 反查）+ WAF 403 -> shop.DEFAULT 覆盖 global.WAF，状态码覆盖 451
	rec = httptest.NewRecorder()
	req = makeErrReq("shop.example.com:443", "/pay", "", blockSceneWAF, "198.51.100.9", "req-shop-1", http.StatusForbidden)
	if err := h.ServeHTTP(rec, req, fallback); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 451 || !strings.Contains(rec.Body.String(), "商城自定义默认 v3") || !strings.Contains(rec.Body.String(), "451") {
		t.Fatalf("shop override failed: status=%d body=%s", rec.Code, rec.Body.String())
	}

	// 5. 仅配置应用绑定、无全局绑定时，未绑定站点 403 回落 next（即 /srv/jiuzhang/blockpage.html）
	appOnly := &BlockPageHandler{
		Apps: map[string]map[string]*blockPageItemJSON{
			"shop": {blockSceneWAF: {PageID: "s-waf", Version: 1, HTML: "<html><body>shop only</body></html>"}},
		},
	}
	if err := appOnly.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	fallbackCalled = false
	rec = httptest.NewRecorder()
	if err := appOnly.ServeHTTP(rec, makeErrReq("other.example.com", "/", "other", blockSceneWAF, "1.1.1.1", "req-fb", http.StatusForbidden), fallback); err != nil {
		t.Fatal(err)
	}
	if !fallbackCalled {
		t.Fatal("unbound app should fall through to static blockpage fallback")
	}
}

func TestGuardWriteTooManyAndL7BlockUseCustomBlockPages(t *testing.T) {
	compiled, err := compileBlockPageMap(map[string]*blockPageItemJSON{
		blockSceneRateLimit: {
			PageID:      "p-rl",
			Version:     2,
			HTML:        `<html><head><style>.box{color:#d97706;}</style></head><body><div class="box">限速 v2：{{retry_after}}秒 / {{request_id}}</div></body></html>`,
			JSONCode:    "custom_cc_limit",
			JSONMessage: "触发自定义限速提示",
		},
		blockSceneAccessControl: {
			PageID:      "p-ac",
			Version:     1,
			HTML:        `<html><body><h1>访问控制自定义页</h1><p>{{message}}</p><p>{{request_id}}</p></body></html>`,
			JSONCode:    "custom_l7_denied",
			JSONMessage: "L7 自定义拒绝",
		},
	})
	if err != nil {
		t.Fatalf("compileBlockPageMap: %v", err)
	}
	g := newTestGuard(t, Guard{AppCode: "shop"})
	g.blockPages = compiled

	// 1. writeTooMany HTML 模式：保留 Retry-After 与自定义样式/占位符
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/order", nil)
	g.writeTooMany(rec, req, "req-rl-1", 45)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "45" || rec.Header().Get("X-Jiuzhang-Request-ID") != "req-rl-1" {
		t.Fatalf("missing required headers: %v", rec.Header())
	}
	if !strings.Contains(rec.Body.String(), "限速 v2：45秒 / req-rl-1") || !strings.Contains(rec.Body.String(), ".box{color:#d97706;}") {
		t.Fatalf("unexpected 429 HTML body: %s", rec.Body.String())
	}

	// 2. writeTooMany JSON 模式
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/api/order", nil)
	req.Header.Set("Accept", "application/json")
	g.writeTooMany(rec, req, "req-rl-2", 30)
	var jb map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &jb); err != nil {
		t.Fatalf("json decode: %v", err)
	}
	if jb["error"] != "custom_cc_limit" || jb["message"] != "触发自定义限速提示" {
		t.Fatalf("unexpected 429 JSON: %v", jb)
	}

	// 3. writeL7Block HTML 模式：使用 ACCESS_CONTROL 自定义页并转义注入消息
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/admin", nil)
	g.writeL7Block(rec, req, "req-l7-1", http.StatusForbidden, `禁止访问<script>x</script>`)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("l7 status=%d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "<script>") || !strings.Contains(rec.Body.String(), "访问控制自定义页") {
		t.Fatalf("unexpected l7 HTML: %s", rec.Body.String())
	}
}

func TestGuardServeSetsBlockSceneForCorazaAndBlacklist(t *testing.T) {
	// 验证 Guard 在 IP 黑名单拦截和下游 Coraza 中断时正确写入 Caddy 请求变量，
	// 供 server errors 路由中的 jiuzhang_block_page 精确区分场景与真实客户端 IP。
	g := newTestGuard(t, Guard{
		AppID:   "app-uuid-1",
		AppCode: "shop",
	})

	// 场景 A：下游返回 Coraza 中断哨兵错误 -> block_scene 应标记为 WAF
	vars := map[string]any{}
	req := httptest.NewRequest(http.MethodGet, "https://shop.example.com/search?q=sqli", nil)
	req.RemoteAddr = "198.51.100.55:12345"
	req.Header.Set("X-Request-Id", "req-coraza-1")
	req = req.WithContext(context.WithValue(req.Context(), caddyhttp.VarsCtxKey, vars))
	rec := httptest.NewRecorder()

	corazaNext := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return caddyhttp.HandlerError{
			ID:         "tx-999",
			StatusCode: http.StatusForbidden,
			Err:        fmt.Errorf("%s", corazaInterruptionMessage),
		}
	})
	err := g.ServeHTTP(rec, req, corazaNext)
	if err == nil {
		t.Fatal("expected coraza HandlerError to bubble to Caddy error chain")
	}
	if vars[varBlockPageScene] != blockSceneWAF || vars[varBlockPageAppCode] != "shop" || vars[varBlockPageClientIP] != "198.51.100.55" {
		t.Fatalf("unexpected block page vars after coraza interruption: %+v", vars)
	}
}

func TestSanitizeRichBlockHTMLAdversarialMXSSAndVoidTags(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		banned []string
		want   []string
	}{
		{
			name:   "nested_closing_style_escape",
			in:     `<style></sty</stylele><script>alert(1)</script></style><p>SAFE</p>`,
			banned: []string{"</style><script", "<script", "alert(1)"},
			want:   []string{"<p>SAFE</p>"},
		},
		{
			name:   "comment_closing_style_escape",
			in:     `<style></sty<//**/stylele><script>alert(1)</script></style><p>SAFE2</p>`,
			banned: []string{"</style><script", "<script", "alert(1)"},
			want:   []string{"<p>SAFE2</p>"},
		},
		{
			name:   "svg_style_mxss_anchor_attr",
			in:     `<svg viewBox="0 0 10 10"><style><a id="</style><img src=x onerror=alert(1)>"></a></style><rect width="10" height="10"/></svg><p>AFTER_SVG</p>`,
			banned: []string{"<style", "<img", "onerror", "alert(1)"},
			want:   []string{"<svg", "<rect", "<p>AFTER_SVG</p>"},
		},
		{
			name:   "svg_style_mxss_foreign_breakout_img",
			in:     `<svg viewBox="0 0 10 10"><style><img src=x onerror=alert(1)></style><rect width="10" height="10"/></svg><p>AFTER_SVG</p>`,
			banned: []string{"<style", "src=", "onerror", "alert(1)"},
			want:   []string{"<svg", "<p>AFTER_SVG</p>"},
		},
		{
			name:   "svg_desc_html_integration_point",
			in:     `<svg viewBox="0 0 10 10"><desc><img src=x onerror=alert(1)><script>alert(2)</script></desc><rect width="10" height="10"/></svg>`,
			banned: []string{"<img", "<script", "onerror", "alert("},
			want:   []string{"<svg", "<rect"},
		},
		{
			name:   "css_escapes_and_image_set",
			in:     `<style>@\69mport "https://evil.example/a.css"; body{background:u\72l(https://evil.example/x.png);background-image:image-set("https://evil.example/y.png" 1x);color:#222;}</style><p>CSS</p>`,
			banned: []string{"@import", "evil.example", "image-set"},
			want:   []string{"color:#222", "<p>CSS</p>"},
		},
		{
			name:   "void_dropped_tags_preserve_siblings",
			in:     `<div class="a"><link rel="stylesheet" href="x"><input name="y"><base href="https://evil.example"><p>KEEP_ME</p></div>`,
			banned: []string{"<link", "<input", "<base"},
			want:   []string{`<div class="a">`, `<p>KEEP_ME</p>`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := sanitizeRichBlockHTML(tc.in)
			low := strings.ToLower(out)
			for _, b := range tc.banned {
				if strings.Contains(low, strings.ToLower(b)) {
					t.Fatalf("case %s: banned %q survived:\n%s", tc.name, b, out)
				}
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Fatalf("case %s: expected %q missing:\n%s", tc.name, w, out)
				}
			}
		})
	}
}
