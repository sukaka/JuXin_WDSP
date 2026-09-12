package jiuzhang_guard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newGuardWithBlockResponse 构建带自定义阻断响应的测试 Guard（newTestGuard 绕过
// Provision，故在此显式走装配期编译——与生产路径同一 compileBlockResponse）。
func newGuardWithBlockResponse(t *testing.T, br *blockResponseJSON) *Guard {
	t.Helper()
	g := newTestGuard(t, Guard{BlockResponse: br})
	compiled, err := compileBlockResponse(br)
	if err != nil {
		t.Fatalf("compileBlockResponse: %v", err)
	}
	g.blockResponse = compiled
	return g
}

// TestWriteTooManyDefaultUnchanged 未配置 block_response 时响应与历史版本逐字节一致：
// 默认 HTML 模板、默认 JSON 错误结构、Retry-After 与 X-Jiuzhang-Request-ID 头不变。
func TestWriteTooManyDefaultUnchanged(t *testing.T) {
	g := newGuardWithBlockResponse(t, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	g.writeTooMany(rec, req, "req-123", 7)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "7" || rec.Header().Get("X-Jiuzhang-Request-ID") != "req-123" {
		t.Fatalf("headers: %v", rec.Header())
	}
	want := `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><title>请求过于频繁</title></head>` +
		`<body><h1>429 请求过于频繁</h1><p>请稍后重试。</p><p>请求编号：req-123</p></body></html>`
	if rec.Body.String() != want {
		t.Fatalf("default HTML body changed:\n got: %s\nwant: %s", rec.Body.String(), want)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Accept", "application/json")
	g.writeTooMany(rec, req, "req-123", 7)
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json body: %v", err)
	}
	if body["error"] != "too_many_requests" || body["message"] != "请求过于频繁，请稍后重试" || body["request_id"] != "req-123" {
		t.Fatalf("default JSON body changed: %v", body)
	}
}

// TestWriteTooManyCustom 自定义标题/正文与 JSON 文案生效；缺省字段回落内置默认；
// 请求编号行恒保留；响应头行为不变。
func TestWriteTooManyCustom(t *testing.T) {
	g := newGuardWithBlockResponse(t, &blockResponseJSON{
		HTMLTitle:   "访问受限",
		HTMLBody:    `<h2>系统繁忙</h2><p>请一分钟后重试</p>`,
		JSONCode:    "rate_limited",
		JSONMessage: "触发频率限制",
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	g.writeTooMany(rec, req, "req-abc", 60)
	body := rec.Body.String()
	if !strings.Contains(body, "<title>访问受限</title>") ||
		!strings.Contains(body, `<h2>系统繁忙</h2><p>请一分钟后重试</p>`) ||
		!strings.Contains(body, `<p>请求编号：req-abc</p>`) {
		t.Fatalf("custom HTML body: %s", body)
	}
	if rec.Header().Get("Retry-After") != "60" || rec.Header().Get("X-Jiuzhang-Request-ID") != "req-abc" {
		t.Fatalf("headers changed: %v", rec.Header())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Accept", "application/json")
	g.writeTooMany(rec, req, "req-abc", 60)
	var jb map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &jb); err != nil {
		t.Fatalf("json body: %v", err)
	}
	if jb["error"] != "rate_limited" || jb["message"] != "触发频率限制" || jb["request_id"] != "req-abc" {
		t.Fatalf("custom JSON body: %v", jb)
	}
}

// TestWriteTooManyCustomJSONOnly 仅配置 JSON 文案时 HTML 走内置默认模板（逐字节一致）。
func TestWriteTooManyCustomJSONOnly(t *testing.T) {
	g := newGuardWithBlockResponse(t, &blockResponseJSON{JSONMessage: "慢一点"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	g.writeTooMany(rec, req, "req-1", 3)
	want := `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><title>请求过于频繁</title></head>` +
		`<body><h1>429 请求过于频繁</h1><p>请稍后重试。</p><p>请求编号：req-1</p></body></html>`
	if rec.Body.String() != want {
		t.Fatalf("HTML should stay default when only JSON customized:\n got: %s", rec.Body.String())
	}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Accept", "application/json")
	g.writeTooMany(rec, req, "req-1", 3)
	var jb map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &jb); err != nil {
		t.Fatalf("json body: %v", err)
	}
	if jb["error"] != "too_many_requests" || jb["message"] != "慢一点" {
		t.Fatalf("partial JSON override: %v", jb)
	}
}

// TestBlockResponseSanitize HTML 正文白名单净化：script/事件属性/注释被移除，
// 文本转义，白名单标签保留但不带任何属性；标题渲染时整串转义（不入净化产物）。
func TestBlockResponseSanitize(t *testing.T) {
	in := `<h1 onclick="alert(1)">标题</h1><script>alert("x")</script>` +
		`<p style="color:red">正文 <b>加粗</b></p><!-- 注释 --><img src=x onerror=alert(1)>` +
		`<a href="javascript:alert(1)">链</a>`
	out := sanitizeBlockHTML(in)
	for _, banned := range []string{"script", "onclick", "onerror", "style=", "href", "<img", "<!--", "javascript:"} {
		if strings.Contains(out, banned) {
			t.Fatalf("sanitized body contains %q: %s", banned, out)
		}
	}
	for _, want := range []string{"<h1>标题</h1>", "<p>正文 <b>加粗</b></p>"} {
		if !strings.Contains(out, want) {
			t.Fatalf("sanitized body missing %q: %s", want, out)
		}
	}

	// 标题中的 HTML 注入在渲染时被整串转义
	g := newGuardWithBlockResponse(t, &blockResponseJSON{HTMLTitle: `<script>alert(1)</script>`})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	g.writeTooMany(rec, req, "req-9", 5)
	body := rec.Body.String()
	if strings.Contains(body, "<script>") {
		t.Fatalf("title injection not escaped: %s", body)
	}
	if !strings.Contains(body, `&lt;script&gt;`) {
		t.Fatalf("title should be escaped: %s", body)
	}
}

// TestValidateBlockResponse 装配期校验：超上限/非法错误码拒绝（fail-closed），
// 边界与合法配置通过；nil 与全空视为未配置。
func TestValidateBlockResponse(t *testing.T) {
	if err := validateBlockResponse(nil); err != nil {
		t.Fatalf("nil config: %v", err)
	}
	if c, err := compileBlockResponse(&blockResponseJSON{}); err != nil || c != nil {
		t.Fatalf("empty config should compile to nil: %v %+v", err, c)
	}
	if err := validateBlockResponse(&blockResponseJSON{
		HTMLTitle:   strings.Repeat("a", maxBlockResponseTitleBytes),
		HTMLBody:    strings.Repeat("p", maxBlockResponseBodyBytes),
		JSONCode:    "rate_limited.v2",
		JSONMessage: strings.Repeat("m", maxBlockResponseJSONMsgBytes),
	}); err != nil {
		t.Fatalf("boundary values should pass: %v", err)
	}
	oversize := []struct {
		name string
		cfg  *blockResponseJSON
	}{
		{"title", &blockResponseJSON{HTMLTitle: strings.Repeat("a", maxBlockResponseTitleBytes+1)}},
		{"body", &blockResponseJSON{HTMLBody: strings.Repeat("p", maxBlockResponseBodyBytes+1)}},
		{"code_len", &blockResponseJSON{JSONCode: strings.Repeat("c", maxBlockResponseJSONCode+1)}},
		{"msg", &blockResponseJSON{JSONMessage: strings.Repeat("m", maxBlockResponseJSONMsgBytes+1)}},
		{"code_charset", &blockResponseJSON{JSONCode: `bad code<script>`}},
	}
	for _, tc := range oversize {
		if err := validateBlockResponse(tc.cfg); err == nil {
			t.Fatalf("%s: expected rejection", tc.name)
		}
	}
}
