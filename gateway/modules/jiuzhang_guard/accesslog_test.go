package jiuzhang_guard

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// newAccessLogTestGuard 构建开启全量访问日志的测试 Guard。
func newAccessLogTestGuard(t *testing.T, cfg *accessLogJSON) (*Guard, string) {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "access-full.jsonl")
	if cfg.LogPath == "" {
		cfg.LogPath = logPath
	} else {
		logPath = cfg.LogPath
	}
	g := newTestGuard(t, Guard{
		AppID: "app1", AppCode: "shop", AccessLog: cfg,
	})
	aw, err := newAccessLogWriter(cfg.LogPath)
	if err != nil {
		t.Fatal(err)
	}
	g.accessLog = aw
	t.Cleanup(func() { aw.close() })
	return g, logPath
}

// readAccessLogRecords 读取 JSON Lines 访问日志。
func readAccessLogRecords(t *testing.T, path string) []accessLogRecord {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []accessLogRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for sc.Scan() {
		var rec accessLogRecord
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatalf("bad json line: %v", err)
		}
		out = append(out, rec)
	}
	return out
}

func TestAccessLogCapturesRequestAndResponse(t *testing.T) {
	g, logPath := newAccessLogTestGuard(t, &accessLogJSON{
		Enabled: true, CaptureRequestHeaders: true, CaptureRequestBody: true,
		CaptureResponseHeaders: true, CaptureResponseBody: true, BodyLimitKB: 64,
	})
	called := false
	next := caddyHTTPHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		// 下游必须仍能读到完整请求体
		body := make([]byte, 128)
		n, _ := r.Body.Read(body)
		if !strings.Contains(string(body[:n]), "username") {
			t.Errorf("downstream lost request body")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "sid=abc123")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"ok":true}`))
		return nil
	})
	r := httptest.NewRequest("POST", "http://waf-test.local/login?next=/home&token=secret-token",
		strings.NewReader(`{"username":"u1","password":"p@ssw0rd"}`))
	r.RemoteAddr = "203.0.113.10:4321"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Cookie", "sid=zzz")
	r.Header.Set("X-Request-Id", "req-001")
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, r, next); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("downstream not called")
	}
	recs := readAccessLogRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	rec0 := recs[0]
	if rec0.RequestID != "req-001" || rec0.Method != "POST" || rec0.ResponseStatus != 200 {
		t.Errorf("basic fields wrong: %+v", rec0)
	}
	if rec0.ClientIP != "203.0.113.10" || rec0.ClientPort != 4321 {
		t.Errorf("client addr wrong: %s:%d", rec0.ClientIP, rec0.ClientPort)
	}
	if rec0.BytesIn <= 0 || rec0.BytesOut <= 0 {
		t.Errorf("bytes counters wrong: in=%d out=%d", rec0.BytesIn, rec0.BytesOut)
	}
	// 敏感头掩码
	if got := rec0.RequestHeaders["Cookie"]; len(got) == 0 || got[0] != "masked" {
		t.Errorf("cookie not masked: %v", got)
	}
	if got := rec0.ResponseHeaders["Set-Cookie"]; len(got) == 0 || got[0] != "masked" {
		t.Errorf("set-cookie not masked: %v", got)
	}
	// 请求体敏感键值掩码
	if strings.Contains(rec0.RequestBody, "p@ssw0rd") {
		t.Errorf("request body password leaked: %s", rec0.RequestBody)
	}
	if !strings.Contains(rec0.RequestBody, `"password":"masked"`) {
		t.Errorf("request body not masked as expected: %s", rec0.RequestBody)
	}
	// 查询串敏感参数掩码
	if strings.Contains(rec0.URI, "secret-token") {
		t.Errorf("uri token leaked: %s", rec0.URI)
	}
	// 响应体留痕
	if rec0.ResponseBody != `{"ok":true}` {
		t.Errorf("response body wrong: %q", rec0.ResponseBody)
	}
	if rec0.WAFAction != "ALLOW" {
		t.Errorf("waf_action should be ALLOW for 200, got %q", rec0.WAFAction)
	}
}

func TestAccessLogDisabledByDefault(t *testing.T) {
	g := newTestGuard(t, Guard{AppID: "app1", AppCode: "shop"})
	called := false
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, req("203.0.113.66:1234", nil), nextHandler{&called}); err != nil || !called {
		t.Fatalf("unexpected: err=%v called=%v", err, called)
	}
	if g.accessLog != nil {
		t.Fatal("access log writer should be nil when disabled")
	}
}

func TestAccessLogBodyTruncation(t *testing.T) {
	g, logPath := newAccessLogTestGuard(t, &accessLogJSON{
		Enabled: true, CaptureRequestBody: true, CaptureResponseBody: true, BodyLimitKB: 1,
	})
	next := caddyHTTPHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		// 留痕截断不得影响业务：下游必须仍能读到完整请求体（已读前缀 + 剩余流拼回）
		body, _ := io.ReadAll(r.Body)
		if len(body) != 4096 {
			t.Errorf("downstream body len = %d, want 4096", len(body))
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(strings.Repeat("b", 4096)))
		return nil
	})
	r := httptest.NewRequest("POST", "http://waf-test.local/upload", strings.NewReader(strings.Repeat("a", 4096)))
	r.RemoteAddr = "203.0.113.11:1"
	r.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, r, next); err != nil {
		t.Fatal(err)
	}
	recs := readAccessLogRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	if !recs[0].RequestBodyTruncated || len(recs[0].RequestBody) != 1024 {
		t.Errorf("request body truncation wrong: truncated=%v len=%d", recs[0].RequestBodyTruncated, len(recs[0].RequestBody))
	}
	if !recs[0].ResponseBodyTruncated || len(recs[0].ResponseBody) != 1024 {
		t.Errorf("response body truncation wrong: truncated=%v len=%d", recs[0].ResponseBodyTruncated, len(recs[0].ResponseBody))
	}
	if recs[0].BytesIn != 4096 || recs[0].BytesOut != 4096 {
		t.Errorf("byte counters should reflect full size: in=%d out=%d", recs[0].BytesIn, recs[0].BytesOut)
	}
}

func TestAccessLogSkipsSSEResponseBody(t *testing.T) {
	g, logPath := newAccessLogTestGuard(t, &accessLogJSON{
		Enabled: true, CaptureResponseBody: true, BodyLimitKB: 64,
	})
	next := caddyHTTPHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		if f, ok := w.(http.Flusher); ok {
			f.Flush() // 必须可透传 Flush，否则 SSE 下游恐慌/阻塞
		} else {
			t.Error("wrapped writer lost http.Flusher")
		}
		_, _ = w.Write([]byte("data: hello\n\n"))
		return nil
	})
	r := httptest.NewRequest("GET", "http://waf-test.local/stream", nil)
	r.RemoteAddr = "203.0.113.12:1"
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, r, next); err != nil {
		t.Fatal(err)
	}
	recs := readAccessLogRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	if recs[0].ResponseBody != "" {
		t.Errorf("SSE response body should not be captured, got %q", recs[0].ResponseBody)
	}
	if recs[0].BytesOut <= 0 {
		t.Errorf("bytes_out should still be counted, got %d", recs[0].BytesOut)
	}
}

func TestAccessLogOrigin403NotMarkedWAFBlock(t *testing.T) {
	// 源站自返 403（错误链无 WAF 归属证据）：如实记录状态码，不得误标 WAF 拦截（回落 ALLOW）
	g, logPath := newAccessLogTestGuard(t, &accessLogJSON{Enabled: true})
	next := caddyHTTPHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("blocked by origin"))
		return nil
	})
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, req("203.0.113.66:1234", nil), next); err != nil {
		t.Fatal(err)
	}
	recs := readAccessLogRecords(t, logPath)
	if len(recs) != 1 || recs[0].ResponseStatus != 403 || recs[0].WAFAction != "ALLOW" {
		t.Fatalf("origin 403 must not be marked as WAF block: %+v", recs)
	}
}

func TestAccessLogWAFActionAttribution(t *testing.T) {
	// waf_action 仅当错误链确证 WAF 归属（coraza 中断哨兵 / guard API 防护管线阻断）才记 BLOCK
	cases := []struct {
		name        string
		writeStatus int // >0 时处理器先写状态码再返回错误（模拟 Coraza 响应体相位阻断）
		handlerErr  error
		wantAction  string
		wantStatus  int
	}{
		{"coraza request-phase interruption", 0,
			caddyhttp.Error(http.StatusForbidden, errors.New(corazaInterruptionMessage)), "BLOCK", 403},
		{"coraza response-phase interruption", http.StatusForbidden,
			caddyhttp.Error(http.StatusForbidden, errors.New(corazaInterruptionMessage)), "BLOCK", 403},
		{"guard api protection block", 0,
			caddyhttp.Error(http.StatusForbidden, errors.New("request blocked by api protection")), "BLOCK", 403},
		{"guard api rate limit", 0,
			caddyhttp.Error(http.StatusTooManyRequests, errors.New("api request rate limited")), "BLOCK", 429},
		{"guard api temp block", 0,
			caddyhttp.Error(http.StatusForbidden, errors.New("api client temporarily blocked")), "BLOCK", 403},
		{"non-waf handler error 403", 0,
			caddyhttp.Error(http.StatusForbidden, errors.New("upstream rejected")), "ALLOW", 403},
		{"non-waf handler error 502", 0,
			caddyhttp.Error(http.StatusBadGateway, errors.New("dial tcp 10.0.0.1:80: connect refused")), "ALLOW", 502},
		{"plain error keeps zero status", 0, errors.New("boom"), "ALLOW", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g, logPath := newAccessLogTestGuard(t, &accessLogJSON{Enabled: true})
			next := caddyHTTPHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				if c.writeStatus > 0 {
					w.WriteHeader(c.writeStatus)
				}
				return c.handlerErr
			})
			rec := httptest.NewRecorder()
			if err := g.ServeHTTP(rec, req("203.0.113.66:1234", nil), next); err == nil {
				t.Fatal("expected downstream error to propagate")
			}
			recs := readAccessLogRecords(t, logPath)
			if len(recs) != 1 {
				t.Fatalf("expected 1 record, got %d", len(recs))
			}
			if recs[0].WAFAction != c.wantAction || recs[0].ResponseStatus != c.wantStatus {
				t.Fatalf("attribution wrong: action=%q status=%d, want %q/%d",
					recs[0].WAFAction, recs[0].ResponseStatus, c.wantAction, c.wantStatus)
			}
		})
	}
}

func TestAccessLogStatusNormalizedWhenNoExplicitWrite(t *testing.T) {
	// 处理器未显式写状态码且正常返回：与 API 捕获侧 outcome() 同口径归一为 200
	g, logPath := newAccessLogTestGuard(t, &accessLogJSON{Enabled: true})
	next := caddyHTTPHandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, req("203.0.113.66:1234", nil), next); err != nil {
		t.Fatal(err)
	}
	recs := readAccessLogRecords(t, logPath)
	if len(recs) != 1 || recs[0].ResponseStatus != http.StatusOK || recs[0].WAFAction != "ALLOW" {
		t.Fatalf("status normalization wrong: %+v", recs)
	}
}

func TestAccessLogWriteFailureDoesNotBreakRequest(t *testing.T) {
	g := newTestGuard(t, Guard{AppID: "app1", AppCode: "shop", AccessLog: &accessLogJSON{Enabled: true}})
	// 指向已关闭的 writer 模拟写盘失败
	logPath := filepath.Join(t.TempDir(), "access-full.jsonl")
	aw, err := newAccessLogWriter(logPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = aw.close()
	g.accessLog = aw
	called := false
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, req("203.0.113.66:1234", nil), nextHandler{&called}); err != nil || !called {
		t.Fatalf("write failure must not break request: err=%v called=%v", err, called)
	}
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// ---------- 脱敏与 writer 单元测试 ----------

func TestMaskAccessLogHeaders(t *testing.T) {
	in := map[string][]string{
		"Cookie":        {"sid=abc"},
		"Authorization": {"Bearer tok"},
		"X-Api-Key":     {"k1"},
		"Accept":        {"text/html"},
	}
	out := maskAccessLogHeaders(in)
	for _, h := range []string{"Cookie", "Authorization", "X-Api-Key"} {
		if out[h][0] != "masked" {
			t.Errorf("%s not masked: %v", h, out[h])
		}
	}
	if out["Accept"][0] != "text/html" {
		t.Errorf("non-sensitive header changed: %v", out["Accept"])
	}
	if in["Cookie"][0] != "sid=abc" {
		t.Error("input map mutated")
	}
}

func TestMaskAccessLogBody(t *testing.T) {
	cases := []struct{ name, ct, in, wantGone, wantHas string }{
		{"form", "application/x-www-form-urlencoded",
			"username=u&password=p123&x=1", "p123", "password=masked"},
		{"form url-encoded key", "application/x-www-form-urlencoded",
			"pass%77ord=p%40ss&x=1", "p%40ss", "pass%77ord=masked"},
		{"form url-encoded value", "application/x-www-form-urlencoded",
			"password=a%26b%3Dc&x=1", "a%26b%3Dc", "password=masked"},
		{"json compact", "application/json",
			`{"password":"p123","u":"x"}`, "p123", `"password":"masked"`},
		{"json space before colon", "application/json",
			`{"token" : "t123"}`, "t123", `"token":"masked"`},
		{"json nested", "application/json",
			`{"a":{"password":"p123"}}`, "p123", `"password":"masked"`},
		{"json escaped quotes in value", "application/json",
			`{"password":"a\"b\"c"}`, `a\"b\"c`, `"password":"masked"`},
		// 截断残片走启发式兜底：任意空白形态 + 转义感知（残片无收尾引号，掩码保持残片形态）
		{"json truncated space form", "application/json",
			`{"token" : "abc`, "abc", `"token" : "masked`},
		{"json truncated escaped quote", "application/json",
			`{"password":"a\"b`, `a\"b`, `"password":"masked`},
		// 未知/非 JSON 类型：两种启发式保守兜底
		{"unknown text form shape", "text/plain",
			"user password=hunter2 logged", "hunter2", "password=masked"},
		{"unknown json shape", "",
			`{"secret":"s3cr3t"}`, "s3cr3t", `"secret":"masked"`},
	}
	for _, c := range cases {
		got := maskAccessLogBody(c.in, c.ct)
		if strings.Contains(got, c.wantGone) {
			t.Errorf("%s: sensitive value leaked: %s", c.name, got)
		}
		if !strings.Contains(got, c.wantHas) {
			t.Errorf("%s: expected %q in %q", c.name, c.wantHas, got)
		}
	}
	if maskAccessLogBody("", "application/json") != "" {
		t.Error("empty body should stay empty")
	}
}

func TestMaskAccessLogQuery(t *testing.T) {
	got := maskAccessLogQuery("a=1&token=t0k&key=k3y")
	if strings.Contains(got, "t0k") || strings.Contains(got, "k3y") {
		t.Errorf("sensitive query params leaked: %s", got)
	}
	if !strings.Contains(got, "a=1") {
		t.Errorf("non-sensitive param changed: %s", got)
	}
	if got := maskAccessLogURI("/p?token=abc"); !strings.HasPrefix(got, "/p?token=masked") {
		t.Errorf("uri mask wrong: %s", got)
	}
	// URL 编码的参数名必须解码后比对：pass%77ord= / %74oken= 不得绕过掩码，
	// 命中后保留参数名原始编码形态、仅掩码值
	got = maskAccessLogQuery("pass%77ord=Secret123&%74oken=t0k&x=1")
	if strings.Contains(got, "Secret123") || strings.Contains(got, "t0k") {
		t.Errorf("url-encoded sensitive keys bypassed mask: %s", got)
	}
	if !strings.Contains(got, "pass%77ord=masked") || !strings.Contains(got, "%74oken=masked") {
		t.Errorf("encoded keys should keep original form with masked value: %s", got)
	}
	// 非法 % 转义的键解码失败：保持原样不过掩（无法确证敏感）
	if got := maskAccessLogQuery("pass%zzord=Secret123"); got != "pass%zzord=Secret123" {
		t.Errorf("undecodable key should stay untouched, got %s", got)
	}
}

func TestIsTextualContentType(t *testing.T) {
	textual := []string{"text/html; charset=utf-8", "application/json", "application/problem+json",
		"text/plain", "application/xml", "application/x-www-form-urlencoded"}
	for _, ct := range textual {
		if !isTextualContentType(ct) {
			t.Errorf("%s should be textual", ct)
		}
	}
	nonTextual := []string{"", "text/event-stream", "application/octet-stream", "image/png", "application/zip"}
	for _, ct := range nonTextual {
		if isTextualContentType(ct) {
			t.Errorf("%s should not be textual", ct)
		}
	}
}

func TestCaptureResponseWriterStatusAndBytes(t *testing.T) {
	rec := httptest.NewRecorder()
	cw := &captureResponseWriter{ResponseWriter: rec, cfg: &accessLogJSON{CaptureResponseBody: true}, bodyLimit: 16}
	cw.Header().Set("Content-Type", "application/json")
	cw.WriteHeader(201)
	if _, err := cw.Write([]byte(`{"a":"12345678901234567890"}`)); err != nil {
		t.Fatal(err)
	}
	if cw.status != 201 || cw.bytesOut != 28 {
		t.Errorf("status/bytes wrong: %d/%d", cw.status, cw.bytesOut)
	}
	if !cw.bodyTruncated || cw.body.Len() != 16 {
		t.Errorf("body limit wrong: truncated=%v len=%d", cw.bodyTruncated, cw.body.Len())
	}
	if rec.Code != 201 || rec.Body.Len() != 28 {
		t.Errorf("downstream response changed: code=%d len=%d", rec.Code, rec.Body.Len())
	}
}

// headerSeqRecorder 记录全部 WriteHeader 调用序列（httptest.ResponseRecorder 只记首个，
// 无法验证 1xx 透传纪律）。
type headerSeqRecorder struct {
	header http.Header
	codes  []int
}

func (r *headerSeqRecorder) Header() http.Header         { return r.header }
func (r *headerSeqRecorder) Write(p []byte) (int, error) { return len(p), nil }
func (r *headerSeqRecorder) WriteHeader(code int)        { r.codes = append(r.codes, code) }

func TestCaptureResponseWriterIgnoresInformationalStatus(t *testing.T) {
	// 1xx 信息响应（103 Early Hints）不落定最终状态、不触发采体决策、不提前结算 TTFB；
	// 全部状态码透传下游（与 identitybehavior statusWriter 同一纪律）
	rec := &headerSeqRecorder{header: make(http.Header)}
	tracker := &ttfbTracker{}
	tracker.markDownstreamEntry()
	cw := &captureResponseWriter{ResponseWriter: rec, cfg: &accessLogJSON{CaptureResponseBody: true}, bodyLimit: 16, tracker: tracker}
	cw.Header().Set("Link", "</style.css>; rel=preload")
	cw.WriteHeader(http.StatusEarlyHints)
	if cw.status != 0 || cw.decided || tracker.settled {
		t.Fatalf("1xx must not settle: status=%d decided=%v ttfb_settled=%v", cw.status, cw.decided, tracker.settled)
	}
	cw.Header().Set("Content-Type", "application/json")
	cw.WriteHeader(http.StatusOK)
	if cw.status != http.StatusOK {
		t.Fatalf("final status = %d, want 200", cw.status)
	}
	if !tracker.settled {
		t.Fatal("final response should settle TTFB")
	}
	if len(rec.codes) != 2 || rec.codes[0] != http.StatusEarlyHints || rec.codes[1] != http.StatusOK {
		t.Fatalf("downstream should receive both 103 and 200: %v", rec.codes)
	}
	if !cw.captureBody {
		t.Error("textual final response should enable body capture")
	}
}

func TestAccessLogClientIPBehindTrustedProxy(t *testing.T) {
	// 可信 LB 后：client_ip 必须记真实客户端 IP 而非 LB 连接源地址（与安全事件
	// ClientIP 口径一致）；client_port 保持原始连接端口
	g, logPath := newAPMLogGuard(t, Guard{
		AppID:          "app1",
		TrustedProxies: []proxyJSON{{Name: "lb", CIDR: "10.0.0.1", HeaderType: "X_FORWARDED_FOR", Priority: 1}},
	})
	next := caddyHTTPHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})
	r := httptest.NewRequest("GET", "http://waf-test.local/echo", nil)
	r.RemoteAddr = "10.0.0.1:5555" // LB 连接源
	r.Header.Set("X-Forwarded-For", "198.51.100.9")
	if err := g.ServeHTTP(httptest.NewRecorder(), r, next); err != nil {
		t.Fatal(err)
	}
	recs := readAccessLogRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("expected 1 record, got %d", len(recs))
	}
	if recs[0].ClientIP != "198.51.100.9" {
		t.Errorf("client_ip should be real client behind trusted LB, got %q", recs[0].ClientIP)
	}
	if recs[0].ClientPort != 5555 {
		t.Errorf("client_port should be original connection port, got %d", recs[0].ClientPort)
	}
}

// caddyHTTPHandlerFunc 测试辅助：函数适配 caddyhttp.Handler。
type caddyHTTPHandlerFunc func(http.ResponseWriter, *http.Request) error

func (f caddyHTTPHandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) error { return f(w, r) }
