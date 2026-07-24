package jiuzhang_guard

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	if rec0.WAFAction != "" {
		t.Errorf("waf_action should be empty for 200, got %q", rec0.WAFAction)
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

func TestAccessLogWAFActionBlockOn403(t *testing.T) {
	g, logPath := newAccessLogTestGuard(t, &accessLogJSON{Enabled: true})
	next := caddyHTTPHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("blocked"))
		return nil
	})
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, req("203.0.113.66:1234", nil), next); err != nil {
		t.Fatal(err)
	}
	recs := readAccessLogRecords(t, logPath)
	if len(recs) != 1 || recs[0].WAFAction != "BLOCK" || recs[0].ResponseStatus != 403 {
		t.Fatalf("waf_action inference wrong: %+v", recs)
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
	cases := []struct{ name, in, wantGone, wantHas string }{
		{"form", "username=u&password=p123&x=1", "p123", "password=masked"},
		{"json compact", `{"password":"p123","u":"x"}`, "p123", `"password":"masked"`},
		{"json spaced", `{"token": "t123"}`, "t123", `"token": "masked"`},
	}
	for _, c := range cases {
		got := maskAccessLogBody(c.in)
		if strings.Contains(got, c.wantGone) {
			t.Errorf("%s: sensitive value leaked: %s", c.name, got)
		}
		if !strings.Contains(got, c.wantHas) {
			t.Errorf("%s: expected %q in %q", c.name, c.wantHas, got)
		}
	}
	if maskAccessLogBody("") != "" {
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

// caddyHTTPHandlerFunc 测试辅助：函数适配 caddyhttp.Handler。
type caddyHTTPHandlerFunc func(http.ResponseWriter, *http.Request) error

func (f caddyHTTPHandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) error { return f(w, r) }
