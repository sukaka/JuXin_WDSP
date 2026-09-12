// PostHTTP 端点语义测试（Phase 3 契约 §3/§10）。
package transport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
)

func testRecords(n int) []events.HTTPRecord {
	out := make([]events.HTTPRecord, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, events.HTTPRecord{
			FlowID: "a-1.1.1.1-80-2.2.2.2-8080-1", RequestTS: 1788256800.123,
			SrcIP: "1.1.1.1", SrcPort: 80, DstIP: "2.2.2.2", DstPort: 8080,
			Direction: "ingress", TLSVisibility: "PLAINTEXT",
			Request: &events.HTTPMessage{Method: "GET", Scheme: "http", Host: "h", URI: "/"},
		})
	}
	return out
}

func TestPostHTTPAccepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agents/a1/http" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") == "" {
			t.Error("缺少 Authorization 头")
		}
		var req events.HTTPRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("请求体解析: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(events.HTTPAcceptedResponse{Accepted: len(req.Records)})
	}))
	defer srv.Close()

	c := newClient(t, srv)
	c.SetCredential("cred")
	acc, dup, err := c.PostHTTP(context.Background(), "a1", testRecords(3))
	if err != nil {
		t.Fatal(err)
	}
	if acc != 3 {
		t.Fatalf("accepted=%d", acc)
	}
	if dup != 0 {
		t.Fatalf("v1 服务端无 duplicate 字段，应为 0: %d", dup)
	}
}

func TestPostHTTPServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":{"code":"INTERNAL","message":"db down"}}`))
	}))
	defer srv.Close()

	c := newClient(t, srv)
	_, _, err := c.PostHTTP(context.Background(), "a1", testRecords(1))
	if err == nil {
		t.Fatal("500 应返回错误（调用方转缓存补传）")
	}
	if IsNotFound(err) {
		t.Fatal("500 不应误判 404")
	}
	if IsPermanent(err) {
		t.Fatal("500 为可恢复错误，不应判定永久非法")
	}
}

func TestPostHTTPNotFound(t *testing.T) {
	// 旧服务端无 /http 端点 → 404 → 调用方降级 L0 且不再重试（契约 §10）
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":"NOT_FOUND","message":"no route"}}`))
	}))
	defer srv.Close()

	c := newClient(t, srv)
	_, _, err := c.PostHTTP(context.Background(), "a1", testRecords(1))
	if err == nil {
		t.Fatal("404 应返回错误")
	}
	if !IsNotFound(err) {
		t.Fatalf("IsNotFound 应判定 true: %v", err)
	}
	if IsPermanent(err) {
		t.Fatal("404 走降级路径，不应判定永久非法")
	}
}

// P1-03：v2 响应的 duplicate 计数解析（旧服务端缺省恒 0 已在 Accepted 用例覆盖）。
func TestPostHTTPDuplicateParsed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"accepted":2,"duplicate":1}`))
	}))
	defer srv.Close()
	c := newClient(t, srv)
	acc, dup, err := c.PostHTTP(context.Background(), "a1", testRecords(3))
	if err != nil || acc != 2 || dup != 1 {
		t.Fatalf("accepted=%d duplicate=%d err=%v", acc, dup, err)
	}
}

// P1-03 §4.2.4：400/413/422 判定永久非法；429 判定限速并解析 Retry-After。
func TestHTTPErrorClassification(t *testing.T) {
	for _, code := range []int{http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			_, _ = w.Write([]byte(`{"error":{"code":"BAD_RECORD","message":"invalid"}}`))
		}))
		c := newClient(t, srv)
		_, _, err := c.PostHTTP(context.Background(), "a1", testRecords(1))
		srv.Close()
		if !IsPermanent(err) {
			t.Fatalf("%d 应判定永久非法: %v", code, err)
		}
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"code":"RATE_LIMITED","message":"slow down"}}`))
	}))
	defer srv.Close()
	c := newClient(t, srv)
	_, _, err := c.PostHTTP(context.Background(), "a1", testRecords(1))
	if !IsTooManyRequests(err) {
		t.Fatalf("429 应判定限速: %v", err)
	}
	if IsPermanent(err) {
		t.Fatal("429 为可恢复错误，不应判定永久非法")
	}
	if d := RetryAfterOf(err); d != 7*time.Second {
		t.Fatalf("Retry-After 解析错误: %v", d)
	}
}

// Retry-After 的 HTTP 日期形式与异常值钳制。
func TestParseRetryAfter(t *testing.T) {
	now := time.Now()
	if d := parseRetryAfter("", now); d != 0 {
		t.Fatalf("空头应为 0: %v", d)
	}
	if d := parseRetryAfter("3", now); d != 3*time.Second {
		t.Fatalf("秒数解析错误: %v", d)
	}
	if d := parseRetryAfter("not-a-number", now); d != 0 {
		t.Fatalf("非法值应为 0: %v", d)
	}
	future := now.Add(10 * time.Second).UTC().Format(http.TimeFormat)
	if d := parseRetryAfter(future, now); d < 8*time.Second || d > 10*time.Second {
		t.Fatalf("HTTP 日期解析错误: %v", d)
	}
	if d := parseRetryAfter("99999", now); d != 99999*time.Second {
		t.Fatalf("解析应保持原值（钳制在 RetryAfterOf 层）: %v", d)
	}
	if d := RetryAfterOf(&APIError{StatusCode: 429, RetryAfter: time.Hour}); d != maxRetryAfter {
		t.Fatalf("超上限应钳制: %v", d)
	}
}
