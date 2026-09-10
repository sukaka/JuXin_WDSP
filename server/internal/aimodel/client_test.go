package aimodel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func scopedTestProvider(baseURL string) *Provider {
	return &Provider{
		Type:           ProviderOpenAICompatible,
		BaseURL:        baseURL,
		AllowedTargets: []string{"127.0.0.0/8", "::1/128"},
	}
}

// TestChatSuccess 正常对话：请求路径/鉴权/参数与响应解析。
func TestChatSuccess(t *testing.T) {
	var gotPath, gotAuth string
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		data, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(data, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"content":"你好，世界"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5}}`)
	}))
	defer srv.Close()

	c := NewOpenAIClient()
	res, err := c.ChatProvider(context.Background(), scopedTestProvider(srv.URL), "sk-test", "test-model", ChatRequest{
		Messages:  []ChatMessage{{Role: "user", Content: "你好"}},
		MaxTokens: 100,
		JSONMode:  true,
	})
	if err != nil {
		t.Fatalf("Chat() error = %v", err)
	}
	if gotPath != "/v1/chat/completions" {
		t.Errorf("请求路径 = %s", gotPath)
	}
	if gotAuth != "Bearer sk-test" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if gotBody["model"] != "test-model" {
		t.Errorf("model = %v", gotBody["model"])
	}
	if v, _ := gotBody["stream"].(bool); v {
		t.Error("非流式请求 stream 应为 false")
	}
	rf, ok := gotBody["response_format"].(map[string]interface{})
	if !ok || rf["type"] != "json_object" {
		t.Errorf("JSONMode 应携带 response_format json_object, got %v", gotBody["response_format"])
	}
	if res.Content != "你好，世界" {
		t.Errorf("Content = %q", res.Content)
	}
	if res.FinishReason != "stop" || res.InputTokens != 10 || res.OutputTokens != 5 || res.ModelCode != "test-model" {
		t.Errorf("ChatResult = %+v", res)
	}
}

// TestChatNoAPIKey 未配置密钥时不携带 Authorization 头。
func TestChatNoAPIKey(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}],"usage":{}}`)
	}))
	defer srv.Close()
	c := NewOpenAIClient()
	if _, err := c.ChatProvider(context.Background(), scopedTestProvider(srv.URL), "", "m", ChatRequest{
		Messages: []ChatMessage{{Role: "user", Content: "hi"}},
	}); err != nil {
		t.Fatalf("Chat() error = %v", err)
	}
	if gotAuth != "" {
		t.Errorf("空密钥不应携带 Authorization, got %q", gotAuth)
	}
}

// TestChatFinishReasonNormalize 结束原因归一化。
func TestChatFinishReasonNormalize(t *testing.T) {
	cases := map[string]string{
		"stop":           "stop",
		"":               "stop",
		"length":         "length",
		"max_tokens":     "length",
		"content_filter": "content_filter",
	}
	for in, want := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"choices":[{"message":{"content":"x"},"finish_reason":`+quote(in)+`}],"usage":{}}`)
		}))
		c := NewOpenAIClient()
		res, err := c.ChatProvider(context.Background(), scopedTestProvider(srv.URL), "", "m", ChatRequest{
			Messages: []ChatMessage{{Role: "user", Content: "hi"}},
		})
		srv.Close()
		if err != nil {
			t.Fatalf("finish_reason %q: Chat() error = %v", in, err)
		}
		if res.FinishReason != want {
			t.Errorf("finish_reason %q → %q, want %q", in, res.FinishReason, want)
		}
	}
}

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// TestChatErrors 错误路径：HTTP 错误 / API 错误体 / 空 choices / 非法 JSON / 连接失败。
func TestChatErrors(t *testing.T) {
	serve := func(status int, body string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			io.WriteString(w, body)
		}))
	}
	req := ChatRequest{Messages: []ChatMessage{{Role: "user", Content: "hi"}}}
	c := NewOpenAIClient()

	t.Run("http 500", func(t *testing.T) {
		srv := serve(500, `{"error":{"message":"internal"}}`)
		defer srv.Close()
		_, err := c.ChatProvider(context.Background(), scopedTestProvider(srv.URL), "", "m", req)
		if !errors.Is(err, ErrModelDown) {
			t.Errorf("err = %v, want ErrModelDown", err)
		}
		if !strings.Contains(err.Error(), "status 500") {
			t.Errorf("err 应包含状态码: %v", err)
		}
	})
	t.Run("api error body", func(t *testing.T) {
		srv := serve(200, `{"error":{"message":"quota exceeded"}}`)
		defer srv.Close()
		_, err := c.ChatProvider(context.Background(), scopedTestProvider(srv.URL), "", "m", req)
		if !errors.Is(err, ErrModelDown) || strings.Contains(err.Error(), "quota exceeded") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("empty choices", func(t *testing.T) {
		srv := serve(200, `{"choices":[]}`)
		defer srv.Close()
		_, err := c.ChatProvider(context.Background(), scopedTestProvider(srv.URL), "", "m", req)
		if !errors.Is(err, ErrModelDown) {
			t.Errorf("err = %v, want ErrModelDown", err)
		}
	})
	t.Run("invalid json", func(t *testing.T) {
		srv := serve(200, `not-json`)
		defer srv.Close()
		_, err := c.ChatProvider(context.Background(), scopedTestProvider(srv.URL), "", "m", req)
		if err == nil || !strings.Contains(err.Error(), "invalid model response") {
			t.Errorf("err = %v", err)
		}
		if errors.Is(err, ErrModelDown) {
			t.Error("响应解析失败不应归为 ErrModelDown")
		}
	})
	t.Run("unreachable", func(t *testing.T) {
		srv := serve(200, `{}`)
		srv.Close() // 立即关闭，连接被拒绝
		_, err := c.ChatProvider(context.Background(), scopedTestProvider(srv.URL), "", "m", req)
		if !errors.Is(err, ErrModelDown) {
			t.Errorf("err = %v, want ErrModelDown", err)
		}
	})
}

// sseBody 构造 SSE 流式响应。
const sseBody = "data: {\"choices\":[{\"delta\":{\"content\":\"你\"},\"finish_reason\":null}]}\n\n" +
	"data: {\"choices\":[{\"delta\":{\"content\":\"好\"},\"finish_reason\":null}]}\n\n" +
	"data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2}}\n\n" +
	"data: [DONE]\n\n"

// TestChatStreamSuccess SSE 解析：增量回调、完整内容与 usage。
func TestChatStreamSuccess(t *testing.T) {
	var gotStream bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		data, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(data, &body)
		gotStream, _ = body["stream"].(bool)
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, sseBody)
	}))
	defer srv.Close()

	var deltas []string
	var final *ChatResult
	cb := func(delta string, done bool, res *ChatResult) error {
		if done {
			final = res
			return nil
		}
		deltas = append(deltas, delta)
		return nil
	}
	c := NewOpenAIClient()
	res, err := c.ChatStreamProvider(context.Background(), scopedTestProvider(srv.URL), "", "m", ChatRequest{
		Messages: []ChatMessage{{Role: "user", Content: "hi"}},
	}, cb)
	if err != nil {
		t.Fatalf("ChatStream() error = %v", err)
	}
	if !gotStream {
		t.Error("流式请求 stream 应为 true")
	}
	if strings.Join(deltas, "") != "你好" {
		t.Errorf("deltas = %v", deltas)
	}
	if res.Content != "你好" || res.FinishReason != "stop" || res.InputTokens != 3 || res.OutputTokens != 2 {
		t.Errorf("ChatResult = %+v", res)
	}
	if final != res {
		t.Error("done 回调应携带最终结果")
	}
}

// TestChatStreamTokenEstimate 流式无 usage 时按字符估算 Token。
func TestChatStreamTokenEstimate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"你好世界\"}}]}\n\ndata: [DONE]\n\n")
	}))
	defer srv.Close()
	c := NewOpenAIClient()
	res, err := c.ChatStreamProvider(context.Background(), scopedTestProvider(srv.URL), "", "m", ChatRequest{
		Messages: []ChatMessage{{Role: "user", Content: "hi"}},
	}, func(string, bool, *ChatResult) error { return nil })
	if err != nil {
		t.Fatalf("ChatStream() error = %v", err)
	}
	if res.Content != "你好世界" {
		t.Errorf("Content = %q", res.Content)
	}
	if res.InputTokens <= 0 || res.OutputTokens <= 0 {
		t.Errorf("无 usage 时应估算 Token: in=%d out=%d", res.InputTokens, res.OutputTokens)
	}
}

// TestChatStreamErrors 流式错误路径：HTTP 错误与回调中断。
func TestChatStreamErrors(t *testing.T) {
	req := ChatRequest{Messages: []ChatMessage{{Role: "user", Content: "hi"}}}
	c := NewOpenAIClient()

	t.Run("http 503", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(503)
			io.WriteString(w, `{"error":{"message":"overloaded"}}`)
		}))
		defer srv.Close()
		_, err := c.ChatStreamProvider(context.Background(), scopedTestProvider(srv.URL), "", "m", req, func(string, bool, *ChatResult) error { return nil })
		if !errors.Is(err, ErrModelDown) {
			t.Errorf("err = %v, want ErrModelDown", err)
		}
	})
	t.Run("callback error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, sseBody)
		}))
		defer srv.Close()
		cbErr := errors.New("客户端中断")
		_, err := c.ChatStreamProvider(context.Background(), scopedTestProvider(srv.URL), "", "m", req, func(delta string, done bool, res *ChatResult) error {
			return cbErr
		})
		if !errors.Is(err, cbErr) {
			t.Errorf("err = %v, want 回调错误透传", err)
		}
	})
}

// TestHealthCheck 健康检查：正常返回 nil，异常返回错误。
func TestHealthCheck(t *testing.T) {
	c := NewOpenAIClient()
	okSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"content":"pong"},"finish_reason":"stop"}],"usage":{}}`)
	}))
	defer okSrv.Close()
	if err := c.HealthCheckProvider(context.Background(), scopedTestProvider(okSrv.URL), "", "m"); err != nil {
		t.Errorf("HealthCheck() error = %v", err)
	}
	badSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer badSrv.Close()
	if err := c.HealthCheckProvider(context.Background(), scopedTestProvider(badSrv.URL), "", "m"); err == nil {
		t.Error("后端 500 时 HealthCheck 应返回错误")
	}
}

func TestLegacyClientDoesNotAutoAllowPrivateTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("fail-closed legacy call must not reach private target")
	}))
	defer srv.Close()

	_, err := NewOpenAIClient().Chat(context.Background(), srv.URL, "", "m", ChatRequest{
		Messages: []ChatMessage{{Role: "user", Content: "hi"}},
	})
	if !errors.Is(err, ErrInvalidProviderEndpoint) {
		t.Fatalf("err=%v, want ErrInvalidProviderEndpoint", err)
	}
}

// TestUsageCost 成本计算。
func TestUsageCost(t *testing.T) {
	r := &ChatResult{InputTokens: 2000, OutputTokens: 1000}
	m := &Model{CostInputUnit: 0.5, CostOutputUnit: 0.25}
	if got := r.UsageCost(m); got != 1.25 {
		t.Errorf("UsageCost = %v, want 1.25", got)
	}
}
