package aimodel

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestChatStreamCRLFFrames 验证流式 SSE 客户端同时支持 CRLF（\r\n\r\n）与 LF（\n\n）事件分隔符。
func TestChatStreamCRLFFrames(t *testing.T) {
	crlfSSE := "data: {\"choices\":[{\"delta\":{\"content\":\"九章\"},\"finish_reason\":null}]}\r\n\r\n" +
		"data: {\"choices\":[{\"delta\":{\"content\":\"WDSP\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":2}}\r\n\r\n" +
		"data: [DONE]\r\n\r\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, crlfSSE)
	}))
	defer srv.Close()

	var deltas []string
	res, err := NewOpenAIClient().ChatStreamProvider(context.Background(), scopedTestProvider(srv.URL), "", "m", ChatRequest{
		Messages: []ChatMessage{{Role: "user", Content: "hi"}},
	}, func(delta string, done bool, _ *ChatResult) error {
		if !done {
			deltas = append(deltas, delta)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("ChatStreamProvider CRLF error = %v", err)
	}
	if strings.Join(deltas, "") != "九章WDSP" || res.Content != "九章WDSP" {
		t.Fatalf("unexpected CRLF stream result: deltas=%v res=%+v", deltas, res)
	}
}

// TestChatStreamMidStreamReadErrorFailsClosed 验证上游在流式传输中途断连（非正常 EOF）时，
// 返回 ErrModelDown 错误而非静默把截断文本伪装为 finish_reason=stop 成功返回。
func TestChatStreamMidStreamReadErrorFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 声明 10000 字节响应体但只写 1 条分片后强行劫持并关闭 TCP 连接，触发客户侧 io.ErrUnexpectedEOF
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Content-Length", "10000")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"半截\"},\"finish_reason\":null}]}\n\n")
		if fl, ok := w.(http.Flusher); ok {
			fl.Flush()
		}
		if hj, ok := w.(http.Hijacker); ok {
			conn, _, err := hj.Hijack()
			if err == nil {
				_ = conn.Close()
			}
		}
	}))
	defer srv.Close()

	doneCalled := false
	res, err := NewOpenAIClient().ChatStreamProvider(context.Background(), scopedTestProvider(srv.URL), "", "m", ChatRequest{
		Messages: []ChatMessage{{Role: "user", Content: "hi"}},
	}, func(_ string, done bool, _ *ChatResult) error {
		if done {
			doneCalled = true
		}
		return nil
	})
	if !errors.Is(err, ErrModelDown) {
		t.Fatalf("expected ErrModelDown on mid-stream disconnect, got res=%+v err=%v", res, err)
	}
	if doneCalled {
		t.Fatal("done callback must not be invoked when SSE stream terminated with read error")
	}
}
