package identitybehavior

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/clientip"
	"go.uber.org/zap"
)

// captureStore 记录 Observe 输入的测试存储。
type captureStore struct{ last ObserveInput }

func (s *captureStore) Observe(in ObserveInput) (*Snapshot, error) {
	s.last = in
	return &Snapshot{}, nil
}
func (s *captureStore) Close() error { return nil }

// LOW-G6 回归：前置拦截（temp block/IP deny/risk BLOCK/Coraza 中断）经 caddyhttp.Error
// 返回时响应在 statusWriter 链之外写出，wrapper 采集不到状态码；End 必须从错误链兜底
// 取 HandlerError 状态码，避免被拦截请求全部 status=0 入账。
func TestEndStatusFallbackFromHandlerError(t *testing.T) {
	cfg, err := Compile(&Params{Enabled: true}, zap.NewNop())
	if err != nil || cfg == nil {
		t.Fatalf("compile: %v %v", cfg, err)
	}
	store := &captureStore{}
	ev, _ := newEventTestLogger(t)
	e := NewEngine(cfg, store, ev, Options{Logger: zap.NewNop()})
	res := clientip.Result{ClientIP: mustIP(t, "203.0.113.10")}

	// wrapper 未写任何状态码 + 错误链携带 403（含包装层）：入账 403
	r := httptest.NewRequest(http.MethodGet, "http://waf-test.local/api", nil)
	r.RemoteAddr = "203.0.113.10:1"
	_, obs := e.Begin(httptest.NewRecorder(), r, res)
	if obs == nil {
		t.Fatal("observation expected")
	}
	chainErr := fmt.Errorf("guard: %w", caddyhttp.Error(http.StatusForbidden, fmt.Errorf("access denied")))
	e.End(r, obs, chainErr)
	if store.last.Status != http.StatusForbidden {
		t.Fatalf("blocked request must record 403 from error chain, got %d", store.last.Status)
	}

	// wrapper 已采集到状态码时优先（错误链不覆盖真实写出）
	r2 := httptest.NewRequest(http.MethodGet, "http://waf-test.local/api", nil)
	r2.RemoteAddr = "203.0.113.10:1"
	w2, obs2 := e.Begin(httptest.NewRecorder(), r2, res)
	w2.WriteHeader(http.StatusTeapot)
	e.End(r2, obs2, chainErr)
	if store.last.Status != http.StatusTeapot {
		t.Fatalf("writer-observed status must win over error chain, got %d", store.last.Status)
	}

	// 无错误且未采集：保持 0（仅计 request_count，不编造状态码）
	r3 := httptest.NewRequest(http.MethodGet, "http://waf-test.local/api", nil)
	r3.RemoteAddr = "203.0.113.10:1"
	_, obs3 := e.Begin(httptest.NewRecorder(), r3, res)
	e.End(r3, obs3, nil)
	if store.last.Status != 0 {
		t.Fatalf("no-error/no-write request must keep status 0, got %d", store.last.Status)
	}
}

type wsHijackRecorder struct {
	header   http.Header
	codes    []int
	flushed  int
	hijacked bool
}

func (r *wsHijackRecorder) Header() http.Header         { return r.header }
func (r *wsHijackRecorder) WriteHeader(code int)        { r.codes = append(r.codes, code) }
func (r *wsHijackRecorder) Write(p []byte) (int, error) { return len(p), nil }
func (r *wsHijackRecorder) Flush()                      { r.flushed++ }
func (r *wsHijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	r.hijacked = true
	c1, c2 := net.Pipe()
	_ = c2.Close()
	return c1, bufio.NewReadWriter(bufio.NewReader(c1), bufio.NewWriter(c1)), nil
}

func TestStatusWriterSwitchingProtocolsAndHijack(t *testing.T) {
	cfg, err := Compile(&Params{Enabled: true}, zap.NewNop())
	if err != nil || cfg == nil {
		t.Fatalf("compile: %v %v", cfg, err)
	}
	store := &captureStore{}
	ev, _ := newEventTestLogger(t)
	e := NewEngine(cfg, store, ev, Options{Logger: zap.NewNop()})
	res := clientip.Result{ClientIP: mustIP(t, "203.0.113.11")}

	root := &wsHijackRecorder{header: make(http.Header)}
	outer := &caddyhttp.ResponseWriterWrapper{ResponseWriter: root}
	r := httptest.NewRequest(http.MethodGet, "http://waf-test.local/ws", nil)
	r.RemoteAddr = "203.0.113.11:1"
	w, obs := e.Begin(outer, r, res)
	if obs == nil {
		t.Fatal("observation expected")
	}

	// Provisional 103 must not lock status; 101 Switching Protocols must be recorded as final.
	w.WriteHeader(http.StatusEarlyHints)
	if obs.writer.status != 0 {
		t.Fatalf("103 must remain provisional, got %d", obs.writer.status)
	}
	w.WriteHeader(http.StatusSwitchingProtocols)
	if obs.writer.status != http.StatusSwitchingProtocols {
		t.Fatalf("101 must be recorded as final status, got %d", obs.writer.status)
	}
	// Flush before hijack must not overwrite 101 and must forward through Unwrap-only outer.
	w.(http.Flusher).Flush()
	if root.flushed != 1 || obs.writer.status != http.StatusSwitchingProtocols {
		t.Fatalf("Flush failed: flushed=%d status=%d", root.flushed, obs.writer.status)
	}
	// Direct http.Hijacker assertion must succeed through Caddy ResponseWriterWrapper.
	conn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		t.Fatalf("Hijack failed: %v", err)
	}
	_ = conn.Close()
	if !root.hijacked {
		t.Fatal("root writer not hijacked")
	}
	// Flush after hijack must be a no-op.
	w.(http.Flusher).Flush()
	if root.flushed != 1 {
		t.Fatalf("Flush after Hijack must be a no-op, flushed=%d", root.flushed)
	}
	e.End(r, obs, nil)
	if store.last.Status != http.StatusSwitchingProtocols {
		t.Fatalf("End must observe status 101, got %d", store.last.Status)
	}
	if len(root.codes) != 2 || root.codes[0] != http.StatusEarlyHints || root.codes[1] != http.StatusSwitchingProtocols {
		t.Fatalf("codes = %v, want [103 101]", root.codes)
	}
}
