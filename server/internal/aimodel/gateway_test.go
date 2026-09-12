package aimodel

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fakeKeyResolver 内存密钥解析器。
type fakeKeyResolver struct{ keys map[string]string }

func (f *fakeKeyResolver) DecryptSecret(_ context.Context, ref string) (string, error) {
	k, ok := f.keys[ref]
	if !ok {
		return "", errors.New("secret not found")
	}
	return k, nil
}

// newChatServer 假模型服务：status 控制响应码（可中途切换），hits 记录请求次数。
func newChatServer(t *testing.T, status *int32, hits *int32) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		if s := atomic.LoadInt32(status); s != http.StatusOK {
			w.WriteHeader(int(s))
			io.WriteString(w, `{"error":{"message":"backend down"}}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func testModel(priority int) *Model {
	return &Model{
		ID: uuid.New(), Code: "m-" + uuid.NewString()[:8], Priority: priority,
		TimeoutSeconds: 5, Status: "ACTIVE",
	}
}

func testProvider(baseURL, keyRef string) *Provider {
	return &Provider{
		ID: uuid.New(), Name: "test", Type: ProviderOpenAICompatible,
		BaseURL: baseURL, AllowedTargets: []string{"127.0.0.0/8", "::1/128"}, KeyReference: keyRef,
	}
}

// routeEntry 构造路由项（与 SetRoutes 参数匿名结构一致）。
func routeEntry(m *Model, p *Provider) struct {
	Model    *Model
	Provider *Provider
} {
	return struct {
		Model    *Model
		Provider *Provider
	}{Model: m, Provider: p}
}

func simpleReq() ChatRequest {
	return ChatRequest{Messages: []ChatMessage{{Role: "user", Content: "hi"}}}
}

// TestGatewayNoRoute 无任何路由时返回 ErrNoModel。
func TestGatewayNoRoute(t *testing.T) {
	g := NewGateway(nil)
	_, err := g.Chat(context.Background(), ComplexitySimple, simpleReq())
	if !errors.Is(err, ErrNoModel) {
		t.Errorf("err = %v, want ErrNoModel", err)
	}
}

// TestGatewayFallbackToStandard 复杂度无路由时回退标准模型。
func TestGatewayFallbackToStandard(t *testing.T) {
	status := int32(200)
	var hits int32
	srv := newChatServer(t, &status, &hits)
	g := NewGateway(nil)
	m := testModel(1)
	g.SetRoutes(map[TaskComplexity][]struct {
		Model    *Model
		Provider *Provider
	}{
		ComplexityStandard: {routeEntry(m, testProvider(srv.URL, ""))},
	})
	res, err := g.Chat(context.Background(), ComplexityHigh, simpleReq())
	if err != nil {
		t.Fatalf("Chat() error = %v", err)
	}
	if res.ModelCode != m.Code {
		t.Errorf("ModelCode = %s, want 标准模型 %s", res.ModelCode, m.Code)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("hits = %d, want 1", hits)
	}
}

// TestGatewayAPIKeyResolution 密钥经 KeyResolver 解析后注入 Authorization；
// 引用已配置但解密失败 → 该候选直接判失败（记 Warn），不得空密钥呼叫（401 掩盖配置故障）。
func TestGatewayAPIKeyResolution(t *testing.T) {
	var gotAuth string
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}],"usage":{}}`)
	}))
	defer srv.Close()

	newRouted := func(resolver KeyResolver) *Gateway {
		g := NewGateway(resolver)
		m := testModel(1)
		g.SetRoutes(map[TaskComplexity][]struct {
			Model    *Model
			Provider *Provider
		}{
			ComplexitySimple: {routeEntry(m, testProvider(srv.URL, "ref-1"))},
		})
		return g
	}

	// 引用存在 → 注入密钥
	g := newRouted(&fakeKeyResolver{keys: map[string]string{"ref-1": "sk-secret"}})
	if _, err := g.Chat(context.Background(), ComplexitySimple, simpleReq()); err != nil {
		t.Fatalf("Chat() error = %v", err)
	}
	if gotAuth != "Bearer sk-secret" {
		t.Errorf("Authorization = %q, want Bearer sk-secret", gotAuth)
	}
	// 引用已配置但无法解析 → 候选判失败并返回错误，不发起 HTTP 呼叫（不误报 401/不静默切换）
	hitsBefore := atomic.LoadInt32(&hits)
	g = newRouted(&fakeKeyResolver{keys: map[string]string{}})
	if _, err := g.Chat(context.Background(), ComplexitySimple, simpleReq()); err == nil {
		t.Fatal("密钥解密失败应返回错误（暴露配置故障），不得静默成功")
	}
	if got := atomic.LoadInt32(&hits); got != hitsBefore {
		t.Errorf("密钥解密失败不应发起后端呼叫, hits %d → %d", hitsBefore, got)
	}
	// 熔断不应被配置故障触发（非模型调用失败）
	if g.circuitOpen(uuid.Nil) || len(g.circuit) != 0 {
		t.Error("密钥配置故障不得计入熔断")
	}
}

// TestGatewayPriorityOrder 按 Priority 升序选模型。
func TestGatewayPriorityOrder(t *testing.T) {
	status := int32(200)
	var hits1, hits2 int32
	srv1 := newChatServer(t, &status, &hits1)
	srv2 := newChatServer(t, &status, &hits2)
	g := NewGateway(nil)
	m1, m2 := testModel(1), testModel(2)
	// 故意乱序注册，SetRoutes 应按 Priority 排序
	g.SetRoutes(map[TaskComplexity][]struct {
		Model    *Model
		Provider *Provider
	}{
		ComplexitySimple: {routeEntry(m2, testProvider(srv2.URL, "")), routeEntry(m1, testProvider(srv1.URL, ""))},
	})
	if _, err := g.Chat(context.Background(), ComplexitySimple, simpleReq()); err != nil {
		t.Fatalf("Chat() error = %v", err)
	}
	if atomic.LoadInt32(&hits1) != 1 || atomic.LoadInt32(&hits2) != 0 {
		t.Errorf("应优先调用 Priority=1 的模型: hits1=%d hits2=%d", hits1, hits2)
	}
}

// TestGatewayFailover 主模型失败自动切换备模型。
func TestGatewayFailover(t *testing.T) {
	status1 := int32(500)
	status2 := int32(200)
	var hits1, hits2 int32
	srv1 := newChatServer(t, &status1, &hits1)
	srv2 := newChatServer(t, &status2, &hits2)
	g := NewGateway(nil)
	m1, m2 := testModel(1), testModel(2)
	g.SetRoutes(map[TaskComplexity][]struct {
		Model    *Model
		Provider *Provider
	}{
		ComplexitySimple: {routeEntry(m1, testProvider(srv1.URL, "")), routeEntry(m2, testProvider(srv2.URL, ""))},
	})
	res, err := g.Chat(context.Background(), ComplexitySimple, simpleReq())
	if err != nil {
		t.Fatalf("主模型失败应切换备模型: %v", err)
	}
	if res.ModelCode != m2.Code {
		t.Errorf("ModelCode = %s, want 备模型 %s", res.ModelCode, m2.Code)
	}
	if atomic.LoadInt32(&hits1) != 1 || atomic.LoadInt32(&hits2) != 1 {
		t.Errorf("hits1=%d hits2=%d, want 1/1", hits1, hits2)
	}
}

// TestGatewayCircuitBreaker 连续失败 3 次熔断打开（60s 窗口），冷却后恢复。
func TestGatewayCircuitBreaker(t *testing.T) {
	status := int32(500)
	var hits int32
	srv := newChatServer(t, &status, &hits)
	g := NewGateway(nil)
	m := testModel(1)
	g.SetRoutes(map[TaskComplexity][]struct {
		Model    *Model
		Provider *Provider
	}{
		ComplexitySimple: {routeEntry(m, testProvider(srv.URL, ""))},
	})
	ctx := context.Background()

	// 连续失败 3 次
	for i := 0; i < 3; i++ {
		if _, err := g.Chat(ctx, ComplexitySimple, simpleReq()); !errors.Is(err, ErrModelDown) {
			t.Fatalf("第 %d 次调用应失败(ErrModelDown), got %v", i+1, err)
		}
	}
	if atomic.LoadInt32(&hits) != 3 {
		t.Fatalf("hits = %d, want 3", hits)
	}
	// 熔断打开，窗口约 60s
	if !g.circuitOpen(m.ID) {
		t.Fatal("连续 3 次失败后熔断应打开")
	}
	g.mu.RLock()
	openUntil := g.circuit[m.ID].openUntil
	g.mu.RUnlock()
	if d := time.Until(openUntil); d < 55*time.Second || d > 61*time.Second {
		t.Errorf("熔断窗口应为 60s, got %v", d)
	}
	// 熔断期间不再请求后端
	if _, err := g.Chat(ctx, ComplexitySimple, simpleReq()); !errors.Is(err, ErrModelDown) {
		t.Errorf("熔断期间应直接失败, got %v", err)
	}
	if atomic.LoadInt32(&hits) != 3 {
		t.Errorf("熔断期间不应再请求后端, hits = %d", hits)
	}
	// 模拟冷却结束（截止时间拨到过去）且服务恢复 → 调用成功，熔断复位
	g.mu.Lock()
	g.circuit[m.ID].openUntil = time.Now().Add(-time.Second)
	g.mu.Unlock()
	atomic.StoreInt32(&status, 200)
	res, err := g.Chat(ctx, ComplexitySimple, simpleReq())
	if err != nil {
		t.Fatalf("冷却后应恢复: %v", err)
	}
	if res.Content != "ok" {
		t.Errorf("Content = %q", res.Content)
	}
	if atomic.LoadInt32(&hits) != 4 {
		t.Errorf("hits = %d, want 4", hits)
	}
	g.mu.RLock()
	cs := g.circuit[m.ID]
	g.mu.RUnlock()
	if cs.failures != 0 || !cs.openUntil.IsZero() {
		t.Errorf("成功后熔断状态应复位: %+v", cs)
	}
}

// TestGatewayCircuitResetOnSuccess 成功一次即重置连续失败计数。
func TestGatewayCircuitResetOnSuccess(t *testing.T) {
	status := int32(500)
	var hits int32
	srv := newChatServer(t, &status, &hits)
	g := NewGateway(nil)
	m := testModel(1)
	g.SetRoutes(map[TaskComplexity][]struct {
		Model    *Model
		Provider *Provider
	}{
		ComplexitySimple: {routeEntry(m, testProvider(srv.URL, ""))},
	})
	ctx := context.Background()
	call := func() { _, _ = g.Chat(ctx, ComplexitySimple, simpleReq()) }

	call() // 失败 1
	call() // 失败 2
	atomic.StoreInt32(&status, 200)
	call() // 成功 → 计数清零
	atomic.StoreInt32(&status, 500)
	call() // 失败 1
	call() // 失败 2
	if g.circuitOpen(m.ID) {
		t.Error("失败未连续达到 3 次，熔断不应打开")
	}
	if atomic.LoadInt32(&hits) != 5 {
		t.Errorf("hits = %d, want 5（熔断未打开应每次都调用后端）", hits)
	}
}

// TestGatewayModelCount 跨复杂度去重统计模型数。
func TestGatewayModelCount(t *testing.T) {
	g := NewGateway(nil)
	if g.ModelCount() != 0 {
		t.Errorf("空网关 ModelCount = %d", g.ModelCount())
	}
	m1, m2 := testModel(1), testModel(2)
	p := testProvider("http://127.0.0.1:1", "")
	g.SetRoutes(map[TaskComplexity][]struct {
		Model    *Model
		Provider *Provider
	}{
		ComplexitySimple:   {routeEntry(m1, p)},
		ComplexityStandard: {routeEntry(m1, p), routeEntry(m2, p)},
	})
	if got := g.ModelCount(); got != 2 {
		t.Errorf("ModelCount = %d, want 2（同一模型跨复杂度去重）", got)
	}
}

// TestGatewayHealthCheckAll 批量健康检查按模型返回结果。
func TestGatewayHealthCheckAll(t *testing.T) {
	statusOK := int32(200)
	statusBad := int32(500)
	var hits1, hits2 int32
	srv1 := newChatServer(t, &statusOK, &hits1)
	srv2 := newChatServer(t, &statusBad, &hits2)
	g := NewGateway(nil)
	m1, m2 := testModel(1), testModel(2)
	g.SetRoutes(map[TaskComplexity][]struct {
		Model    *Model
		Provider *Provider
	}{
		ComplexitySimple:   {routeEntry(m1, testProvider(srv1.URL, ""))},
		ComplexityStandard: {routeEntry(m2, testProvider(srv2.URL, ""))},
	})
	results := g.HealthCheckAll(context.Background())
	if len(results) != 2 {
		t.Fatalf("HealthCheckAll 返回 %d 个结果, want 2", len(results))
	}
	if results[m1.ID] != nil {
		t.Errorf("健康模型应无错误: %v", results[m1.ID])
	}
	if results[m2.ID] == nil {
		t.Error("异常模型应返回错误")
	}
	// 单模型健康检查
	if err := g.HealthCheckModel(context.Background(), m1, testProvider(srv1.URL, "")); err != nil {
		t.Errorf("HealthCheckModel() error = %v", err)
	}
}

// TestGatewayChatStream 流式路由调用。
func TestGatewayChatStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"你\"}}]}\n\n")
		io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"好\"},\"finish_reason\":\"stop\"}]}\n\n")
		io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()
	g := NewGateway(nil)
	m := testModel(1)
	m.SupportsStreaming = true
	g.SetRoutes(map[TaskComplexity][]struct {
		Model    *Model
		Provider *Provider
	}{
		ComplexitySimple: {routeEntry(m, testProvider(srv.URL, ""))},
	})
	var deltas []string
	res, err := g.ChatStream(context.Background(), ComplexitySimple, simpleReq(), func(delta string, done bool, r *ChatResult) error {
		deltas = append(deltas, delta)
		return nil
	})
	if err != nil {
		t.Fatalf("ChatStream() error = %v", err)
	}
	if res.Content != "你好" {
		t.Errorf("Content = %q", res.Content)
	}
	if !strings.Contains(strings.Join(deltas, ""), "你好") {
		t.Errorf("deltas = %v", deltas)
	}
}
