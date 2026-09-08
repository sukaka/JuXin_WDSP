package aiorchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/aimodel"
)

// fakeQuotaCost 同时实现 CostRecorder 与 HighCostQuotaChecker 的测试桩。
type fakeQuotaCost struct {
	highCost   bool
	checkErr   error
	checkCalls int
}

func (f *fakeQuotaCost) RecordUsage(context.Context, uuid.UUID, *uuid.UUID, *uuid.UUID, *uuid.UUID, int, int, int, float64) error {
	return nil
}

func (f *fakeQuotaCost) IsHighCostTask(string, int) bool { return f.highCost }

func (f *fakeQuotaCost) CheckHighCostQuota(context.Context, uuid.UUID) error {
	f.checkCalls++
	return f.checkErr
}

// plainCost 仅实现 CostRecorder（不具备高成本配额能力）。
type plainCost struct{}

func (plainCost) RecordUsage(context.Context, uuid.UUID, *uuid.UUID, *uuid.UUID, *uuid.UUID, int, int, int, float64) error {
	return nil
}

// TestCheckHighCostTaskQuotaRejected 高成本任务超日配额时拒绝（fail-closed 错误向上传播）。
func TestCheckHighCostTaskQuotaRejected(t *testing.T) {
	quotaErr := errors.New("ai quota exceeded: high cost task daily quota 20/20")
	cost := &fakeQuotaCost{highCost: true, checkErr: quotaErr}
	o := New(nil, nil, nil, nil, nil, cost, DefaultLimits())

	err := o.checkHighCostTaskQuota(context.Background(), uuid.New(), Plan{TaskType: TaskRootCause}, "根因分析")
	if !errors.Is(err, quotaErr) {
		t.Fatalf("err = %v, want %v", err, quotaErr)
	}
	if cost.checkCalls != 1 {
		t.Fatalf("checkCalls = %d, want 1", cost.checkCalls)
	}
}

// TestCheckHighCostTaskQuotaSkipsCheapTask 非高成本口径任务不触发日配额查询。
func TestCheckHighCostTaskQuotaSkipsCheapTask(t *testing.T) {
	cost := &fakeQuotaCost{highCost: false, checkErr: errors.New("should not be called")}
	o := New(nil, nil, nil, nil, nil, cost, DefaultLimits())

	if err := o.checkHighCostTaskQuota(context.Background(), uuid.New(), Plan{TaskType: TaskGeneralQA}, "你好"); err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if cost.checkCalls != 0 {
		t.Fatalf("checkCalls = %d, want 0（非高成本任务不应查询配额）", cost.checkCalls)
	}
}

// TestCheckHighCostTaskQuotaOptional 成本记录器不具备高成本配额能力时不限制。
func TestCheckHighCostTaskQuotaOptional(t *testing.T) {
	o := New(nil, nil, nil, nil, nil, plainCost{}, DefaultLimits())
	if err := o.checkHighCostTaskQuota(context.Background(), uuid.New(), Plan{TaskType: TaskRootCause}, "根因分析"); err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
}

// composeTestGateway 假模型服务与网关：记录收到的 max_tokens 与呼叫次数。
func composeTestGateway(t *testing.T, maxTokensSeen *int64, hits *int32) *aimodel.Gateway {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		var body struct {
			MaxTokens int `json:"max_tokens"`
		}
		data, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(data, &body)
		atomic.StoreInt64(maxTokensSeen, int64(body.MaxTokens))
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
	}))
	t.Cleanup(srv.Close)

	gw := aimodel.NewGateway(nil)
	m := &aimodel.Model{ID: uuid.New(), Code: "test-model", TimeoutSeconds: 5, Status: "ACTIVE"}
	p := &aimodel.Provider{ID: uuid.New(), Name: "test", Type: aimodel.ProviderOpenAICompatible, BaseURL: srv.URL}
	gw.SetRoutes(map[aimodel.TaskComplexity][]struct {
		Model    *aimodel.Model
		Provider *aimodel.Provider
	}{
		aimodel.ComplexityStandard: {{Model: m, Provider: p}},
	})
	return gw
}

// TestLLMComposeUsesMaxOutputTokens 输出侧用 limits.MaxOutputTokens 替代硬编码 256。
func TestLLMComposeUsesMaxOutputTokens(t *testing.T) {
	var maxTokensSeen int64
	var hits int32
	gw := composeTestGateway(t, &maxTokensSeen, &hits)
	o := New(nil, gw, nil, nil, nil, nil, TaskLimits{MaxDuration: time.Minute, MaxOutputTokens: 999})

	if _, err := o.llmCompose(context.Background(), "sys", "user"); err != nil {
		t.Fatalf("llmCompose err = %v", err)
	}
	if atomic.LoadInt64(&maxTokensSeen) != 999 {
		t.Errorf("max_tokens = %d, want 999（应来自 limits.MaxOutputTokens）", maxTokensSeen)
	}
}

// TestLLMComposeDefaultMaxOutputTokens 未配置 MaxOutputTokens 时保持 256 默认值。
func TestLLMComposeDefaultMaxOutputTokens(t *testing.T) {
	var maxTokensSeen int64
	var hits int32
	gw := composeTestGateway(t, &maxTokensSeen, &hits)
	o := New(nil, gw, nil, nil, nil, nil, TaskLimits{MaxDuration: time.Minute})

	if _, err := o.llmCompose(context.Background(), "sys", "user"); err != nil {
		t.Fatalf("llmCompose err = %v", err)
	}
	if atomic.LoadInt64(&maxTokensSeen) != 256 {
		t.Errorf("max_tokens = %d, want 256（未配置时的默认值）", maxTokensSeen)
	}
}

// TestLLMComposeInputTokenLimit 输入超 MaxInputTokens 时拒绝呼叫（不发起模型请求）。
func TestLLMComposeInputTokenLimit(t *testing.T) {
	var maxTokensSeen int64
	var hits int32
	gw := composeTestGateway(t, &maxTokensSeen, &hits)
	o := New(nil, gw, nil, nil, nil, nil, TaskLimits{MaxDuration: time.Minute, MaxInputTokens: 4})

	_, err := o.llmCompose(context.Background(), "system prompt", "user prompt")
	if !errors.Is(err, ErrLLMInputLimitExceeded) {
		t.Fatalf("err = %v, want ErrLLMInputLimitExceeded", err)
	}
	if atomic.LoadInt32(&hits) != 0 {
		t.Errorf("hits = %d, want 0（超限不应发起模型呼叫）", hits)
	}
}

// TestLLMComposeInputTokenLimitDisabled 未配置 MaxInputTokens 时不做输入侧拦截。
func TestLLMComposeInputTokenLimitDisabled(t *testing.T) {
	var maxTokensSeen int64
	var hits int32
	gw := composeTestGateway(t, &maxTokensSeen, &hits)
	o := New(nil, gw, nil, nil, nil, nil, TaskLimits{MaxDuration: time.Minute})

	if _, err := o.llmCompose(context.Background(), "system prompt", "user prompt"); err != nil {
		t.Fatalf("llmCompose err = %v", err)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Errorf("hits = %d, want 1（未配置上限应正常呼叫）", hits)
	}
}
