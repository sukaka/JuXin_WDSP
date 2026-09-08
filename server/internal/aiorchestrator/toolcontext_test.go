package aiorchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/aitools"
)

// stubTool 最小 Tool 实现（白名单/限额测试用；aitools 的测试替身不跨包导出）。
type stubTool struct{ code string }

func (s stubTool) Code() string                        { return s.code }
func (s stubTool) Name() string                        { return s.code }
func (s stubTool) Description() string                 { return "" }
func (s stubTool) Version() string                     { return "1.0.0" }
func (s stubTool) RiskLevel() string                   { return aitools.RiskReadOnly }
func (s stubTool) RequiredPermission() string          { return "" }
func (s stubTool) TimeoutSeconds() int                 { return 5 }
func (s stubTool) MaxResults() int                     { return 10 }
func (s stubTool) InputSchema() map[string]interface{} { return nil }
func (s stubTool) Run(context.Context, json.RawMessage) (interface{}, error) {
	return map[string]interface{}{"ok": true}, nil
}

// newToolContext 构造带两个注册 Tool 的执行上下文（agentCode 固定为 security_event）。
func newToolContext(maxCalls int, checker AgentToolChecker) *ToolContext {
	reg := aitools.NewRegistry()
	reg.Register(stubTool{code: "log.query"})
	reg.Register(stubTool{code: "security_event.get"})
	return &ToolContext{
		Registry: reg, TaskID: uuid.New(),
		agentCode: "security_event", allowedTools: checker,
		maxToolCalls: maxCalls, calls: new(int64),
	}
}

// TestCallToolAgentToolWhitelist Agent 配置 allowed_tool_ids 时：白名单内放行、白名单外拒绝。
func TestCallToolAgentToolWhitelist(t *testing.T) {
	ctx := context.Background()
	p := &aitools.Principal{UserID: uuid.New(), Username: "u"}
	tc := newToolContext(0, func(_ context.Context, agentCode, toolCode string) bool {
		if agentCode != "security_event" {
			t.Errorf("checker 收到的 agentCode = %q", agentCode)
		}
		return toolCode == "log.query"
	})

	if _, err := tc.CallTool(ctx, p, "log.query", nil); err != nil {
		t.Errorf("白名单内 Tool 应放行: %v", err)
	}
	_, err := tc.CallTool(ctx, p, "security_event.get", nil)
	if !errors.Is(err, ErrAgentToolNotAllowed) {
		t.Errorf("白名单外 Tool err = %v, want ErrAgentToolNotAllowed", err)
	}
}

// TestCallToolWhitelistSkippedWithoutAgentContext 无 Agent 语境（agentCode 为空）不做白名单校验。
func TestCallToolWhitelistSkippedWithoutAgentContext(t *testing.T) {
	tc := newToolContext(0, func(context.Context, string, string) bool { return false })
	tc.agentCode = ""
	if _, err := tc.CallTool(context.Background(), nil, "log.query", nil); err != nil {
		t.Errorf("无 Agent 语境不应触发白名单拒绝: %v", err)
	}
}

// TestCallToolMaxToolCallsEnforced 单任务 Tool 调用上限按共享计数器强制，超限拒绝。
func TestCallToolMaxToolCallsEnforced(t *testing.T) {
	ctx := context.Background()
	tc := newToolContext(2, nil)
	for i := 0; i < 2; i++ {
		if _, err := tc.CallTool(ctx, nil, "log.query", nil); err != nil {
			t.Fatalf("第 %d 次调用应放行: %v", i+1, err)
		}
	}
	if _, err := tc.CallTool(ctx, nil, "log.query", nil); !errors.Is(err, ErrToolCallLimitExceeded) {
		t.Errorf("第 3 次调用 err = %v, want ErrToolCallLimitExceeded", err)
	}
}

// TestCallToolCounterSharedAcrossAgents 同次编排多个 Agent 视图共享任务计数器（TaskID 口径合计）。
func TestCallToolCounterSharedAcrossAgents(t *testing.T) {
	ctx := context.Background()
	calls := new(int64)
	base := newToolContext(1, nil)
	a := base.forAgent(base.TaskID, "security_event", calls)
	b := base.forAgent(base.TaskID, "log_analysis", calls)

	if _, err := a.CallTool(ctx, nil, "log.query", nil); err != nil {
		t.Fatalf("Agent A 首次调用应放行: %v", err)
	}
	// Agent B 的视图共享同一任务计数：第 2 次即超限
	if _, err := b.CallTool(ctx, nil, "log.query", nil); !errors.Is(err, ErrToolCallLimitExceeded) {
		t.Errorf("Agent B 共享计数后 err = %v, want ErrToolCallLimitExceeded", err)
	}
	// 独立任务计数器互不影响
	other := base.forAgent(uuid.New(), "log_analysis", new(int64))
	if _, err := other.CallTool(ctx, nil, "log.query", nil); err != nil {
		t.Errorf("新任务计数器应独立放行: %v", err)
	}
}

// TestCallToolForAgentSetsTaskIdentity forAgent 落定 TaskID 与 agentCode（审计归因与白名单来源）。
func TestCallToolForAgentSetsTaskIdentity(t *testing.T) {
	taskID := uuid.New()
	base := &ToolContext{TaskID: uuid.New()} // 裸基座：无 Agent 语境
	derived := base.forAgent(taskID, "waf_policy", new(int64))
	if derived.TaskID != taskID || derived.agentCode != "waf_policy" {
		t.Errorf("forAgent 视图身份 = (%v, %q)", derived.TaskID, derived.agentCode)
	}
	if base.agentCode != "" {
		t.Error("forAgent 不得修改共享基座")
	}
}
