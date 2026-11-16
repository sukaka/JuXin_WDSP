package aiorchestrator

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/aimodel"
)

// composeSystemPrompt 用录制网关跑一次 composeAnswer，返回首个 LLM 呼叫的 system 提示词。
func composeSystemPrompt(t *testing.T, loader func(context.Context, string) (string, error), overrides map[string]string) string {
	t.Helper()
	var hits int32
	var bodies [][]aimodel.ChatMessage
	gw := continueTestGateway(t, []struct{ content, finish string }{resp("总结", "stop")}, &hits, &bodies)
	o := New(nil, gw, nil, nil, nil, nil, TaskLimits{MaxDuration: time.Minute})
	o.SetPromptLoader(loader)
	if _, _, _, err := o.composeAnswer(context.Background(),
		Plan{TaskType: TaskStatistics}, "统计攻击趋势", "已核实事实", nil, "", nil, uuid.New(), "admin", overrides); err != nil {
		t.Fatalf("composeAnswer err = %v", err)
	}
	if atomic.LoadInt32(&hits) != 1 || len(bodies) != 1 || len(bodies[0]) == 0 {
		t.Fatalf("llm hits = %d bodies = %d, want 1 call", hits, len(bodies))
	}
	return bodies[0][0].Content
}

// TestComposeAnswerPromptOverride 候选 Prompt 仅本次运行覆盖已发布 Prompt（不触碰发布存储）。
func TestComposeAnswerPromptOverride(t *testing.T) {
	published := func(context.Context, string) (string, error) { return "已发布回答规则", nil }

	// 无覆盖：使用已发布 Prompt
	sys := composeSystemPrompt(t, published, nil)
	if !strings.Contains(sys, "已发布回答规则") {
		t.Fatalf("system prompt should contain published prompt: %s", sys)
	}

	// 候选覆盖：本运行使用候选内容，不携带已发布内容
	sys = composeSystemPrompt(t, published, map[string]string{AnswerSummaryPromptCode: "候选回答规则v2"})
	if !strings.Contains(sys, "候选回答规则v2") || strings.Contains(sys, "已发布回答规则") {
		t.Fatalf("override should replace published prompt for this run: %s", sys)
	}

	// 空白候选视为未覆盖，回退已发布 Prompt
	sys = composeSystemPrompt(t, published, map[string]string{AnswerSummaryPromptCode: "  "})
	if !strings.Contains(sys, "已发布回答规则") {
		t.Fatalf("blank override should fall back to published prompt: %s", sys)
	}

	// 无已发布 Prompt + 无覆盖：仅内置安全默认规则（不携带「管理员已发布」段）
	none := func(context.Context, string) (string, error) { return "", nil }
	sys = composeSystemPrompt(t, none, nil)
	if strings.Contains(sys, "管理员已发布的回答规则") {
		t.Fatalf("no published prompt expected: %s", sys)
	}
	if !strings.Contains(sys, "你是企业WAF安全助手的总结器") {
		t.Fatalf("builtin safety rules missing: %s", sys)
	}
}
