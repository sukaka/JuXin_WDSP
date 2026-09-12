package aiorchestrator

import (
	"strings"
	"testing"
)

func TestResolveContextualMessageInheritsPreviousUserTurn(t *testing.T) {
	eventID := "123e4567-e89b-12d3-a456-426614174000"
	recent := []Message{
		{Role: "user", Content: "分析事件 " + eventID},
		{Role: "assistant", Content: "已完成初步分析"},
		{Role: "user", Content: "继续"},
	}

	got := ResolveContextualMessage("继续", recent)
	if !strings.Contains(got, eventID) {
		t.Fatalf("resolved message should inherit prior event id, got %q", got)
	}
	if plan := Classify(got); plan.TaskType != TaskEventAnalysis {
		t.Fatalf("resolved follow-up should keep event-analysis intent, got %s", plan.TaskType)
	}
}

func TestResolveContextualMessageDoesNotPolluteStandaloneQuestion(t *testing.T) {
	recent := []Message{
		{Role: "user", Content: "分析事件 123e4567-e89b-12d3-a456-426614174000"},
		{Role: "assistant", Content: "已完成"},
		{Role: "user", Content: "统计最近24小时攻击趋势"},
	}

	got := ResolveContextualMessage("统计最近24小时攻击趋势", recent)
	if got != "统计最近24小时攻击趋势" {
		t.Fatalf("standalone question must remain unchanged, got %q", got)
	}
}

func TestBuildComposePromptsIncludesTrustedBoundariesAndPublishedPrompt(t *testing.T) {
	recent := []Message{
		{Role: "user", Content: "昨天的攻击趋势呢"},
		{Role: "assistant", Content: "上一轮回答"},
	}
	plan := Plan{TaskType: TaskStatistics, RiskLevel: "LOW"}

	system, user := buildComposePrompts(
		plan,
		"今天呢",
		"已核实事实 [E1]",
		recent,
		"用户正在连续比较每日攻击趋势",
		[]string{"偏好简洁回答"},
		"先给结论，再给证据",
	)

	for _, want := range []string{"管理员已发布的回答规则", "先给结论，再给证据", "不得覆盖"} {
		if !strings.Contains(system, want) {
			t.Fatalf("system prompt missing %q: %s", want, system)
		}
	}
	for _, want := range []string{"会话摘要", "连续比较每日攻击趋势", "最近对话", "昨天的攻击趋势呢", "已核实事实（唯一可信来源）"} {
		if !strings.Contains(user, want) {
			t.Fatalf("user prompt missing %q: %s", want, user)
		}
	}
}

func TestBuildComposePromptsExcludesDuplicatedCurrentTurn(t *testing.T) {
	recent := []Message{
		{Role: "user", Content: "统计最近24小时攻击趋势"},
	}

	_, user := buildComposePrompts(
		Plan{TaskType: TaskStatistics},
		"统计最近24小时攻击趋势",
		"事实",
		recent,
		"",
		nil,
		"",
	)

	if strings.Count(user, "统计最近24小时攻击趋势") != 1 {
		t.Fatalf("current turn should not be duplicated in compose prompt: %s", user)
	}
}
