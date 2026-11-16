// intent_api_test.go API 安全分析意图分类测试（AI 能力增强第一波）：
// API 域问题路由 api_security Agent；普通 WAF 统计/日志/事件问题不得被误路由。
package aiorchestrator

import (
	"strings"
	"testing"
)

// TestClassifyAPISecurityAnalysis API 域问题命中新任务类型并调度 api_security。
func TestClassifyAPISecurityAnalysis(t *testing.T) {
	cases := []string{
		"有哪些影子 API",
		"僵尸接口怎么清理",
		"api 模型版本之间有差异吗",
		"这个接口的参数偏离基线了吗",
		"是否存在 BOLA 越权风险",
		"敏感数据类型有哪些",
		"未整改弱点清单",
		"API 安全态势怎么样",
		"端点学习覆盖率是多少",
		"api 运行时统计",
		"接口风险发现有哪些",
		"shadow api review",
		"统计 api 接口调用量",
	}
	for _, msg := range cases {
		plan := Classify(msg)
		if plan.TaskType != TaskAPISecurityAnalysis {
			t.Errorf("Classify(%q).TaskType = %s, want %s", msg, plan.TaskType, TaskAPISecurityAnalysis)
			continue
		}
		if len(plan.Agents) != 1 || plan.Agents[0] != "api_security" {
			t.Errorf("Classify(%q).Agents = %v, want [api_security]", msg, plan.Agents)
		}
		if plan.RiskLevel != "LOW" {
			t.Errorf("Classify(%q).RiskLevel = %s, want LOW", msg, plan.RiskLevel)
		}
	}
}

// TestClassifyAPIDoesNotHijackWAF 防串线：普通 WAF 问题仍走既有任务类型。
func TestClassifyAPIDoesNotHijackWAF(t *testing.T) {
	cases := map[string]TaskType{
		"统计最近 24 小时攻击类型分布":    TaskStatistics,
		"今天哪种类型的攻击最多":         TaskStatistics,
		"查询今天的访问日志":           TaskLogQuery,
		"942100 这条规则是干什么的":    TaskRuleExplanation,
		"谁在攻击我的网站":            TaskAttackProfile,
		"为什么 WAF 延迟突然升高，帮忙排查": TaskRootCause,
		"生成本周安全周报":            TaskReportSummary,
		"分析一下这条事件":            TaskEventAnalysis,
		"这条拦截是不是误报":           TaskFalsePositive,
		"请给出策略优化建议":           TaskPolicyRec,
		"如果关闭这条规则会怎样":         TaskWhatIf,
		"今天天气怎么样":             TaskGeneralQA,
	}
	for msg, want := range cases {
		plan := Classify(msg)
		if plan.TaskType != want {
			t.Errorf("Classify(%q).TaskType = %s, want %s（API 意图不得串线）", msg, plan.TaskType, want)
		}
	}
}

// TestCapabilityIntroMentionsAPI 能力介绍包含 API 能力描述。
func TestCapabilityIntroMentionsAPI(t *testing.T) {
	intro := CapabilityIntro()
	for _, kw := range []string{"API 安全分析", "影子", "越权", "弱点"} {
		if !strings.Contains(intro, kw) {
			t.Errorf("CapabilityIntro 缺少 %q", kw)
		}
	}
}
