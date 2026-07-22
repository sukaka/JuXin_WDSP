package aiorchestrator

import (
	"fmt"
	"testing"
)

// TestClassifyIntents 覆盖全部意图类型：事件分析/误报/规则解释/画像/攻击链/根因/日志/统计/策略/What-If/报告/通用问答。
func TestClassifyIntents(t *testing.T) {
	cases := []struct {
		name    string
		message string
		want    TaskType
		risk    string
	}{
		{"event analysis", "分析一下这条事件", TaskEventAnalysis, "LOW"},
		{"false positive", "这是误报，请帮忙确认", TaskFalsePositive, "MEDIUM"},
		{"false positive kill", "这条拦截是误杀", TaskFalsePositive, "MEDIUM"},
		{"false positive english", "false positive, please check", TaskFalsePositive, "MEDIUM"},
		{"rule explanation", "942100 这条规则是干什么的", TaskRuleExplanation, "LOW"},
		{"attack profile", "谁在攻击我的网站", TaskAttackProfile, "LOW"},
		{"attack profile 2", "给我攻击者画像", TaskAttackProfile, "LOW"},
		{"attack chain", "帮我还原这次入侵的攻击链", TaskAttackChain, "LOW"},
		{"root cause", "为什么 WAF 延迟突然升高，帮忙排查", TaskRootCause, "LOW"},
		{"log query", "查询今天的访问日志", TaskLogQuery, "LOW"},
		{"statistics", "统计最近 7 天的攻击趋势", TaskStatistics, "LOW"},
		{"policy recommendation", "请给出策略优化建议", TaskPolicyRec, "MEDIUM"},
		{"what-if", "如果关闭这条规则会怎样", TaskWhatIf, "MEDIUM"},
		{"report summary", "生成本周安全周报", TaskReportSummary, "LOW"},
		{"general qa", "今天天气怎么样", TaskGeneralQA, "LOW"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			plan := Classify(c.message)
			if plan.TaskType != c.want {
				t.Errorf("Classify(%q).TaskType = %s, want %s", c.message, plan.TaskType, c.want)
			}
			if plan.RiskLevel != c.risk {
				t.Errorf("Classify(%q).RiskLevel = %s, want %s", c.message, plan.RiskLevel, c.risk)
			}
			if len(plan.Agents) == 0 {
				t.Errorf("Classify(%q).Agents 为空", c.message)
			}
			if plan.Summary == "" {
				t.Errorf("Classify(%q).Summary 为空", c.message)
			}
		})
	}
}

// TestClassifyIDFallback 无规则命中但含事件/规则标识时兜底为事件分析。
func TestClassifyIDFallback(t *testing.T) {
	plan := Classify("帮我看看 ab12cd34-5678-90ab-cdef-1234567890ab")
	if plan.TaskType != TaskEventAnalysis {
		t.Errorf("含 UUID 应兜底为事件分析, got %s", plan.TaskType)
	}
	plan = Classify("编号 942100")
	if plan.TaskType != TaskEventAnalysis {
		t.Errorf("含 6 位数字编号应兜底为事件分析, got %s", plan.TaskType)
	}
	if plan.RiskLevel != "LOW" {
		t.Errorf("兜底风险等级应为 LOW, got %s", plan.RiskLevel)
	}
}

// TestClassifyGreetingNoAgents 问候语不调度业务 Agent，走能力介绍。
func TestClassifyGreetingNoAgents(t *testing.T) {
	for _, msg := range []string{"你好", "您好", "hello", "hi", "你能做什么", "帮助"} {
		plan := Classify(msg)
		if plan.TaskType != TaskGeneralQA {
			t.Errorf("Classify(%q).TaskType = %s, want %s", msg, plan.TaskType, TaskGeneralQA)
		}
		if len(plan.Agents) != 0 {
			t.Errorf("Classify(%q).Agents = %v, want 空（能力介绍）", msg, plan.Agents)
		}
		if plan.Summary != "助手能力介绍" {
			t.Errorf("Classify(%q).Summary = %q", msg, plan.Summary)
		}
	}
}

// TestClassifyGeneralQAAgents 非问候通用问答仅调度 knowledge（不刷 24h 攻击统计）。
func TestClassifyGeneralQAAgents(t *testing.T) {
	plan := Classify("今天天气怎么样")
	if plan.TaskType != TaskGeneralQA {
		t.Fatalf("TaskType = %s, want %s", plan.TaskType, TaskGeneralQA)
	}
	if len(plan.Agents) != 1 || plan.Agents[0] != "knowledge" {
		t.Fatalf("Agents = %v, want [knowledge]", plan.Agents)
	}
}

// TestIsGreetingOrHelp 问候与业务词区分。
func TestIsGreetingOrHelp(t *testing.T) {
	if !IsGreetingOrHelp("你好") || !IsGreetingOrHelp("Hello!") {
		t.Fatal("问候应识别")
	}
	if IsGreetingOrHelp("误报分析") || IsGreetingOrHelp("统计攻击") {
		t.Fatal("业务问题不应识别为问候")
	}
	if CapabilityIntro() == "" {
		t.Fatal("CapabilityIntro 不应为空")
	}
}

// TestExtractIDs 提取事件 UUID、规则 ID 与合法 IP。
func TestExtractIDs(t *testing.T) {
	msg := "事件 ab12cd34-5678-90ab-cdef-1234567890ab 命中规则 942100，来源 IP 10.1.2.3"
	eventIDs, ruleIDs, ips := ExtractIDs(msg)
	if len(eventIDs) != 1 || eventIDs[0] != "ab12cd34-5678-90ab-cdef-1234567890ab" {
		t.Errorf("eventIDs = %v", eventIDs)
	}
	if len(ruleIDs) != 1 || ruleIDs[0] != 942100 {
		t.Errorf("ruleIDs = %v", ruleIDs)
	}
	if len(ips) != 1 || ips[0] != "10.1.2.3" {
		t.Errorf("ips = %v", ips)
	}
}

// TestExtractIDsRuleIDFormats 覆盖各规则 ID 段（CRS 94x-96x 为 6 位、项目自定义 7100x/8000x 为 7 位）。
func TestExtractIDsRuleIDFormats(t *testing.T) {
	_, ruleIDs, _ := ExtractIDs("规则 951234 与 8000123 以及 7100456")
	if len(ruleIDs) != 3 {
		t.Fatalf("ruleIDs = %v", ruleIDs)
	}
	want := []int{951234, 8000123, 7100456}
	for i, w := range want {
		if ruleIDs[i] != w {
			t.Errorf("ruleIDs[%d] = %d, want %d", i, ruleIDs[i], w)
		}
	}
}

// TestExtractIDsInvalidIP 段值超过 255 的 IP 被剔除。
func TestExtractIDsInvalidIP(t *testing.T) {
	_, _, ips := ExtractIDs("可疑地址 999.1.1.1 和 10.0.0.256 以及 1.2.3.4")
	if len(ips) != 1 || ips[0] != "1.2.3.4" {
		t.Errorf("ips = %v, want [1.2.3.4]", ips)
	}
}

// TestExtractIDsLimit 每类标识最多提取 5 个。
func TestExtractIDsLimit(t *testing.T) {
	msg := ""
	for i := 0; i < 7; i++ {
		msg += fmt.Sprintf("%08x-1111-1111-1111-111111111111 ", i)
	}
	eventIDs, _, _ := ExtractIDs(msg)
	if len(eventIDs) != 5 {
		t.Errorf("eventIDs 数量 = %d, want 5", len(eventIDs))
	}
}

// TestExtractIDsEmpty 无标识时返回空。
func TestExtractIDsEmpty(t *testing.T) {
	eventIDs, ruleIDs, ips := ExtractIDs("没有任何标识的普通问题")
	if len(eventIDs) != 0 || len(ruleIDs) != 0 || len(ips) != 0 {
		t.Errorf("应全部为空, got %v %v %v", eventIDs, ruleIDs, ips)
	}
}
