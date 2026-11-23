package aiorchestrator

import (
	"fmt"
	"strings"
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
		{"statistics natural top attack", "今天哪种类型的攻击最多", TaskStatistics, "LOW"},
		{"statistics natural common attack", "最常见的攻击类型是什么", TaskStatistics, "LOW"},
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

func TestClassifyAttackRankingUsesSecurityEventOnly(t *testing.T) {
	plan := Classify("今天哪种类型的攻击最多")
	if len(plan.Agents) != 1 || plan.Agents[0] != "security_event" {
		t.Fatalf("expected only security_event agent, got %#v", plan.Agents)
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

func TestPlanForTaskTypeAllTypes(t *testing.T) {
	wantAgents := map[TaskType][]string{
		TaskEventAnalysis:       {"security_event"},
		TaskFalsePositive:       {"waf_policy", "security_event"},
		TaskRuleExplanation:     {"waf_policy", "knowledge"},
		TaskAttackProfile:       {"security_event", "log_analysis"},
		TaskAttackChain:         {"security_event", "log_analysis"},
		TaskRootCause:           {"ops_diagnostic", "log_analysis"},
		TaskLogQuery:            {"log_analysis"},
		TaskStatistics:          {"security_event"},
		TaskPolicyRec:           {"waf_policy"},
		TaskWhatIf:              {"waf_policy"},
		TaskReportSummary:       {"report"},
		TaskGeneralQA:           {"knowledge"},
		TaskAPISecurityAnalysis: {"api_security"},
	}
	for tt, want := range wantAgents {
		plan, ok := PlanForTaskType(tt)
		if !ok {
			t.Fatalf("PlanForTaskType(%q) ok=false, want true", tt)
		}
		if plan.TaskType != tt {
			t.Errorf("Plan.TaskType = %q, want %q", plan.TaskType, tt)
		}
		if len(plan.Agents) != len(want) {
			t.Fatalf("PlanForTaskType(%q).Agents = %v, want %v", tt, plan.Agents, want)
		}
		for i := range want {
			if plan.Agents[i] != want[i] {
				t.Errorf("PlanForTaskType(%q).Agents[%d] = %q, want %q", tt, i, plan.Agents[i], want[i])
			}
		}
		if plan.RiskLevel == "" || plan.Summary == "" {
			t.Errorf("PlanForTaskType(%q) missing risk/summary: %+v", tt, plan)
		}
		// 防御性拷贝检查：修改返回的 Agents 不得影响后续调用
		plan.Agents[0] = "mutated"
		again, _ := PlanForTaskType(tt)
		if again.Agents[0] != want[0] {
			t.Fatalf("PlanForTaskType(%q) leaked mutable Agents slice", tt)
		}
	}
	for _, bogus := range []TaskType{"", "BOGUS"} {
		if _, ok := PlanForTaskType(bogus); ok {
			t.Errorf("PlanForTaskType(%q) ok=true, want false", bogus)
		}
	}
}

func TestExtractIDsIPv6AndMixedOrder(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		want []string
	}{
		{"ipv6 bare", "请分析 2001:db8::1 的行为", []string{"2001:db8::1"}},
		{"ipv6 loopback", "来自 ::1 的请求", []string{"::1"}},
		{"ipv6 bracketed port", "来源 [2001:db8::1]:8080 异常", []string{"2001:db8::1"}},
		{"ipv6 prefix IP", "IP:2001:db8::1 命中规则", []string{"2001:db8::1"}},
		{"ipv6 prefix src", "src:2001:db8::1 命中规则", []string{"2001:db8::1"}},
		{"ipv6 adjacent cjk", "对2001:db8::1做画像", []string{"2001:db8::1"}},
		{"ipv6 leading zero canonical", "分析 2001:0db8::1", []string{"2001:db8::1"}},
		{"ipv4 mapped ipv6", "来源 ::ffff:192.0.2.1", []string{"192.0.2.1"}},
		{"ipv6 then ipv4 order", "2001:db8::1 compare with 10.0.0.1", []string{"2001:db8::1", "10.0.0.1"}},
		{"ipv4 then ipv6 order", "10.0.0.1 compare with 2001:db8::1", []string{"10.0.0.1", "2001:db8::1"}},
		{"sentence period", "来自 1.2.3.4. 和 2001:db8::1.", []string{"1.2.3.4", "2001:db8::1"}},
		{"reject timestamps macs bogus", "2026-11-20T05:05:41Z 12:34:56 00:11:22:33:44:55 std::vector foo::bar :: 2001:db8::1foo 1.2.3.4foo 999.1.1.1 10.0.0.256 1.2.3.4.5", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, ips := ExtractIDs(tc.msg)
			if len(ips) != len(tc.want) {
				t.Fatalf("ExtractIDs(%q) ips=%v, want %v", tc.msg, ips, tc.want)
			}
			for i := range tc.want {
				if ips[i] != tc.want[i] {
					t.Errorf("ips[%d]=%q, want %q (all=%v)", i, ips[i], tc.want[i], ips)
				}
			}
		})
	}

	// 校验后限 5 个 IP：前置大量时间戳/非法 IP 不得挤占有效 IP 名额
	noisy := strings.Repeat("12:34:56 999.1.1.1 ", 6) + "2001:db8::1"
	_, _, ips := ExtractIDs(noisy)
	if len(ips) != 1 || ips[0] != "2001:db8::1" {
		t.Fatalf("post-validation cap failed: got %v", ips)
	}

	// 7 个有效 IPv4/IPv6 上限截断为 5 个
	seven := "10.0.0.1 2001:db8::1 10.0.0.2 2001:db8::2 10.0.0.3 2001:db8::3 10.0.0.4"
	_, _, ips = ExtractIDs(seven)
	if len(ips) != 5 {
		t.Fatalf("expected 5 IPs cap, got %d (%v)", len(ips), ips)
	}
}
