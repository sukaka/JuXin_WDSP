// intent.go 意图分类与任务规划（确定性规则，可测试）。
package aiorchestrator

import (
	"regexp"
	"strings"
)

// TaskType 任务类型。
type TaskType string

const (
	TaskEventAnalysis   TaskType = "EVENT_ANALYSIS"
	TaskFalsePositive   TaskType = "FALSE_POSITIVE_ANALYSIS"
	TaskRuleExplanation TaskType = "RULE_EXPLANATION"
	TaskAttackProfile   TaskType = "ATTACK_PROFILE"
	TaskAttackChain     TaskType = "ATTACK_CHAIN"
	TaskRootCause       TaskType = "ROOT_CAUSE_ANALYSIS"
	TaskLogQuery        TaskType = "LOG_QUERY"
	TaskStatistics      TaskType = "STATISTICS_QUERY"
	TaskPolicyRec       TaskType = "POLICY_RECOMMENDATION"
	TaskWhatIf          TaskType = "WHAT_IF_ANALYSIS"
	TaskReportSummary   TaskType = "REPORT_SUMMARY"
	TaskGeneralQA       TaskType = "GENERAL_SECURITY_QA"
)

// intentRule 意图规则（优先级排序）。
type intentRule struct {
	typ     TaskType
	pattern *regexp.Regexp
	agents  []string // 调度 Agent
}

var intentRules = []intentRule{
	{TaskFalsePositive, regexp.MustCompile(`误报|false.?positive`), []string{"waf_policy", "security_event"}},
	{TaskRuleExplanation, regexp.MustCompile(`规则.*(解释|什么意思|干什么|用途)|\b\d{6,7}\b.*(规则|解释)`), []string{"waf_policy", "knowledge"}},
	{TaskAttackChain, regexp.MustCompile(`攻击链|攻击过程|入侵过程|chain`), []string{"security_event", "log_analysis"}},
	{TaskRootCause, regexp.MustCompile(`为什么.*(延迟|失败|异常|升高|不足|错误|慢|积压|崩溃)|根因|root.?cause|怎么回事|排查`), []string{"ops_diagnostic", "log_analysis"}},
	{TaskAttackProfile, regexp.MustCompile(`画像|谁在攻击|哪个ip|来源|攻击者`), []string{"security_event", "log_analysis"}},
	{TaskFalsePositive, regexp.MustCompile(`误杀|误拦|误阻断`), []string{"waf_policy", "security_event"}},
	{TaskEventAnalysis, regexp.MustCompile(`事件.*分析|分析.*事件|这条事件|这个事件|分析一下`), []string{"security_event"}},
	{TaskPolicyRec, regexp.MustCompile(`策略.*(建议|优化|调整|推荐)|优化.*策略|调优|建议.*规则`), []string{"waf_policy"}},
	{TaskWhatIf, regexp.MustCompile(`what.?if|如果.*(关掉|关闭|启用|改成|切换|调整)|模拟|假设`), []string{"waf_policy"}},
	{TaskReportSummary, regexp.MustCompile(`(日报|周报|月报|总结|汇总).*(安全|攻击|运营)?|(安全|攻击|运营).*(日报|周报|月报|总结|汇总)`), []string{"report"}},
	{TaskLogQuery, regexp.MustCompile(`日志|log|查询.*请求|请求.*记录`), []string{"log_analysis"}},
	{TaskStatistics, regexp.MustCompile(`统计|趋势|排行|top|多少|数量|分布`), []string{"security_event", "log_analysis"}},
}

// Plan 任务计划摘要（前端可展示，非私有思维链）。
type Plan struct {
	TaskType  TaskType `json:"task_type"`
	Agents    []string `json:"agents"`
	RiskLevel string   `json:"risk_level"`
	Summary   string   `json:"summary"`
}

// Classify 意图分类（确定性规则 + 上下文 hint）。
func Classify(message string) Plan {
	// 问候/能力询问：不调度业务 Agent，由编排器返回能力介绍（避免把「你好」当规则关键字搜索）
	if IsGreetingOrHelp(message) {
		return Plan{
			TaskType:  TaskGeneralQA,
			Agents:    nil,
			RiskLevel: "LOW",
			Summary:   "助手能力介绍",
		}
	}
	msg := strings.ToLower(message)
	for _, rule := range intentRules {
		if rule.pattern.MatchString(msg) {
			return Plan{
				TaskType:  rule.typ,
				Agents:    rule.agents,
				RiskLevel: riskOf(rule.typ),
				Summary:   summaryOf(rule.typ, rule.agents),
			}
		}
	}
	// 含事件ID/规则ID/Request ID → 事件分析
	if regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}`).MatchString(msg) || regexp.MustCompile(`\b\d{6,7}\b`).MatchString(msg) {
		return Plan{TaskType: TaskEventAnalysis, Agents: []string{"security_event"}, RiskLevel: "LOW",
			Summary: "识别到事件/规则标识，执行安全事件分析"}
	}
	// 通用问答默认只走知识库，不拉 24h 攻击统计（避免闲聊/非安全问题刷屏运营数据）
	return Plan{TaskType: TaskGeneralQA, Agents: []string{"knowledge"}, RiskLevel: "LOW",
		Summary: "通用安全问答"}
}

// IsGreetingOrHelp 识别问候、寒暄与「你能做什么」类能力询问。
// 此类消息不应触发规则库关键字搜索或安全事件统计。
func IsGreetingOrHelp(message string) bool {
	m := strings.TrimSpace(strings.ToLower(message))
	m = strings.Trim(m, " \t\r\n!！?？.。~～、,，")
	if m == "" {
		return true
	}
	// 精确/前缀匹配的常见问候与帮助话术
	phrases := []string{
		"你好", "您好", "嗨", "哈喽", "hello", "hi", "hey",
		"在吗", "在不在", "早上好", "下午好", "晚上好", "午安",
		"谢谢", "感谢", "多谢", "拜拜", "再见", "bye",
		"帮助", "help", "怎么用", "使用说明", "使用帮助",
		"你是谁", "你是干什么的", "你能做什么", "你会什么", "能做什么",
		"有什么功能", "功能介绍", "介绍一下", "介绍下自己",
	}
	for _, p := range phrases {
		if m == p {
			return true
		}
		// 允许短尾缀：「你好啊」「hello!」等（总长不超过短语 + 4 个字符）
		if strings.HasPrefix(m, p) {
			rest := strings.TrimPrefix(m, p)
			if len([]rune(rest)) <= 4 && !hasSecurityKeyword(rest) {
				return true
			}
		}
	}
	// 极短且无安全语义的闲聊（≤3 字）
	if len([]rune(m)) <= 3 && !hasSecurityKeyword(m) {
		return true
	}
	return false
}

// hasSecurityKeyword 粗粒度安全语义探测（用于排除误把业务词当问候）。
func hasSecurityKeyword(s string) bool {
	return regexp.MustCompile(`攻击|事件|规则|waf|拦截|阻断|误报|日志|统计|策略|黑名单|白名单|sql|xss|cc|ip|封禁|告警`).MatchString(s)
}

// CapabilityIntro 助手能力介绍正文（确定性模板，不经 LLM）。
func CapabilityIntro() string {
	return strings.TrimSpace(`
**九章 AI 安全助手**

您好，我是企业 WAF 安全运营助手，可基于本系统真实数据协助研判，不会编造未查询到的事实。

**我能帮您：**
1. 安全事件分析（粘贴事件 UUID）
2. 误报 / 误杀研判
3. 规则解释（如「942100 是干什么的」）
4. 攻击画像、攻击链关联
5. 统计与趋势（如「最近 24 小时攻击类型分布」）
6. 策略建议、根因排查、报告总结

**可以这样问：**
- 统计最近 24 小时攻击类型分布
- 942100 规则是干什么的
- 谁在攻击我的网站
- 分析事件 <事件UUID>
- 这条拦截是不是误报

> 回答仅供辅助决策；涉及生产变更请走既有审核与发布流程。
`)
}

func riskOf(t TaskType) string {
	switch t {
	case TaskFalsePositive, TaskPolicyRec, TaskWhatIf:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func summaryOf(t TaskType, agents []string) string {
	names := map[TaskType]string{
		TaskEventAnalysis:   "安全事件分析",
		TaskFalsePositive:   "误报研判",
		TaskRuleExplanation: "规则解释",
		TaskAttackProfile:   "攻击画像",
		TaskAttackChain:     "攻击链关联",
		TaskRootCause:       "根因分析",
		TaskLogQuery:        "日志查询",
		TaskStatistics:      "统计问答",
		TaskPolicyRec:       "策略优化建议",
		TaskWhatIf:          "What-If 策略模拟",
		TaskReportSummary:   "报告总结",
		TaskGeneralQA:       "通用安全问答",
	}
	return names[t] + "（调度: " + strings.Join(agents, ", ") + "）"
}

// ExtractIDs 从消息提取事件ID/规则ID/IP/时间范围提示。
func ExtractIDs(message string) (eventIDs []string, ruleIDs []int, ips []string) {
	idRe := regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`)
	eventIDs = idRe.FindAllString(message, 5)
	// CRS 规则 ID 为 6 位（如 942100），自定义规则号段 7100000-7199999、内置 8000xxx
	ruleRe := regexp.MustCompile(`\b(9[1-6]\d{4}|7100\d{3}|8000\d{3})\b`)
	for _, m := range ruleRe.FindAllString(message, 5) {
		var n int
		for _, r := range m {
			n = n*10 + int(r-'0')
		}
		ruleIDs = append(ruleIDs, n)
	}
	ipRe := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	for _, ip := range ipRe.FindAllString(message, 5) {
		parts := 0
		valid := true
		for _, seg := range strings.Split(ip, ".") {
			n := 0
			for _, r := range seg {
				n = n*10 + int(r-'0')
			}
			if n > 255 {
				valid = false
				break
			}
			parts++
		}
		if valid && parts == 4 {
			ips = append(ips, ip)
		}
	}
	return
}
