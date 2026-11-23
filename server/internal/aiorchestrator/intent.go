// intent.go 意图分类与任务规划（确定性规则，可测试）。
package aiorchestrator

import (
	"net"
	"regexp"
	"strings"
)

var contextualFollowUpPattern = regexp.MustCompile(`^(?:继续|接着|往下|再查|再看看|详细点|展开|那|那么|这个|这个呢|该事件|该规则|昨天呢|今天呢|上周呢|本周呢|上个月呢|本月呢|刚才|之前|上面|前面|同一个|相比|对比)`)

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
	// TaskAPISecurityAnalysis API 安全分析（阶段8 / WDSP 形态专属；调度 api_security Agent，
	// 纯 WAF 形态该 Agent 未注册，编排器跳过未注册 Agent 不产生伪造事实）。
	TaskAPISecurityAnalysis TaskType = "API_SECURITY_ANALYSIS"
)

// taskTypeAgents 每种任务类型的规范调度 Agent（intentRules 与 PlanForTaskType 的唯一真源）。
var taskTypeAgents = map[TaskType][]string{
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

func agentsOf(t TaskType) ([]string, bool) {
	agents, ok := taskTypeAgents[t]
	if !ok {
		return nil, false
	}
	return append([]string(nil), agents...), true
}

// PlanForTaskType 根据已知 TaskType 构造确定性任务计划（返回 Agents 的防御性拷贝）。
func PlanForTaskType(t TaskType) (Plan, bool) {
	agents, ok := agentsOf(t)
	if !ok {
		return Plan{}, false
	}
	return Plan{
		TaskType:  t,
		Agents:    agents,
		RiskLevel: riskOf(t),
		Summary:   summaryOf(t, agents),
	}, true
}

// intentRule 意图规则（优先级排序）。
type intentRule struct {
	typ     TaskType
	pattern *regexp.Regexp
}

var intentRules = []intentRule{
	{TaskFalsePositive, regexp.MustCompile(`误报|false.?positive`)},
	{TaskRuleExplanation, regexp.MustCompile(`规则.*(解释|什么意思|干什么|用途)|\b\d{6,7}\b.*(规则|解释)`)},
	{TaskAttackChain, regexp.MustCompile(`攻击链|攻击过程|入侵过程|chain`)},
	{TaskRootCause, regexp.MustCompile(`为什么.*(延迟|失败|异常|升高|不足|错误|慢|积压|崩溃)|根因|root.?cause|怎么回事|排查`)},
	{TaskAttackProfile, regexp.MustCompile(`画像|谁在攻击|哪个ip|来源|攻击者`)},
	{TaskFalsePositive, regexp.MustCompile(`误杀|误拦|误阻断`)},
	// API 安全分析：高信号词（影子/僵尸/越权/BOLA/BFLA/参数偏离/敏感数据/弱点等）直接命中；
	// 泛词（资产/态势/模型/风险/统计等）必须与 api|接口|端点|字段 共现才路由，
	// 避免把普通 WAF 统计/日志问题误路由到 API 域。位置在「事件分析/统计/日志」之前。
	{TaskAPISecurityAnalysis, regexp.MustCompile(`shadow|zombie|bola|bfla|越权|参数偏离|涉敏|敏感数据|影子|僵尸|弱点` +
		`|(?:api|接口|端点|字段)[^。，,；;]{0,16}(?:资产|态势|模型|schema|参数|风险|学习|发现|偏离|覆盖|清单|分类|图谱|运行时|规范|敏感|统计|调用量)` +
		`|(?:资产|态势|模型|schema|参数|风险|学习|发现|偏离|覆盖|清单|分类|图谱|运行时|规范|敏感|统计|调用量)[^。，,；;]{0,16}(?:api|接口|端点|字段)`)},
	{TaskEventAnalysis, regexp.MustCompile(`事件.*分析|分析.*事件|这条事件|这个事件|分析一下`)},
	{TaskPolicyRec, regexp.MustCompile(`策略.*(建议|优化|调整|推荐)|优化.*策略|调优|建议.*规则`)},
	{TaskWhatIf, regexp.MustCompile(`what.?if|如果.*(关掉|关闭|启用|改成|切换|调整)|模拟|假设`)},
	{TaskReportSummary, regexp.MustCompile(`(日报|周报|月报|总结|汇总).*(安全|攻击|运营)?|(安全|攻击|运营).*(日报|周报|月报|总结|汇总)`)},
	{TaskLogQuery, regexp.MustCompile(`日志|log|查询.*请求|请求.*记录`)},
	{TaskStatistics, regexp.MustCompile(`统计|趋势|排行|top|多少|数量|分布|占比|(?:攻击|安全事件|拦截).*(?:最多|最高|最常见|主要|首位|第一)|(?:最多|最高|最常见|主要|首位|第一).*(?:攻击|安全事件|拦截)`)},
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
			if plan, ok := PlanForTaskType(rule.typ); ok {
				return plan
			}
		}
	}
	// 含事件ID/规则ID/Request ID → 事件分析
	if regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}`).MatchString(msg) || regexp.MustCompile(`\b\d{6,7}\b`).MatchString(msg) {
		if plan, ok := PlanForTaskType(TaskEventAnalysis); ok {
			plan.Summary = "识别到事件/规则标识，执行安全事件分析"
			return plan
		}
	}
	// 通用问答默认只走知识库，不拉 24h 攻击统计（避免闲聊/非安全问题刷屏运营数据）
	plan, _ := PlanForTaskType(TaskGeneralQA)
	plan.Summary = "通用安全问答"
	return plan
}

// ResolveContextualMessage 为短追问继承上一条用户问题中的事件、规则、IP 和查询条件。
// 最近消息可能包含当前轮，因此会先跳过最后一条与当前问题相同的用户消息；
// 助手消息永远不会拼入 Agent 输入，避免把模型输出当作可信指令。
func ResolveContextualMessage(message string, recent []Message) string {
	current := strings.TrimSpace(message)
	if current == "" || !isContextualFollowUp(current) {
		return message
	}

	skippedCurrent := false
	for i := len(recent) - 1; i >= 0; i-- {
		m := recent[i]
		if !strings.EqualFold(strings.TrimSpace(m.Role), "user") {
			continue
		}
		content := strings.TrimSpace(m.Content)
		if content == "" {
			continue
		}
		if !skippedCurrent && content == current {
			skippedCurrent = true
			continue
		}
		return content + "\n当前追问：" + current
	}
	return message
}

func isContextualFollowUp(message string) bool {
	m := strings.Trim(strings.ToLower(strings.TrimSpace(message)), " \t\r\n!！?？.。~～、,，")
	if m == "" || len([]rune(m)) > 40 {
		return false
	}
	return contextualFollowUpPattern.MatchString(m)
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
7. API 安全分析（WDSP 形态：影子/僵尸接口、模型与参数偏离、BOLA/BFLA 越权风险、弱点整改、敏感数据）

**可以这样问：**
- 统计最近 24 小时攻击类型分布
- 942100 规则是干什么的
- 谁在攻击我的网站
- 分析事件 <事件UUID>
- 这条拦截是不是误报
- 有哪些影子 API？当前是否存在越权风险

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
		TaskEventAnalysis:       "安全事件分析",
		TaskFalsePositive:       "误报研判",
		TaskRuleExplanation:     "规则解释",
		TaskAttackProfile:       "攻击画像",
		TaskAttackChain:         "攻击链关联",
		TaskRootCause:           "根因分析",
		TaskLogQuery:            "日志查询",
		TaskStatistics:          "统计问答",
		TaskPolicyRec:           "策略优化建议",
		TaskWhatIf:              "What-If 策略模拟",
		TaskReportSummary:       "报告总结",
		TaskGeneralQA:           "通用安全问答",
		TaskAPISecurityAnalysis: "API 安全分析",
	}
	return names[t] + "（调度: " + strings.Join(agents, ", ") + "）"
}

var ipExtractRe = regexp.MustCompile(`(?:^|[^0-9a-zA-Z.])((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:.]*:[0-9a-fA-F:.]*:[0-9a-fA-F:.]*)`)

func isASCIIAlnum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// ExtractIDs 从消息提取事件ID/规则ID/IP（单遍提取 IPv4/IPv6，经 net.ParseIP 校验后限 5 个）。
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
	for _, loc := range ipExtractRe.FindAllStringSubmatchIndex(message, -1) {
		if len(loc) < 4 || loc[2] < 0 || loc[3] <= loc[2] {
			continue
		}
		candStart, candEnd := loc[2], loc[3]
		cand := message[candStart:candEnd]
		if strings.Contains(cand, ":") {
			if candEnd < len(message) && isASCIIAlnum(message[candEnd]) {
				continue
			}
			cand = strings.TrimRight(cand, ".")
			if strings.HasPrefix(cand, ":") && !strings.HasPrefix(cand, "::") {
				cand = cand[1:]
			}
			if strings.HasSuffix(cand, ":") && !strings.HasSuffix(cand, "::") {
				cand = cand[:len(cand)-1]
			}
			if cand == "" || cand == "::" {
				continue
			}
		} else {
			if candEnd < len(message) && (isASCIIAlnum(message[candEnd]) || (message[candEnd] == '.' && candEnd+1 < len(message) && message[candEnd+1] >= '0' && message[candEnd+1] <= '9')) {
				continue
			}
		}
		parsed := net.ParseIP(cand)
		if parsed == nil {
			continue
		}
		ips = append(ips, parsed.String())
		if len(ips) >= 5 {
			break
		}
	}
	return
}
