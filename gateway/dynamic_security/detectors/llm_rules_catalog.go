package detectors

import "sort"

// LLMBuiltinRuleItem 描述网关实际执行的单条内置 LLM 安全检测规则（直接从编译期正则读取，保证零漂移）。
type LLMBuiltinRuleItem struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	Pattern       string `json:"pattern"`
	EngineRuleID  string `json:"engine_rule_id"`
	ObserveAction string `json:"observe_action"`
	ProtectAction string `json:"protect_action"`
}

// LLMBuiltinRuleCategory 描述一组内置 LLM 安全检测规则及其检查范围与对应策略开关。
type LLMBuiltinRuleCategory struct {
	Key            string               `json:"key"`
	Title          string               `json:"title"`
	Scope          string               `json:"scope"`
	PolicySwitches []string             `json:"policy_switches"`
	InspectedPaths []string             `json:"inspected_paths"`
	Notes          string               `json:"notes"`
	Rules          []LLMBuiltinRuleItem `json:"rules"`
}

// LLMBuiltinRulesCatalog 是网关内置 LLM 安全检测规则目录（供管理端只读展示实际检测内容）。
type LLMBuiltinRulesCatalog struct {
	PromptPaths        []string                 `json:"prompt_paths"`
	OutputPaths        []string                 `json:"output_paths"`
	MaxOutputTexts     int                      `json:"max_output_texts"`
	MaxOutputTextBytes int                      `json:"max_output_text_bytes"`
	Categories         []LLMBuiltinRuleCategory `json:"categories"`
}

var llmInjectionMeta = map[string][2]string{
	"ignore_previous_instructions":    {"英文忽略前序指令", "检测要求模型忽略先前指令、提示词或安全规则的典型注入表达"},
	"disregard_instructions":          {"英文无视既有指令", "检测要求模型无视（disregard）已有指令、规则或提示词的注入表达"},
	"forget_or_override_instructions": {"英文覆盖/绕过安全护栏", "检测要求遗忘、覆盖、绕过或停用规则/安全护栏（guardrails/safety filters）的越狱指令"},
	"jailbreak_keyword":               {"越狱关键词（jailbreak）", "检测请求中明确包含 jailbreak 越狱攻击关键词"},
	"dan_mode":                        {"DAN 越狱模式", "检测 Do Anything Now / DAN mode 经典角色扮演越狱指令"},
	"reveal_system_prompt":            {"英文窃取系统提示词", "检测诱使模型输出、打印、重复或泄露 system/initial/hidden prompt 的指令"},
	"cn_ignore_instructions":          {"中文忽略前序指令", "检测中文形态下要求忽略之前/上述/全部指令或设定的提示词注入"},
	"cn_reveal_system_prompt":         {"中文窃取系统提示词", "检测中文形态下要求泄露、透露、输出或打印系统提示词/初始指令的探测"},
}

var llmContentMeta = map[string][2]string{
	"cn_build_explosive":  {"中文危险爆炸物制作", "高置信匹配请求或输出中涉及制作/合成炸弹、爆炸物或炸药的内容"},
	"cn_malware":          {"中文恶意代码/木马生成", "高置信匹配要求编写、生成或开发木马、病毒、勒索软件或恶意脚本的内容"},
	"cn_credential_theft": {"中文凭据窃取", "高置信匹配涉及窃取、盗取或骗取密码、口令、账号或身份凭据的内容"},
	"cn_intrusion":        {"中文系统入侵指令", "高置信匹配涉及入侵、攻陷或控制服务器、网站、内网或数据库的内容"},
	"en_malware":          {"英文恶意软件生成", "高置信匹配英文请求/输出中编写或生成 malware、ransomware、keylogger、trojan 等内容"},
	"en_credential_theft": {"英文凭据窃取/钓鱼", "高置信匹配英文请求/输出中窃取或钓鱼获取 password、credential、token 等内容"},
	"en_explosive":        {"英文爆炸物制作", "高置信匹配英文请求/输出中制造或合成 bomb、explosive 的内容"},
}

var llmPIIMeta = map[string][2]string{
	"EMAIL": {"电子邮箱地址", "匹配标准电子邮箱格式（输入侧仅观察记录，输出侧在防护模式可阻断；事件不落原文）"},
	"CN_ID": {"中国大陆 18 位身份证号", "匹配 18 位公民身份号码格式（含出生日期段与末位校验位 X）"},
	"PHONE": {"中国大陆 11 位手机号", "匹配 13–19 号段 11 位手机号码格式"},
}

// BuiltinLLMSecurityRulesCatalog 返回网关实际生效的内置 LLM 安全检测规则全集。
// 所有正则表达式均直接读取自运行期已编译的 *regexp.Regexp，避免文档与网关逻辑漂移。
func BuiltinLLMSecurityRulesCatalog() LLMBuiltinRulesCatalog {
	promptPaths := make([]string, 0, len(llmPromptValuePaths))
	for path := range llmPromptValuePaths {
		promptPaths = append(promptPaths, path)
	}
	sort.Strings(promptPaths)

	outputPaths := []string{
		"output_text",
		"choices[].text",
		"choices[].message.content",
		"choices[].message.content[].text",
		"choices[].content",
		"output[].text",
		"output[].message.content",
		"output[].content",
		"output[].content[].text",
	}

	injectionRules := make([]LLMBuiltinRuleItem, 0, len(llmInjectionRules))
	for _, r := range llmInjectionRules {
		meta := llmInjectionMeta[r.name]
		name := meta[0]
		if name == "" {
			name = r.name
		}
		injectionRules = append(injectionRules, LLMBuiltinRuleItem{
			ID:            r.name,
			Name:          name,
			Description:   meta[1],
			Pattern:       r.re.String(),
			EngineRuleID:  "llm.prompt_injection",
			ObserveAction: "OBSERVE / LOW (+5)",
			ProtectAction: "BLOCK / HIGH (+50)",
		})
	}

	contentRules := make([]LLMBuiltinRuleItem, 0, len(llmOutputContentRules))
	for _, r := range llmOutputContentRules {
		meta := llmContentMeta[r.name]
		name := meta[0]
		if name == "" {
			name = r.name
		}
		contentRules = append(contentRules, LLMBuiltinRuleItem{
			ID:            r.name,
			Name:          name,
			Description:   meta[1],
			Pattern:       r.re.String(),
			EngineRuleID:  "llm.input_content_violation / llm.output_content_violation",
			ObserveAction: "OBSERVE / MEDIUM (+15)",
			ProtectAction: "BLOCK / HIGH (+50)",
		})
	}

	piiRules := make([]LLMBuiltinRuleItem, 0, len(llmPIIPatterns))
	for _, item := range llmPIIPatterns {
		meta := llmPIIMeta[item.dataType]
		name := meta[0]
		if name == "" {
			name = item.dataType
		}
		piiRules = append(piiRules, LLMBuiltinRuleItem{
			ID:            item.dataType,
			Name:          name,
			Description:   meta[1],
			Pattern:       item.re.String(),
			EngineRuleID:  "llm.pii_detected（输入）/ llm.output_pii_detected（输出）",
			ObserveAction: "OBSERVE / MEDIUM（输入 +10，输出 +15）",
			ProtectAction: "输入仅 OBSERVE (+10)；输出 BLOCK / HIGH (+50)",
		})
	}

	return LLMBuiltinRulesCatalog{
		PromptPaths:        promptPaths,
		OutputPaths:        outputPaths,
		MaxOutputTexts:     maxLLMOutputTexts,
		MaxOutputTextBytes: maxLLMOutputTextBytes,
		Categories: []LLMBuiltinRuleCategory{
			{
				Key:            "prompt_injection",
				Title:          "提示词注入攻击防护规则",
				Scope:          "input",
				PolicySwitches: []string{"prompt_injection_enabled"},
				InspectedPaths: promptPaths,
				Notes:          "采用 RE2 线性时间正则匹配留存 Prompt 标量（单请求最多记录 5 条命中，同一文本命中首条规则即止；所有事件仅记录规则名与字段位置，不落原文）。",
				Rules:          injectionRules,
			},
			{
				Key:            "content_filter",
				Title:          "恶意/有害内容过滤规则（输入与输出共用）",
				Scope:          "input_and_output",
				PolicySwitches: []string{"input_content_enabled", "output_content_enabled"},
				InspectedPaths: append(append([]string(nil), promptPaths...), outputPaths...),
				Notes:          "输入侧由「输入恶意内容过滤」开关控制；输出侧由「输出有害内容过滤」开关控制（仅对完整非流式 JSON 响应生效，单次最多检查 32 段文本、每段上限 64 KiB）。",
				Rules:          contentRules,
			},
			{
				Key:            "pii_detection",
				Title:          "敏感个人信息（PII）识别规则（输入与输出共用）",
				Scope:          "input_and_output",
				PolicySwitches: []string{"pii_detection_enabled", "output_pii_enabled"},
				InspectedPaths: append(append([]string(nil), promptPaths...), outputPaths...),
				Notes:          "输入侧命中固定记为 OBSERVE/MEDIUM（不阻断正常业务输入）；输出侧在防护模式（PROTECT）命中将直接阻断并返回 403，所有事件严格脱敏不留存 PII 原文。",
				Rules:          piiRules,
			},
		},
	}
}
