// validate.go A2A 协议安全策略与 AgBOM 资产输入校验（纯函数，无网络 IO）。
package apia2a

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/jiuzhang-waf/server/internal/accesscontrolevents"
)

// FieldError 字段级校验错误。
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidationError 校验错误集合（handler 映射为 400 details）。
type ValidationError struct {
	Errors []FieldError
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("a2a validation failed: %d field(s)", len(e.Errors))
}

func validMode(m string) bool {
	return m == ModeOff || m == ModeObserve || m == ModeProtect
}

func validAgentStatus(s string) bool {
	return s == AgentStatusDiscovered || s == AgentStatusApproved || s == AgentStatusBlocked
}

func validEventTypeFilter(t string) bool {
	switch t {
	case accesscontrolevents.EventTypeA2AAgentCardDiscovered,
		accesscontrolevents.EventTypeA2AObserved,
		accesscontrolevents.EventTypeA2ABlocked,
		accesscontrolevents.EventTypeA2ALoopKilled,
		accesscontrolevents.EventTypeA2ALethalTrifecta:
		return true
	default:
		return false
	}
}

// NormalizePolicy 归一化 A2A 策略字段（大小写、去空白、去重）。
func NormalizePolicy(p *Policy) {
	p.SchemaVersion = SchemaVersion
	p.Mode = strings.ToUpper(strings.TrimSpace(p.Mode))
	p.A2APathPrefixes = normalizeStrings(p.A2APathPrefixes)
	p.AllowedCallerAgents = normalizeStrings(p.AllowedCallerAgents)
	p.ConfidentialReadPatterns = normalizeStrings(p.ConfidentialReadPatterns)
	p.ExternalEgressPatterns = normalizeStrings(p.ExternalEgressPatterns)
}

// ValidatePolicy 校验应用级 A2A 安全策略全字段边界。
func ValidatePolicy(p *Policy) []FieldError {
	errs := []FieldError{}
	add := func(field, msg string) {
		errs = append(errs, FieldError{Field: field, Message: msg})
	}

	if !validMode(p.Mode) {
		add("mode", "仅支持 OFF / OBSERVE / PROTECT")
	}

	if len(p.A2APathPrefixes) > MaxPathPrefixes {
		add("a2a_path_prefixes", fmt.Sprintf("A2A 路径前缀数量不能超过 %d 条", MaxPathPrefixes))
	}
	for i, path := range p.A2APathPrefixes {
		field := fmt.Sprintf("a2a_path_prefixes[%d]", i)
		if !strings.HasPrefix(path, "/") {
			add(field, "A2A 路径前缀必须以 / 开头")
		} else if len(path) > MaxPathLen {
			add(field, fmt.Sprintf("单条 A2A 路径前缀长度不能超过 %d 字符", MaxPathLen))
		} else if strings.ContainsAny(path, "?#") {
			add(field, "A2A 路径前缀不得包含查询参数（?）或锚点（#）")
		} else if hasControlChars(path) || strings.ContainsAny(path, " \t") {
			add(field, "A2A 路径前缀不得包含空白或控制字符")
		}
	}

	if len(p.AllowedCallerAgents) > MaxAllowedAgents {
		add("allowed_caller_agents", fmt.Sprintf("允许调用 Agent 数量不能超过 %d 条", MaxAllowedAgents))
	}
	for i, name := range p.AllowedCallerAgents {
		field := fmt.Sprintf("allowed_caller_agents[%d]", i)
		if len(name) > MaxAllowedAgentNameLen {
			add(field, fmt.Sprintf("单个允许调用 Agent 标识长度不能超过 %d 字符", MaxAllowedAgentNameLen))
		} else if hasControlChars(name) {
			add(field, "允许调用 Agent 标识不得包含控制字符")
		}
	}

	if p.MaxDelegationDepth < MinDelegationDepth || p.MaxDelegationDepth > MaxDelegationDepth {
		add("max_delegation_depth", fmt.Sprintf("最大委派深度必须在 %d~%d 之间", MinDelegationDepth, MaxDelegationDepth))
	}
	if p.LoopWindowSeconds < MinLoopWindowSeconds || p.LoopWindowSeconds > MaxLoopWindowSeconds {
		add("loop_window_seconds", fmt.Sprintf("递归循环检测窗口必须在 %d~%d 秒之间", MinLoopWindowSeconds, MaxLoopWindowSeconds))
	}
	if p.MaxCallsPerTaskWindow < MinCallsPerTaskWindow || p.MaxCallsPerTaskWindow > MaxCallsPerTaskWindow {
		add("max_calls_per_task_window", fmt.Sprintf("单窗口最大调用次数必须在 %d~%d 之间", MinCallsPerTaskWindow, MaxCallsPerTaskWindow))
	}

	validatePatternList(p.ConfidentialReadPatterns, "confidential_read_patterns", "机密读取匹配模式", add)
	validatePatternList(p.ExternalEgressPatterns, "external_egress_patterns", "外部出口匹配模式", add)

	return errs
}

func validatePatternList(patterns []string, field, label string, add func(string, string)) {
	if len(patterns) > MaxPatterns {
		add(field, fmt.Sprintf("%s数量不能超过 %d 条", label, MaxPatterns))
	}
	for i, pat := range patterns {
		itemField := fmt.Sprintf("%s[%d]", field, i)
		if len(pat) > MaxPatternLen {
			add(itemField, fmt.Sprintf("单条%s长度不能超过 %d 字符", label, MaxPatternLen))
		} else if hasControlChars(pat) {
			add(itemField, fmt.Sprintf("%s不得包含控制字符", label))
		}
	}
}

// NormalizeAgent 归一化 AgBOM Agent 字段。
func NormalizeAgent(a *Agent) {
	a.AgentName = strings.TrimSpace(a.AgentName)
	a.AgentURL = strings.TrimSpace(a.AgentURL)
	a.AgentVersion = strings.TrimSpace(a.AgentVersion)
	a.Status = strings.ToUpper(strings.TrimSpace(a.Status))
	a.Description = strings.TrimSpace(a.Description)
	a.Skills = normalizeStrings(a.Skills)
	a.AllowedSkills = normalizeStrings(a.AllowedSkills)
	a.AuthSchemes = normalizeStrings(a.AuthSchemes)
}

// ValidateCreateAgent 校验人工登记 Agent 输入。
func ValidateCreateAgent(a *Agent) []FieldError {
	errs := []FieldError{}
	add := func(field, msg string) {
		errs = append(errs, FieldError{Field: field, Message: msg})
	}

	if a.AgentName == "" {
		add("agent_name", "Agent 名称不能为空")
	} else if len(a.AgentName) > MaxAgBOMAgentNameLen {
		add("agent_name", fmt.Sprintf("Agent 名称长度不能超过 %d 字符", MaxAgBOMAgentNameLen))
	} else if hasControlChars(a.AgentName) {
		add("agent_name", "Agent 名称不得包含控制字符")
	}

	if a.AgentURL != "" {
		if len(a.AgentURL) > MaxAgentURLLen {
			add("agent_url", fmt.Sprintf("Agent 地址长度不能超过 %d 字符", MaxAgentURLLen))
		} else if hasControlChars(a.AgentURL) || strings.ContainsAny(a.AgentURL, " \t") {
			add("agent_url", "Agent 地址不得包含空白或控制字符")
		} else if !(strings.HasPrefix(a.AgentURL, "/") && !strings.HasPrefix(a.AgentURL, "//")) {
			u, err := url.Parse(a.AgentURL)
			if err != nil || (!strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https")) || u.Hostname() == "" || u.User != nil {
				add("agent_url", "Agent 地址须为合法 http(s) URL（不含内嵌凭据）或以单 / 开头的相对路径")
			}
		}
	}

	if len(a.AgentVersion) > MaxAgentVersionLen {
		add("agent_version", fmt.Sprintf("Agent 版本长度不能超过 %d 字符", MaxAgentVersionLen))
	} else if hasControlChars(a.AgentVersion) {
		add("agent_version", "Agent 版本不得包含控制字符")
	}

	validateTagList(a.Skills, "skills", "技能列表", MaxSkills, MaxSkillLen, add)
	validateTagList(a.AuthSchemes, "auth_schemes", "认证方案", MaxAuthSchemes, MaxAuthSchemeLen, add)

	errs = append(errs, ValidateUpdateAgent(a.Status, a.Description, a.AllowedSkills)...)
	return errs
}

// ValidateUpdateAgent 校验审批/编辑 Agent 输入。
func ValidateUpdateAgent(status, description string, allowedSkills []string) []FieldError {
	errs := []FieldError{}
	add := func(field, msg string) {
		errs = append(errs, FieldError{Field: field, Message: msg})
	}

	if !validAgentStatus(status) {
		add("status", "仅支持 DISCOVERED / APPROVED / BLOCKED")
	}
	if len(description) > MaxDescriptionLen {
		add("description", fmt.Sprintf("描述长度不能超过 %d 字符", MaxDescriptionLen))
	} else if hasDisallowedTextControlChars(description) {
		add("description", "描述不得包含非法控制字符")
	}
	validateTagList(allowedSkills, "allowed_skills", "允许技能列表", MaxSkills, MaxSkillLen, add)
	return errs
}

func validateTagList(items []string, field, label string, maxItems, maxItemLen int, add func(string, string)) {
	if len(items) > maxItems {
		add(field, fmt.Sprintf("%s数量不能超过 %d 条", label, maxItems))
	}
	for i, s := range items {
		itemField := fmt.Sprintf("%s[%d]", field, i)
		if len(s) > maxItemLen {
			add(itemField, fmt.Sprintf("单条%s长度不能超过 %d 字符", label, maxItemLen))
		} else if hasControlChars(s) {
			add(itemField, fmt.Sprintf("%s不得包含控制字符", label))
		}
	}
}

func normalizeStrings(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func hasControlChars(s string) bool {
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

func hasDisallowedTextControlChars(s string) bool {
	for _, c := range s {
		if c == '\n' || c == '\t' {
			continue
		}
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}
