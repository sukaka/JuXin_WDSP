package ratelimitpolicies

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// 校验边界
const (
	maxNameLen         = 200
	maxDescriptionLen  = 500
	maxURIPatternLen   = 256
	maxRequestsLimit   = 1000000
	maxWindowSeconds   = 86400
	minBlockSeconds    = 60
	maxBlockSeconds    = 86400 * 30
	maxPriority        = 10000
	burstLimitMultiple = 10 // burst_capacity 上限 = requests_limit 的倍数
)

// FieldError 是一条字段级校验错误。
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidationError 聚合全部校验错误（不遇到第一个错误就停止）。
type ValidationError struct {
	Errors []FieldError
}

// Error 实现 error 接口。
func (e *ValidationError) Error() string {
	parts := make([]string, 0, len(e.Errors))
	for _, fe := range e.Errors {
		parts = append(parts, fe.Field+": "+fe.Message)
	}
	return strings.Join(parts, "; ")
}

// Unwrap 暴露哨兵错误，便于 errors.Is(err, ErrInvalidInput)。
func (e *ValidationError) Unwrap() error { return ErrInvalidInput }

var (
	validScopeTypes = map[string]bool{
		ScopeGlobal: true, ScopeApplication: true, ScopeURI: true,
	}
	validDimensions = map[string]bool{
		DimensionClientIP: true, DimensionApplication: true,
		DimensionClientIPAndURI: true, DimensionClientIPAndApplication: true,
	}
	validAlgorithms = map[string]bool{
		AlgorithmTokenBucket: true, AlgorithmSlidingWindow: true,
	}
	validActions = map[string]bool{
		ActionLog: true, ActionObserve: true, ActionReject: true, ActionTempBlock: true,
	}
	validURIMatchTypes = map[string]bool{
		URIMatchAll: true, URIMatchExact: true, URIMatchPrefix: true, URIMatchRegex: true,
	}
	validStatuses = map[string]bool{
		StatusActive: true, StatusDisabled: true,
	}
)

// ValidateInput 校验限速策略输入，返回全部字段错误（无错误时返回空切片）。
// 纯函数，不依赖数据库，可独立单测。
func ValidateInput(p *Policy) []FieldError {
	errs := []FieldError{}
	add := func(field, msg string) {
		errs = append(errs, FieldError{Field: field, Message: msg})
	}

	// 名称与描述
	if strings.TrimSpace(p.Name) == "" {
		add("name", "策略名称不能为空")
	} else if utf8.RuneCountInString(p.Name) > maxNameLen {
		add("name", fmt.Sprintf("策略名称不能超过%d个字符", maxNameLen))
	}
	if utf8.RuneCountInString(p.Description) > maxDescriptionLen {
		add("description", fmt.Sprintf("策略描述不能超过%d个字符", maxDescriptionLen))
	}

	// 作用范围与应用关联
	if !validScopeTypes[p.ScopeType] {
		add("scope_type", "无效的作用范围，必须是 GLOBAL/APPLICATION/URI")
	} else {
		switch p.ScopeType {
		case ScopeGlobal:
			if p.ApplicationID != nil {
				add("application_id", "GLOBAL 范围不得关联应用")
			}
		case ScopeApplication, ScopeURI:
			if p.ApplicationID == nil {
				add("application_id", "APPLICATION/URI 范围必须关联应用")
			}
		}
	}

	// URI 匹配
	if !validURIMatchTypes[p.URIMatchType] {
		add("uri_match_type", "无效的URI匹配方式，必须是 ALL/EXACT/PREFIX/REGEX")
	} else {
		validateURIPattern(p, add)
	}

	// 统计维度
	if !validDimensions[p.Dimension] {
		add("dimension", "无效的统计维度")
	}

	// 算法
	if !validAlgorithms[p.Algorithm] {
		add("algorithm", "无效的限速算法，必须是 TOKEN_BUCKET/SLIDING_WINDOW")
	}

	// 阈值（安全要求：禁止负数、零窗口）
	if p.RequestsLimit < 1 || p.RequestsLimit > maxRequestsLimit {
		add("requests_limit", fmt.Sprintf("请求数阈值必须在 1~%d 之间", maxRequestsLimit))
	}
	if p.WindowSeconds < 1 || p.WindowSeconds > maxWindowSeconds {
		add("window_seconds", fmt.Sprintf("统计窗口必须在 1~%d 秒之间", maxWindowSeconds))
	}
	if p.BurstCapacity < 0 {
		add("burst_capacity", "突发容量不能为负数")
	} else if p.RequestsLimit >= 1 && p.BurstCapacity > p.RequestsLimit*burstLimitMultiple {
		add("burst_capacity", fmt.Sprintf("突发容量不能超过请求数阈值的%d倍（0 表示取阈值）", burstLimitMultiple))
	}

	// 触发动作
	if !validActions[p.Action] {
		add("action", "无效的触发动作，必须是 LOG/OBSERVE/REJECT/TEMP_BLOCK")
	}
	if p.BlockDurationSeconds < 0 {
		add("block_duration_seconds", "封禁时长不能为负数")
	} else if p.Action == ActionTempBlock &&
		(p.BlockDurationSeconds < minBlockSeconds || p.BlockDurationSeconds > maxBlockSeconds) {
		add("block_duration_seconds", fmt.Sprintf("临时封禁时长必须在 %d~%d 秒之间", minBlockSeconds, maxBlockSeconds))
	}

	// 状态（创建前置校验可不携带）
	if p.Status != "" && !validStatuses[p.Status] {
		add("status", "无效的状态，必须是 ACTIVE/DISABLED")
	}

	// 优先级
	if p.Priority < 0 || p.Priority > maxPriority {
		add("priority", fmt.Sprintf("优先级必须在 0~%d 之间", maxPriority))
	}

	// 生效时间范围
	if p.EffectiveFrom != nil && p.EffectiveUntil != nil &&
		!p.EffectiveFrom.Before(*p.EffectiveUntil) {
		add("effective_until", "生效时间必须早于失效时间")
	}

	return errs
}

// validateURIPattern 按匹配方式校验 URI pattern。
func validateURIPattern(p *Policy, add func(field, msg string)) {
	pattern := p.URIPattern
	switch p.URIMatchType {
	case URIMatchAll:
		if pattern != "" {
			add("uri_pattern", "匹配方式为 ALL 时 uri_pattern 必须为空")
		}
	case URIMatchExact, URIMatchPrefix:
		if pattern == "" {
			add("uri_pattern", "EXACT/PREFIX 匹配必须填写 uri_pattern")
			return
		}
		if !strings.HasPrefix(pattern, "/") {
			add("uri_pattern", "uri_pattern 必须以 / 开头")
		}
		if utf8.RuneCountInString(pattern) > maxURIPatternLen {
			add("uri_pattern", fmt.Sprintf("uri_pattern 不能超过%d个字符", maxURIPatternLen))
		}
		if hasControlChar(pattern) {
			add("uri_pattern", "uri_pattern 禁止包含控制字符")
		}
	case URIMatchRegex:
		if pattern == "" {
			add("uri_pattern", "REGEX 匹配必须填写 uri_pattern")
			return
		}
		if utf8.RuneCountInString(pattern) > maxURIPatternLen {
			add("uri_pattern", fmt.Sprintf("uri_pattern 不能超过%d个字符", maxURIPatternLen))
		}
		// Go regexp 基于 RE2，线性时间匹配，天然免疫 ReDoS
		if _, err := regexp.Compile(pattern); err != nil {
			add("uri_pattern", "正则表达式语法错误: "+err.Error())
		}
	}
}

// hasControlChar 判断是否包含控制字符（含 \n \r \t \x00 等）。
func hasControlChar(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}
