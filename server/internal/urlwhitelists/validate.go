package urlwhitelists

import (
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	MaxNameRunes    = 200
	MaxPatternBytes = 512
	MaxReasonRunes  = 500
	MaxPriority     = 10000
)

var allowedMethods = map[string]bool{
	"GET": true, "HEAD": true, "POST": true, "PUT": true,
	"PATCH": true, "DELETE": true, "OPTIONS": true,
}

func hasControlChar(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// NormalizeMethods 规范化并去重 HTTP 方法列表（空表示全部方法）。
func NormalizeMethods(in []string) ([]string, error) {
	if len(in) == 0 {
		return []string{}, nil
	}
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, m := range in {
		u := strings.ToUpper(strings.TrimSpace(m))
		if u == "" {
			continue
		}
		if !allowedMethods[u] {
			return nil, fmt.Errorf("%w: 不支持的 HTTP 方法 %q", ErrInvalidInput, m)
		}
		if !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out, nil
}

// NormalizeURIPattern 校验并规范化 URL 路径/正则模式。
func NormalizeURIPattern(matchType, raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "", fmt.Errorf("%w: URL 路径或正则不能为空", ErrInvalidInput)
	}
	if len(p) > MaxPatternBytes {
		return "", fmt.Errorf("%w: URL 路径或正则不能超过 %d 字节", ErrInvalidInput, MaxPatternBytes)
	}
	if hasControlChar(p) {
		return "", fmt.Errorf("%w: URL 路径或正则不能包含控制字符", ErrInvalidInput)
	}
	switch matchType {
	case MatchExact, MatchPrefix:
		if !strings.HasPrefix(p, "/") {
			return "", fmt.Errorf("%w: 精确/前缀匹配路径必须以 / 开头", ErrInvalidInput)
		}
		if strings.ContainsAny(p, "?# \t") {
			return "", fmt.Errorf("%w: 精确/前缀匹配路径不得包含查询参数（?）、锚点（#）或空白字符", ErrInvalidInput)
		}
		// 拒绝显式相对穿越段，防规则配置歧义
		for _, seg := range strings.Split(p, "/") {
			if seg == ".." || seg == "." {
				return "", fmt.Errorf("%w: URL 路径不得包含相对路径段 . 或 ..", ErrInvalidInput)
			}
		}
		trailingSlash := matchType == MatchPrefix && len(p) > 1 && strings.HasSuffix(p, "/")
		cleaned := path.Clean(p)
		if !strings.HasPrefix(cleaned, "/") {
			cleaned = "/" + cleaned
		}
		if trailingSlash && !strings.HasSuffix(cleaned, "/") {
			cleaned += "/"
		}
		return cleaned, nil
	case MatchRegex:
		if _, err := regexp.Compile(p); err != nil {
			return "", fmt.Errorf("%w: 无效的正则表达式: %v", ErrInvalidInput, err)
		}
		return p, nil
	default:
		return "", fmt.Errorf("%w: 匹配方式仅支持 EXACT、PREFIX 或 REGEX", ErrInvalidInput)
	}
}

// ValidateInput 校验新建输入并原地规范化。
func ValidateInput(in *CreateInput, now time.Time) error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || utf8.RuneCountInString(in.Name) > MaxNameRunes || hasControlChar(in.Name) {
		return fmt.Errorf("%w: 规则名称长度必须在 1~%d 个字符之间且不含控制字符", ErrInvalidInput, MaxNameRunes)
	}
	in.ScopeType = strings.ToUpper(strings.TrimSpace(in.ScopeType))
	switch in.ScopeType {
	case ScopeGlobal:
		if in.ApplicationID != nil {
			return fmt.Errorf("%w: 全局规则不得指定应用", ErrInvalidInput)
		}
	case ScopeApplication:
		if in.ApplicationID == nil {
			return fmt.Errorf("%w: 应用级规则必须选择目标应用", ErrInvalidInput)
		}
	default:
		return fmt.Errorf("%w: 生效范围仅支持 GLOBAL 或 APPLICATION", ErrInvalidInput)
	}
	if in.MatchType == "" {
		in.MatchType = MatchExact
	} else {
		in.MatchType = strings.ToUpper(strings.TrimSpace(in.MatchType))
	}
	pat, err := NormalizeURIPattern(in.MatchType, in.URIPattern)
	if err != nil {
		return err
	}
	in.URIPattern = pat

	methods, err := NormalizeMethods(in.Methods)
	if err != nil {
		return err
	}
	in.Methods = methods

	if in.Priority < 0 || in.Priority > MaxPriority {
		return fmt.Errorf("%w: 优先级必须在 0~%d 之间", ErrInvalidInput, MaxPriority)
	}
	if in.ValidityType == "" {
		in.ValidityType = ValidityPermanent
	} else {
		in.ValidityType = strings.ToUpper(strings.TrimSpace(in.ValidityType))
	}
	if err := validateValidity(in.ValidityType, in.EffectiveFrom, in.EffectiveUntil, now); err != nil {
		return err
	}
	in.Reason = strings.TrimSpace(in.Reason)
	if utf8.RuneCountInString(in.Reason) > MaxReasonRunes {
		return fmt.Errorf("%w: 原因说明不超过 %d 字符", ErrInvalidInput, MaxReasonRunes)
	}
	in.SourceType = strings.ToUpper(strings.TrimSpace(in.SourceType))
	switch in.SourceType {
	case "", SourceManual:
		in.SourceType = SourceManual
		if in.SourceEventID != nil {
			return fmt.Errorf("%w: 仅 SECURITY_EVENT 来源允许携带 source_event_id", ErrInvalidInput)
		}
	case SourceSecurityEvent:
		if in.SourceEventID == nil {
			return fmt.Errorf("%w: SECURITY_EVENT 来源必须提供有效的 source_event_id", ErrInvalidInput)
		}
	default:
		return fmt.Errorf("%w: 来源类型仅支持 MANUAL 或 SECURITY_EVENT", ErrInvalidInput)
	}
	return nil
}

func validateUpdateInput(in *UpdateInput, now time.Time) error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || utf8.RuneCountInString(in.Name) > MaxNameRunes || hasControlChar(in.Name) {
		return fmt.Errorf("%w: 规则名称长度必须在 1~%d 个字符之间且不含控制字符", ErrInvalidInput, MaxNameRunes)
	}
	in.MatchType = strings.ToUpper(strings.TrimSpace(in.MatchType))
	pat, err := NormalizeURIPattern(in.MatchType, in.URIPattern)
	if err != nil {
		return err
	}
	in.URIPattern = pat

	methods, err := NormalizeMethods(in.Methods)
	if err != nil {
		return err
	}
	in.Methods = methods

	if in.Priority < 0 || in.Priority > MaxPriority {
		return fmt.Errorf("%w: 优先级必须在 0~%d 之间", ErrInvalidInput, MaxPriority)
	}
	in.ValidityType = strings.ToUpper(strings.TrimSpace(in.ValidityType))
	if err := validateValidity(in.ValidityType, in.EffectiveFrom, in.EffectiveUntil, now); err != nil {
		return err
	}
	in.Reason = strings.TrimSpace(in.Reason)
	if utf8.RuneCountInString(in.Reason) > MaxReasonRunes {
		return fmt.Errorf("%w: 原因说明不超过 %d 字符", ErrInvalidInput, MaxReasonRunes)
	}
	return nil
}

func validateValidity(validityType string, from, until *time.Time, now time.Time) error {
	switch validityType {
	case ValidityPermanent:
		if until != nil {
			return fmt.Errorf("%w: 永久规则不得设置失效时间", ErrInvalidTime)
		}
	case ValidityTemporary:
		if until == nil {
			return fmt.Errorf("%w: 临时规则必须设置失效时间", ErrInvalidTime)
		}
		if !until.After(now) {
			return fmt.Errorf("%w: 失效时间必须晚于当前时间", ErrInvalidTime)
		}
		if from != nil && !until.After(*from) {
			return fmt.Errorf("%w: 失效时间必须晚于生效时间", ErrInvalidTime)
		}
	default:
		return fmt.Errorf("%w: 有效期类型仅支持 PERMANENT 或 TEMPORARY", ErrInvalidInput)
	}
	return nil
}
