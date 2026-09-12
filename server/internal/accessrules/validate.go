package accessrules

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"
)

// ProtectedChecker 由 protectedaddresses.Store 实现（构造注入，可为 nil 表示不检查）。
type ProtectedChecker interface {
	IsProtected(ctx context.Context, ip string) (bool, string, error)
}

// NormalizeAddress 严格解析并规范化地址（单 IP 或 CIDR）。
// 规则：netip 严格解析；v4 映射 v6 归一为 v4；CIDR 掩码化为规范形式；
// 禁止域名、协议前缀、端口、通配符、带区域（zone）地址与控制字符。
func NormalizeAddress(raw string) (normalized string, ipVersion string, err error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", fmt.Errorf("%w: 地址不能为空", ErrInvalidAddress)
	}
	if len(s) > 64 {
		return "", "", fmt.Errorf("%w: 地址长度超过64字符", ErrInvalidAddress)
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return "", "", fmt.Errorf("%w: 地址包含控制字符", ErrInvalidAddress)
		}
	}
	if strings.Contains(s, "://") {
		return "", "", fmt.Errorf("%w: 不允许包含协议前缀", ErrInvalidAddress)
	}
	if strings.ContainsAny(s, "*") {
		return "", "", fmt.Errorf("%w: 不支持通配符地址", ErrInvalidAddress)
	}
	if strings.Contains(s, "/") {
		p, perr := netip.ParsePrefix(s)
		if perr != nil {
			return "", "", fmt.Errorf("%w: 无效的CIDR地址: %s", ErrInvalidAddress, raw)
		}
		if p.Addr().Is4In6() {
			// v4 映射 v6 前缀归一为 v4（位数按 v6 计，需减 96）
			bits := p.Bits() - 96
			if bits < 0 {
				return "", "", fmt.Errorf("%w: 无效的CIDR地址: %s", ErrInvalidAddress, raw)
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), bits)
		}
		p = p.Masked()
		if p.Addr().Is4() {
			return p.String(), IPVersion4, nil
		}
		return p.String(), IPVersion6, nil
	}
	addr, aerr := netip.ParseAddr(s)
	if aerr != nil {
		return "", "", fmt.Errorf("%w: 无效的IP地址: %s", ErrInvalidAddress, raw)
	}
	if addr.Zone() != "" {
		return "", "", fmt.Errorf("%w: 不支持带区域(zone)的地址", ErrInvalidAddress)
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String(), IPVersion4, nil
	}
	return addr.String(), IPVersion6, nil
}

// ValidateInput 校验创建输入。空的可选枚举字段会被填上默认值：
// ScopeType→GLOBAL、ValidityType→PERMANENT、SourceType→MANUAL。
func ValidateInput(in *CreateInput, now time.Time) error {
	in.Name = strings.TrimSpace(in.Name)
	if n := utf8.RuneCountInString(in.Name); n == 0 || n > 200 {
		return fmt.Errorf("%w: 规则名称必填且不超过200字符", ErrInvalidInput)
	}
	if utf8.RuneCountInString(in.Reason) > 500 {
		return fmt.Errorf("%w: 原因说明不超过500字符", ErrInvalidInput)
	}
	if in.RuleType != RuleTypeAllow && in.RuleType != RuleTypeDeny {
		return fmt.Errorf("%w: 规则类型必须为 ALLOW 或 DENY", ErrInvalidInput)
	}
	if in.ScopeType == "" {
		in.ScopeType = ScopeGlobal
	}
	switch in.ScopeType {
	case ScopeGlobal:
		if in.ApplicationID != nil {
			return fmt.Errorf("%w: 全局规则不允许指定应用", ErrInvalidInput)
		}
	case ScopeApplication:
		if in.ApplicationID == nil {
			return fmt.Errorf("%w: 应用级规则必须指定应用", ErrInvalidInput)
		}
	default:
		return fmt.Errorf("%w: 生效范围必须为 GLOBAL 或 APPLICATION", ErrInvalidInput)
	}
	if _, _, err := NormalizeAddress(in.Address); err != nil {
		return err
	}
	if err := validateValidity(&in.ValidityType, in.EffectiveFrom, in.EffectiveUntil, now); err != nil {
		return err
	}
	if in.SourceType == "" {
		in.SourceType = SourceManual
	}
	switch in.SourceType {
	case SourceManual, SourceSecurityEvent, SourceImport, SourceAutoBlock, SourceSystem:
	default:
		return fmt.Errorf("%w: 无效的来源类型: %s", ErrInvalidInput, in.SourceType)
	}
	return nil
}

// validateUpdateInput 校验更新输入。
func validateUpdateInput(in *UpdateInput, now time.Time) error {
	in.Name = strings.TrimSpace(in.Name)
	if n := utf8.RuneCountInString(in.Name); n == 0 || n > 200 {
		return fmt.Errorf("%w: 规则名称必填且不超过200字符", ErrInvalidInput)
	}
	if utf8.RuneCountInString(in.Reason) > 500 {
		return fmt.Errorf("%w: 原因说明不超过500字符", ErrInvalidInput)
	}
	if _, _, err := NormalizeAddress(in.Address); err != nil {
		return err
	}
	return validateValidity(&in.ValidityType, in.EffectiveFrom, in.EffectiveUntil, now)
}

// validateValidity 校验有效期组合。
func validateValidity(validityType *string, from, until *time.Time, now time.Time) error {
	if *validityType == "" {
		*validityType = ValidityPermanent
	}
	switch *validityType {
	case ValidityPermanent:
		if until != nil {
			return fmt.Errorf("%w: 永久规则不允许设置失效时间", ErrInvalidTime)
		}
	case ValidityTemporary:
		if until == nil {
			return fmt.Errorf("%w: 临时规则必须设置失效时间", ErrInvalidTime)
		}
		if !until.After(now) {
			return fmt.Errorf("%w: 失效时间必须晚于当前时间", ErrInvalidTime)
		}
	default:
		return fmt.Errorf("%w: 有效期类型必须为 PERMANENT 或 TEMPORARY", ErrInvalidInput)
	}
	if from != nil && until != nil && !until.After(*from) {
		return fmt.Errorf("%w: 失效时间必须晚于生效时间", ErrInvalidTime)
	}
	return nil
}

// CheckProtected 保护地址检查：DENY 规则命中保护地址时拒绝。
// checker 为 nil 或规则类型为 ALLOW 时不检查。
func CheckProtected(ctx context.Context, checker ProtectedChecker, ruleType, address string) error {
	if checker == nil || ruleType != RuleTypeDeny {
		return nil
	}
	hit, name, err := checker.IsProtected(ctx, address)
	if err != nil {
		return fmt.Errorf("保护地址检查失败: %w", err)
	}
	if hit {
		return fmt.Errorf("%w: 地址 %s 命中保护地址「%s」，禁止加入黑名单", ErrProtectedAddress, address, name)
	}
	return nil
}

// parseTimeFlex 解析时间，支持 RFC3339 与常见日期时间格式。
func parseTimeFlex(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, l := range layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("无效的时间格式: %s（支持 RFC3339 / YYYY-MM-DD HH:mm:ss / YYYY-MM-DD）", s)
}

// IsProtectedError 判断错误是否为保护地址冲突（供调用方判定审计风险级别）。
func IsProtectedError(err error) bool {
	return errors.Is(err, ErrProtectedAddress)
}
