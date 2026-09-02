// validate.go 行为策略输入校验（PUT 全量更新前置；与 store.Update 共用同一校验）。
package behaviorpolicy

import (
	"fmt"
	"net/netip"
)

// 校验边界
const (
	maxThreshold   = 100000 // 计数阈值上限
	maxScore       = 100    // 单信号分值上限
	maxListEntries = 1024   // 白名单/路径列表条数上限
	maxPathLen     = 255    // 敏感路径单项长度上限
	maxUALen       = 128    // UA 白名单单项长度上限
	maxFieldLen    = 64     // 枚举标识字段名长度上限
)

// FieldError 字段级校验错误。
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidationError 校验错误集合（handler 转 400 响应 details）。
type ValidationError struct {
	Errors []FieldError
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("behavior policy validation failed: %d field(s)", len(e.Errors))
}

// Validate 校验策略全字段，返回字段级错误列表（空 = 通过）：
// 比率 0-1、阈值 0-100000、sensitive_paths 每项以 / 开头、scores 键限定 10 种信号
// 且值 0-100、whitelist_ips 每项合法 CIDR 或 IP、whitelist_uas 每项 ≤128 字符。
func Validate(p *Policy) []FieldError {
	errs := []FieldError{}
	add := func(field, msg string) {
		errs = append(errs, FieldError{Field: field, Message: msg})
	}

	if p.Mode != ModeObserve {
		add("mode", "当前仅支持 OBSERVE 观测模式")
	}

	// 比率 0-1
	if p.URIEnumNewRatioThreshold < 0 || p.URIEnumNewRatioThreshold > 1 {
		add("uri_enum_new_ratio_threshold", "比率必须在 0~1 之间")
	}
	if p.NotFoundRatioThreshold < 0 || p.NotFoundRatioThreshold > 1 {
		add("not_found_ratio_threshold", "比率必须在 0~1 之间")
	}

	// 计数阈值 0-100000
	for _, item := range []struct {
		field string
		value int
	}{
		{"uri_enum_unique_threshold", p.URIEnumUniqueThreshold},
		{"not_found_min_requests", p.NotFoundMinRequests},
		{"method_enum_threshold", p.MethodEnumThreshold},
		{"param_mutation_threshold", p.ParamMutationThreshold},
		{"auth_fail_threshold", p.AuthFailThreshold},
		{"low_slow_sensitive_min_hits", p.LowSlowSensitiveMinHits},
		{"account_enum_threshold", p.AccountEnumThreshold},
		{"object_enum_threshold", p.ObjectEnumThreshold},
	} {
		if item.value < 0 || item.value > maxThreshold {
			add(item.field, fmt.Sprintf("阈值必须在 0~%d 之间", maxThreshold))
		}
	}

	// 敏感路径：每项以 / 开头
	if len(p.SensitivePaths) > maxListEntries {
		add("sensitive_paths", fmt.Sprintf("最多 %d 条", maxListEntries))
	}
	for i, sp := range p.SensitivePaths {
		if sp == "" || sp[0] != '/' {
			add(fmt.Sprintf("sensitive_paths[%d]", i), "敏感路径必须以 / 开头")
			continue
		}
		if len(sp) > maxPathLen {
			add(fmt.Sprintf("sensitive_paths[%d]", i), fmt.Sprintf("长度不能超过 %d 字符", maxPathLen))
		}
	}

	// 信号分值：键限定 10 种信号，值 0-100
	for sig, score := range p.Scores {
		if !validSignalSet[sig] {
			add("scores", "未知的信号类型: "+sig)
			continue
		}
		if score < 0 || score > maxScore {
			add("scores."+sig, fmt.Sprintf("分值必须在 0~%d 之间", maxScore))
		}
	}

	validateIdentifierFields := func(field string, values []string) {
		if len(values) > maxListEntries {
			add(field, fmt.Sprintf("最多 %d 条", maxListEntries))
		}
		for i, value := range values {
			if value == "" || len(value) > maxFieldLen {
				add(fmt.Sprintf("%s[%d]", field, i), fmt.Sprintf("字段名长度必须在 1~%d 字符之间", maxFieldLen))
			}
		}
	}
	validateIdentifierFields("account_identifier_fields", p.AccountIdentifierFields)
	validateIdentifierFields("object_identifier_fields", p.ObjectIdentifierFields)

	// IP 白名单：每项合法 CIDR 或 IP
	if len(p.WhitelistIPs) > maxListEntries {
		add("whitelist_ips", fmt.Sprintf("最多 %d 条", maxListEntries))
	}
	for i, ip := range p.WhitelistIPs {
		if _, err := netip.ParseAddr(ip); err != nil {
			if _, perr := netip.ParsePrefix(ip); perr != nil {
				add(fmt.Sprintf("whitelist_ips[%d]", i), "必须是合法的 IP 或 CIDR: "+ip)
			}
		}
	}

	// UA 白名单：每项非空且 ≤128 字符
	if len(p.WhitelistUAs) > maxListEntries {
		add("whitelist_uas", fmt.Sprintf("最多 %d 条", maxListEntries))
	}
	for i, ua := range p.WhitelistUAs {
		if ua == "" || len(ua) > maxUALen {
			add(fmt.Sprintf("whitelist_uas[%d]", i), fmt.Sprintf("UA 片段长度必须在 1~%d 字符之间", maxUALen))
		}
	}
	return errs
}
