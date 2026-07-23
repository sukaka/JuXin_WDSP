package parser

import (
	"net/url"
	"strconv"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// extractFormFields 解析 application/x-www-form-urlencoded 表单：
// 只记录字段名与推断类型（不落明文值），受 MaxFieldCount 限制（超限置 FieldCapped）。
func (p *Parsed) extractFormFields(raw []byte, limits dsctx.ParseLimits) {
	for _, pair := range strings.Split(string(raw), "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		key, err := url.QueryUnescape(k)
		if err != nil || key == "" {
			continue
		}
		if _, ok := p.FormFields[key]; ok {
			continue // schema 去重：同名参数只记录一次
		}
		if p.FieldCount >= limits.MaxFieldCount {
			p.FieldCapped = true
			return
		}
		if dv, derr := url.QueryUnescape(v); derr == nil {
			v = dv
		}
		p.FormFields[key] = inferScalarType(v)
		p.FieldCount++
	}
}

// inferScalarType 由文本值推断粗类型（与 JSON 字段类型词汇一致：string|number|bool）。
func inferScalarType(v string) string {
	if v == "true" || v == "false" {
		return "bool"
	}
	if looksNumeric(v) {
		return "number"
	}
	return "string"
}

// looksNumeric 首字符预筛 + ParseFloat，避免把 "NaN"/"Inf" 等误判为 number。
func looksNumeric(s string) bool {
	if s == "" {
		return false
	}
	c := s[0]
	if !(c >= '0' && c <= '9' || c == '-' || c == '+' || c == '.') {
		return false
	}
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}
