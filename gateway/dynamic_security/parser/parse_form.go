package parser

import (
	"net/url"
	"strconv"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// extractFormFields 解析 application/x-www-form-urlencoded 表单：
// 记录字段名与推断类型，受 MaxFieldCount 限制（超限置 FieldCapped）；
// 仅当 RetainFormScalarValues 为 true 时额外留存截断标量值（不落事件/日志）。
// 重复键保留首值语义（同名只记一次），但登记歧义（只记名+次数，不落值）。
func (p *Parsed) extractFormFields(raw []byte, limits dsctx.ParseLimits) {
	counts := make(map[string]int, 8)
	var firstSeen []string // 首见序（歧义登记确定性输出）
	for _, pair := range strings.Split(string(raw), "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		key, err := url.QueryUnescape(k)
		if err != nil || key == "" {
			continue
		}
		if counts[key] == 0 {
			firstSeen = append(firstSeen, key)
		}
		counts[key]++
		if _, ok := p.FormFields[key]; ok {
			continue // schema 去重：同名参数只记录一次（首值语义；歧义在循环后统一登记）
		}
		if p.FieldCount >= limits.MaxFieldCount {
			p.FieldCapped = true
			break
		}
		if dv, derr := url.QueryUnescape(v); derr == nil {
			v = dv
		}
		p.FormFields[key] = inferScalarType(v)
		if limits.RetainFormScalarValues {
			p.FormValues[key] = truncateScalarValue(v)
		}
		p.FieldCount++
	}
	// 重复键歧义登记（只记名+总次数，不落值；按首见序输出）
	for _, key := range firstSeen {
		if n := counts[key]; n > 1 {
			p.addAmbiguity(ParamAmbiguity{Location: AmbLocationForm, ParameterName: key, ValueCount: n})
		}
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
