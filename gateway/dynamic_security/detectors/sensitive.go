package detectors

import (
	"fmt"
	"regexp"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// 敏感字段名检测：仅按字段名/路径模式匹配，不触碰任何字段值。
// Evidence 只记录字段路径与数据类型标签。

// SensitivePattern 敏感字段名模式（DataType 为证据中的数据类型标签）。
type SensitivePattern struct {
	DataType string `json:"data_type"`
	Pattern  string `json:"pattern"`
}

// CompiledSensitivePattern 编译后的模式（opaque，由 CompileSensitivePatterns 产出）。
type CompiledSensitivePattern struct {
	dataType string
	re       *regexp.Regexp
}

// defaultSensitivePatterns 内置字段名模式（中英常见命名；编译期正则表）。
// 短关键字（tel/pan）加非字母边界防 hotel/company 误命中。
var defaultSensitivePatterns = []SensitivePattern{
	{DataType: "phone", Pattern: `(?i)(phone|mobile|telephone|shouji|(^|[^a-z])tel([^a-z]|$))`},
	{DataType: "email", Pattern: `(?i)(e?_?mail|youxiang)`},
	{DataType: "id_card", Pattern: `(?i)(id_?card|idcard|identity|shenfenzheng|(^|[^a-z])sfz([^a-z]|$))`},
	{DataType: "bank_card", Pattern: `(?i)(bank_?card|card_?(number|no)|(^|[^a-z])pan([^a-z]|$)|yinhangka)`},
	{DataType: "credential", Pattern: `(?i)(password|passwd|pwd|secret|token|api_?key|apikey|access_?key|private_?key|mima)`},
}

// maxSensitiveMatches 单请求敏感字段 match 上限（防超大报文撑爆事件）。
const maxSensitiveMatches = 20

// CompileSensitivePatterns 编译模式表；in 为 nil 时使用内置默认表。
func CompileSensitivePatterns(in []SensitivePattern) ([]CompiledSensitivePattern, error) {
	if in == nil {
		in = defaultSensitivePatterns
	}
	out := make([]CompiledSensitivePattern, 0, len(in))
	for _, p := range in {
		if p.DataType == "" || p.Pattern == "" {
			return nil, fmt.Errorf("sensitive pattern: data_type and pattern required")
		}
		re, err := regexp.Compile(p.Pattern)
		if err != nil {
			return nil, fmt.Errorf("sensitive pattern %q: %w", p.DataType, err)
		}
		out = append(out, CompiledSensitivePattern{dataType: p.DataType, re: re})
	}
	return out, nil
}

// CheckSensitiveData 敏感字段检测：JSON/Form/XML 字段名命中 → SENSITIVE_FIELD（OBSERVE）；
// Query 键名命中（URL 明文外泄）→ SENSITIVE_IN_QUERY（BLOCK 类，PROTECT 下可阻断）。
func CheckSensitiveData(ctx *dsctx.RequestContext, p *parser.Parsed, patterns []CompiledSensitivePattern) {
	if ctx == nil || p == nil || len(patterns) == 0 {
		return
	}
	n := 0
	// Query 优先（高危，URL 明文）
	for k := range p.Query {
		if n >= maxSensitiveMatches {
			return
		}
		if typ, ok := matchSensitive(k, patterns); ok {
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector: "sensitive_data",
				RuleID:   "sensitive.in_query",
				Category: "BLOCK",
				Severity: "HIGH",
				Message:  "sensitive field in url query",
				Evidence: map[string]string{
					"field":     k,
					"data_type": typ,
					"location":  "query",
				},
				ScoreDelta: 40,
			})
			n++
		}
	}
	n += scanFieldNames(ctx, p.JSONFields, "json", patterns, maxSensitiveMatches-n)
	if n >= maxSensitiveMatches {
		return
	}
	n += scanFieldNames(ctx, p.FormFields, "form", patterns, maxSensitiveMatches-n)
	if n >= maxSensitiveMatches {
		return
	}
	scanFieldNames(ctx, p.XMLFields, "xml", patterns, maxSensitiveMatches-n)
}

// scanFieldNames 扫描一类字段名集合，返回产生的 match 数。
func scanFieldNames(ctx *dsctx.RequestContext, fields map[string]string, location string, patterns []CompiledSensitivePattern, budget int) int {
	if budget <= 0 {
		return 0
	}
	n := 0
	for name := range fields {
		if n >= budget {
			break
		}
		if typ, ok := matchSensitive(name, patterns); ok {
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector: "sensitive_data",
				RuleID:   "sensitive.field",
				Category: "OBSERVE",
				Severity: "MEDIUM",
				Message:  "sensitive field name observed",
				Evidence: map[string]string{
					"field":     name,
					"data_type": typ,
					"location":  location,
				},
				ScoreDelta: 10,
			})
			n++
		}
	}
	return n
}

// matchSensitive 返回命中的数据类型标签。
func matchSensitive(fieldName string, patterns []CompiledSensitivePattern) (string, bool) {
	for _, p := range patterns {
		if p.re.MatchString(fieldName) {
			return p.dataType, true
		}
	}
	return "", false
}
