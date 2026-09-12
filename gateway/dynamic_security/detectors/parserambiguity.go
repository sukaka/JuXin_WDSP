package detectors

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// Parser 歧义检测（阶段2 Parser Detector，docs/WDSP_AI_PENTEST_PROTECTION_ENHANCEMENT.md
// 阶段2「Duplicate JSON Key / Duplicate Query Parameter / Duplicate Header /
// Duplicate Form Parameter / Parameter Ambiguity」）。
//
// 红线：detector 名用 api_parser，不复用 api_schema——决策引擎对 api_schema+BLOCK
// 组合实断（decision/engine.go 可信阻断源），歧义规则默认 OBSERVE（文档 §18.2）。
// Severity=MEDIUM 是服务端物化门槛（apiruntime/findings.go：severity≥MEDIUM 才落
// findings 表）；动作仍由 Category=OBSERVE 决定，PROTECT 下也仅定案观测。
// DetectorMatch 无 RuleCode/RuleVersion 字段，文档规则码与版本（§18.1）经
// Message/Evidence 携带。证据只含 parameter_name/location/value_count/rule_code(/path)
// 元信息，原始值永不入列。
//
// 另承载解析截断可见性（PARSER-FIELD-CAP-001）：Query/Body 字段数配额截断
// （parser.Parsed.QueryCapped/FieldCapped）产一条 OBSERVE 明细，使
// 「配额耗尽导致后续解析被跳过」在事件流中可见（原仅落 ctx 字段无消费方）。

// parserAmbiguityRuleID/规则码词表（位置 → 规则 ID + 文档规则码；钉死，两端契约）。
var parserAmbiguityRules = map[string]struct {
	ruleID   string
	ruleCode string
}{
	parser.AmbLocationJSON:   {"parser.duplicate_json_key", "PARSER-DUP-JSON-001"},
	parser.AmbLocationQuery:  {"parser.duplicate_query_param", "PARSER-DUP-QUERY-001"},
	parser.AmbLocationHeader: {"parser.duplicate_header", "PARSER-DUP-HEADER-001"},
	parser.AmbLocationForm:   {"parser.duplicate_form_param", "PARSER-DUP-FORM-001"},
}

// parserAmbiguityRuleVersion 规则版本（文档 §18.1 版本化纪律；随 Message 携带）。
const parserAmbiguityRuleVersion = "v1.0.0"

// CheckParserAmbiguity 对解析层登记的每条歧义产出一条 finding（只写 Matches，不定案）；
// 字段数截断（QueryCapped/FieldCapped）另产一条 parser.field_count_capped finding——
// 截断标记原只写 ctx 字段无任何消费方，攻击（如 ≥MaxFieldCount 个 distinct query 键）
// 在事件流中不可见；截断事实必须进事件流供审计与人工研判。
func CheckParserAmbiguity(ctx *dsctx.RequestContext, p *parser.Parsed) {
	if ctx == nil || p == nil {
		return
	}
	// 排序遍历：事件确定性（query/header 采集自 map 迭代，顺序不稳定；
	// 同 schema.go missing_field 键序排序先例）
	ambs := make([]parser.ParamAmbiguity, len(p.Ambiguities))
	copy(ambs, p.Ambiguities)
	sort.Slice(ambs, func(i, j int) bool {
		a, b := ambs[i], ambs[j]
		if a.Location != b.Location {
			return a.Location < b.Location
		}
		if a.ParameterName != b.ParameterName {
			return a.ParameterName < b.ParameterName
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.ValueCount < b.ValueCount
	})
	for _, a := range ambs {
		rule, ok := parserAmbiguityRules[a.Location]
		if !ok {
			continue // 未知位置词表：宽容跳过（解析层只写 AmbLocation* 词表）
		}
		evidence := map[string]string{
			"parameter_name": a.ParameterName,
			"location":       a.Location,
			"value_count":    strconv.Itoa(a.ValueCount),
			"rule_code":      rule.ruleCode,
		}
		if a.Path != "" {
			evidence["path"] = a.Path
		}
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector:   "api_parser",
			RuleID:     rule.ruleID,
			Category:   "OBSERVE",
			Severity:   "MEDIUM", // 服务端物化门槛；动作由 Category=OBSERVE 决定
			Message:    fmt.Sprintf("%s %s: duplicate %s parameter %q (x%d)", rule.ruleCode, parserAmbiguityRuleVersion, a.Location, a.ParameterName, a.ValueCount),
			Evidence:   evidence,
			ScoreDelta: 20, // <50：单条永不抬为阻断（决策引擎 ≥50 分支不触发）
		})
	}
	// 字段数截断可见性：Query/Body 各自独立配额（见 parser.Parsed.QueryCapped/FieldCapped
	// 注释），任一截断产一条 OBSERVE 明细；与歧义规则同纪律（api_parser 非可信阻断源，
	// OBSERVE + ScoreDelta<50，PROTECT 下也仅定案观测）。证据只含截断位置与规则码。
	var capped []string
	if p.QueryCapped {
		capped = append(capped, parser.AmbLocationQuery)
	}
	if p.FieldCapped {
		capped = append(capped, "body")
	}
	if len(capped) > 0 {
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector:   "api_parser",
			RuleID:     "parser.field_count_capped",
			Category:   "OBSERVE",
			Severity:   "MEDIUM", // 服务端物化门槛；动作由 Category=OBSERVE 决定
			Message:    fmt.Sprintf("PARSER-FIELD-CAP-001 %s: field count cap reached (%s), excess fields not parsed", parserAmbiguityRuleVersion, strings.Join(capped, ",")),
			Evidence:   map[string]string{"location": strings.Join(capped, ","), "rule_code": "PARSER-FIELD-CAP-001"},
			ScoreDelta: 20, // <50：单条永不抬为阻断
		})
	}
}
