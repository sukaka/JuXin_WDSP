// relationvalue.go 字段间值比较关系运行时检测（阶段8 任务书 §23 扩展；词表迁移 000147/000154/000159）：
// 在 relationcheck.go 的存在性判定（REQUIRES/MUTEX/CO_OCCURS）之外，补可确定性判定的
// 值比较关系与数组聚合关系：
//
//	EQUALS        等值：两端值字符串相等，不相等 → schema.relation_equals；
//	NOT_EQUALS    不等值：两端值字符串须不相等，相等 → schema.relation_not_equals（000154）；
//	GREATER_THAN  A 值数值须严格大于 B 值，否则 → schema.relation_greater_than；
//	LESS_THAN     A 值数值须严格小于 B 值，否则 → schema.relation_less_than；
//	TIME_BEFORE   A 值时间须严格早于 B 值，否则 → schema.relation_time_before；
//	TIME_AFTER    A 值时间须严格晚于 B 值，否则 → schema.relation_time_after；
//	COUNT_MATCHES 数量一致（000159，§23「数量一致」）：A 整数值须等于 B 数组长度
//	              （item_count == len(items)），否则 → schema.relation_count_matches；
//	SUM_MATCHES   汇总关系（000159，§23「汇总关系」）：A 数值须等于 B 数组元素数值和
//	              （total == Σ items[].price），否则 → schema.relation_sum_matches。
//
// 判定纪律（每类的字段引用/类型要求/判定规则）：
//   - 字段引用复用 ParamRelationRef（QUERY/HEADER/BODY/PATH 可取值；COOKIE 整头脱敏不可取）；
//   - 任一端参数缺失或值不可得（脱敏头、COOKIE、未留存标量值的 BODY）→ 不判定
//     （缺失语义归 REQUIRES，值比较不重复报告）；
//   - 类型要求：GREATER_THAN/LESS_THAN 要求两端值均可解析为 float64；
//     TIME_BEFORE/TIME_AFTER 要求两端值均可解析为时间（RFC3339(Nano)、
//     "2006-01-02 15:04:05"、"2006-01-02" 或纯数字 Unix 秒）；解析失败 → 不判定
//     （类型不符不产生信号，避免把非数值/非时间参数误报为违例）；
//   - 比较为严格序：相等对 GREATER_THAN/LESS_THAN/TIME_BEFORE/TIME_AFTER 均为违例；
//   - 数组聚合关系（COUNT_MATCHES/SUM_MATCHES）：
//     B 端必须为 BODY 数组路径（COUNT：数组本身如 items；SUM：数组元素数值路径如
//     items[].price，与 walkJSON 路径口径一致），其他位置无数组留存 → 不判定；
//     A 端类型要求：COUNT 须可解析为 int64（"3.0"/"3.5" 等类型不符 → 不判定），
//     SUM 须可解析为 float64；
//     SUM 容差口径：浮点求和比较用混合容差 |want-sum| <= 1e-9 * max(1,|want|,|sum|)
//     （覆盖二进制浮点累加误差，量级远小于一分钱级业务违例，不会放过真实偏差）；
//     B 数组超 parser maxArrayAggElements（Truncated）或聚合趟超总预算
//     （NumAggCapped）→ 不判定（半份求和不产信号，防误判）；
//   - 违例只产 OBSERVE 级信号，任何模式下都不升级 BLOCK 类（值/聚合比较为辅助信号，
//     与 REQUIRES/MUTEX 的可定案阻断语义区分）；
//   - 证据不落明文值：只写参数标识 + sha256 前 16 位指纹与值长度；聚合关系附数组
//     长度/聚合计数元数据，不落求和结果。
//
// 任务书 §23 其余关系缺口（请求内不可判定，不硬造，降级为不实现）：
//   - 父子对象关系：需对象层级/归属真值（父对象清单或归属基准），请求内仅有参数值，
//     无可比对真值；
//   - 租户关系 / 所有者关系：需身份→租户/所有者基线映射。请求上下文仅有
//     IdentityFingerprint（无租户/所有者真值），JWT 信任链也只验证主体不携带租户基线；
//     归 AUTHZ/BOLA 线设计（docs/API_BOLA_BFLA_MULTI_TENANT_AUTHORIZATION_DESIGN.md，
//     server apiauthz 已承载 OWNER 单关系基线）。
package detectors

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"strconv"
	"strings"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// 值比较/数组聚合关系类型词表（与发布侧迁移 000147/000154/000159 CHECK 一致）。
const (
	// RelationTypeEquals 等值：两端值字符串相等。
	RelationTypeEquals = "EQUALS"
	// RelationTypeNotEquals 不等值：两端值字符串须不相等（EQUALS 对偶）。
	RelationTypeNotEquals = "NOT_EQUALS"
	// RelationTypeGreaterThan A 值数值严格大于 B 值。
	RelationTypeGreaterThan = "GREATER_THAN"
	// RelationTypeLessThan A 值数值严格小于 B 值。
	RelationTypeLessThan = "LESS_THAN"
	// RelationTypeTimeBefore A 值时间严格早于 B 值。
	RelationTypeTimeBefore = "TIME_BEFORE"
	// RelationTypeTimeAfter A 值时间严格晚于 B 值。
	RelationTypeTimeAfter = "TIME_AFTER"
	// RelationTypeCountMatches 数量一致：A 整数值须等于 B 数组长度（000159，§23）。
	RelationTypeCountMatches = "COUNT_MATCHES"
	// RelationTypeSumMatches 汇总关系：A 数值须等于 B 数组元素数值和（000159，§23）。
	RelationTypeSumMatches = "SUM_MATCHES"
)

// valueRelationTypes 值比较/聚合关系类型集合（校验与分派共用）。
var valueRelationTypes = map[string]bool{
	RelationTypeEquals:       true,
	RelationTypeNotEquals:    true,
	RelationTypeGreaterThan:  true,
	RelationTypeLessThan:     true,
	RelationTypeTimeBefore:   true,
	RelationTypeTimeAfter:    true,
	RelationTypeCountMatches: true,
	RelationTypeSumMatches:   true,
}

// relationTimeLayouts 时间值可接受格式（无时区格式按 UTC 解析；RFC3339Nano 兼容 RFC3339）。
var relationTimeLayouts = []string{time.RFC3339Nano, "2006-01-02 15:04:05", "2006-01-02"}

// checkValueRelation 值比较关系判定：违例产 OBSERVE 级信号；缺失/类型不符不判定。
func checkValueRelation(ctx *dsctx.RequestContext, p *parser.Parsed, rel ParamRelation) {
	aVal, aOK := relationParamValue(p, rel.ParamA)
	bVal, bOK := relationParamValue(p, rel.ParamB)
	if !aOK || !bOK {
		return
	}
	var ruleID, message string
	var violated bool
	switch strings.ToUpper(rel.RelationType) {
	case RelationTypeEquals:
		ruleID, message = "schema.relation_equals", "equal-value relation violated (EQUALS relation)"
		violated = aVal != bVal
	case RelationTypeNotEquals:
		ruleID, message = "schema.relation_not_equals", "distinct-value relation violated (NOT_EQUALS relation)"
		violated = aVal == bVal
	case RelationTypeGreaterThan, RelationTypeLessThan:
		a, errA := strconv.ParseFloat(strings.TrimSpace(aVal), 64)
		b, errB := strconv.ParseFloat(strings.TrimSpace(bVal), 64)
		if errA != nil || errB != nil {
			return // 类型不符：不判定
		}
		if strings.ToUpper(rel.RelationType) == RelationTypeGreaterThan {
			ruleID, message = "schema.relation_greater_than", "numeric order relation violated (GREATER_THAN relation)"
			violated = !(a > b)
		} else {
			ruleID, message = "schema.relation_less_than", "numeric order relation violated (LESS_THAN relation)"
			violated = !(a < b)
		}
	case RelationTypeTimeBefore, RelationTypeTimeAfter:
		ta, okA := parseRelationTime(aVal)
		tb, okB := parseRelationTime(bVal)
		if !okA || !okB {
			return // 类型不符：不判定
		}
		if strings.ToUpper(rel.RelationType) == RelationTypeTimeBefore {
			ruleID, message = "schema.relation_time_before", "time order relation violated (TIME_BEFORE relation)"
			violated = !ta.Before(tb)
		} else {
			ruleID, message = "schema.relation_time_after", "time order relation violated (TIME_AFTER relation)"
			violated = !ta.After(tb)
		}
	default:
		return
	}
	if !violated {
		return
	}
	// 值比较违例只产信号：任何模式下维持 OBSERVE 级，不升级 BLOCK 类
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector:   "api_schema",
		RuleID:     ruleID,
		Category:   "OBSERVE",
		Severity:   "MEDIUM",
		Message:    message,
		Evidence:   relationValueEvidence(rel, aVal, bVal),
		ScoreDelta: 15,
	})
}

// relationParamValue 关系一端参数的取值（与 relationParamPresent 的位置语义一致）。
// 值不可得返回 false：脱敏头/COOKIE（仅存在性可用）、BODY 未留存标量值
// （ParseLimits.RetainJSONScalarValues=off 时 JSONValues 恒空）。
func relationParamValue(p *parser.Parsed, ref ParamRelationRef) (string, bool) {
	switch strings.ToUpper(ref.Location) {
	case "QUERY":
		v, ok := p.Query[ref.Name]
		return v, ok
	case "HEADER":
		v, ok := p.Headers[strings.ToLower(ref.Name)]
		if !ok || v == "[redacted]" {
			return "", false
		}
		return v, true
	case "BODY":
		path := ref.Path
		if path == "" {
			path = ref.Name
		}
		v, ok := p.JSONValues[path]
		return v, ok
	case "PATH":
		return pathSegmentValue(p, ref.Name, ref.Path)
	default:
		// COOKIE 整头脱敏及未知位置：值不可得
		return "", false
	}
}

// parseRelationTime 时间值解析：RFC3339(Nano) / "2006-01-02 15:04:05" / "2006-01-02" /
// 纯数字 Unix 秒。均不可解析返回 false（类型不符由调用方按「不判定」处理）。
func parseRelationTime(v string) (time.Time, bool) {
	s := strings.TrimSpace(v)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range relationTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	if isAllDigits(s) {
		if sec, err := strconv.ParseInt(s, 10, 64); err == nil {
			return time.Unix(sec, 0).UTC(), true
		}
	}
	return time.Time{}, false
}

// isAllDigits 纯 ASCII 数字串判定（Unix 秒形式；空串 false）。
func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return len(s) > 0
}

// relationValueEvidence 值比较关系证据：在关系标识之上加两端值的脱敏指纹
// （sha256 前 16 位 + 值长度），永不落明文值。
func relationValueEvidence(rel ParamRelation, aVal, bVal string) map[string]string {
	ev := relationEvidence(rel)
	aHash, aLen := relationValueFingerprint(aVal)
	bHash, bLen := relationValueFingerprint(bVal)
	ev["value_a_sha256"] = aHash
	ev["value_a_len"] = aLen
	ev["value_b_sha256"] = bHash
	ev["value_b_len"] = bLen
	return ev
}

// relationValueFingerprint 值脱敏指纹：sha256 十六进制前 16 位 + 值长度。
func relationValueFingerprint(v string) (hash, length string) {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:8]), strconv.Itoa(len(v))
}

// relationSumTolerance 汇总关系浮点容差：混合相对/绝对口径
// |want-sum| <= 1e-9 * max(1,|want|,|sum|)。覆盖二进制浮点累加误差
// （如 0.1+0.2≠0.3），量级远小于一分钱级业务违例，不会放过真实偏差。
func relationSumEquals(want, sum float64) bool {
	m := math.Max(math.Max(math.Abs(want), math.Abs(sum)), 1)
	return math.Abs(want-sum) <= 1e-9*m
}

// relationArrayLen B 端数组长度取值：仅 BODY 位置有数组长度留存（parser.JSONArrayLen，
// walkJSON 同口径路径）；其他位置无数组语义 → 不判定。
func relationArrayLen(p *parser.Parsed, ref ParamRelationRef) (int, bool) {
	if strings.ToUpper(ref.Location) != "BODY" {
		return 0, false
	}
	path := ref.Path
	if path == "" {
		path = ref.Name
	}
	n, ok := p.JSONArrayLen[path]
	return n, ok
}

// relationNumAgg B 端数组元素数值聚合取值：仅 BODY 位置且路径含 "[]" 段
// （如 items[].price）；聚合趟截断（NumAggCapped）或来源数组超上限（Truncated）
// 不返回值——半份求和参与判定必误判。Count==0（无数值元素）同样不判定。
func relationNumAgg(p *parser.Parsed, ref ParamRelationRef) (parser.NumArrayAgg, bool) {
	if p.NumAggCapped || strings.ToUpper(ref.Location) != "BODY" {
		return parser.NumArrayAgg{}, false
	}
	path := ref.Path
	if path == "" {
		path = ref.Name
	}
	agg, ok := p.JSONNumAgg[path]
	if !ok || agg.Truncated || agg.Count == 0 {
		return parser.NumArrayAgg{}, false
	}
	return agg, true
}

// checkAggregateRelation 数组聚合关系判定（COUNT_MATCHES/SUM_MATCHES，任务书 §23
// 「数量一致」「汇总关系」）：违例产 OBSERVE 级信号；缺失/截断/类型不符不判定。
func checkAggregateRelation(ctx *dsctx.RequestContext, p *parser.Parsed, rel ParamRelation) {
	aVal, aOK := relationParamValue(p, rel.ParamA)
	if !aOK {
		return
	}
	var ruleID, message string
	var violated bool
	var bMeta string // B 端聚合元数据（数组长度/聚合计数），不落求和结果
	switch strings.ToUpper(rel.RelationType) {
	case RelationTypeCountMatches:
		n, ok := relationArrayLen(p, rel.ParamB)
		if !ok {
			return
		}
		want, err := strconv.ParseInt(strings.TrimSpace(aVal), 10, 64)
		if err != nil {
			return // 类型不符：A 端须为整数值（"3.0"/"3.5"/非数字均不判定）
		}
		ruleID, message = "schema.relation_count_matches", "array count relation violated (COUNT_MATCHES relation)"
		violated = int64(n) != want
		bMeta = strconv.Itoa(n)
	case RelationTypeSumMatches:
		agg, ok := relationNumAgg(p, rel.ParamB)
		if !ok {
			return
		}
		want, err := strconv.ParseFloat(strings.TrimSpace(aVal), 64)
		if err != nil {
			return // 类型不符：A 端须可解析为数值
		}
		ruleID, message = "schema.relation_sum_matches", "array sum relation violated (SUM_MATCHES relation)"
		violated = !relationSumEquals(want, agg.Sum)
		bMeta = strconv.Itoa(agg.Count)
	default:
		return
	}
	if !violated {
		return
	}
	// 与值比较同一纪律：任何模式下维持 OBSERVE 级，不升级 BLOCK 类
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector:   "api_schema",
		RuleID:     ruleID,
		Category:   "OBSERVE",
		Severity:   "MEDIUM",
		Message:    message,
		Evidence:   relationAggregateEvidence(rel, aVal, bMeta),
		ScoreDelta: 15,
	})
}

// relationAggregateEvidence 聚合关系证据：关系标识 + A 端值脱敏指纹 + B 端聚合
// 元数据（数组长度/聚合计数），永不落明文值与求和结果。
func relationAggregateEvidence(rel ParamRelation, aVal, bMeta string) map[string]string {
	ev := relationEvidence(rel)
	aHash, aLen := relationValueFingerprint(aVal)
	ev["value_a_sha256"] = aHash
	ev["value_a_len"] = aLen
	ev["param_b_agg_count"] = bMeta
	return ev
}
