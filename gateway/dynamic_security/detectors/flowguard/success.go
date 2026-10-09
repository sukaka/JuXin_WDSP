// success.go 成功判定式运行期求值（NG-FLOW-03 §1.4/D4 冻结：三形态可组合与——
// 全部配置的条件同时成立才判成功；HTTP 2xx 不是通用成功证据，§9.3）。
//
// 形态（与 FLOW-01 ParseSuccessRule 形态校验同词表，运行期解析同样自实现不引库）：
//  1. status_codes：响应状态码集合（实际码 ∈ 集合）；
//  2. body_jsonpath_equals：body JSONPath 受限子集等值（仅 $.a.b.c 点路径逐段下钻
//     + 标量等值；数组下标/通配/过滤器不在子集——FLOW-01 装配期已拒收，运行期
//     只实现子集语义）；
//  3. graphql_errors_empty：GraphQL 响应 errors 为空（字段缺席或空数组）。
//
// 读取纪律：仅命中强流程绑定且配置了 body 判定式（形态②③）的步骤由装配侧读体，
// 有界 ≤64KB——超限/未捕获/解析失败/路径缺失/值不等/码不在集合，一律按「判定
// 不命中 UNKNOWN」如实返回（F04：超时可能已成功，UNKNOWN 入对账不自动回滚）。
// 证据读数（命中形态/实际值，AZ-03 证据纪律）：实际值截断 64 字符如实呈现。
package flowguard

import (
	"encoding/json"
	"strconv"
	"strings"
)

// maxSuccessValueEvidenceLen 证据中判定读数（期望/实际值）的截断长度。
const maxSuccessValueEvidenceLen = 64

// SuccessVerdict 判定式求值结果。
type SuccessVerdict struct {
	// Hit 判定式命中（全部配置形态成立）——调用方据此 commit。
	Hit bool
	// Detail 子原因（证据明细）：hit / status_mismatch / body_over_limit /
	// body_unavailable / body_unparseable / jsonpath_not_found /
	// jsonpath_not_scalar / jsonpath_mismatch / graphql_errors_present /
	// graphql_errors_shape / rule_missing。
	Detail string
	// Evidence 判定读数（命中形态/实际值，截断如实呈现；不含响应体大段内容）。
	Evidence map[string]string
}

// EvaluateSuccess 成功判定式求值（三形态可组合与）。body 仅形态②③需要；
// 未配置 body 形态时 body 传 nil 零开销。bodyTruncated = 体超 64KB 有界上限
// （超限按判定不命中 UNKNOWN 如实处理）。
func EvaluateSuccess(rule *SuccessRule, status int, body []byte, bodyTruncated bool) SuccessVerdict {
	v := SuccessVerdict{Detail: "hit", Evidence: map[string]string{}}
	if rule == nil {
		// 运行期防御分支：FLOW-01 装配校验已保证判定式必填且至少一形态；
		// 无配置该步骤恒 UNKNOWN（§9.3/D4——2xx 不是通用成功证据）
		v.Detail = "rule_missing"
		return v
	}
	forms := make([]string, 0, 3)

	// 形态一：状态码集合
	if len(rule.StatusCodes) > 0 {
		forms = append(forms, "status_codes")
		v.Evidence["status"] = strconv.Itoa(status)
		if !statusCodeIn(rule.StatusCodes, status) {
			v.Detail = "status_mismatch"
			v.Evidence["rule_forms"] = strings.Join(forms, ",")
			return v
		}
	}

	// 形态②③需要 body：统一解析一次
	needBody := rule.BodyJSONPathEquals != nil || rule.GraphQLErrorsEmpty
	var doc any
	if needBody {
		if bodyTruncated {
			v.Detail = "body_over_limit"
			v.Evidence["rule_forms"] = formsString(forms)
			return v
		}
		if body == nil {
			v.Detail = "body_unavailable"
			v.Evidence["rule_forms"] = formsString(forms)
			return v
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			v.Detail = "body_unparseable"
			v.Evidence["rule_forms"] = formsString(forms)
			return v
		}
	}

	// 形态二：JSONPath 受限子集等值（仅点路径+标量等值）
	if rule.BodyJSONPathEquals != nil {
		forms = append(forms, "body_jsonpath_equals")
		jp := rule.BodyJSONPathEquals
		v.Evidence["jsonpath_path"] = jp.Path
		actual, found, scalar := jsonPathGet(doc, jp.Path)
		switch {
		case !found:
			v.Detail = "jsonpath_not_found"
		case !scalar:
			v.Detail = "jsonpath_not_scalar"
		case !scalarEqual(actual, jp.Value):
			v.Detail = "jsonpath_mismatch"
		}
		v.Evidence["jsonpath_expect"] = truncateEvidenceValue(jsonScalarString(jp.Value))
		if found && scalar {
			v.Evidence["jsonpath_actual"] = truncateEvidenceValue(jsonScalarString(actual))
		}
		if v.Detail != "hit" {
			v.Evidence["rule_forms"] = formsString(forms)
			return v
		}
	}

	// 形态三：GraphQL errors 为空
	if rule.GraphQLErrorsEmpty {
		forms = append(forms, "graphql_errors_empty")
		obj, ok := doc.(map[string]any)
		if !ok {
			v.Detail = "body_unparseable"
			v.Evidence["rule_forms"] = formsString(forms)
			return v
		}
		errs, present := obj["errors"]
		switch {
		case !present:
			v.Evidence["graphql_errors"] = "absent"
		case errs == nil:
			// "errors":null 非合法 GraphQL 形态（规范：无错误即省略）——形态无法解析如实 UNKNOWN
			v.Detail = "graphql_errors_shape"
			v.Evidence["graphql_errors"] = "null"
		default:
			arr, isArr := errs.([]any)
			if !isArr {
				v.Detail = "graphql_errors_shape"
				v.Evidence["graphql_errors"] = "non_array"
			} else if len(arr) > 0 {
				v.Detail = "graphql_errors_present"
				v.Evidence["graphql_errors"] = strconv.Itoa(len(arr))
			} else {
				v.Evidence["graphql_errors"] = "empty"
			}
		}
		if v.Detail != "hit" {
			v.Evidence["rule_forms"] = formsString(forms)
			return v
		}
	}

	v.Evidence["rule_forms"] = formsString(forms)
	v.Hit = true
	return v
}

// formsString 证据形态清单（已评估形态 + 全部配置形态如实标注）。
func formsString(evaluated []string) string {
	return strings.Join(evaluated, ",")
}

func statusCodeIn(set []int, status int) bool {
	for _, c := range set {
		if c == status {
			return true
		}
	}
	return false
}

// jsonPathGet 受限子集路径求值：仅 $.a.b.c 点路径逐段下钻（段标识符形态由
// FLOW-01 jsonPathSubset 装配期锁定；本函数不再正则核对——子集之外的路径形态
// 到不了运行期）。返回 (值, 找到, 为标量)；中间段遇非对象/缺失即未找到。
func jsonPathGet(doc any, path string) (any, bool, bool) {
	if !strings.HasPrefix(path, "$.") {
		return nil, false, false
	}
	cur := doc
	for _, seg := range strings.Split(strings.TrimPrefix(path, "$."), ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false, false
		}
		next, present := obj[seg]
		if !present {
			return nil, false, false
		}
		cur = next
	}
	switch cur.(type) {
	case map[string]any, []any:
		return cur, true, false
	default:
		return cur, true, true
	}
}

// scalarEqual 标量等值（JSON 解码口径：数值统一 float64；类型不同即不等，
// 字符串 "1" ≠ 数值 1——等值判定不做跨类型猜义）。
func scalarEqual(actual, expected any) bool {
	switch e := expected.(type) {
	case string:
		a, ok := actual.(string)
		return ok && a == e
	case bool:
		a, ok := actual.(bool)
		return ok && a == e
	case float64:
		a, ok := actual.(float64)
		return ok && a == e
	default:
		return false
	}
}

// jsonScalarString 标量值的证据文本形态（截断前）。
func jsonScalarString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64)
	case nil:
		return "null"
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		return string(raw)
	}
}

func truncateEvidenceValue(s string) string {
	if len(s) > maxSuccessValueEvidenceLen {
		return s[:maxSuccessValueEvidenceLen] + "…"
	}
	return s
}
