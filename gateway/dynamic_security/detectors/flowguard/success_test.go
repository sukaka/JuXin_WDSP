// success_test.go 成功判定式运行期求值矩阵（§1.4 三形态逐正反 + 组合与 +
// JSONPath 子集 + 有界读取纪律 + 形态无法解析如实 UNKNOWN）。
package flowguard

import (
	"strings"
	"testing"
)

func TestEvaluateSuccessStatusCodes(t *testing.T) {
	rule := &SuccessRule{StatusCodes: []int{200, 201}}
	if v := EvaluateSuccess(rule, 200, nil, false); !v.Hit {
		t.Fatalf("200 ∈ 集合应命中: %+v", v)
	}
	v := EvaluateSuccess(rule, 204, nil, false)
	if v.Hit || v.Detail != "status_mismatch" || v.Evidence["status"] != "204" {
		t.Fatalf("204 不命中应 status_mismatch: %+v", v)
	}
	// 2xx 不是通用成功证据：无判定式恒 UNKNOWN
	v = EvaluateSuccess(nil, 200, nil, false)
	if v.Hit || v.Detail != "rule_missing" {
		t.Fatalf("无判定式应 rule_missing: %+v", v)
	}
}

func TestEvaluateSuccessJSONPath(t *testing.T) {
	body := []byte(`{"status":"PAID","data":{"state":"DONE","count":3,"ok":true}}`)
	cases := []struct {
		name   string
		rule   *SuccessRule
		body   []byte
		status int
		hit    bool
		detail string
	}{
		{"字符串等值命中", &SuccessRule{BodyJSONPathEquals: &JSONPathEquals{Path: "$.status", Value: "PAID"}}, body, 200, true, "hit"},
		{"嵌套点路径命中", &SuccessRule{BodyJSONPathEquals: &JSONPathEquals{Path: "$.data.state", Value: "DONE"}}, body, 200, true, "hit"},
		{"数值等值命中", &SuccessRule{BodyJSONPathEquals: &JSONPathEquals{Path: "$.data.count", Value: float64(3)}}, body, 200, true, "hit"},
		{"布尔等值命中", &SuccessRule{BodyJSONPathEquals: &JSONPathEquals{Path: "$.data.ok", Value: true}}, body, 200, true, "hit"},
		{"值不等", &SuccessRule{BodyJSONPathEquals: &JSONPathEquals{Path: "$.status", Value: "FAILED"}}, body, 200, false, "jsonpath_mismatch"},
		{"路径缺失", &SuccessRule{BodyJSONPathEquals: &JSONPathEquals{Path: "$.absent", Value: "X"}}, body, 200, false, "jsonpath_not_found"},
		{"中间段非对象", &SuccessRule{BodyJSONPathEquals: &JSONPathEquals{Path: "$.status.sub", Value: "X"}}, body, 200, false, "jsonpath_not_found"},
		{"终值为对象非标量", &SuccessRule{BodyJSONPathEquals: &JSONPathEquals{Path: "$.data", Value: "x"}}, body, 200, false, "jsonpath_not_scalar"},
		{"类型严格：字符串≠数值", &SuccessRule{BodyJSONPathEquals: &JSONPathEquals{Path: "$.data.count", Value: "3"}}, body, 200, false, "jsonpath_mismatch"},
		{"类型严格：数值≠字符串", &SuccessRule{BodyJSONPathEquals: &JSONPathEquals{Path: "$.status", Value: float64(0)}}, body, 200, false, "jsonpath_mismatch"},
	}
	for _, tc := range cases {
		v := EvaluateSuccess(tc.rule, tc.status, tc.body, false)
		if v.Hit != tc.hit || v.Detail != tc.detail {
			t.Errorf("%s: got hit=%v detail=%q want hit=%v detail=%q", tc.name, v.Hit, v.Detail, tc.hit, tc.detail)
		}
	}
	// 证据读数（命中形态/实际值，截断）
	v := EvaluateSuccess(&SuccessRule{BodyJSONPathEquals: &JSONPathEquals{Path: "$.status", Value: "FAILED"}}, 200, body, false)
	if v.Evidence["jsonpath_actual"] != "PAID" || v.Evidence["jsonpath_expect"] != "FAILED" || v.Evidence["rule_forms"] != "body_jsonpath_equals" {
		t.Fatalf("证据读数 = %+v", v.Evidence)
	}
}

func TestEvaluateSuccessGraphQLErrors(t *testing.T) {
	rule := &SuccessRule{GraphQLErrorsEmpty: true}
	cases := []struct {
		name   string
		body   string
		hit    bool
		detail string
	}{
		{"errors 缺席", `{"data":{"ok":true}}`, true, "hit"},
		{"errors 空数组", `{"data":{},"errors":[]}`, true, "hit"},
		{"errors 非空", `{"errors":[{"message":"boom"}]}`, false, "graphql_errors_present"},
		{"errors null 形态非法", `{"errors":null}`, false, "graphql_errors_shape"},
		{"errors 非数组", `{"errors":{"message":"x"}}`, false, "graphql_errors_shape"},
		{"顶层非对象", `[1,2]`, false, "body_unparseable"},
	}
	for _, tc := range cases {
		v := EvaluateSuccess(rule, 200, []byte(tc.body), false)
		if v.Hit != tc.hit || v.Detail != tc.detail {
			t.Errorf("%s: got hit=%v detail=%q want %v/%q", tc.name, v.Hit, v.Detail, tc.hit, tc.detail)
		}
	}
}

func TestEvaluateSuccessCombinedAND(t *testing.T) {
	rule := &SuccessRule{
		StatusCodes:        []int{200},
		BodyJSONPathEquals: &JSONPathEquals{Path: "$.status", Value: "PAID"},
		GraphQLErrorsEmpty: true,
	}
	body := []byte(`{"status":"PAID"}`)
	if v := EvaluateSuccess(rule, 200, body, false); !v.Hit {
		t.Fatalf("三形态全成立应命中: %+v", v)
	}
	if v := EvaluateSuccess(rule, 200, body, false); v.Evidence["rule_forms"] != "status_codes,body_jsonpath_equals,graphql_errors_empty" {
		t.Fatalf("形态清单 = %q", v.Evidence["rule_forms"])
	}
	// 任一形态不成立即不命中（组合与）
	if v := EvaluateSuccess(rule, 201, body, false); v.Hit || v.Detail != "status_mismatch" {
		t.Fatalf("码不在集合: %+v", v)
	}
	if v := EvaluateSuccess(rule, 200, []byte(`{"status":"PENDING"}`), false); v.Hit || v.Detail != "jsonpath_mismatch" {
		t.Fatalf("值不等: %+v", v)
	}
	if v := EvaluateSuccess(rule, 200, []byte(`{"status":"PAID","errors":[{"message":"x"}]}`), false); v.Hit || v.Detail != "graphql_errors_present" {
		t.Fatalf("errors 非空: %+v", v)
	}
}

func TestEvaluateSuccessBodyDiscipline(t *testing.T) {
	rule := &SuccessRule{BodyJSONPathEquals: &JSONPathEquals{Path: "$.status", Value: "PAID"}}
	// 超 64KB 有界上限：按判定不命中 UNKNOWN 如实处理
	if v := EvaluateSuccess(rule, 200, nil, true); v.Hit || v.Detail != "body_over_limit" {
		t.Fatalf("超限应 body_over_limit: %+v", v)
	}
	// 体未捕获（流式/劫持）：body_unavailable
	if v := EvaluateSuccess(rule, 200, nil, false); v.Hit || v.Detail != "body_unavailable" {
		t.Fatalf("缺体应 body_unavailable: %+v", v)
	}
	// 解析失败：body_unparseable
	if v := EvaluateSuccess(rule, 200, []byte(`{"status":`), false); v.Hit || v.Detail != "body_unparseable" {
		t.Fatalf("非法 JSON 应 body_unparseable: %+v", v)
	}
	// status-codes-only 判定不需要 body：nil body 照常求值（零体开销纪律）
	if v := EvaluateSuccess(&SuccessRule{StatusCodes: []int{200}}, 200, nil, true); !v.Hit {
		t.Fatalf("纯码判定不受体限影响: %+v", v)
	}
}

func TestEvaluateSuccessEvidenceTruncation(t *testing.T) {
	long := strings.Repeat("x", 100)
	body := []byte(`{"status":"` + long + `"}`)
	v := EvaluateSuccess(&SuccessRule{BodyJSONPathEquals: &JSONPathEquals{Path: "$.status", Value: "Y"}}, 200, body, false)
	actual := v.Evidence["jsonpath_actual"]
	if v.Hit || !strings.HasSuffix(actual, "…") || len(strings.TrimSuffix(actual, "…")) != maxSuccessValueEvidenceLen {
		t.Fatalf("实际值应截断为 64 前缀+省略号: %q", actual)
	}
}
