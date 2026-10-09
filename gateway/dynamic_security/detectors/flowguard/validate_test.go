// validate_test.go 强流程定义校验（§1.1 冻结规则逐条正反；与 server 侧
// server/internal/strongflow/validate.go 同词表同边界）。
package flowguard

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// validStep 合法步骤基线（各用例在其上变异）。
func validStep() Step {
	return Step{
		StepKey:        "pay",
		EndpointKey:    "POST /v1/orders/{id}/pay",
		Sequence:       2,
		SuccessRule:    json.RawMessage(`{"status_codes":[200],"body_jsonpath_equals":{"path":"$.status","value":"PAID"}}`),
		TimeoutSeconds: 60,
		RetrySemantics: RetryNotRetryable,
		LeaseSeconds:   30,
	}
}

// validDefinition 合法定义基线：两步串行（create→pay）。
func validDefinition() Definition {
	first := validStep()
	first.StepKey = "create"
	first.EndpointKey = "POST /v1/orders"
	first.Sequence = 1
	first.RetrySemantics = RetryIdempotent
	return Definition{
		ID:                "9f1c2f70-6f3a-4b9a-9a2d-2d0c3f0a9e01",
		ApplicationID:     "app-1",
		Name:              "checkout",
		Version:           1,
		Status:            StatusActive,
		BindingPathPrefix: "/v1/orders",
		InstanceKeyParam:  "query:order_id",
		Mode:              ModeObserve,
		Steps:             []Step{first, validStep()},
	}
}

// mutateDefinition 在合法基线上变异后校验，断言拒绝且错误含 want。
func mutateDefinition(t *testing.T, name string, mutate func(*Definition), want string) {
	t.Helper()
	d := validDefinition()
	mutate(&d)
	err := ValidateDefinitions([]Definition{d})
	if err == nil {
		t.Errorf("%s: 应拒绝", name)
		return
	}
	if !strings.Contains(err.Error(), want) {
		t.Errorf("%s: 错误 %q 未含 %q", name, err.Error(), want)
	}
	ce, ok := err.(*ConfigError)
	if !ok || ce.Index != 0 {
		t.Errorf("%s: 错误应为 *ConfigError 且 Index=0: %T %v", name, err, err)
	}
}

// TestValidateDefinitionsAcceptValid 合法定义（含夹紧边界值与三形态组合与）放行。
func TestValidateDefinitionsAcceptValid(t *testing.T) {
	if err := ValidateDefinitions(nil); err != nil {
		t.Fatalf("nil 定义集 = 零行为，不应报错: %v", err)
	}
	if err := ValidateDefinitions([]Definition{}); err != nil {
		t.Fatalf("空定义集 = 零行为，不应报错: %v", err)
	}
	d := validDefinition()
	// 夹紧边界值：timeout 15/600、lease 15/300 恰在界内
	d.Steps[0].TimeoutSeconds, d.Steps[0].LeaseSeconds = TimeoutSecondsMin, LeaseSecondsMin
	d.Steps[1].TimeoutSeconds, d.Steps[1].LeaseSeconds = TimeoutSecondsMax, LeaseSecondsMax
	// 组合与：状态码集合 + JSONPath 等值 + GraphQL errors 空 三形态并存
	d.Steps[1].SuccessRule = json.RawMessage(
		`{"status_codes":[200,201],"body_jsonpath_equals":{"path":"$.data.state","value":"DONE"},"graphql_errors_empty":true}`)
	if err := ValidateDefinitions([]Definition{d}); err != nil {
		t.Fatalf("合法定义应放行: %v", err)
	}
	// 缺省值容忍：mode/status 缺省合法（装配层归一 OBSERVE/ACTIVE）
	d.Mode, d.Status = "", ""
	if err := ValidateDefinitions([]Definition{d}); err != nil {
		t.Fatalf("mode/status 缺省应放行: %v", err)
	}
}

// TestValidateDefinitionFields 定义级字段逐条正反。
func TestValidateDefinitionFields(t *testing.T) {
	mutateDefinition(t, "id 空", func(d *Definition) { d.ID = " " }, "id 必填")
	mutateDefinition(t, "application_id 空", func(d *Definition) { d.ApplicationID = "" }, "application_id 必填")
	mutateDefinition(t, "name 空", func(d *Definition) { d.Name = "" }, "name 必填")
	mutateDefinition(t, "name 超长", func(d *Definition) { d.Name = strings.Repeat("流", 256) }, "name 必填且不超过")
	mutateDefinition(t, "version 0", func(d *Definition) { d.Version = 0 }, "version 必须 ≥1")
	mutateDefinition(t, "version 负", func(d *Definition) { d.Version = -2 }, "version 必须 ≥1")
	mutateDefinition(t, "status DRAFT 拒收", func(d *Definition) { d.Status = "DRAFT" }, "status 非法")
	mutateDefinition(t, "status 小写拒收", func(d *Definition) { d.Status = "active" }, "status 非法")
	// 育龄窗（§8.4-1 裁决）：RETIRED 入词表合法（存在非终态实例的 RETIRED 版本
	// 随发布面下发供存量实例续跑）
	{
		d := validDefinition()
		d.Status = "RETIRED"
		if err := ValidateDefinitions([]Definition{d}); err != nil {
			t.Errorf("status RETIRED 育龄窗应放行: %v", err)
		}
	}
	mutateDefinition(t, "前缀空", func(d *Definition) { d.BindingPathPrefix = "" }, "binding_path_prefix 必填")
	mutateDefinition(t, "前缀无斜杠", func(d *Definition) { d.BindingPathPrefix = "v1/orders" }, "/ 开头")
	mutateDefinition(t, "前缀超长", func(d *Definition) { d.BindingPathPrefix = "/" + strings.Repeat("a", 512) }, "binding_path_prefix")
	mutateDefinition(t, "mode 词表外", func(d *Definition) { d.Mode = "BLOCK" }, "mode 非法")
	mutateDefinition(t, "mode 小写拒收", func(d *Definition) { d.Mode = "observe" }, "mode 非法")
	mutateDefinition(t, "steps 空", func(d *Definition) { d.Steps = nil }, "至少包含一个步骤")
	mutateDefinition(t, "steps 超上限", func(d *Definition) {
		d.Steps = nil
		for i := 1; i <= MaxStepsPerDefinition+1; i++ {
			s := validStep()
			s.StepKey = fmt.Sprintf("s%d", i)
			s.Sequence = i
			d.Steps = append(d.Steps, s)
		}
	}, "步骤数超上限")
}

// TestValidateInstanceKeyParam 实例引用来源形态（query:<名> / path:<段序>）正反。
func TestValidateInstanceKeyParam(t *testing.T) {
	for _, ok := range []string{"query:order_id", "path:3", "path:0", "query:订单号", "query: a " /*首尾空白归一*/} {
		d := validDefinition()
		d.InstanceKeyParam = ok
		if err := ValidateDefinitions([]Definition{d}); err != nil {
			t.Errorf("instance_key_param %q 应放行: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "query:", "path:", "path:-1", "path:1a", "header:x-id",
		"body:order.id", "query:a b", "query:a\tb", "QUERY:order_id"} {
		d := validDefinition()
		d.InstanceKeyParam = bad
		if err := ValidateDefinitions([]Definition{d}); err == nil {
			t.Errorf("instance_key_param %q 应拒绝", bad)
		} else if !strings.Contains(err.Error(), "instance_key_param 非法") {
			t.Errorf("instance_key_param %q 错误 %q 未含词表说明", bad, err.Error())
		}
	}
	d := validDefinition()
	d.InstanceKeyParam = "query:" + strings.Repeat("a", 200)
	if err := ValidateDefinitions([]Definition{d}); err == nil {
		t.Error("instance_key_param 超长应拒绝")
	}
}

// TestValidateStepsStructure step_key 唯一 / sequence 单调（唯一承载）/ 首步唯一最小。
func TestValidateStepsStructure(t *testing.T) {
	mutateDefinition(t, "step_key 空", func(d *Definition) { d.Steps[0].StepKey = " " }, "step_key 必填")
	mutateDefinition(t, "step_key 超长", func(d *Definition) { d.Steps[0].StepKey = strings.Repeat("s", 129) }, "step_key 必填且不超过")
	mutateDefinition(t, "step_key 重复", func(d *Definition) { d.Steps[1].StepKey = "create" }, `step_key "create" 重复`)
	mutateDefinition(t, "sequence 0", func(d *Definition) { d.Steps[0].Sequence = 0 }, "sequence 必须 ≥1")
	mutateDefinition(t, "sequence 负", func(d *Definition) { d.Steps[1].Sequence = -1 }, "sequence 必须 ≥1")
	// sequence 重复即首步唯一最小违例的承载（同最小值两步 = 重复 sequence）
	mutateDefinition(t, "sequence 重复/首步并列", func(d *Definition) { d.Steps[1].Sequence = 1 }, "sequence 1 重复")
	mutateDefinition(t, "endpoint_key 空", func(d *Definition) { d.Steps[0].EndpointKey = "" }, "endpoint_key 必填")
	mutateDefinition(t, "endpoint_key 超长", func(d *Definition) {
		d.Steps[0].EndpointKey = "POST /" + strings.Repeat("a", 560)
	}, "endpoint_key 必填且不超过")
	// 正：sequence 非连续（组间允许间隔）且乱序给出——校验不依赖数组序
	d := validDefinition()
	third := validStep()
	third.StepKey, third.Sequence = "notify", 10
	d.Steps = []Step{d.Steps[1], third, d.Steps[0]}
	if err := ValidateDefinitions([]Definition{d}); err != nil {
		t.Errorf("乱序/间隔 sequence 应放行: %v", err)
	}
}

// TestValidateStepsParallelGroup parallel_group 相邻规则正反。
func TestValidateStepsParallelGroup(t *testing.T) {
	// 正：同组 {2,3} 相邻
	d := validDefinition()
	third := validStep()
	third.StepKey, third.Sequence, third.ParallelGroup = "notify", 3, "g1"
	d.Steps[1].ParallelGroup = "g1"
	d.Steps = append(d.Steps, third)
	if err := ValidateDefinitions([]Definition{d}); err != nil {
		t.Fatalf("相邻并行组应放行: %v", err)
	}
	// 反：同组 {2,4} 不相邻
	mutateDefinition(t, "并行组不相邻", func(d *Definition) {
		s := validStep()
		s.StepKey, s.Sequence, s.ParallelGroup = "notify", 4, "g1"
		d.Steps[1].ParallelGroup = "g1"
		d.Steps = append(d.Steps, s)
	}, "不相邻")
	// 反：同组被串行步骤隔断（{1,3} 夹 seq2 串行）
	mutateDefinition(t, "并行组被隔断", func(d *Definition) {
		s := validStep()
		s.StepKey, s.Sequence, s.ParallelGroup = "notify", 3, "g1"
		d.Steps[0].ParallelGroup = "g1"
		d.Steps = append(d.Steps, s)
	}, "不相邻")
	// 反：单步组
	mutateDefinition(t, "单步并行组", func(d *Definition) { d.Steps[0].ParallelGroup = "solo" }, "仅一步")
	// 反：组名超长
	mutateDefinition(t, "组名超长", func(d *Definition) {
		d.Steps[0].ParallelGroup = strings.Repeat("g", 129)
		d.Steps[1].ParallelGroup = d.Steps[0].ParallelGroup
	}, "parallel_group 超")
}

// TestValidateStepsClamps timeout/lease 夹紧区间逐边界正反（词表外拒收不夹紧猜义）。
func TestValidateStepsClamps(t *testing.T) {
	mutateDefinition(t, "timeout 下界外", func(d *Definition) { d.Steps[0].TimeoutSeconds = TimeoutSecondsMin - 1 }, "timeout_seconds 词表外")
	mutateDefinition(t, "timeout 上界外", func(d *Definition) { d.Steps[0].TimeoutSeconds = TimeoutSecondsMax + 1 }, "timeout_seconds 词表外")
	mutateDefinition(t, "timeout 缺失=0", func(d *Definition) { d.Steps[0].TimeoutSeconds = 0 }, "timeout_seconds 词表外")
	mutateDefinition(t, "lease 下界外", func(d *Definition) { d.Steps[0].LeaseSeconds = LeaseSecondsMin - 1 }, "lease_seconds 词表外")
	mutateDefinition(t, "lease 上界外", func(d *Definition) { d.Steps[0].LeaseSeconds = LeaseSecondsMax + 1 }, "lease_seconds 词表外")
	mutateDefinition(t, "lease 缺失=0", func(d *Definition) { d.Steps[0].LeaseSeconds = 0 }, "lease_seconds 词表外")
}

// TestValidateRetrySemantics retry_semantics 词表正反。
func TestValidateRetrySemantics(t *testing.T) {
	for _, ok := range []string{RetryIdempotent, RetryNotRetryable, RetryRequiresReview} {
		d := validDefinition()
		d.Steps[0].RetrySemantics = ok
		if err := ValidateDefinitions([]Definition{d}); err != nil {
			t.Errorf("retry_semantics %q 应放行: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "idempotent", "RETRYABLE", "SAFE"} {
		mutateDefinition(t, "retry_semantics="+bad, func(d *Definition) { d.Steps[0].RetrySemantics = bad }, "retry_semantics 非法")
	}
}

// TestValidateSuccessRule success_rule 三形态词表正反（含组合与、受限子集、白名单键）。
func TestValidateSuccessRule(t *testing.T) {
	good := []string{
		`{"status_codes":[200]}`,                                      // 形态一
		`{"status_codes":[100,599]}`,                                  // 状态码边界
		`{"body_jsonpath_equals":{"path":"$.status","value":"PAID"}}`, // 形态二
		`{"body_jsonpath_equals":{"path":"$.a.b2","value":1}}`,        // 多级点路径+数值
		`{"body_jsonpath_equals":{"path":"$.ok","value":true}}`,       // 布尔等值
		`{"graphql_errors_empty":true}`,                               // 形态三
		`{"status_codes":[200],"body_jsonpath_equals":{"path":"$.s","value":"X"},"graphql_errors_empty":true}`, // 组合与三形态
		`{"graphql_errors_empty":false,"status_codes":[200]}`,                                                  // 显式 false 不成立形态，组合其他形态合法
	}
	for _, raw := range good {
		d := validDefinition()
		d.Steps[0].SuccessRule = json.RawMessage(raw)
		if err := ValidateDefinitions([]Definition{d}); err != nil {
			t.Errorf("success_rule %s 应放行: %v", raw, err)
		}
	}

	bad := []struct{ name, raw, want string }{
		{"缺失", "", "必填"},
		{"null", `null`, "必填"},
		{"空对象无形态", `{}`, "至少配置一种"},
		{"单 false 无形态", `{"graphql_errors_empty":false}`, "至少配置一种"},
		{"空状态码集合", `{"status_codes":[]}`, "至少配置一种"},
		{"状态码过小", `{"status_codes":[99]}`, "100~599"},
		{"状态码过大", `{"status_codes":[600]}`, "100~599"},
		{"状态码非整数", `{"status_codes":["200"]}`, "反序列化失败"},
		{"未知键拒收", `{"jsonpath_contains":{"path":"$.s","value":"X"}}`, "反序列化失败"},
		{"未知键与合法形态并存仍拒收", `{"status_codes":[200],"extra":true}`, "反序列化失败"},
		{"畸形 JSON", `{"status_codes":[200`, "反序列化失败"},
		{"多余内容", `{"status_codes":[200]} {"x":1}`, "多余内容"},
		{"路径无根", `{"body_jsonpath_equals":{"path":"a.b","value":1}}`, "path 形态非法"},
		{"路径仅根", `{"body_jsonpath_equals":{"path":"$","value":1}}`, "path 形态非法"},
		{"路径下标", `{"body_jsonpath_equals":{"path":"$.a[0]","value":1}}`, "path 形态非法"},
		{"路径引号", `{"body_jsonpath_equals":{"path":"$['a']","value":1}}`, "path 形态非法"},
		{"路径通配", `{"body_jsonpath_equals":{"path":"$.a.*","value":1}}`, "path 形态非法"},
		{"路径连字符段", `{"body_jsonpath_equals":{"path":"$.a-b","value":1}}`, "path 形态非法"},
		{"路径空尾段", `{"body_jsonpath_equals":{"path":"$.a.","value":1}}`, "path 形态非法"},
		{"路径数字首段", `{"body_jsonpath_equals":{"path":"$.1a","value":1}}`, "path 形态非法"},
		{"等值缺失", `{"body_jsonpath_equals":{"path":"$.s"}}`, "value 必填"},
		{"等值 null", `{"body_jsonpath_equals":{"path":"$.s","value":null}}`, "value 必填"},
	}
	for _, tc := range bad {
		d := validDefinition()
		d.Steps[0].SuccessRule = json.RawMessage(tc.raw)
		err := ValidateDefinitions([]Definition{d})
		if err == nil {
			t.Errorf("%s: success_rule %s 应拒绝", tc.name, tc.raw)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: 错误 %q 未含 %q", tc.name, err.Error(), tc.want)
		}
	}
	// 体量上限（与 server 侧 maxSuccessRuleBytes 同边界）
	d := validDefinition()
	d.Steps[0].SuccessRule = json.RawMessage(`{"status_codes":[200],"graphql_errors_empty":true,"body_jsonpath_equals":{"path":"$.` +
		strings.Repeat("a", maxSuccessRuleBytes) + `","value":"x"}}`)
	if err := ValidateDefinitions([]Definition{d}); err == nil ||
		!strings.Contains(err.Error(), "字节") {
		t.Errorf("success_rule 超 %d 字节应拒绝: %v", maxSuccessRuleBytes, err)
	}
}

// TestParseSuccessRuleNullVsAbsent 未配置与非法显式区分（缺失/空/null → nil,nil）。
func TestParseSuccessRuleNullVsAbsent(t *testing.T) {
	for _, raw := range []json.RawMessage{nil, {}, []byte("  "), []byte("null"), []byte(" null ")} {
		rule, err := ParseSuccessRule(raw)
		if err != nil || rule != nil {
			t.Errorf("raw=%q 应 (nil,nil)，得 (%v,%v)", raw, rule, err)
		}
	}
}

// TestValidateDefinitionsErrorIndex 错误定位：第二条定义违规时 Index=1。
func TestValidateDefinitionsErrorIndex(t *testing.T) {
	bad := validDefinition()
	bad.ID, bad.Name, bad.Version = "d2", "checkout-v2", 2
	bad.Steps[0].TimeoutSeconds = 1
	err := ValidateDefinitions([]Definition{validDefinition(), bad})
	ce, ok := err.(*ConfigError)
	if !ok || ce.Index != 1 || !strings.Contains(ce.Error(), "definition[1]") {
		t.Fatalf("错误定位应为 [1]: %T %v", err, err)
	}
}
