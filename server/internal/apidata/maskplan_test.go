// maskplan_test.go 脱敏计划求值纯函数测试：优先级合并、作用域匹配、排除生效。
package apidata

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

// mkRule 构造规则（测试辅助；Exclusions 用合法 JSON 或 nil）。
func mkRule(scope, fieldPath, dataType, algorithm string, exclusions string) MaskingRule {
	r := MaskingRule{
		ID:        uuid.New(),
		Name:      "r-" + uuid.NewString()[:6],
		Enabled:   true,
		Scope:     scope,
		FieldPath: fieldPath,
		Algorithm: algorithm,
		Params:    json.RawMessage(`{}`),
	}
	if dataType != "" {
		r.DataType = &dataType
	}
	if exclusions != "" {
		r.Exclusions = json.RawMessage(exclusions)
	} else {
		r.Exclusions = json.RawMessage(`{}`)
	}
	return r
}

func withApp(r MaskingRule, appID uuid.UUID) MaskingRule {
	r.ApplicationID = &appID
	return r
}

func withEndpoint(r MaskingRule, key string) MaskingRule {
	r.EndpointKey = &key
	return r
}

// TestMaskPlanPriorityMerge GLOBAL < APPLICATION < ENDPOINT 同键覆盖；不同键合并保留。
func TestMaskPlanPriorityMerge(t *testing.T) {
	appID := uuid.New()
	epKey := "GET /orders/{id}"

	rules := []MaskingRule{
		mkRule(ScopeGlobal, "json.phone", "", "MASK", ""),                          // 全局 MASK
		withApp(mkRule(ScopeApplication, "json.phone", "", "HASH", ""), appID),     // 应用级覆盖
		withEndpoint(mkRule(ScopeEndpoint, "json.phone", "", "REMOVE", ""), epKey), // 端点级再覆盖
		mkRule(ScopeGlobal, "json.email", "", "MASK", ""),                          // 不同键保留
		withEndpoint(mkRule(ScopeEndpoint, "", "id_card", "HASH", ""), epKey),      // data_type 键
	}
	plan := MaskPlanForEndpoint(epKey, &appID, rules, nil)
	if len(plan) != 3 {
		t.Fatalf("plan=%+v", plan)
	}
	byKey := map[string]MaskPlanEntry{}
	for _, e := range plan {
		key := e.FieldPath
		if key == "" {
			key = "dt:" + e.DataType
		}
		byKey[key] = e
	}
	if e := byKey["json.phone"]; e.Algorithm != "REMOVE" || e.Scope != ScopeEndpoint {
		t.Fatalf("phone entry=%+v", e)
	}
	if e := byKey["json.email"]; e.Algorithm != "MASK" || e.Scope != ScopeGlobal {
		t.Fatalf("email entry=%+v", e)
	}
	if e := byKey["dt:id_card"]; e.Algorithm != "HASH" || e.Scope != ScopeEndpoint {
		t.Fatalf("id_card entry=%+v", e)
	}

	// 无端点级规则时应用级生效
	plan = MaskPlanForEndpoint(epKey, &appID, rules[:2], nil)
	if len(plan) != 1 || plan[0].Algorithm != "HASH" || plan[0].Scope != ScopeApplication {
		t.Fatalf("app-level plan=%+v", plan)
	}
}

// TestMaskPlanScopeMatch 作用域不匹配的规则不生效；disabled 不生效。
func TestMaskPlanScopeMatch(t *testing.T) {
	appID := uuid.New()
	otherApp := uuid.New()
	epKey := "GET /a"

	rules := []MaskingRule{
		withApp(mkRule(ScopeApplication, "json.phone", "", "MASK", ""), otherApp),   // 应用不匹配
		withEndpoint(mkRule(ScopeEndpoint, "json.phone", "", "MASK", ""), "GET /b"), // 端点不匹配
		mkRule(ScopeGlobal, "json.token", "", "MASK", ""),
	}
	// 禁用规则
	disabled := mkRule(ScopeGlobal, "json.secret", "", "MASK", "")
	disabled.Enabled = false
	rules = append(rules, disabled)

	plan := MaskPlanForEndpoint(epKey, &appID, rules, nil)
	if len(plan) != 1 || plan[0].FieldPath != "json.token" {
		t.Fatalf("plan=%+v", plan)
	}
	// applicationID 为 nil 时 APPLICATION 规则不生效
	plan = MaskPlanForEndpoint(epKey, nil, []MaskingRule{
		withApp(mkRule(ScopeApplication, "json.phone", "", "MASK", ""), appID),
	}, nil)
	if len(plan) != 0 {
		t.Fatalf("nil app plan=%+v", plan)
	}
}

// TestMaskPlanExclusions 排除生效：identity/role 精确、ip 精确/CIDR；nil 请求上下文不排除。
func TestMaskPlanExclusions(t *testing.T) {
	epKey := "GET /a"
	rules := []MaskingRule{
		mkRule(ScopeGlobal, "json.phone", "", "MASK", `{"identity":["fp-1"]}`),
		mkRule(ScopeGlobal, "json.email", "", "MASK", `{"role":["AUDIT_ADMIN"]}`),
		mkRule(ScopeGlobal, "json.id_card", "", "MASK", `{"ip":["10.0.0.0/8","1.2.3.4"]}`),
		mkRule(ScopeGlobal, "json.bank_card", "", "HASH", `{"identity":["fp-other"]}`),
	}

	// nil 请求上下文：不排除（发布/预览场景）
	plan := MaskPlanForEndpoint(epKey, nil, rules, nil)
	if len(plan) != 4 {
		t.Fatalf("nil-req plan=%d", len(plan))
	}

	// identity 命中排除
	plan = MaskPlanForEndpoint(epKey, nil, rules, &MaskRequest{Identity: "fp-1"})
	assertAbsent(t, plan, "json.phone")
	assertPresent(t, plan, "json.bank_card") // 非命中 identity 保留

	// role 命中排除
	plan = MaskPlanForEndpoint(epKey, nil, rules, &MaskRequest{Role: "AUDIT_ADMIN"})
	assertAbsent(t, plan, "json.email")

	// CIDR 包含命中排除
	plan = MaskPlanForEndpoint(epKey, nil, rules, &MaskRequest{ClientIP: "10.9.8.7"})
	assertAbsent(t, plan, "json.id_card")
	// 精确 IP 命中
	plan = MaskPlanForEndpoint(epKey, nil, rules, &MaskRequest{ClientIP: "1.2.3.4"})
	assertAbsent(t, plan, "json.id_card")
	// 网段外不排除
	plan = MaskPlanForEndpoint(epKey, nil, rules, &MaskRequest{ClientIP: "11.0.0.1"})
	assertPresent(t, plan, "json.id_card")

	// 排除对象随计划下发（供网关按请求求值）
	for _, e := range plan {
		if e.FieldPath == "json.id_card" && (e.Exclusions == nil || len(e.Exclusions.IP) != 2) {
			t.Fatalf("entry exclusions=%+v", e)
		}
	}
}

// TestMaskPlanInvalidExclusionsFailClosed 损坏的 exclusions 按无排除处理（fail 向脱敏侧）。
func TestMaskPlanInvalidExclusionsFailClosed(t *testing.T) {
	epKey := "GET /a"
	rules := []MaskingRule{
		mkRule(ScopeGlobal, "json.phone", "", "MASK", `{"identity": "not-an-array"}`),
	}
	plan := MaskPlanForEndpoint(epKey, nil, rules, &MaskRequest{Identity: "fp-1"})
	if len(plan) != 1 {
		t.Fatalf("fail-closed plan=%+v", plan)
	}
}

func assertPresent(t *testing.T, plan []MaskPlanEntry, fieldPath string) {
	t.Helper()
	for _, e := range plan {
		if e.FieldPath == fieldPath {
			return
		}
	}
	t.Fatalf("expect %s present, plan=%+v", fieldPath, plan)
}

func assertAbsent(t *testing.T, plan []MaskPlanEntry, fieldPath string) {
	t.Helper()
	for _, e := range plan {
		if e.FieldPath == fieldPath {
			t.Fatalf("expect %s absent, plan=%+v", fieldPath, plan)
		}
	}
}
