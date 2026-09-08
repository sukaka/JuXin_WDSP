// guard_authz_test.go 授权基线下发键（api_role_baselines / api_field_permissions）注入单测（W4-GW）：
// 仅 WDSP 开启且非空时注入；关闭或空时 JSON 不出现对应键（json tag 为跨分片契约，不得改动）。
package gatewayconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestBuildGuardHandlerAuthzRules 授权基线两段：开启且有值时按契约键注入；
// WDSP 关闭或空切片时一律不注入（与既有下发面最小纪律一致）。
func TestBuildGuardHandlerAuthzRules(t *testing.T) {
	newCfg := func() *GuardConfig {
		g := testGuardConfig()
		g.APIDynamicProtection = true
		g.APIProtectionMode = "OBSERVE"
		g.APIRoleBaselines = []GuardRoleBaseline{{
			EndpointKey: "GET /v1/orders", Role: "ops", Method: "GET", Action: "READ", Allowed: true,
		}}
		g.APIFieldPermissions = []GuardFieldPermission{{
			EndpointKey: "POST /v1/orders", FieldPath: "json.role", Direction: "REQUEST", Attribute: "FORBIDDEN",
		}}
		return g
	}
	app := AppData{AppID: "app-1", Code: "shop"}

	// 开启：两段注入且 json tag 与契约一致
	raw, err := json.Marshal(buildGuardHandler(newCfg(), app, 0))
	if err != nil {
		t.Fatal(err)
	}
	j := string(raw)
	for _, want := range []string{
		`"api_role_baselines"`, `"endpoint_key":"GET /v1/orders"`, `"role":"ops"`,
		`"method":"GET"`, `"action":"READ"`, `"allowed":true`,
		`"api_field_permissions"`, `"endpoint_key":"POST /v1/orders"`, `"field_path":"json.role"`,
		`"direction":"REQUEST"`, `"attribute":"FORBIDDEN"`, `"role":""`, `"tenant":""`,
	} {
		if !strings.Contains(j, want) {
			t.Errorf("handler json missing %s: %s", want, j)
		}
	}

	// WDSP 关闭：两段一律不注入
	off := newCfg()
	off.APIDynamicProtection = false
	raw, _ = json.Marshal(buildGuardHandler(off, app, 0))
	j = string(raw)
	for _, key := range []string{"api_role_baselines", "api_field_permissions"} {
		if strings.Contains(j, `"`+key+`"`) {
			t.Errorf("%s must not be injected when api dynamic protection disabled", key)
		}
	}

	// 开启但空：不注入（网关无下发键时行为与现状完全一致）
	empty := testGuardConfig()
	empty.APIDynamicProtection = true
	raw, _ = json.Marshal(buildGuardHandler(empty, app, 0))
	j = string(raw)
	for _, key := range []string{"api_role_baselines", "api_field_permissions"} {
		if strings.Contains(j, `"`+key+`"`) {
			t.Errorf("%s must be omitted when empty", key)
		}
	}
}
