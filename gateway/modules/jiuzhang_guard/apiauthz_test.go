package jiuzhang_guard

import (
	"encoding/json"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

// TestGuardConfigAPIAuthzRulesJSON api_role_baselines / api_field_permissions 发布字段反序列化
// （json tag 为跨分片契约）；旧版配置无此键时为 nil（Caddy 反序列化忽略未知键，前向/后向兼容）。
func TestGuardConfigAPIAuthzRulesJSON(t *testing.T) {
	raw := `{
		"app_id": "app-1",
		"events_log": "/var/log/caddy/guard-events.log",
		"api_dynamic_protection": true,
		"api_protection_mode": "OBSERVE",
		"api_role_baselines": [
			{"endpoint_key": "GET /v1/orders", "role": "ops", "method": "GET", "action": "READ", "allowed": true}
		],
		"api_field_permissions": [
			{"endpoint_key": "POST /v1/orders", "field_path": "json.role", "direction": "REQUEST",
			 "attribute": "FORBIDDEN", "role": "", "tenant": ""}
		],
		"future_unknown_key": {"anything": true}
	}`
	var g Guard
	if err := json.Unmarshal([]byte(raw), &g); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(g.APIRoleBaselines) != 1 {
		t.Fatalf("role baselines = %+v", g.APIRoleBaselines)
	}
	b := g.APIRoleBaselines[0]
	if b.EndpointKey != "GET /v1/orders" || b.Role != "ops" || b.Method != "GET" || b.Action != "READ" || !b.Allowed {
		t.Fatalf("bad baseline: %+v", b)
	}
	if len(g.APIFieldPermissions) != 1 {
		t.Fatalf("field permissions = %+v", g.APIFieldPermissions)
	}
	pm := g.APIFieldPermissions[0]
	if pm.EndpointKey != "POST /v1/orders" || pm.FieldPath != "json.role" ||
		pm.Direction != "REQUEST" || pm.Attribute != "FORBIDDEN" || pm.Role != "" || pm.Tenant != "" {
		t.Fatalf("bad permission: %+v", pm)
	}

	// 旧配置（无该键）：nil，零行为变化
	var legacy Guard
	if err := json.Unmarshal([]byte(`{"app_id":"a","events_log":"/tmp/e.log"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.APIRoleBaselines != nil || legacy.APIFieldPermissions != nil {
		t.Fatal("legacy config must leave authz rules nil")
	}
}

// TestGuardValidateAuthzRules 授权基线配置校验：合法通过；非法 direction/attribute/缺字段拒绝
// （未启用防护时不校验，零行为变化）。
func TestGuardValidateAuthzRules(t *testing.T) {
	base := func() *Guard { return &Guard{EventsLog: "x", APIDynamicProtection: true} }

	// 合法通过
	g := base()
	g.APIRoleBaselines = []detectors.RoleBaseline{
		{EndpointKey: "GET /v1/orders", Role: "ops", Method: "GET", Action: "READ", Allowed: true},
	}
	g.APIFieldPermissions = []detectors.FieldPermission{
		{EndpointKey: "POST /v1/orders", FieldPath: "json.role", Direction: "REQUEST", Attribute: "FORBIDDEN"},
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("valid authz rules must pass: %v", err)
	}

	// 非法 attribute 拒绝
	g = base()
	g.APIFieldPermissions = []detectors.FieldPermission{
		{EndpointKey: "POST /v1/orders", FieldPath: "json.role", Direction: "REQUEST", Attribute: "HIDDEN"},
	}
	if err := g.Validate(); err == nil {
		t.Fatal("bad attribute must be rejected")
	}

	// 非法 direction 拒绝
	g = base()
	g.APIFieldPermissions = []detectors.FieldPermission{
		{EndpointKey: "POST /v1/orders", FieldPath: "json.role", Direction: "UPLOAD", Attribute: "FORBIDDEN"},
	}
	if err := g.Validate(); err == nil {
		t.Fatal("bad direction must be rejected")
	}

	// 基线缺 role 拒绝
	g = base()
	g.APIRoleBaselines = []detectors.RoleBaseline{{EndpointKey: "GET /v1/orders", Method: "GET"}}
	if err := g.Validate(); err == nil {
		t.Fatal("baseline without role must be rejected")
	}

	// 未启用 API 动态防护：不校验（与值级敏感规则同一纪律）
	g = &Guard{EventsLog: "x"}
	g.APIFieldPermissions = []detectors.FieldPermission{
		{EndpointKey: "POST /v1/orders", FieldPath: "json.role", Direction: "UPLOAD", Attribute: "HIDDEN"},
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("disabled protection must skip authz validation: %v", err)
	}
}
