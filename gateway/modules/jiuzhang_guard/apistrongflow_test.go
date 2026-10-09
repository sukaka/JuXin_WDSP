// apistrongflow_test.go api_strong_flows 发布段（NG-FLOW-01）反序列化、装配校验
// （fail-closed）与段缺失零行为（NG-T-C01）。
package jiuzhang_guard

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors/flowguard"
)

// strongFlowSectionJSON 合法 api_strong_flows 段（同 id 两版本并存）。
const strongFlowSectionJSON = `[
	{
		"id": "9f1c2f70-6f3a-4b9a-9a2d-2d0c3f0a9e01",
		"application_id": "app-1",
		"name": "checkout",
		"version": 1,
		"status": "ACTIVE",
		"binding_path_prefix": "/v1/orders",
		"instance_key_param": "query:order_id",
		"mode": "OBSERVE",
		"created_by": "admin",
		"created_at": "2026-10-01T08:00:00Z",
		"activated_at": "2026-10-02T08:00:00Z",
		"steps": [
			{"id": "s-1", "step_key": "create", "endpoint_key": "POST /v1/orders", "sequence": 1,
			 "success_rule": {"status_codes": [200, 201]}, "timeout_seconds": 60,
			 "retry_semantics": "IDEMPOTENT", "lease_seconds": 30},
			{"id": "s-2", "step_key": "pay", "endpoint_key": "POST /v1/orders/{id}/pay", "sequence": 2,
			 "success_rule": {"body_jsonpath_equals": {"path": "$.status", "value": "PAID"}, "graphql_errors_empty": true},
			 "timeout_seconds": 600, "retry_semantics": "NOT_RETRYABLE", "lease_seconds": 300, "allows_202": true}
		]
	},
	{
		"id": "9f1c2f70-6f3a-4b9a-9a2d-2d0c3f0a9e01",
		"application_id": "app-1",
		"name": "checkout",
		"version": 2,
		"status": "ACTIVE",
		"binding_path_prefix": "/v1/orders",
		"instance_key_param": "path:3",
		"mode": "PROTECT",
		"steps": [
			{"step_key": "create", "endpoint_key": "POST /v1/orders", "sequence": 1,
			 "success_rule": {"status_codes": [200]}, "timeout_seconds": 15,
			 "retry_semantics": "IDEMPOTENT", "lease_seconds": 15},
			{"step_key": "reserve", "endpoint_key": "POST /v1/orders/{id}/reserve", "sequence": 2,
			 "success_rule": {"status_codes": [200]}, "timeout_seconds": 15,
			 "retry_semantics": "REQUIRES_REVIEW", "parallel_group": "g", "lease_seconds": 15},
			{"step_key": "pay", "endpoint_key": "POST /v1/orders/{id}/pay", "sequence": 3,
			 "success_rule": {"status_codes": [200]}, "timeout_seconds": 15,
			 "retry_semantics": "NOT_RETRYABLE", "parallel_group": "g", "lease_seconds": 15}
		]
	}
]`

// TestGuardConfigAPIStrongFlowsJSON 发布字段反序列化（逐字段线契约）；旧版配置
// 无此键时为 nil（Caddy 反序列化忽略未知键，前向/后向兼容）。
func TestGuardConfigAPIStrongFlowsJSON(t *testing.T) {
	raw := `{
		"app_id": "app-1",
		"events_log": "/var/log/caddy/guard-events.log",
		"api_dynamic_protection": true,
		"api_protection_mode": "OBSERVE",
		"api_strong_flows": ` + strongFlowSectionJSON + `,
		"future_unknown_key": {"anything": true}
	}`
	var g Guard
	if err := json.Unmarshal([]byte(raw), &g); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(g.APIStrongFlows) != 2 {
		t.Fatalf("strong flows = %+v", g.APIStrongFlows)
	}
	d1 := g.APIStrongFlows[0]
	if d1.ID != "9f1c2f70-6f3a-4b9a-9a2d-2d0c3f0a9e01" || d1.Version != 1 || d1.Mode != "OBSERVE" ||
		d1.BindingPathPrefix != "/v1/orders" || d1.InstanceKeyParam != "query:order_id" ||
		d1.CreatedBy != "admin" || d1.CreatedAt == nil || d1.ActivatedAt == nil {
		t.Fatalf("definition v1 = %+v", d1)
	}
	pay := d1.Steps[1]
	if pay.StepKey != "pay" || pay.Sequence != 2 || pay.TimeoutSeconds != 600 ||
		pay.LeaseSeconds != 300 || pay.RetrySemantics != "NOT_RETRYABLE" || !pay.Allows202 {
		t.Fatalf("pay step = %+v", pay)
	}
	rule, err := flowguard.ParseSuccessRule(pay.SuccessRule)
	if err != nil || rule == nil || rule.BodyJSONPathEquals == nil ||
		rule.BodyJSONPathEquals.Path != "$.status" || !rule.GraphQLErrorsEmpty {
		t.Fatalf("pay success_rule = %+v err=%v", rule, err)
	}

	// 装配（与 Provision/Validate 同一路径）：同 id 多版本并存，稳定序
	reg, err := flowguard.BuildRegistry(g.APIStrongFlows)
	if err != nil {
		t.Fatalf("build registry: %v", err)
	}
	if reg.Len() != 2 {
		t.Fatalf("registry len = %d, want 2（同 id 多版本并存）", reg.Len())
	}
	if _, ok := reg.Get(d1.ID, 1); !ok {
		t.Fatal("registry 应含 version 1")
	}
	if _, ok := reg.Get(d1.ID, 2); !ok {
		t.Fatal("registry 应含 version 2")
	}

	// 旧配置（无该键）：nil，零行为变化
	var legacy Guard
	if err := json.Unmarshal([]byte(`{"app_id":"a","events_log":"/tmp/e.log"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.APIStrongFlows != nil {
		t.Fatal("legacy config must leave strong flows nil")
	}
	// 空数组同样零行为（NG-T-C01）
	if r, err := flowguard.BuildRegistry([]flowguard.Definition{}); r != nil || err != nil {
		t.Fatalf("空数组应 (nil,nil)，得 (%v,%v)", r, err)
	}
}

// TestGuardConfigAPIStrongFlowsRejectInvalid 非法定义装配期拒绝（Validate 与
// Provision 共用 flowguard.BuildRegistry；不静默吞错——错误须指明下标与原因）。
func TestGuardConfigAPIStrongFlowsRejectInvalid(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"step_key 重复", `{"id":"d","application_id":"a","name":"f","version":1,"binding_path_prefix":"/x","instance_key_param":"query:o","steps":[
			{"step_key":"a","endpoint_key":"GET /x","sequence":1,"success_rule":{"status_codes":[200]},"timeout_seconds":15,"retry_semantics":"IDEMPOTENT","lease_seconds":15},
			{"step_key":"a","endpoint_key":"GET /y","sequence":2,"success_rule":{"status_codes":[200]},"timeout_seconds":15,"retry_semantics":"IDEMPOTENT","lease_seconds":15}]}`, "step_key"},
		{"timeout 越界", `{"id":"d","application_id":"a","name":"f","version":1,"binding_path_prefix":"/x","instance_key_param":"query:o","steps":[
			{"step_key":"a","endpoint_key":"GET /x","sequence":1,"success_rule":{"status_codes":[200]},"timeout_seconds":601,"retry_semantics":"IDEMPOTENT","lease_seconds":15}]}`, "timeout_seconds 词表外"},
		{"判定式未知键", `{"id":"d","application_id":"a","name":"f","version":1,"binding_path_prefix":"/x","instance_key_param":"query:o","steps":[
			{"step_key":"a","endpoint_key":"GET /x","sequence":1,"success_rule":{"status_codes":[200],"jsonpath_contains":{}},"timeout_seconds":15,"retry_semantics":"IDEMPOTENT","lease_seconds":15}]}`, "反序列化失败"},
		{"status DRAFT 拒收", `{"id":"d","application_id":"a","name":"f","version":1,"status":"DRAFT","binding_path_prefix":"/x","instance_key_param":"query:o","steps":[
			{"step_key":"a","endpoint_key":"GET /x","sequence":1,"success_rule":{"status_codes":[200]},"timeout_seconds":15,"retry_semantics":"IDEMPOTENT","lease_seconds":15}]}`, "status 非法"},
	}
	for _, tc := range cases {
		var g Guard
		if err := json.Unmarshal([]byte(`{"app_id":"a","events_log":"/tmp/e.log","api_dynamic_protection":true,"api_strong_flows":[`+tc.raw+`]}`), &g); err != nil {
			t.Fatalf("%s: unmarshal: %v", tc.name, err)
		}
		err := g.Validate()
		if err == nil {
			t.Errorf("%s: Validate 应拒绝", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: 错误 %q 未含 %q", tc.name, err.Error(), tc.want)
		}
		if !strings.Contains(err.Error(), "strong flow definition[0]") {
			t.Errorf("%s: 错误 %q 未含定义下标", tc.name, err.Error())
		}
	}
}

// TestGuardValidateAPIStrongFlowsAbsentOK 段缺失时 Validate 零行为通过。
func TestGuardValidateAPIStrongFlowsAbsentOK(t *testing.T) {
	g := &Guard{EventsLog: "x", APIDynamicProtection: true}
	if err := g.Validate(); err != nil {
		t.Fatalf("段缺失应零行为通过: %v", err)
	}
}

// TestGuardProvisionAPIStrongFlows 真实 Provision 路径：合法段装配成功且
// 非法段拒绝整体配置加载（fail-closed）；段缺失零行为（无 registry）。
func TestGuardProvisionAPIStrongFlows(t *testing.T) {
	newGuard := func(t *testing.T, section string) *Guard {
		t.Helper()
		g := &Guard{
			AppID: "app-1", AppCode: "shop",
			EventsLog:            filepath.Join(t.TempDir(), "events.log"),
			APIDynamicProtection: true,
			APIProtectionMode:    "OBSERVE",
		}
		if section != "" {
			var defs []flowguard.Definition
			if err := json.Unmarshal([]byte(section), &defs); err != nil {
				t.Fatalf("unmarshal section: %v", err)
			}
			g.APIStrongFlows = defs
		}
		return g
	}

	// 段缺失：零行为（装配产物 nil）
	resetSharedEngineForTest()
	t.Cleanup(resetSharedEngineForTest)
	g := newGuard(t, "")
	if err := g.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("段缺失 Provision 应通过: %v", err)
	}
	if g.apiStrongFlows != nil {
		t.Fatalf("段缺失装配产物应为 nil，得 %+v", g.apiStrongFlows)
	}
	t.Cleanup(func() { _ = g.Cleanup() })

	// 合法段：装配成功，同 id 多版本并存
	resetSharedEngineForTest()
	g = newGuard(t, strongFlowSectionJSON)
	if err := g.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("合法段 Provision 应通过: %v", err)
	}
	if g.apiStrongFlows == nil || g.apiStrongFlows.Len() != 2 {
		t.Fatalf("装配产物 = %+v", g.apiStrongFlows)
	}
	t.Cleanup(func() { _ = g.Cleanup() })

	// 非法段：fail-closed 拒绝整体配置加载
	resetSharedEngineForTest()
	g = newGuard(t, `[{"id":"d","application_id":"a","name":"f","version":1,"binding_path_prefix":"/x","instance_key_param":"query:o","steps":[
		{"step_key":"a","endpoint_key":"GET /x","sequence":1,"success_rule":{"status_codes":[200]},"timeout_seconds":15,"retry_semantics":"IDEMPOTENT","lease_seconds":301}]}]`)
	if err := g.Provision(caddy.Context{Context: context.Background()}); err == nil {
		t.Fatal("非法段 Provision 应拒绝加载")
	} else if !strings.Contains(err.Error(), "strong flow definition") {
		t.Errorf("错误须指名强流程定义段: %v", err)
	}
}
