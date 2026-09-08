// apirelations_test.go api_parameter_relations 发布字段反序列化与按端点归组（W11-REL）。
package jiuzhang_guard

import (
	"encoding/json"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

// api_parameter_relations 发布字段反序列化（平铺列表，装配期按 endpoint_key 归组）；
// 旧版配置无此键时为 nil（Caddy 反序列化忽略未知键，前向/后向兼容）。
func TestGuardConfigAPIParameterRelationsJSON(t *testing.T) {
	raw := `{
		"app_id": "app-1",
		"events_log": "/var/log/caddy/guard-events.log",
		"api_dynamic_protection": true,
		"api_protection_mode": "PROTECT",
		"api_parameter_relations": [
			{"endpoint_key": "GET /v1/orders", "relation_type": "REQUIRES",
			 "param_a": {"location": "QUERY", "path": "page", "name": "page"},
			 "param_b": {"location": "QUERY", "path": "page_size", "name": "page_size"}},
			{"endpoint_key": "POST /v1/orders", "relation_type": "MUTEX",
			 "param_a": {"location": "BODY", "path": "buyer.phone", "name": "phone"},
			 "param_b": {"location": "BODY", "path": "buyer.email", "name": "email"}},
			{"endpoint_key": "GET /v1/orders", "relation_type": "CO_OCCURS",
			 "param_a": {"location": "QUERY", "path": "from", "name": "from"},
			 "param_b": {"location": "QUERY", "path": "to", "name": "to"}}
		],
		"future_unknown_key": {"anything": true}
	}`
	var g Guard
	if err := json.Unmarshal([]byte(raw), &g); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(g.APIParameterRelations) != 3 {
		t.Fatalf("relations len = %d, want 3 (%+v)", len(g.APIParameterRelations), g.APIParameterRelations)
	}
	r0 := g.APIParameterRelations[0]
	if r0.EndpointKey != "GET /v1/orders" || r0.RelationType != "REQUIRES" ||
		r0.ParamA.Name != "page" || r0.ParamB.Location != "QUERY" {
		t.Errorf("first relation = %+v", r0)
	}
	// 配置校验 + 按端点归组（与 Provision 同一路径）
	if err := detectors.ValidateParamRelations(g.APIParameterRelations); err != nil {
		t.Fatalf("validate: %v", err)
	}
	grouped := detectors.GroupParamRelations(g.APIParameterRelations)
	if len(grouped["GET /v1/orders"]) != 2 || len(grouped["POST /v1/orders"]) != 1 {
		t.Fatalf("grouped = %+v", grouped)
	}

	// 旧配置（无该键）：nil，零行为变化
	var legacy Guard
	if err := json.Unmarshal([]byte(`{"app_id":"a","events_log":"/tmp/e.log"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.APIParameterRelations != nil {
		t.Fatal("legacy config must leave relations nil")
	}
}
