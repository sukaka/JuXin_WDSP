package jiuzhang_guard

import (
	"encoding/json"
	"testing"
)

// api_parameter_constraints 发布字段反序列化（端点键 → 参数约束列表）；
// 旧版配置无此键时为 nil（Caddy 反序列化忽略未知键，前向/后向兼容）。
func TestGuardConfigAPIParameterConstraintsJSON(t *testing.T) {
	raw := `{
		"app_id": "app-1",
		"events_log": "/var/log/caddy/guard-events.log",
		"api_dynamic_protection": true,
		"api_protection_mode": "OBSERVE",
		"api_parameter_constraints": {
			"GET /v1/orders": [
				{"location": "QUERY", "name": "page", "path": "page", "base_type": "number",
				 "required": true, "constraints": {"minimum": 1, "maximum": 1000}},
				{"location": "QUERY", "name": "status", "path": "status", "base_type": "string",
				 "required": false, "constraints": {"enum": ["PAID", "CLOSED"], "max_length": 16}},
				{"location": "BODY", "name": "name", "path": "buyer.name", "base_type": "string",
				 "required": false, "constraints": {"max_length": 64}}
			]
		},
		"future_unknown_key": {"anything": true}
	}`
	var g Guard
	if err := json.Unmarshal([]byte(raw), &g); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	list := g.APIParameterConstraints["GET /v1/orders"]
	if len(list) != 3 {
		t.Fatalf("constraints len = %d, want 3 (%+v)", len(list), g.APIParameterConstraints)
	}
	if !list[0].Required || list[0].Constraints["minimum"] != float64(1) {
		t.Errorf("first constraint = %+v", list[0])
	}
	if list[1].Constraints["max_length"] != float64(16) {
		t.Errorf("enum constraint = %+v", list[1].Constraints)
	}
	if list[2].Location != "BODY" || list[2].Path != "buyer.name" {
		t.Errorf("body constraint = %+v", list[2])
	}

	// 旧配置（无该键）：nil，零行为变化
	var legacy Guard
	if err := json.Unmarshal([]byte(`{"app_id":"a","events_log":"/tmp/e.log"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.APIParameterConstraints != nil {
		t.Fatal("legacy config must leave constraints nil")
	}
}
