// apiflow_test.go api_flow_baselines 发布字段反序列化、装配校验与按端点归组（§44）。
package jiuzhang_guard

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

// api_flow_baselines 发布字段反序列化（流程粒度：flow_id + steps 内嵌）；
// 旧版配置无此键时为 nil（Caddy 反序列化忽略未知键，前向/后向兼容）。
func TestGuardConfigAPIFlowBaselinesJSON(t *testing.T) {
	raw := `{
		"app_id": "app-1",
		"events_log": "/var/log/caddy/guard-events.log",
		"api_dynamic_protection": true,
		"api_protection_mode": "OBSERVE",
		"api_flow_baselines": [
			{"flow_id": "checkout", "steps": [
				{"step_id": "browse", "endpoint_key": "GET /v1/items", "sequence": 1, "predecessors": []},
				{"step_id": "pay", "endpoint_key": "POST /v1/orders/{id}/pay", "sequence": 2,
				 "predecessors": ["browse"], "terminal": true, "state_from": "CREATED", "state_to": "PAID"}
			]}
		],
		"future_unknown_key": {"anything": true}
	}`
	var g Guard
	if err := json.Unmarshal([]byte(raw), &g); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(g.APIFlowBaselines) != 1 || g.APIFlowBaselines[0].FlowID != "checkout" ||
		len(g.APIFlowBaselines[0].Steps) != 2 {
		t.Fatalf("flow baselines = %+v", g.APIFlowBaselines)
	}
	pay := g.APIFlowBaselines[0].Steps[1]
	if pay.EndpointKey != "POST /v1/orders/{id}/pay" || pay.Sequence != 2 ||
		len(pay.Predecessors) != 1 || !pay.Terminal || pay.StateFrom != "CREATED" || pay.StateTo != "PAID" {
		t.Fatalf("pay step = %+v", pay)
	}

	// 配置校验 + 按端点归组（与 Provision 同一路径）：跨端点步骤各挂一份流程引用
	if err := detectors.ValidateFlowBaselines(g.APIFlowBaselines); err != nil {
		t.Fatalf("validate: %v", err)
	}
	grouped := detectors.GroupFlowBaselines(g.APIFlowBaselines)
	if len(grouped) != 2 || len(grouped["GET /v1/items"]) != 1 || len(grouped["POST /v1/orders/{id}/pay"]) != 1 {
		t.Fatalf("grouped = %+v", grouped)
	}
	if grouped["POST /v1/orders/{id}/pay"][0].FlowID != "checkout" {
		t.Fatalf("grouped flow = %+v", grouped["POST /v1/orders/{id}/pay"][0])
	}

	// 旧配置（无该键）：nil，零行为变化
	var legacy Guard
	if err := json.Unmarshal([]byte(`{"app_id":"a","events_log":"/tmp/e.log"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.APIFlowBaselines != nil {
		t.Fatal("legacy config must leave flow baselines nil")
	}
}

// 非法基线装配期拒绝（Validate 与 Provision 共用 detectors.ValidateFlowBaselines；
// 不静默吞错——错误须指明基线下标与原因）。
func TestGuardConfigAPIFlowBaselinesRejectInvalid(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"空 flow_id", `{"flow_id":"","steps":[{"step_id":"a","endpoint_key":"GET /x","sequence":1}]}`, "flow_id 为空"},
		{"前置未声明", `{"flow_id":"f","steps":[{"step_id":"a","endpoint_key":"GET /x","sequence":1,"predecessors":["ghost"]}]}`, "前置步骤未声明"},
		{"前置自引用", `{"flow_id":"f","steps":[{"step_id":"a","endpoint_key":"GET /x","sequence":1,"predecessors":["a"]}]}`, "自引用"},
		{"step_id 重复", `{"flow_id":"f","steps":[{"step_id":"a","endpoint_key":"GET /x","sequence":1},{"step_id":"a","endpoint_key":"GET /y","sequence":2}]}`, "step_id 重复"},
		{"步骤缺端点", `{"flow_id":"f","steps":[{"step_id":"a","sequence":1}]}`, "endpoint_key 为空"},
	}
	for _, tc := range cases {
		var g Guard
		if err := json.Unmarshal([]byte(`{"app_id":"a","events_log":"/tmp/e.log","api_dynamic_protection":true,"api_flow_baselines":[`+tc.raw+`]}`), &g); err != nil {
			t.Fatalf("%s: unmarshal: %v", tc.name, err)
		}
		err := detectors.ValidateFlowBaselines(g.APIFlowBaselines)
		if err == nil {
			t.Errorf("%s: 应拒绝", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: 错误 %q 未含 %q", tc.name, err.Error(), tc.want)
		}
	}
}
