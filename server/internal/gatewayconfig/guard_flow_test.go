// api_flow_baselines 仅 WDSP 开启且有启用流程基线时注入；关闭/为空时 JSON 不出现该键
// （与 api_parameter_relations 同一纪律）；stripAPIGuardSections 一并剥除。
package gatewayconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildGuardHandlerAPIFlowBaselines(t *testing.T) {
	newCfg := func() *GuardConfig {
		g := testGuardConfig()
		g.APIDynamicProtection = true
		g.APIProtectionMode = "OBSERVE"
		g.APIFlowBaselines = []GuardFlowBaseline{{
			FlowID: "checkout", MaxPerWindow: 5, RateWindowSeconds: 30,
			Steps: []GuardFlowStep{
				{StepID: "browse", EndpointKey: "GET /v1/items", Sequence: 1, Predecessors: []string{}},
				{StepID: "pay", EndpointKey: "POST /v1/orders/{id}/pay", Sequence: 2,
					Predecessors: []string{"browse"}, Terminal: true, StateFrom: "CREATED", StateTo: "PAID",
					MaxPerWindow: 2, RateWindowSeconds: 10, CancelsFlow: true},
			},
		}}
		return g
	}
	app := AppData{AppID: "app-1", Code: "shop"}

	// 开启：注入且词汇原样下发
	h := buildGuardHandler(newCfg(), app, 0)
	raw, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	j := string(raw)
	for _, want := range []string{`"api_flow_baselines"`, `"flow_id":"checkout"`, `"step_id":"pay"`,
		`"endpoint_key":"POST /v1/orders/{id}/pay"`, `"predecessors":["browse"]`,
		`"state_from":"CREATED"`, `"state_to":"PAID"`,
		`"max_per_window":5`, `"max_per_window":2`, `"cancels_flow":true`} {
		if !strings.Contains(j, want) {
			t.Errorf("handler json missing %s: %s", want, j)
		}
	}
	// omitempty：流程级 1 处 + pay 步骤 1 处；browse 步骤未声明不出现；取消语义仅 pay
	if n := strings.Count(j, `"max_per_window"`); n != 2 {
		t.Errorf(`max_per_window occurrences = %d, want 2 (omitempty on zero): %s`, n, j)
	}
	if n := strings.Count(j, `"rate_window_seconds"`); n != 2 {
		t.Errorf(`rate_window_seconds occurrences = %d, want 2 (omitempty on zero): %s`, n, j)
	}
	if n := strings.Count(j, `"cancels_flow"`); n != 1 {
		t.Errorf(`cancels_flow occurrences = %d, want 1 (omitempty on false): %s`, n, j)
	}

	// 有基线但 WDSP 关闭：不注入
	off := newCfg()
	off.APIDynamicProtection = false
	raw, _ = json.Marshal(buildGuardHandler(off, app, 0))
	if strings.Contains(string(raw), "api_flow_baselines") {
		t.Error("flow baselines must not be injected when api dynamic protection disabled")
	}

	// 开启但无启用基线：不注入
	empty := newCfg()
	empty.APIFlowBaselines = nil
	raw, _ = json.Marshal(buildGuardHandler(empty, app, 0))
	if strings.Contains(string(raw), "api_flow_baselines") {
		t.Error("flow baselines key must be omitted when empty")
	}

	// 回滚门控：stripAPIGuardSections 剥除该段（快照为 WDSP 开启期产物）
	stripped := stripAPIGuardSections(newCfg())
	if stripped.APIFlowBaselines != nil {
		t.Error("stripAPIGuardSections must drop api_flow_baselines")
	}
	raw, _ = json.Marshal(buildGuardHandler(stripped, app, 0))
	if strings.Contains(string(raw), "api_flow_baselines") {
		t.Error("stripped config must not emit api_flow_baselines")
	}
}
