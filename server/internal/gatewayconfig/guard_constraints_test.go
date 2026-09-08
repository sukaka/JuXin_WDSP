package gatewayconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

// api_parameter_constraints 仅 WDSP 开启且有约束时注入；关闭/为空时 JSON 不出现该键
// （Caddy 反序列化忽略未知键，但保持下发面最小、与 api_formal_schemas 同一纪律）。
func TestBuildGuardHandlerAPIParameterConstraints(t *testing.T) {
	newCfg := func() *GuardConfig {
		g := testGuardConfig()
		g.APIDynamicProtection = true
		g.APIProtectionMode = "OBSERVE"
		g.APIParameterConstraints = map[string][]GuardParamConstraint{
			"GET /v1/orders": {
				{
					Location: "QUERY", Name: "page", Path: "page", BaseType: "number",
					Required:    true,
					Constraints: map[string]any{"minimum": float64(1), "maximum": float64(1000)},
				},
				{
					Location: "QUERY", Name: "status", Path: "status", BaseType: "string",
					Constraints: map[string]any{"enum": []any{"PAID", "CLOSED"}, "max_length": float64(16)},
				},
			},
		}
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
	for _, want := range []string{`"api_parameter_constraints"`, `"GET /v1/orders"`, `"minimum"`, `"maximum"`, `"enum"`, `"max_length"`, `"required":true`} {
		if !strings.Contains(j, want) {
			t.Errorf("handler json missing %s: %s", want, j)
		}
	}

	// 有约束但 WDSP 关闭：不注入
	off := newCfg()
	off.APIDynamicProtection = false
	raw, _ = json.Marshal(buildGuardHandler(off, app, 0))
	if strings.Contains(string(raw), "api_parameter_constraints") {
		t.Error("constraints must not be injected when api dynamic protection disabled")
	}

	// 开启但无约束：不注入
	empty := newCfg()
	empty.APIParameterConstraints = nil
	raw, _ = json.Marshal(buildGuardHandler(empty, app, 0))
	if strings.Contains(string(raw), "api_parameter_constraints") {
		t.Error("constraints key must be omitted when empty")
	}
}
