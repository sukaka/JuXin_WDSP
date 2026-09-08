// api_parameter_relations 仅 WDSP 开启且有已确认关系时注入；关闭/为空时 JSON 不出现该键
// （与 api_parameter_constraints 同一纪律；只有 confirmed 关系进入强制检测）。
package gatewayconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildGuardHandlerAPIParameterRelations(t *testing.T) {
	newCfg := func() *GuardConfig {
		g := testGuardConfig()
		g.APIDynamicProtection = true
		g.APIProtectionMode = "OBSERVE"
		g.APIParameterRelations = []GuardParamRelation{
			{
				EndpointKey:  "GET /v1/orders",
				RelationType: "REQUIRES",
				ParamA:       GuardParamRef{Location: "QUERY", Path: "page", Name: "page"},
				ParamB:       GuardParamRef{Location: "QUERY", Path: "page_size", Name: "page_size"},
			},
			{
				EndpointKey:  "POST /v1/orders",
				RelationType: "MUTEX",
				ParamA:       GuardParamRef{Location: "BODY", Path: "buyer.phone", Name: "phone"},
				ParamB:       GuardParamRef{Location: "BODY", Path: "buyer.email", Name: "email"},
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
	for _, want := range []string{`"api_parameter_relations"`, `"relation_type":"REQUIRES"`, `"relation_type":"MUTEX"`,
		`"param_a"`, `"param_b"`, `"location":"BODY"`, `"path":"buyer.phone"`} {
		if !strings.Contains(j, want) {
			t.Errorf("handler json missing %s: %s", want, j)
		}
	}

	// 有关系但 WDSP 关闭：不注入
	off := newCfg()
	off.APIDynamicProtection = false
	raw, _ = json.Marshal(buildGuardHandler(off, app, 0))
	if strings.Contains(string(raw), "api_parameter_relations") {
		t.Error("relations must not be injected when api dynamic protection disabled")
	}

	// 开启但无已确认关系：不注入
	empty := newCfg()
	empty.APIParameterRelations = nil
	raw, _ = json.Marshal(buildGuardHandler(empty, app, 0))
	if strings.Contains(string(raw), "api_parameter_relations") {
		t.Error("relations key must be omitted when empty")
	}
}
