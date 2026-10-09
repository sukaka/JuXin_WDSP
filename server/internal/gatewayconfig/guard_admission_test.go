// api_admission 段仅 WDSP 开启时按应用注入（冻结契约 api_admission.policies.<application_id>）；
// 本应用无策略（OFF）/WDSP 关闭/被 stripAPIGuardSections 剥除时 JSON 不出现该键
// （与 jwt_trust/api_exceptions 同一纪律）。
package gatewayconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildGuardHandlerAPIAdmission(t *testing.T) {
	const (
		appObserve = "11111111-1111-1111-1111-111111111111"
		appProtect = "22222222-2222-2222-2222-222222222222"
	)
	newCfg := func() *GuardConfig {
		g := testGuardConfig()
		g.APIDynamicProtection = true
		g.APIProtectionMode = "OBSERVE"
		g.APIAdmission = map[string]*GuardAPIAdmissionPolicy{
			appObserve: {Mode: "OBSERVE", ConfirmedEndpoints: []string{}},
			appProtect: {Mode: "PROTECT", ConfirmedEndpoints: []string{"GET /v1/orders/{id}", "POST /v1/login"}},
		}
		return g
	}

	// OBSERVE 应用：无确认端点也出现（空数组语义=无确认端点，契约键名原样下发）
	h := buildGuardHandler(newCfg(), AppData{AppID: appObserve, Code: "obs"}, 0)
	raw, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	j := string(raw)
	for _, want := range []string{`"api_admission"`, `"policies"`, `"` + appObserve + `"`,
		`"mode":"OBSERVE"`, `"confirmed_endpoints":[]`} {
		if !strings.Contains(j, want) {
			t.Errorf("handler json missing %s: %s", want, j)
		}
	}
	if strings.Contains(j, appProtect) {
		t.Errorf("他应用策略不应注入本应用 handler: %s", j)
	}

	// PROTECT 应用：确认集透传
	raw, _ = json.Marshal(buildGuardHandler(newCfg(), AppData{AppID: appProtect, Code: "pro"}, 0))
	j = string(raw)
	for _, want := range []string{`"mode":"PROTECT"`, `"GET /v1/orders/{id}"`, `"POST /v1/login"`} {
		if !strings.Contains(j, want) {
			t.Errorf("handler json missing %s: %s", want, j)
		}
	}

	// mode=OFF 应用（policies 中无条目）：不出现该键，网关准入判定零行为变化
	raw, _ = json.Marshal(buildGuardHandler(newCfg(), AppData{AppID: "33333333-3333-3333-3333-333333333333", Code: "off"}, 0))
	if strings.Contains(string(raw), "api_admission") {
		t.Error("OFF 应用不应出现 api_admission 键")
	}

	// 有策略但 WDSP 关闭：不注入（与纯 WAF 逐字节一致）
	off := newCfg()
	off.APIDynamicProtection = false
	raw, _ = json.Marshal(buildGuardHandler(off, AppData{AppID: appProtect, Code: "pro"}, 0))
	if strings.Contains(string(raw), "api_admission") {
		t.Error("api_admission must not be injected when api dynamic protection disabled")
	}

	// 回滚门控：stripAPIGuardSections 剥除该段（快照为 WDSP 开启期产物）
	stripped := stripAPIGuardSections(newCfg())
	if stripped.APIAdmission != nil {
		t.Error("stripAPIGuardSections must drop api_admission")
	}
	raw, _ = json.Marshal(buildGuardHandler(stripped, AppData{AppID: appProtect, Code: "pro"}, 0))
	if strings.Contains(string(raw), "api_admission") {
		t.Error("stripped config must not emit api_admission")
	}
}
