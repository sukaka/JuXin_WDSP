// api_graphql 段仅 WDSP 开启且策略 enabled 时按应用注入（冻结契约
// api_graphql.policies.<application_id>）；未启用/WDSP 关闭/被 stripAPIGuardSections
// 剥除时 JSON 不出现该键（与 api_admission 同一纪律）。
package gatewayconfig

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/gqlast"
)

func TestBuildGuardHandlerAPIGraphQL(t *testing.T) {
	const appGQL = "44444444-4444-4444-4444-444444444444"
	newCfg := func() *GuardConfig {
		g := testGuardConfig()
		g.APIDynamicProtection = true
		g.APIProtectionMode = "OBSERVE"
		g.APIGraphQL = map[string]*GuardGraphQLPolicy{
			appGQL: {
				Enabled:           true,
				Limits:            GuardGraphQLLimits{MaxDocBytes: 131072, MaxDepth: 8},
				Weights:           gqlast.WeightsConfig{DefaultFieldWeight: 2},
				Budget:            gqlast.BudgetConfig{PerRequest: 100, WindowBudget: 1000},
				TrustedDocDigests: []string{"0123456789abcdef0123456789abcdef"},
			},
		}
		return g
	}

	// enabled 应用：契约键原样下发（policies.<appid> 包装）
	h := buildGuardHandler(newCfg(), AppData{AppID: appGQL, Code: "gql"}, 0)
	raw, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	j := string(raw)
	for _, want := range []string{`"api_graphql"`, `"policies"`, `"` + appGQL + `"`,
		`"enabled":true`, `"max_doc_bytes":131072`, `"max_depth":8`,
		`"default_field_weight":2`, `"per_request_budget":100`,
		`"trusted_doc_digests":["0123456789abcdef0123456789abcdef"]`} {
		if !strings.Contains(j, want) {
			t.Errorf("handler json missing %s: %s", want, j)
		}
	}

	// 其他应用：不下发该键（本应用无策略即零行为变化）
	raw, _ = json.Marshal(buildGuardHandler(newCfg(), AppData{AppID: "55555555-5555-5555-5555-555555555555", Code: "oth"}, 0))
	if strings.Contains(string(raw), "api_graphql") {
		t.Error("无策略应用不应出现 api_graphql 键")
	}

	// enabled=false：不下发（与无段同语义）
	off := newCfg()
	off.APIGraphQL[appGQL].Enabled = false
	raw, _ = json.Marshal(buildGuardHandler(off, AppData{AppID: appGQL, Code: "gql"}, 0))
	if strings.Contains(string(raw), "api_graphql") {
		t.Error("enabled=false 不应出现 api_graphql 键")
	}

	// 有策略但 WDSP 关闭：不注入（与纯 WAF 逐字节一致）
	waf := newCfg()
	waf.APIDynamicProtection = false
	raw, _ = json.Marshal(buildGuardHandler(waf, AppData{AppID: appGQL, Code: "gql"}, 0))
	if strings.Contains(string(raw), "api_graphql") {
		t.Error("api_graphql must not be injected when api dynamic protection disabled")
	}

	// 回滚门控：stripAPIGuardSections 剥除该段
	stripped := stripAPIGuardSections(newCfg())
	if stripped.APIGraphQL != nil {
		t.Error("stripAPIGuardSections must drop api_graphql")
	}
	raw, _ = json.Marshal(buildGuardHandler(stripped, AppData{AppID: appGQL, Code: "gql"}, 0))
	if strings.Contains(string(raw), "api_graphql") {
		t.Error("stripped config must not emit api_graphql")
	}
}
