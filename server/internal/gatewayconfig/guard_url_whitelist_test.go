package gatewayconfig

import (
	"encoding/json"
	"testing"
)

func TestBuildGuardHandlerURLWhitelistInjection(t *testing.T) {
	app := AppData{AppID: "app-1", Code: "shop"}

	// 未配置 URL 白名单时不下发 global_url_allow / app_url_allow，与历史版本逐字节一致
	emptyCfg := testGuardConfig()
	hEmpty := buildGuardHandler(emptyCfg, app, 0)
	if _, ok := hEmpty["global_url_allow"]; ok {
		t.Fatal("empty GlobalURLAllow should not inject global_url_allow")
	}
	if _, ok := hEmpty["app_url_allow"]; ok {
		t.Fatal("empty AppURLAllow should not inject app_url_allow")
	}

	// 配置全局与本应用 URL 白名单时正确下发
	cfg := testGuardConfig()
	cfg.GlobalURLAllow = []GuardURLAllowRule{{
		ID:         "u-g-1",
		MatchType:  "EXACT",
		URIPattern: "/healthz",
		Methods:    []string{"GET"},
		Priority:   10,
	}}
	cfg.AppRules["shop"] = &GuardAppRules{
		Allow: []GuardRule{},
		Deny:  []GuardRule{},
		URLAllow: []GuardURLAllowRule{{
			ID:         "u-a-1",
			MatchType:  "PREFIX",
			URIPattern: "/api/public",
			Priority:   20,
		}},
		Policies: []GuardPolicy{},
	}
	h := buildGuardHandler(cfg, app, 0)
	raw, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("marshal guard handler: %v", err)
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal guard handler: %v", err)
	}
	if _, ok := decoded["global_url_allow"]; !ok {
		t.Fatalf("missing global_url_allow in %s", string(raw))
	}
	if _, ok := decoded["app_url_allow"]; !ok {
		t.Fatalf("missing app_url_allow in %s", string(raw))
	}
}
