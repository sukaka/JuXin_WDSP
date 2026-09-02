// identity_behavior_test.go identity_behavior 段下发单元测试（WDSP AI 自动化渗透防护增强 阶段1）。
package gatewayconfig

import "testing"

// TestBuildGuardHandlerIdentityBehavior 策略段注入：identity_behavior 与 identity_events_log
// 随 GuardConfig 进入 guard 处理器 JSON（含 enabled=false 显式下发——网关行为检测零行为）。
func TestBuildGuardHandlerIdentityBehavior(t *testing.T) {
	g := &GuardConfig{
		IdentityBehavior: &GuardIdentityBehavior{
			Enabled:                  true,
			Mode:                     "OBSERVE",
			PolicyVersion:            "3",
			URIEnumUniqueThreshold:   50,
			URIEnumNewRatioThreshold: 0.8,
			NotFoundRatioThreshold:   0.7,
			NotFoundMinRequests:      30,
			MethodEnumThreshold:      4,
			ParamMutationThreshold:   30,
			AuthFailThreshold:        10,
			LowSlowSensitiveMinHits:  10,
			AccountEnumThreshold:     20,
			ObjectEnumThreshold:      25,
			AccountIdentifierFields:  []string{"account_id", "email"},
			ObjectIdentifierFields:   []string{"object_id"},
			SensitivePaths:           []string{"/.git", "/.env"},
			Scores:                   map[string]int{"URI_ENUMERATION": 15, "AUTH_FAIL_PROBE": 15},
			WhitelistIPs:             []string{"10.0.0.0/8"},
			WhitelistUAs:             []string{"internal-monitor"},
		},
		IdentityEventsLog: "/var/log/caddy/identity-events.log",
	}
	h := buildGuardHandler(g, AppData{AppID: "app-1", Code: "shop"}, 0)

	ib, ok := h["identity_behavior"].(*GuardIdentityBehavior)
	if !ok {
		t.Fatalf("identity_behavior missing or wrong type: %T", h["identity_behavior"])
	}
	if !ib.Enabled || ib.Mode != "OBSERVE" || ib.PolicyVersion != "3" || ib.URIEnumUniqueThreshold != 50 || ib.AccountEnumThreshold != 20 || ib.ObjectEnumThreshold != 25 {
		t.Errorf("identity_behavior = %+v", ib)
	}
	if ib.Scores["URI_ENUMERATION"] != 15 || ib.SensitivePaths[0] != "/.git" || ib.WhitelistIPs[0] != "10.0.0.0/8" {
		t.Errorf("identity_behavior collections = %+v", ib)
	}
	if ib.AccountIdentifierFields[0] != "account_id" || ib.ObjectIdentifierFields[0] != "object_id" {
		t.Errorf("identity_behavior identifier fields = %+v/%+v", ib.AccountIdentifierFields, ib.ObjectIdentifierFields)
	}
	if h["identity_events_log"] != "/var/log/caddy/identity-events.log" {
		t.Errorf("identity_events_log = %v", h["identity_events_log"])
	}
}

// TestBuildGuardHandlerIdentityBehaviorDisabled enabled=false 显式下发（网关零行为）。
func TestBuildGuardHandlerIdentityBehaviorDisabled(t *testing.T) {
	g := &GuardConfig{
		IdentityBehavior:  &GuardIdentityBehavior{Enabled: false, Mode: "OBSERVE", PolicyVersion: "1"},
		IdentityEventsLog: "/var/log/caddy/identity-events.log",
	}
	h := buildGuardHandler(g, AppData{AppID: "app-1", Code: "shop"}, 0)
	ib, ok := h["identity_behavior"].(*GuardIdentityBehavior)
	if !ok || ib.Enabled {
		t.Fatalf("identity_behavior disabled not propagated: %+v", h["identity_behavior"])
	}
}

// TestBuildGuardHandlerIdentityBehaviorAbsent 未注入策略时两段均不出现（零行为变化）。
func TestBuildGuardHandlerIdentityBehaviorAbsent(t *testing.T) {
	g := &GuardConfig{}
	h := buildGuardHandler(g, AppData{AppID: "app-1", Code: "shop"}, 0)
	if _, exists := h["identity_behavior"]; exists {
		t.Errorf("identity_behavior should be absent when nil")
	}
	if _, exists := h["identity_events_log"]; exists {
		t.Errorf("identity_events_log should be absent when policy nil")
	}
}
