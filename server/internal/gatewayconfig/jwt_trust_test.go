// jwt_trust_test.go jwt_trust 段下发单元测试（WDSP P0-03）。
package gatewayconfig

import "testing"

func testJWTPolicy() *GuardJWTTrustPolicy {
	return &GuardJWTTrustPolicy{
		SchemaVersion: 1,
		ApplicationID: "7b1a2c3d-0000-4000-8000-000000000001",
		Mode:          "PROTECT",
		Version:       3,
		Selectors: []GuardJWTSelector{
			{Methods: []string{"GET", "POST"}, PathPrefix: "/api", TokenRequired: true},
		},
		Issuers: []GuardJWTIssuer{
			{
				IssuerConfigID:   "jwtiss_0123456789abcdef",
				Issuer:           "https://idp.example.com/",
				Audiences:        []string{"shop-api"},
				Algorithms:       []string{"RS256"},
				ClockSkewSeconds: 30,
				RoleClaims:       []string{"roles", "groups"},
				KeySourceType:    "STATIC_JWKS",
				JWKS:             []byte(`{"keys":[{"kty":"RSA","kid":"k1","n":"x","e":"AQAB"}]}`),
				KeysetVersion:    "deadbeef",
			},
		},
	}
}

// TestBuildGuardHandlerJWTTrust jwt_trust 按应用注入 guard 处理器 JSON
// （仅 WDSP 开启且本应用有策略时；含策略版本与 issuer 配置 ID/keyset 版本溯源标识）。
func TestBuildGuardHandlerJWTTrust(t *testing.T) {
	g := &GuardConfig{
		APIDynamicProtection: true,
		APIProtectionMode:    "PROTECT",
		JWTTrust:             map[string]*GuardJWTTrustPolicy{"shop": testJWTPolicy()},
	}
	h := buildGuardHandler(g, AppData{AppID: "app-1", Code: "shop"}, 0)

	pol, ok := h["jwt_trust"].(*GuardJWTTrustPolicy)
	if !ok {
		t.Fatalf("jwt_trust missing or wrong type: %T", h["jwt_trust"])
	}
	if pol.Mode != "PROTECT" || pol.Version != 3 || pol.SchemaVersion != 1 {
		t.Errorf("jwt_trust = %+v", pol)
	}
	if len(pol.Selectors) != 1 || !pol.Selectors[0].TokenRequired || pol.Selectors[0].PathPrefix != "/api" {
		t.Errorf("jwt_trust selectors = %+v", pol.Selectors)
	}
	if len(pol.Issuers) != 1 || pol.Issuers[0].IssuerConfigID == "" || pol.Issuers[0].KeysetVersion != "deadbeef" {
		t.Errorf("jwt_trust issuers = %+v", pol.Issuers)
	}
	if got := pol.Issuers[0].RoleClaims; len(got) != 2 || got[0] != "roles" || got[1] != "groups" {
		t.Errorf("jwt_trust role claims = %v", got)
	}
}

// TestBuildGuardHandlerJWTTrustOtherApp 策略按应用隔离：其他应用的策略不注入本应用。
func TestBuildGuardHandlerJWTTrustOtherApp(t *testing.T) {
	g := &GuardConfig{
		APIDynamicProtection: true,
		APIProtectionMode:    "PROTECT",
		JWTTrust:             map[string]*GuardJWTTrustPolicy{"other": testJWTPolicy()},
	}
	h := buildGuardHandler(g, AppData{AppID: "app-1", Code: "shop"}, 0)
	if _, exists := h["jwt_trust"]; exists {
		t.Errorf("jwt_trust should be absent for app without policy")
	}
}

// TestBuildGuardHandlerJWTTrustGated 纯 WAF 形态（WDSP 关闭）不下发 jwt_trust 段。
func TestBuildGuardHandlerJWTTrustGated(t *testing.T) {
	g := &GuardConfig{
		JWTTrust: map[string]*GuardJWTTrustPolicy{"shop": testJWTPolicy()},
	}
	h := buildGuardHandler(g, AppData{AppID: "app-1", Code: "shop"}, 0)
	if _, exists := h["jwt_trust"]; exists {
		t.Errorf("jwt_trust should be gated by APIDynamicProtection")
	}
}

// TestStripAPIGuardSectionsJWTTrust 回滚覆盖快照门控剥除 jwt_trust 段
// （防跨重启把 JWT 强制校验回放到纯 WAF 形态）。
func TestStripAPIGuardSectionsJWTTrust(t *testing.T) {
	g := &GuardConfig{
		APIDynamicProtection: true,
		APIProtectionMode:    "PROTECT",
		JWTTrust:             map[string]*GuardJWTTrustPolicy{"shop": testJWTPolicy()},
	}
	stripped := stripAPIGuardSections(g)
	if stripped.JWTTrust != nil {
		t.Errorf("jwt_trust should be stripped, got %+v", stripped.JWTTrust)
	}
	if g.JWTTrust == nil {
		t.Errorf("strip should not mutate input")
	}
}
