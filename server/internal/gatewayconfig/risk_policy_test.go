// risk_policy_test.go risk_policy 段下发单元测试（WDSP AI 自动化渗透防护增强 阶段3）。
package gatewayconfig

import "testing"

// TestBuildGuardHandlerRiskPolicy 策略段注入：risk_policy 随 GuardConfig 进入 guard
// 处理器 JSON（含 enabled=false 显式下发——网关风险处置零行为）。
// 回归防线：快照序列化 GuardConfig 自带 risk_policy 键，但网关消费的是处理器 map，
// 本测试锁住「处理器 map 必须注入」这一真实消费路径。
func TestBuildGuardHandlerRiskPolicy(t *testing.T) {
	g := &GuardConfig{
		RiskPolicy: &GuardRiskPolicy{
			Enabled:             true,
			Mode:                "PROTECT",
			Version:             2,
			BlockThreshold:      80,
			RateLimitThreshold:  40,
			RateLimitRPS:        10,
			SignalWindowSeconds: 86400,
			Scores:              map[string]int{"WAF": 50, "HEADLESS": 10},
			RiskLevels:          map[string]int{"medium": 20, "high": 40, "critical": 70},
		},
	}
	h := buildGuardHandler(g, AppData{AppID: "app-1", Code: "shop"}, 0)

	rp, ok := h["risk_policy"].(*GuardRiskPolicy)
	if !ok {
		t.Fatalf("risk_policy missing or wrong type: %T", h["risk_policy"])
	}
	if !rp.Enabled || rp.Mode != "PROTECT" || rp.Version != 2 || rp.BlockThreshold != 80 || rp.RateLimitThreshold != 40 {
		t.Errorf("risk_policy = %+v", rp)
	}
	if rp.Scores["WAF"] != 50 || rp.RiskLevels["critical"] != 70 {
		t.Errorf("risk_policy collections = %+v", rp)
	}
}

// TestBuildGuardHandlerRiskPolicyDisabled enabled=false 显式下发（网关零行为）。
func TestBuildGuardHandlerRiskPolicyDisabled(t *testing.T) {
	g := &GuardConfig{
		RiskPolicy: &GuardRiskPolicy{Enabled: false, Mode: "OBSERVE", Version: 1},
	}
	h := buildGuardHandler(g, AppData{AppID: "app-1", Code: "shop"}, 0)
	rp, ok := h["risk_policy"].(*GuardRiskPolicy)
	if !ok || rp.Enabled {
		t.Fatalf("risk_policy disabled not propagated: %+v", h["risk_policy"])
	}
}

// TestBuildGuardHandlerRiskPolicyAbsent 未注入策略时该段不出现（零行为变化）。
func TestBuildGuardHandlerRiskPolicyAbsent(t *testing.T) {
	g := &GuardConfig{}
	h := buildGuardHandler(g, AppData{AppID: "app-1", Code: "shop"}, 0)
	if _, exists := h["risk_policy"]; exists {
		t.Errorf("risk_policy should be absent when nil")
	}
}
