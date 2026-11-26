package gatewayconfig

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/capability"
)

func testAICrawlPolicy(mode string, labyrinth bool) *GuardAICrawlPolicy {
	return &GuardAICrawlPolicy{
		SchemaVersion:           1,
		ApplicationID:           "7b1a2c3d-0000-4000-8000-000000000001",
		Mode:                    mode,
		Version:                 2,
		DefaultAIAction:         "HTTP_402",
		ContentSignal:           "ai-train=no, search=yes, ai-input=no",
		VerifyWebBotAuth:        true,
		LabyrinthEnabled:        labyrinth,
		LabyrinthInjectLinks:    labyrinth,
		LabyrinthMaxDepth:       5,
		LabyrinthMaxConcurrency: 256,
		LabyrinthDelayMs:        150,
		HTTP402:                 GuardAICrawlHTTP402{Message: "Payment required", PriceHint: "0.001 USD"},
		Rules: []GuardAICrawlRule{
			{ID: "r1", Name: "Block training", Category: "AI_TRAINING", Action: "TARPIT", Priority: 10},
		},
		Directories: []GuardAICrawlerDirectory{
			{ID: "d1", Slug: "openai", Name: "OpenAI", Category: "AI_AGENT", Keys: []GuardAICrawlerKey{}},
		},
	}
}

func TestBuildGuardHandlerAICrawlAndSecretRedactionReplay(t *testing.T) {
	oldKey := strings.Repeat("a", 64)
	newKey := strings.Repeat("b", 64)

	g := testGuardConfig()
	g.APIDynamicProtection = true
	g.APIProtectionMode = "PROTECT"
	g.AICrawlPolicy = map[string]*GuardAICrawlPolicy{"shop": testAICrawlPolicy("PROTECT", true)}
	g.AICrawlLabyrinthKeyHex = oldKey

	// 1. 注入本应用处理器并携带运行时 labyrinth_key_hex
	h := buildGuardHandler(g, AppData{AppID: "app-1", Code: "shop"}, 0)
	pol, ok := h["ai_crawl_policy"].(*GuardAICrawlPolicy)
	if !ok || pol == nil {
		t.Fatalf("ai_crawl_policy missing: %T", h["ai_crawl_policy"])
	}
	if pol.LabyrinthKeyHex != oldKey {
		t.Fatalf("expected runtime labyrinth_key_hex %q, got %q", oldKey, pol.LabyrinthKeyHex)
	}
	// 其他应用隔离
	hOther := buildGuardHandler(g, AppData{AppID: "app-2", Code: "other"}, 0)
	if _, exists := hOther["ai_crawl_policy"]; exists {
		t.Fatal("ai_crawl_policy should not be injected for unrelated app")
	}
	// 纯 WAF（APIDynamicProtection=false）与 stripAPIGuardSections 均剥除
	stripped := stripAPIGuardSections(g)
	if stripped.AICrawlPolicy != nil || stripped.AICrawlLabyrinthKeyHex != "" {
		t.Fatalf("stripAPIGuardSections must drop ai_crawl_policy and key: %+v", stripped)
	}

	// 2. RedactConfigSecrets 脱敏 labyrinth_key_hex 且 reinjectConfigSecrets 回滚重注入新密钥
	plainJSON := generateGuardJSON(t, g)
	if !strings.Contains(plainJSON, oldKey) {
		t.Fatal("generated config should contain runtime labyrinth_key_hex")
	}
	redacted, err := RedactConfigSecrets(plainJSON)
	if err != nil {
		t.Fatalf("RedactConfigSecrets: %v", err)
	}
	if strings.Contains(redacted, oldKey) {
		t.Fatalf("redacted config leaked labyrinth_key_hex: %s", redacted)
	}
	if !strings.Contains(redacted, `"labyrinth_key_hex":"***"`) {
		t.Fatalf("redacted config missing *** placeholder: %s", redacted)
	}

	// 重注入当前密钥
	newGuard := testGuardConfig()
	newGuard.APIDynamicProtection = true
	newGuard.AICrawlLabyrinthKeyHex = newKey
	p := &Publisher{guard: &fakeGuardProvider{buildCfg: newGuard}}
	reinjected, err := p.reinjectConfigSecrets(context.Background(), redacted)
	if err != nil {
		t.Fatalf("reinjectConfigSecrets: %v", err)
	}
	if !strings.Contains(reinjected, newKey) || strings.Contains(reinjected, oldKey) || strings.Contains(reinjected, `"***"`) {
		t.Fatalf("reinjected config invalid: %s", reinjected)
	}

	// 3. 回滚回归：当前配置已关闭迷宫（labyrinth_enabled=false）但系统设置仍保留加密密钥时，
	// 正常发布不会向 handler 注入 labyrinth_key_hex，而回滚到历史含 labyrinth_key_hex:"***" 快照仍可重注入成功
	disabledGuard := testGuardConfig()
	disabledGuard.APIDynamicProtection = true
	disabledGuard.AICrawlPolicy = map[string]*GuardAICrawlPolicy{"shop": testAICrawlPolicy("OBSERVE", false)}
	disabledGuard.AICrawlLabyrinthKeyHex = newKey
	hDisabled := buildGuardHandler(disabledGuard, AppData{AppID: "app-1", Code: "shop"}, 0)
	if polDisabled, ok := hDisabled["ai_crawl_policy"].(*GuardAICrawlPolicy); !ok || polDisabled.LabyrinthKeyHex != "" {
		t.Fatalf("disabled labyrinth handler must not receive labyrinth_key_hex: %+v", hDisabled["ai_crawl_policy"])
	}
	pRollbackFromDisabled := &Publisher{guard: &fakeGuardProvider{buildCfg: disabledGuard}}
	reinjectedFromDisabled, err := pRollbackFromDisabled.reinjectConfigSecrets(context.Background(), redacted)
	if err != nil {
		t.Fatalf("reinjectConfigSecrets when current labyrinth_enabled=false: %v", err)
	}
	if !strings.Contains(reinjectedFromDisabled, newKey) || strings.Contains(reinjectedFromDisabled, `"***"`) {
		t.Fatalf("rollback from labyrinth_enabled=false failed to reinject live key: %s", reinjectedFromDisabled)
	}

	// 缺当前迷宫密钥时 fail-closed
	emptyGuard := testGuardConfig()
	pMissing := &Publisher{guard: &fakeGuardProvider{buildCfg: emptyGuard}}
	if _, err := pMissing.reinjectConfigSecrets(context.Background(), redacted); err == nil || !strings.Contains(err.Error(), "labyrinth_key_hex") {
		t.Fatalf("missing current labyrinth key must fail-closed, got %v", err)
	}
}

func TestCapabilityGateJWTBindingAndAICrawl(t *testing.T) {
	// 1. 9A-1 JWT Binding: OBSERVE / NONE 不触发需求；PROTECT + active TokenBinding 触发 jwt.binding=jwtbind/1
	jwtObserve := &GuardConfig{
		JWTTrust: map[string]*GuardJWTTrustPolicy{
			"shop": {
				SchemaVersion: 2,
				Mode:          "OBSERVE",
				Issuers:       []GuardJWTIssuer{{Issuer: "https://idp", TokenBinding: &GuardJWTTokenBinding{Mode: "DPOP_REQUIRED"}}},
			},
		},
	}
	if f := capabilityFactsFromGuard(jwtObserve); f.JWTBindingProtect {
		t.Fatal("OBSERVE JWT policy should not require jwt.binding capability")
	}

	jwtProtect := &GuardConfig{
		JWTTrust: map[string]*GuardJWTTrustPolicy{
			"shop": {
				SchemaVersion: 2,
				Mode:          "PROTECT",
				Issuers:       []GuardJWTIssuer{{Issuer: "https://idp", TokenBinding: &GuardJWTTokenBinding{Mode: "DPOP_REQUIRED"}}},
			},
		},
	}
	if f := capabilityFactsFromGuard(jwtProtect); !f.JWTBindingProtect {
		t.Fatal("PROTECT JWT policy with active token_binding must set JWTBindingProtect")
	}
	reqJWT := RequiredCapabilities(CapabilityFacts{JWTBindingProtect: true})
	if v := detectorVersion(reqJWT, "jwt.binding"); v != "jwtbind/1" {
		t.Fatalf("expected detectors.jwt.binding=jwtbind/1, got %+v", reqJWT.Detectors)
	}

	// 旧节点缺 jwt.binding → fail-closed；新节点放行
	oldDir := t.TempDir()
	writeManifest(t, oldDir, fullManifest("gw-old", time.Now().UTC()))
	pOld := &Publisher{sidecarDir: oldDir}
	if ok, code, msg := pOld.evaluateCapabilityGate(context.Background(), jwtProtect); ok || code != "CAPABILITY_MISSING" || !strings.Contains(msg, "detectors.jwt.binding") {
		t.Fatalf("old node must fail-closed on JWTBindingProtect: ok=%v code=%s msg=%s", ok, code, msg)
	}

	newDir := t.TempDir()
	m := fullManifest("gw-new", time.Now().UTC())
	m.Detectors = append(m.Detectors,
		capability.DetectorCap{Name: "jwt.binding", Version: "jwtbind/1"},
		capability.DetectorCap{Name: "aicrawl", Version: "aicrawl/1"},
	)
	m.Actions = append(m.Actions, "tarpit", "http_402")
	writeManifest(t, newDir, m)
	pNew := &Publisher{sidecarDir: newDir}
	if ok, code, msg := pNew.evaluateCapabilityGate(context.Background(), jwtProtect); !ok || code != "" {
		t.Fatalf("capable node must pass JWTBindingProtect: ok=%v code=%s msg=%s", ok, code, msg)
	}

	// 2. 9A-2 AI Crawl: OBSERVE/OFF 不触发需求；PROTECT 触发 aicrawl=aicrawl/1 + actions tarpit & http_402
	aiObserve := &GuardConfig{
		AICrawlPolicy: map[string]*GuardAICrawlPolicy{"shop": testAICrawlPolicy("OBSERVE", true)},
	}
	if f := capabilityFactsFromGuard(aiObserve); f.AICrawlProtect {
		t.Fatal("OBSERVE ai_crawl_policy should not set AICrawlProtect")
	}
	if ok, _, _ := pOld.evaluateCapabilityGate(context.Background(), aiObserve); !ok {
		t.Fatal("old node should allow OBSERVE ai_crawl_policy for rolling upgrade")
	}

	aiProtect := &GuardConfig{
		AICrawlPolicy: map[string]*GuardAICrawlPolicy{"shop": testAICrawlPolicy("PROTECT", false)},
	}
	if f := capabilityFactsFromGuard(aiProtect); !f.AICrawlProtect {
		t.Fatal("PROTECT ai_crawl_policy must set AICrawlProtect")
	}
	if ok, code, msg := pOld.evaluateCapabilityGate(context.Background(), aiProtect); ok || code != "CAPABILITY_MISSING" ||
		!strings.Contains(msg, "detectors.aicrawl") || !strings.Contains(msg, "actions.tarpit") || !strings.Contains(msg, "actions.http_402") {
		t.Fatalf("old node must fail-closed listing aicrawl+tarpit+http_402: ok=%v code=%s msg=%s", ok, code, msg)
	}
	if ok, code, msg := pNew.evaluateCapabilityGate(context.Background(), aiProtect); !ok || code != "" {
		t.Fatalf("capable node must pass AICrawlProtect: ok=%v code=%s msg=%s", ok, code, msg)
	}

	// 验证 GuardJWTTokenBinding JSON 序列化字段与冻结契约一致
	rawJWT, err := json.Marshal(jwtProtect.JWTTrust["shop"])
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"schema_version":2`, `"token_binding"`, `"mode":"DPOP_REQUIRED"`} {
		if !strings.Contains(string(rawJWT), want) {
			t.Errorf("marshaled jwt_trust missing %s: %s", want, rawJWT)
		}
	}
}
