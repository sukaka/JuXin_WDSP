package gatewayconfig

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/capability"
)

func testSemanticGuardPolicy(mode string) *GuardSemanticGuardPolicy {
	return &GuardSemanticGuardPolicy{
		SchemaVersion:           1,
		ApplicationID:           "8b1a2c3d-0000-4000-8000-000000000088",
		Mode:                    mode,
		Version:                 2,
		SocketPath:              "/var/run/caddy/sidecars/semantic.sock",
		TimeoutMs:               15,
		MaxConcurrency:          32,
		MaxInputRunes:           4096,
		BlockThreshold:          0.85,
		ObserveThreshold:        0.50,
		FailPolicy:              "FAIL_OPEN",
		InspectLLMPrompts:       true,
		InspectMCPContent:       true,
		InspectWebGrayzone:      true,
		CircuitFailureThreshold: 5,
		CircuitOpenSeconds:      30,
	}
}

func TestBuildGuardHandlerSemanticGuardPolicyAndStrip(t *testing.T) {
	g := testGuardConfig()
	g.APIDynamicProtection = true
	g.APIProtectionMode = "PROTECT"
	g.SemanticGuardPolicy = map[string]*GuardSemanticGuardPolicy{
		"llm-app": testSemanticGuardPolicy("PROTECT"),
	}

	// 1. 本应用注入 semantic_guard_policy，字段符合 16 键冻结契约
	h := buildGuardHandler(g, AppData{AppID: "app-1", Code: "llm-app"}, 0)
	pol, ok := h["semantic_guard_policy"].(*GuardSemanticGuardPolicy)
	if !ok || pol == nil {
		t.Fatalf("semantic_guard_policy missing: %T", h["semantic_guard_policy"])
	}
	raw, err := json.Marshal(pol)
	if err != nil {
		t.Fatalf("marshal semantic_guard_policy: %v", err)
	}
	for _, want := range []string{
		`"schema_version":1`,
		`"application_id":"8b1a2c3d-0000-4000-8000-000000000088"`,
		`"mode":"PROTECT"`,
		`"version":2`,
		`"socket_path":"/var/run/caddy/sidecars/semantic.sock"`,
		`"timeout_ms":15`,
		`"max_concurrency":32`,
		`"max_input_runes":4096`,
		`"block_threshold":0.85`,
		`"observe_threshold":0.5`,
		`"fail_policy":"FAIL_OPEN"`,
		`"inspect_llm_prompts":true`,
		`"inspect_mcp_content":true`,
		`"inspect_web_grayzone":true`,
		`"circuit_failure_threshold":5`,
		`"circuit_open_seconds":30`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("semantic_guard_policy JSON missing %s: %s", want, raw)
		}
	}

	// 2. 其他应用隔离
	hOther := buildGuardHandler(g, AppData{AppID: "app-2", Code: "other"}, 0)
	if _, exists := hOther["semantic_guard_policy"]; exists {
		t.Fatal("semantic_guard_policy must not be injected for unrelated app")
	}

	// 3. WDSP 关闭时不下发
	gOff := *g
	gOff.APIDynamicProtection = false
	hOff := buildGuardHandler(&gOff, AppData{AppID: "app-1", Code: "llm-app"}, 0)
	if _, exists := hOff["semantic_guard_policy"]; exists {
		t.Fatal("semantic_guard_policy must be gated by APIDynamicProtection")
	}

	// 4. stripAPIGuardSections 剥除且不修改原配置
	stripped := stripAPIGuardSections(g)
	if stripped.SemanticGuardPolicy != nil {
		t.Fatalf("stripAPIGuardSections must drop SemanticGuardPolicy, got %+v", stripped.SemanticGuardPolicy)
	}
	if g.SemanticGuardPolicy == nil {
		t.Fatal("stripAPIGuardSections must not mutate input")
	}
}

func TestCapabilityGateSemanticProtect(t *testing.T) {
	oldDir := t.TempDir()
	writeManifest(t, oldDir, fullManifest("gw-old", time.Now().UTC()))
	pOld := &Publisher{sidecarDir: oldDir}

	newDir := t.TempDir()
	m := fullManifest("gw-new", time.Now().UTC())
	m.Detectors = append(m.Detectors, capability.DetectorCap{Name: "semantic", Version: "semantic/1"})
	writeManifest(t, newDir, m)
	pNew := &Publisher{sidecarDir: newDir}

	// 1. OFF / OBSERVE 不触发能力门禁（支持滚动升级）
	for _, mode := range []string{"OFF", "OBSERVE"} {
		cfg := &GuardConfig{SemanticGuardPolicy: map[string]*GuardSemanticGuardPolicy{"llm-app": testSemanticGuardPolicy(mode)}}
		if f := capabilityFactsFromGuard(cfg); f.SemanticProtect {
			t.Fatalf("%s must not set SemanticProtect", mode)
		}
		if ok, code, msg := pOld.evaluateCapabilityGate(context.Background(), cfg); !ok {
			t.Fatalf("%s must pass on old node: code=%s msg=%s", mode, code, msg)
		}
	}

	// 2. PROTECT 触发 detectors.semantic=semantic/1 门禁
	cfgProtect := &GuardConfig{SemanticGuardPolicy: map[string]*GuardSemanticGuardPolicy{"llm-app": testSemanticGuardPolicy("PROTECT")}}
	f := capabilityFactsFromGuard(cfgProtect)
	if !f.SemanticProtect {
		t.Fatal("PROTECT must set SemanticProtect")
	}
	req := RequiredCapabilities(f)
	if v := detectorVersion(req, "semantic"); v != "semantic/1" {
		t.Fatalf("expected detectors.semantic=semantic/1, got %+v", req.Detectors)
	}
	if ok, code, msg := pOld.evaluateCapabilityGate(context.Background(), cfgProtect); ok || code != "CAPABILITY_MISSING" || !strings.Contains(msg, "detectors.semantic") {
		t.Fatalf("old node must fail-closed for semantic PROTECT: ok=%v code=%s msg=%s", ok, code, msg)
	}
	if ok, code, msg := pNew.evaluateCapabilityGate(context.Background(), cfgProtect); !ok || code != "" {
		t.Fatalf("capable node must pass for semantic PROTECT: ok=%v code=%s msg=%s", ok, code, msg)
	}
}
