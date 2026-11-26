package gatewayconfig

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/capability"
)

func testA2APolicy(mode string) *GuardA2APolicy {
	return &GuardA2APolicy{
		SchemaVersion:            1,
		ApplicationID:            "8b1a2c3d-0000-4000-8000-000000000099",
		Mode:                     mode,
		Version:                  2,
		CardDiscoveryEnabled:     true,
		A2APathPrefixes:          []string{"/a2a", "/.well-known/agent.json", "/.well-known/agent-card.json"},
		AllowedCallerAgents:      []string{"planner-agent"},
		MaxDelegationDepth:       3,
		EnforceScopeAttenuation:  true,
		LoopWindowSeconds:        60,
		MaxCallsPerTaskWindow:    20,
		LethalTrifectaEnabled:    true,
		ConfidentialReadPatterns: []string{"/api/v1/secrets", "read_secret"},
		ExternalEgressPatterns:   []string{"send_email", "webhook"},
	}
}

func TestBuildGuardHandlerA2APolicyAndStrip(t *testing.T) {
	g := testGuardConfig()
	g.APIDynamicProtection = true
	g.APIProtectionMode = "PROTECT"
	g.APIA2APolicy = map[string]*GuardA2APolicy{
		"agent-app": testA2APolicy("PROTECT"),
	}

	// 1. 本应用注入 api_a2a_policy，字段符合冻结契约
	h := buildGuardHandler(g, AppData{AppID: "app-1", Code: "agent-app"}, 0)
	pol, ok := h["api_a2a_policy"].(*GuardA2APolicy)
	if !ok || pol == nil {
		t.Fatalf("api_a2a_policy missing: %T", h["api_a2a_policy"])
	}
	raw, err := json.Marshal(pol)
	if err != nil {
		t.Fatalf("marshal api_a2a_policy: %v", err)
	}
	for _, want := range []string{
		`"schema_version":1`,
		`"mode":"PROTECT"`,
		`"card_discovery_enabled":true`,
		`"a2a_path_prefixes":["/a2a","/.well-known/agent.json","/.well-known/agent-card.json"]`,
		`"allowed_caller_agents":["planner-agent"]`,
		`"max_delegation_depth":3`,
		`"enforce_scope_attenuation":true`,
		`"loop_window_seconds":60`,
		`"max_calls_per_task_window":20`,
		`"lethal_trifecta_enabled":true`,
		`"confidential_read_patterns"`,
		`"external_egress_patterns"`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("api_a2a_policy JSON missing %s: %s", want, raw)
		}
	}

	// 2. 其他应用隔离
	hOther := buildGuardHandler(g, AppData{AppID: "app-2", Code: "other"}, 0)
	if _, exists := hOther["api_a2a_policy"]; exists {
		t.Fatal("api_a2a_policy must not be injected for unrelated app")
	}

	// 3. WDSP 关闭时不下发
	gOff := *g
	gOff.APIDynamicProtection = false
	hOff := buildGuardHandler(&gOff, AppData{AppID: "app-1", Code: "agent-app"}, 0)
	if _, exists := hOff["api_a2a_policy"]; exists {
		t.Fatal("api_a2a_policy must be gated by APIDynamicProtection")
	}

	// 4. stripAPIGuardSections 剥除且不修改原配置
	stripped := stripAPIGuardSections(g)
	if stripped.APIA2APolicy != nil {
		t.Fatalf("stripAPIGuardSections must drop APIA2APolicy, got %+v", stripped.APIA2APolicy)
	}
	if g.APIA2APolicy == nil {
		t.Fatal("stripAPIGuardSections must not mutate input")
	}
}

func TestCapabilityGateA2AProtect(t *testing.T) {
	oldDir := t.TempDir()
	writeManifest(t, oldDir, fullManifest("gw-old", time.Now().UTC()))
	pOld := &Publisher{sidecarDir: oldDir}

	newDir := t.TempDir()
	m := fullManifest("gw-new", time.Now().UTC())
	m.Detectors = append(m.Detectors, capability.DetectorCap{Name: "a2aguard", Version: "a2a/1"})
	writeManifest(t, newDir, m)
	pNew := &Publisher{sidecarDir: newDir}

	// 1. OFF / OBSERVE 不触发能力门禁（支持滚动升级）
	for _, mode := range []string{"OFF", "OBSERVE"} {
		cfg := &GuardConfig{APIA2APolicy: map[string]*GuardA2APolicy{"agent-app": testA2APolicy(mode)}}
		if f := capabilityFactsFromGuard(cfg); f.A2AProtect {
			t.Fatalf("%s must not set A2AProtect", mode)
		}
		if ok, code, msg := pOld.evaluateCapabilityGate(context.Background(), cfg); !ok {
			t.Fatalf("%s must pass on old node: code=%s msg=%s", mode, code, msg)
		}
	}

	// 2. PROTECT 触发 detectors.a2aguard=a2a/1 门禁
	cfgProtect := &GuardConfig{APIA2APolicy: map[string]*GuardA2APolicy{"agent-app": testA2APolicy("PROTECT")}}
	f := capabilityFactsFromGuard(cfgProtect)
	if !f.A2AProtect {
		t.Fatal("PROTECT must set A2AProtect")
	}
	req := RequiredCapabilities(f)
	if v := detectorVersion(req, "a2aguard"); v != "a2a/1" {
		t.Fatalf("expected detectors.a2aguard=a2a/1, got %+v", req.Detectors)
	}
	if ok, code, msg := pOld.evaluateCapabilityGate(context.Background(), cfgProtect); ok || code != "CAPABILITY_MISSING" || !strings.Contains(msg, "detectors.a2aguard") {
		t.Fatalf("old node must fail-closed for A2A PROTECT: ok=%v code=%s msg=%s", ok, code, msg)
	}
	if ok, code, msg := pNew.evaluateCapabilityGate(context.Background(), cfgProtect); !ok || code != "" {
		t.Fatalf("capable node must pass for A2A PROTECT: ok=%v code=%s msg=%s", ok, code, msg)
	}
}

func TestCapabilityGateMCPPinningProtectAndOmitEmpty(t *testing.T) {
	// 1. 零值新字段 omitempty 验证（保持与存量 G1 快照 100% 向后兼容）
	rawTool, err := json.Marshal(GuardMCPTool{ToolName: "refund", ToolHash: "mcp-tool-sha256:v1:abc"})
	if err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"pinned_definition_hash", "pin_enforcement"} {
		if strings.Contains(string(rawTool), absent) {
			t.Errorf("empty GuardMCPTool field %q must be omitted: %s", absent, rawTool)
		}
	}
	rawBind, err := json.Marshal(GuardMCPBinding{ApplicationID: "a1", EndpointPath: "/mcp", CatalogName: "pay", Mode: "OBSERVE"})
	if err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"response_guard_mode", "require_session_binding", "oauth_resource_metadata_url"} {
		if strings.Contains(string(rawBind), absent) {
			t.Errorf("empty GuardMCPBinding field %q must be omitted: %s", absent, rawBind)
		}
	}

	// 2. 事实提取矩阵：
	//    - PROTECT binding without pinning/session/response_guard PROTECT -> MCPToolCallProtect only (acl_v1 + mcp/2)
	//    - OBSERVE binding even with response_guard_mode=PROTECT -> neither protect fact
	//    - PROTECT binding + response_guard_mode=PROTECT -> MCPPinningProtect
	//    - PROTECT binding + require_session_binding=true -> MCPPinningProtect
	//    - PROTECT binding + catalog tool pin_enforcement=PROTECT -> MCPPinningProtect
	baseProtect := &GuardConfig{
		APIMCPBindings: []GuardMCPBinding{
			{ApplicationID: "a1", EndpointPath: "/mcp", CatalogName: "pay", Mode: "PROTECT", ResponseGuardMode: "SANITIZE"},
		},
		APIMCPToolCatalogs: []GuardMCPToolCatalog{
			{Name: "pay", Tools: []GuardMCPTool{{ToolName: "refund", PinEnforcement: "OBSERVE"}}},
		},
	}
	if f := capabilityFactsFromGuard(baseProtect); !f.MCPToolCallProtect || f.MCPPinningProtect {
		t.Fatalf("plain G1 PROTECT binding should not require MCPPinningProtect: %+v", f)
	}

	observeOnly := &GuardConfig{
		APIMCPBindings: []GuardMCPBinding{
			{ApplicationID: "a1", EndpointPath: "/mcp", CatalogName: "pay", Mode: "OBSERVE", ResponseGuardMode: "PROTECT", RequireSessionBinding: true},
		},
		APIMCPToolCatalogs: []GuardMCPToolCatalog{
			{Name: "pay", Tools: []GuardMCPTool{{ToolName: "refund", PinEnforcement: "PROTECT"}}},
		},
	}
	if f := capabilityFactsFromGuard(observeOnly); f.MCPToolCallProtect || f.MCPPinningProtect {
		t.Fatalf("OBSERVE binding must not trigger protect facts: %+v", f)
	}

	triggerCases := map[string]*GuardConfig{
		"response_guard_protect": {
			APIMCPBindings: []GuardMCPBinding{
				{ApplicationID: "a1", EndpointPath: "/mcp", CatalogName: "pay", Mode: "PROTECT", ResponseGuardMode: "PROTECT"},
			},
		},
		"require_session_binding": {
			APIMCPBindings: []GuardMCPBinding{
				{ApplicationID: "a1", EndpointPath: "/mcp", CatalogName: "pay", Mode: "PROTECT", RequireSessionBinding: true},
			},
		},
		"tool_pin_enforcement_protect": {
			APIMCPBindings: []GuardMCPBinding{
				{ApplicationID: "a1", EndpointPath: "/mcp", CatalogName: "pay", Mode: "PROTECT"},
			},
			APIMCPToolCatalogs: []GuardMCPToolCatalog{
				{Name: "pay", Tools: []GuardMCPTool{{ToolName: "refund", PinnedDefinitionHash: "mcp-def-sha256:v1:abc", PinEnforcement: "PROTECT"}}},
			},
		},
	}

	aclOnlyDir := t.TempDir()
	mACL := fullManifest("gw-acl", time.Now().UTC())
	mACL.Protocols["mcp"] = "acl_v1"
	mACL.Detectors = append(mACL.Detectors, capability.DetectorCap{Name: "mcp.toolcall", Version: "mcp/2"})
	writeManifest(t, aclOnlyDir, mACL)
	pACL := &Publisher{sidecarDir: aclOnlyDir}

	pinDir := t.TempDir()
	mPin := fullManifest("gw-pin", time.Now().UTC())
	mPin.Protocols["mcp"] = "pin_v2"
	mPin.Detectors = append(mPin.Detectors,
		capability.DetectorCap{Name: "mcp.toolcall", Version: "mcp/2"},
		capability.DetectorCap{Name: "mcp.pinning", Version: "mcppin/1"},
	)
	writeManifest(t, pinDir, mPin)
	pPin := &Publisher{sidecarDir: pinDir}

	for name, cfg := range triggerCases {
		t.Run(name, func(t *testing.T) {
			f := capabilityFactsFromGuard(cfg)
			if !f.MCPToolCallProtect || !f.MCPPinningProtect {
				t.Fatalf("%s expected both MCPToolCallProtect and MCPPinningProtect, got %+v", name, f)
			}
			req := RequiredCapabilities(f)
			if req.Protocols["mcp"] != "pin_v2" {
				t.Fatalf("%s expected protocols.mcp=pin_v2, got %+v", name, req.Protocols)
			}
			if v := detectorVersion(req, "mcp.pinning"); v != "mcppin/1" {
				t.Fatalf("%s expected detectors.mcp.pinning=mcppin/1, got %+v", name, req.Detectors)
			}
			if ok, code, msg := pACL.evaluateCapabilityGate(context.Background(), cfg); ok || code != "CAPABILITY_MISSING" || !strings.Contains(msg, "detectors.mcp.pinning") {
				t.Fatalf("%s acl_v1-only node must fail-closed: ok=%v code=%s msg=%s", name, ok, code, msg)
			}
			if ok, code, msg := pPin.evaluateCapabilityGate(context.Background(), cfg); !ok || code != "" {
				t.Fatalf("%s pin_v2 node must pass: ok=%v code=%s msg=%s", name, ok, code, msg)
			}
		})
	}
}
