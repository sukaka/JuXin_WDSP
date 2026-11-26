package gatewayconfig

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/capability"
)

func testClientSidePolicy(mode, cspMode string) *GuardClientSidePolicy {
	return &GuardClientSidePolicy{
		SchemaVersion:            1,
		ApplicationID:            "8b1a2c3d-0000-4000-8000-000000000001",
		Mode:                     mode,
		Version:                  2,
		CSPMode:                  cspMode,
		SensitivePaths:           []string{"/login", "/checkout"},
		ProbeEnabled:             true,
		StripUnauthorizedScripts: mode == "PROTECT",
		AllowedScriptOrigins:     []string{"'self'", "https://cdn.example.com"},
		AllowedConnectOrigins:    []string{"'self'"},
		AllowedFormOrigins:       []string{"'self'"},
		CustomCSPDirectives:      "object-src 'none'",
		AuthorizedScripts: []GuardClientSideScript{
			{ScriptURL: "https://cdn.example.com/app.js", ScriptType: "EXTERNAL", SRIHash: "sha384-dGVzdA==", Status: "AUTHORIZED"},
		},
	}
}

func TestBuildGuardHandlerClientSidePolicyAndStrip(t *testing.T) {
	g := testGuardConfig()
	g.APIDynamicProtection = true
	g.APIProtectionMode = "PROTECT"
	g.ClientSidePolicy = map[string]*GuardClientSidePolicy{
		"shop": testClientSidePolicy("PROTECT", "ENFORCE"),
	}

	// 1. 本应用注入 client_side_policy，字段符合冻结契约
	h := buildGuardHandler(g, AppData{AppID: "app-1", Code: "shop"}, 0)
	pol, ok := h["client_side_policy"].(*GuardClientSidePolicy)
	if !ok || pol == nil {
		t.Fatalf("client_side_policy missing: %T", h["client_side_policy"])
	}
	raw, err := json.Marshal(pol)
	if err != nil {
		t.Fatalf("marshal client_side_policy: %v", err)
	}
	for _, want := range []string{
		`"schema_version":1`,
		`"mode":"PROTECT"`,
		`"csp_mode":"ENFORCE"`,
		`"sensitive_paths":["/login","/checkout"]`,
		`"probe_enabled":true`,
		`"strip_unauthorized_scripts":true`,
		`"allowed_script_origins"`,
		`"allowed_connect_origins"`,
		`"allowed_form_origins"`,
		`"custom_csp_directives":"object-src 'none'"`,
		`"authorized_scripts"`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("client_side_policy JSON missing %s: %s", want, raw)
		}
	}

	// 2. 其他应用隔离
	hOther := buildGuardHandler(g, AppData{AppID: "app-2", Code: "other"}, 0)
	if _, exists := hOther["client_side_policy"]; exists {
		t.Fatal("client_side_policy must not be injected for unrelated app")
	}

	// 3. WDSP 关闭时不下发
	gOff := *g
	gOff.APIDynamicProtection = false
	hOff := buildGuardHandler(&gOff, AppData{AppID: "app-1", Code: "shop"}, 0)
	if _, exists := hOff["client_side_policy"]; exists {
		t.Fatal("client_side_policy must be gated by APIDynamicProtection")
	}

	// 4. stripAPIGuardSections 剥除且不修改原配置
	stripped := stripAPIGuardSections(g)
	if stripped.ClientSidePolicy != nil {
		t.Fatalf("stripAPIGuardSections must drop ClientSidePolicy, got %+v", stripped.ClientSidePolicy)
	}
	if g.ClientSidePolicy == nil {
		t.Fatal("stripAPIGuardSections must not mutate input")
	}
}

func TestCapabilityGateClientSide(t *testing.T) {
	oldDir := t.TempDir()
	writeManifest(t, oldDir, fullManifest("gw-old", time.Now().UTC()))
	pOld := &Publisher{sidecarDir: oldDir}

	newDir := t.TempDir()
	m := fullManifest("gw-new", time.Now().UTC())
	m.Detectors = append(m.Detectors, capability.DetectorCap{Name: "clientside", Version: "clientside/1"})
	writeManifest(t, newDir, m)
	pNew := &Publisher{sidecarDir: newDir}

	// 1. OFF / OBSERVE+REPORT_ONLY 不触发能力门禁（支持滚动升级）
	for _, tc := range []struct {
		name    string
		mode    string
		cspMode string
	}{
		{"OFF+OFF", "OFF", "OFF"},
		{"OBSERVE+REPORT_ONLY", "OBSERVE", "REPORT_ONLY"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &GuardConfig{
				ClientSidePolicy: map[string]*GuardClientSidePolicy{"shop": testClientSidePolicy(tc.mode, tc.cspMode)},
			}
			if f := capabilityFactsFromGuard(cfg); f.ClientSideProtect {
				t.Fatalf("%s should not set ClientSideProtect", tc.name)
			}
			if ok, code, msg := pOld.evaluateCapabilityGate(context.Background(), cfg); !ok {
				t.Fatalf("%s must pass on old node: code=%s msg=%s", tc.name, code, msg)
			}
		})
	}

	// 2. Mode==PROTECT 或 CSPMode==ENFORCE 均触发 detectors.clientside=clientside/1 门禁
	for _, tc := range []struct {
		name    string
		mode    string
		cspMode string
	}{
		{"PROTECT+OFF", "PROTECT", "OFF"},
		{"OBSERVE+ENFORCE", "OBSERVE", "ENFORCE"},
		{"PROTECT+ENFORCE", "PROTECT", "ENFORCE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &GuardConfig{
				ClientSidePolicy: map[string]*GuardClientSidePolicy{"shop": testClientSidePolicy(tc.mode, tc.cspMode)},
			}
			f := capabilityFactsFromGuard(cfg)
			if !f.ClientSideProtect {
				t.Fatalf("%s must set ClientSideProtect", tc.name)
			}
			req := RequiredCapabilities(f)
			if v := detectorVersion(req, "clientside"); v != "clientside/1" {
				t.Fatalf("expected detectors.clientside=clientside/1, got %+v", req.Detectors)
			}
			if ok, code, msg := pOld.evaluateCapabilityGate(context.Background(), cfg); ok || code != "CAPABILITY_MISSING" || !strings.Contains(msg, "detectors.clientside") {
				t.Fatalf("old node must fail-closed for %s: ok=%v code=%s msg=%s", tc.name, ok, code, msg)
			}
			if ok, code, msg := pNew.evaluateCapabilityGate(context.Background(), cfg); !ok || code != "" {
				t.Fatalf("capable node must pass for %s: ok=%v code=%s msg=%s", tc.name, ok, code, msg)
			}
		})
	}
}
