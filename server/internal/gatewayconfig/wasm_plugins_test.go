package gatewayconfig

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/capability"
)

func testWasmPlugin(id, name, mode string, priority int) GuardWasmPlugin {
	return GuardWasmPlugin{
		ID:           id,
		Name:         name,
		Version:      1,
		ABIVersion:   "wdsp_v1",
		Mode:         mode,
		SHA256:       strings.Repeat("a", 64),
		WasmBase64:   "AGFzbQEAAAA=",
		Priority:     priority,
		TimeoutMs:    2,
		MaxMemoryKB:  4096,
		MaxBodyBytes: 65536,
		FailPolicy:   "FAIL_OPEN",
		PathPrefixes: []string{"/api/"},
	}
}

func TestBuildGuardHandlerWasmPluginsMergeAndStrip(t *testing.T) {
	g := testGuardConfig()
	g.APIDynamicProtection = true
	g.APIProtectionMode = "PROTECT"
	g.WasmPlugins = map[string]*GuardWasmPluginsConfig{
		WasmPluginsGlobalScopeKey: {
			SchemaVersion: 1,
			Plugins:       []GuardWasmPlugin{testWasmPlugin("p-global", "global-bot", "OBSERVE", 200)},
		},
		"shop-app": {
			SchemaVersion: 1,
			ApplicationID: "8b1a2c3d-0000-4000-8000-000000000099",
			Plugins:       []GuardWasmPlugin{testWasmPlugin("p-app", "shop-rule", "PROTECT", 50)},
		},
	}

	// 1. 本应用合并全局 + 应用级插件并按 priority 升序排序，字段符合冻结契约
	h := buildGuardHandler(g, AppData{AppID: "8b1a2c3d-0000-4000-8000-000000000099", Code: "shop-app"}, 0)
	wp, ok := h["wasm_plugins"].(*GuardWasmPluginsConfig)
	if !ok || wp == nil {
		t.Fatalf("wasm_plugins missing: %T", h["wasm_plugins"])
	}
	if wp.SchemaVersion != 1 || wp.ApplicationID != "8b1a2c3d-0000-4000-8000-000000000099" {
		t.Fatalf("unexpected header fields: %+v", wp)
	}
	if len(wp.Plugins) != 2 || wp.Plugins[0].ID != "p-app" || wp.Plugins[1].ID != "p-global" {
		t.Fatalf("expected priority-sorted merged plugins [p-app, p-global], got %+v", wp.Plugins)
	}
	raw, err := json.Marshal(wp)
	if err != nil {
		t.Fatalf("marshal wasm_plugins: %v", err)
	}
	for _, want := range []string{
		`"schema_version":1`,
		`"application_id":"8b1a2c3d-0000-4000-8000-000000000099"`,
		`"abi_version":"wdsp_v1"`,
		`"mode":"PROTECT"`,
		`"sha256":"` + strings.Repeat("a", 64) + `"`,
		`"wasm_base64":"AGFzbQEAAAA="`,
		`"priority":50`,
		`"timeout_ms":2`,
		`"max_memory_kb":4096`,
		`"max_body_bytes":65536`,
		`"fail_policy":"FAIL_OPEN"`,
		`"path_prefixes":["/api/"]`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("wasm_plugins JSON missing %s: %s", want, raw)
		}
	}

	// 2. 其他应用仅继承全局插件，不泄漏 shop-app 私有插件
	hOther := buildGuardHandler(g, AppData{AppID: "app-2", Code: "other"}, 0)
	wpOther, ok := hOther["wasm_plugins"].(*GuardWasmPluginsConfig)
	if !ok || wpOther == nil || len(wpOther.Plugins) != 1 || wpOther.Plugins[0].ID != "p-global" || wpOther.ApplicationID != "app-2" {
		t.Fatalf("other app should only inherit global plugin, got %+v", wpOther)
	}

	// 3. WDSP 关闭时不下发
	gOff := *g
	gOff.APIDynamicProtection = false
	hOff := buildGuardHandler(&gOff, AppData{AppID: "app-1", Code: "shop-app"}, 0)
	if _, exists := hOff["wasm_plugins"]; exists {
		t.Fatal("wasm_plugins must be gated by APIDynamicProtection")
	}

	// 4. stripAPIGuardSections 剥除且不修改原配置
	stripped := stripAPIGuardSections(g)
	if stripped.WasmPlugins != nil {
		t.Fatalf("stripAPIGuardSections must drop WasmPlugins, got %+v", stripped.WasmPlugins)
	}
	if g.WasmPlugins == nil {
		t.Fatal("stripAPIGuardSections must not mutate input")
	}
}

func TestCapabilityGateWasmPluginProtect(t *testing.T) {
	oldDir := t.TempDir()
	writeManifest(t, oldDir, fullManifest("gw-old", time.Now().UTC()))
	pOld := &Publisher{sidecarDir: oldDir}

	newDir := t.TempDir()
	m := fullManifest("gw-new", time.Now().UTC())
	m.Detectors = append(m.Detectors, capability.DetectorCap{Name: "wasmplugin", Version: "wasm/1"})
	writeManifest(t, newDir, m)
	pNew := &Publisher{sidecarDir: newDir}

	// 1. OFF / OBSERVE 不触发能力门禁（支持滚动升级）
	for _, mode := range []string{"OFF", "OBSERVE"} {
		cfg := &GuardConfig{
			WasmPlugins: map[string]*GuardWasmPluginsConfig{
				"shop-app": {
					SchemaVersion: 1,
					ApplicationID: "app-1",
					Plugins:       []GuardWasmPlugin{testWasmPlugin("p-1", "obs", mode, 100)},
				},
			},
		}
		if f := capabilityFactsFromGuard(cfg); f.WasmPluginProtect {
			t.Fatalf("%s must not set WasmPluginProtect", mode)
		}
		if ok, code, msg := pOld.evaluateCapabilityGate(context.Background(), cfg); !ok {
			t.Fatalf("%s must pass on old node: code=%s msg=%s", mode, code, msg)
		}
	}

	// 2. PROTECT 触发 detectors.wasmplugin=wasm/1 门禁
	cfgProtect := &GuardConfig{
		WasmPlugins: map[string]*GuardWasmPluginsConfig{
			"shop-app": {
				SchemaVersion: 1,
				ApplicationID: "app-1",
				Plugins:       []GuardWasmPlugin{testWasmPlugin("p-1", "blk", "PROTECT", 100)},
			},
		},
	}
	f := capabilityFactsFromGuard(cfgProtect)
	if !f.WasmPluginProtect {
		t.Fatal("PROTECT must set WasmPluginProtect")
	}
	req := RequiredCapabilities(f)
	if v := detectorVersion(req, "wasmplugin"); v != "wasm/1" {
		t.Fatalf("expected detectors.wasmplugin=wasm/1, got %+v", req.Detectors)
	}
	if ok, code, msg := pOld.evaluateCapabilityGate(context.Background(), cfgProtect); ok || code != "CAPABILITY_MISSING" || !strings.Contains(msg, "detectors.wasmplugin") {
		t.Fatalf("old node must fail-closed for wasmplugin PROTECT: ok=%v code=%s msg=%s", ok, code, msg)
	}
	if ok, code, msg := pNew.evaluateCapabilityGate(context.Background(), cfgProtect); !ok || code != "" {
		t.Fatalf("capable node must pass for wasmplugin PROTECT: ok=%v code=%s msg=%s", ok, code, msg)
	}
}
