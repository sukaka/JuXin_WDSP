package guardconfig

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

type fakeWasmPluginLister struct {
	configs map[string]*gatewayconfig.GuardWasmPluginsConfig
	err     error
}

func (f fakeWasmPluginLister) ListForGuard(context.Context) (map[string]*gatewayconfig.GuardWasmPluginsConfig, error) {
	return f.configs, f.err
}

func testGuardWasmPluginConfig(mode, shaHex, wasmBase64 string) *gatewayconfig.GuardWasmPluginsConfig {
	return &gatewayconfig.GuardWasmPluginsConfig{
		SchemaVersion: 1,
		ApplicationID: "app-1",
		Plugins: []gatewayconfig.GuardWasmPlugin{
			{
				ID:           "plugin-1",
				Name:         "custom-detector",
				Version:      2,
				ABIVersion:   "wdsp_v1",
				Mode:         mode,
				SHA256:       shaHex,
				WasmBase64:   wasmBase64,
				Priority:     100,
				TimeoutMs:    2,
				MaxMemoryKB:  4096,
				MaxBodyBytes: 65536,
				FailPolicy:   "FAIL_OPEN",
				PathPrefixes: []string{"/api/"},
			},
		},
	}
}

func TestLoadWasmPluginsAndFailHard(t *testing.T) {
	// 1. nil lister -> no-op
	cfg := &gatewayconfig.GuardConfig{}
	if err := (&Provider{}).loadWasmPlugins(context.Background(), cfg); err != nil {
		t.Fatalf("nil lister should succeed: %v", err)
	}
	if cfg.WasmPlugins != nil {
		t.Fatalf("expected nil WasmPlugins, got %+v", cfg.WasmPlugins)
	}

	// 2. lister 失败中止发布（fail-hard）
	pErr := &Provider{wasmPlugins: fakeWasmPluginLister{err: errors.New("db down")}}
	if err := pErr.loadWasmPlugins(context.Background(), &gatewayconfig.GuardConfig{}); err == nil {
		t.Fatal("lister error must fail-hard")
	}

	// 3. 空插件列表不下发段
	pEmpty := &Provider{wasmPlugins: fakeWasmPluginLister{configs: map[string]*gatewayconfig.GuardWasmPluginsConfig{}}}
	cfgEmpty := &gatewayconfig.GuardConfig{}
	if err := pEmpty.loadWasmPlugins(context.Background(), cfgEmpty); err != nil {
		t.Fatalf("empty map should succeed: %v", err)
	}
	if cfgEmpty.WasmPlugins != nil {
		t.Fatalf("empty map must keep WasmPlugins nil, got %+v", cfgEmpty.WasmPlugins)
	}

	// 4. 正常加载填充
	sha := strings.Repeat("1", 64)
	pOK := &Provider{wasmPlugins: fakeWasmPluginLister{
		configs: map[string]*gatewayconfig.GuardWasmPluginsConfig{
			"shop-app": testGuardWasmPluginConfig("PROTECT", sha, "AGFzbQEAAAA="),
		},
	}}
	cfgOK := &gatewayconfig.GuardConfig{}
	if err := pOK.loadWasmPlugins(context.Background(), cfgOK); err != nil {
		t.Fatalf("loadWasmPlugins: %v", err)
	}
	if cfgOK.WasmPlugins["shop-app"] == nil || len(cfgOK.WasmPlugins["shop-app"].Plugins) != 1 {
		t.Fatalf("unexpected cfg.WasmPlugins: %+v", cfgOK.WasmPlugins)
	}
}

func TestAPIPolicyVersionIncludesWasmPluginMetaNotRawBase64(t *testing.T) {
	base := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{})

	sha1 := strings.Repeat("a", 64)
	sha2 := strings.Repeat("b", 64)

	cfg1 := &gatewayconfig.GuardConfig{
		WasmPlugins: map[string]*gatewayconfig.GuardWasmPluginsConfig{
			"shop-app": testGuardWasmPluginConfig("OBSERVE", sha1, "BASE64_BLOB_ONE"),
		},
	}
	v1 := computeAPIPolicyVersion(cfg1)
	if v1 == base {
		t.Fatal("adding wasm_plugins must change api_policy_version")
	}

	// 仅改变 raw wasm_base64 而元数据与 sha256 不变时，版本戳必须保持一致（证明 raw base64 不入哈希）
	cfgSameMetaDiffBlob := &gatewayconfig.GuardConfig{
		WasmPlugins: map[string]*gatewayconfig.GuardWasmPluginsConfig{
			"shop-app": testGuardWasmPluginConfig("OBSERVE", sha1, "DIFFERENT_LARGE_BASE64_BLOB_IGNORED_BY_HASH"),
		},
	}
	if got := computeAPIPolicyVersion(cfgSameMetaDiffBlob); got != v1 {
		t.Fatalf("api_policy_version must hash plugin metadata+sha256, not raw wasm_base64: %s vs %s", v1, got)
	}

	// 改变 sha256 必须产生新版本戳
	cfgDiffSHA := &gatewayconfig.GuardConfig{
		WasmPlugins: map[string]*gatewayconfig.GuardWasmPluginsConfig{
			"shop-app": testGuardWasmPluginConfig("OBSERVE", sha2, "BASE64_BLOB_ONE"),
		},
	}
	if got := computeAPIPolicyVersion(cfgDiffSHA); got == v1 {
		t.Fatal("changing wasm plugin sha256 must change api_policy_version")
	}

	// 改变 mode 必须产生新版本戳
	cfgDiffMode := &gatewayconfig.GuardConfig{
		WasmPlugins: map[string]*gatewayconfig.GuardWasmPluginsConfig{
			"shop-app": testGuardWasmPluginConfig("PROTECT", sha1, "BASE64_BLOB_ONE"),
		},
	}
	if got := computeAPIPolicyVersion(cfgDiffMode); got == v1 {
		t.Fatal("changing wasm plugin mode must change api_policy_version")
	}
}
