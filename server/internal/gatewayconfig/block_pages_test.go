package gatewayconfig

import (
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/applications"
)

func TestBuildGuardBlockPagesConfigAndPriority(t *testing.T) {
	cfg, err := buildGuardBlockPagesConfig([]blockPageBindingRow{
		{AppCode: "", Scene: BlockPageSceneDefault, PageID: "p-g-def", PageName: "全局默认", Version: 1, HTML: "<html>g-def</html>"},
		{AppCode: "", Scene: BlockPageSceneWAF, PageID: "p-g-waf", PageName: "全局WAF", Version: 2, HTML: "<html>g-waf</html>"},
		{AppCode: "shop", Scene: BlockPageSceneDefault, PageID: "p-s-def", PageName: "商城默认", Version: 3, HTML: "<html>s-def</html>"},
		{AppCode: "shop", Scene: BlockPageSceneRateLimit, PageID: "p-s-rl", PageName: "商城限速", Version: 1, StatusCode: 429, HTML: "<html>s-rl</html>", JSONCode: "shop_limit", JSONMessage: "稍候再试"},
	})
	if err != nil {
		t.Fatalf("buildGuardBlockPagesConfig: %v", err)
	}
	if cfg == nil || cfg.IsEmpty() {
		t.Fatalf("expected non-empty config")
	}

	// shop: WAF 应优先继承 shop.DEFAULT（高于 global.WAF），RATE_LIMIT 取 shop.RATE_LIMIT
	shopResolved := cfg.ResolveForApp("shop")
	if shopResolved[BlockPageSceneWAF].PageID != "p-s-def" {
		t.Fatalf("shop WAF = %s, want p-s-def (app DEFAULT overrides global WAF)", shopResolved[BlockPageSceneWAF].PageID)
	}
	if shopResolved[BlockPageSceneRateLimit].PageID != "p-s-rl" {
		t.Fatalf("shop RATE_LIMIT = %s, want p-s-rl", shopResolved[BlockPageSceneRateLimit].PageID)
	}
	if shopResolved[BlockPageSceneAccessControl].PageID != "p-s-def" {
		t.Fatalf("shop ACCESS_CONTROL = %s, want p-s-def", shopResolved[BlockPageSceneAccessControl].PageID)
	}

	// portal（未单独配置应用绑定）：WAF 取 global.WAF，ACCESS_CONTROL/RATE_LIMIT 继承 global.DEFAULT
	portalResolved := cfg.ResolveForApp("portal")
	if portalResolved[BlockPageSceneWAF].PageID != "p-g-waf" {
		t.Fatalf("portal WAF = %s, want p-g-waf", portalResolved[BlockPageSceneWAF].PageID)
	}
	if portalResolved[BlockPageSceneAccessControl].PageID != "p-g-def" {
		t.Fatalf("portal ACCESS_CONTROL = %s, want p-g-def", portalResolved[BlockPageSceneAccessControl].PageID)
	}
}

func TestBuildGuardBlockPagesConfigValidation(t *testing.T) {
	cases := []struct {
		name string
		row  blockPageBindingRow
	}{
		{"invalid_scene", blockPageBindingRow{Scene: "OTHER", HTML: "<p>x</p>"}},
		{"empty_html", blockPageBindingRow{Scene: BlockPageSceneWAF, HTML: "  "}},
		{"oversize_html", blockPageBindingRow{Scene: BlockPageSceneWAF, HTML: strings.Repeat("a", maxGuardBlockPageHTMLBytes+1)}},
		{"bad_status", blockPageBindingRow{Scene: BlockPageSceneWAF, HTML: "<p>x</p>", StatusCode: 200}},
		{"bad_json_code", blockPageBindingRow{Scene: BlockPageSceneWAF, HTML: "<p>x</p>", JSONCode: "bad code!"}},
	}
	for _, tc := range cases {
		if _, err := buildGuardBlockPagesConfig([]blockPageBindingRow{tc.row}); err == nil {
			t.Errorf("%s: expected validation error", tc.name)
		}
	}
}

func TestGenerateInjectsBlockPagesAndZeroRegressionWhenEmpty(t *testing.T) {
	app := AppData{
		AppID: "app-uuid-1", Code: "shop", ProtectionMode: applications.ModeProtect,
		Domains:   []applications.Domain{{NormalizedHostname: "shop.example.com", HTTPEnabled: true, HTTPPort: intPtr(8080), Status: "ACTIVE"}},
		Upstreams: []applications.Upstream{{NormalizedHost: "127.0.0.1", Port: 9001, Status: "ACTIVE", Weight: 1}},
	}

	// 未配置 BlockPages：不下发 jiuzhang_block_page，不污染 guard JSON
	genEmpty, err := Generate(GenerateInput{
		Apps:        []AppData{app},
		AdminSocket: "/var/run/caddy/admin.sock",
		Guard:       testGuardConfig(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(genEmpty.JSON, "jiuzhang_block_page") || strings.Contains(genEmpty.JSON, `"block_pages"`) {
		t.Fatalf("block_pages must be omitted when nil: %s", genEmpty.JSON)
	}

	// 配置 BlockPages（纯 WAF 形态 APIDynamicProtection=false 同样下发）
	cfg := testGuardConfig()
	cfg.BlockPages = &GuardBlockPagesConfig{
		Global: map[string]*GuardBlockPageItem{
			BlockPageSceneWAF: {PageID: "p1", Version: 2, HTML: "<html><body>WAF v2</body></html>"},
		},
	}
	gen, err := Generate(GenerateInput{
		Apps:        []AppData{app},
		AdminSocket: "/var/run/caddy/admin.sock",
		Guard:       cfg,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"handler":"jiuzhang_block_page"`,
		`"host_to_app_code":{"shop.example.com":"shop"}`,
		`"block_pages"`,
		`"WAF"`,
		"WAF v2",
	} {
		if !strings.Contains(gen.JSON, want) {
			t.Errorf("generated JSON missing %q", want)
		}
	}

	// 脱敏与 stripAPIGuardSections 不得破坏 BlockPages
	redacted, err := RedactConfigSecrets(gen.JSON)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(redacted, "WAF v2") {
		t.Error("RedactConfigSecrets must preserve block_pages HTML")
	}
	stripped := stripAPIGuardSections(cfg)
	if stripped.BlockPages == nil || stripped.BlockPages.Global[BlockPageSceneWAF] == nil {
		t.Error("stripAPIGuardSections must preserve BlockPages (full product line feature)")
	}
}
