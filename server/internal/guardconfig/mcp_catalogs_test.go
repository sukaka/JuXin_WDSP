// mcp_catalogs_test.go MCP 工具目录与绑定下发单测（NG-MCP G1 批次 B1，纯函数不依赖
// 数据库）：两加载器未注入/查询失败 Warn 跳过返回 nil（空段=网关 MCP 管控零行为）、
// 正常读取透传（形状+稳定序）；jwt_trust 覆盖发布校验警示谓词两态（§1.5/§1.14）。
// APPROVED-only 语义由 PG 契约测试（SQL review_status='APPROVED' 过滤）覆盖。
package guardconfig

import (
	"context"
	"errors"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// fakeMCPCatalogLister 内存版 MCP 目录读取（可注入错误路径）。
type fakeMCPCatalogLister struct {
	catalogs []gatewayconfig.GuardMCPToolCatalog
	err      error
}

func (f *fakeMCPCatalogLister) ListEnabledMCPCatalogs(ctx context.Context) ([]gatewayconfig.GuardMCPToolCatalog, error) {
	_ = ctx
	return f.catalogs, f.err
}

// fakeMCPBindingLister 内存版 MCP 绑定读取（可注入错误路径）。
type fakeMCPBindingLister struct {
	bindings []gatewayconfig.GuardMCPBinding
	err      error
}

func (f *fakeMCPBindingLister) ListAllMCPBindings(ctx context.Context) ([]gatewayconfig.GuardMCPBinding, error) {
	_ = ctx
	return f.bindings, f.err
}

// TestLoadAPIMCPToolCatalogsTolerance 目录段：未注入 nil；查询失败（如 000181 表未
// 建立）Warn 跳过返回 nil（空段=零行为，不 fail-hard 拖垮发布）；正常读取透传
// （目录头+APPROVED 工具行形状原样——APPROVED-only 过滤在 SQL 层，PG 契约覆盖）。
func TestLoadAPIMCPToolCatalogsTolerance(t *testing.T) {
	p := &Provider{}
	if got := p.loadAPIMCPToolCatalogs(context.Background()); got != nil {
		t.Fatalf("nil lister must yield nil: %v", got)
	}
	p = &Provider{mcpCatalogs: &fakeMCPCatalogLister{err: errors.New(`relation "mcp_tool_catalogs" does not exist`)}}
	if got := p.loadAPIMCPToolCatalogs(context.Background()); got != nil {
		t.Fatalf("missing table must be tolerated: %v", got)
	}
	rows := []gatewayconfig.GuardMCPToolCatalog{{
		Name: "pay-mcp", ServiceIdentity: "mcp://pay.example.com", ProtocolVersion: "2025-11-25",
		CatalogHash: "mcp-catalog-sha256:v1:abc",
		Tools: []gatewayconfig.GuardMCPTool{{
			ToolName: "refund", ToolVersion: "1.0.0", ToolHash: "mcp-tool-sha256:v1:def",
			PinnedDefinitionHash: "mcp-def-sha256:v1:0123", PinEnforcement: "PROTECT",
			RiskLevel: "HIGH", DataClassification: "UNKNOWN",
		}},
	}}
	p = &Provider{mcpCatalogs: &fakeMCPCatalogLister{catalogs: rows}}
	got := p.loadAPIMCPToolCatalogs(context.Background())
	if len(got) != 1 || got[0].Name != "pay-mcp" || len(got[0].Tools) != 1 ||
		got[0].Tools[0].ToolHash != "mcp-tool-sha256:v1:def" ||
		got[0].Tools[0].PinnedDefinitionHash != "mcp-def-sha256:v1:0123" ||
		got[0].Tools[0].PinEnforcement != "PROTECT" {
		t.Fatalf("目录段透传: %+v", got)
	}
}

// TestLoadAPIMCPBindingsTolerance 绑定段：未注入 nil；查询失败 Warn 跳过返回 nil；
// 正常读取透传（application_id/endpoint_path/catalog_name/mode 全字段+顺序原样）。
func TestLoadAPIMCPBindingsTolerance(t *testing.T) {
	p := &Provider{}
	if got := p.loadAPIMCPBindings(context.Background()); got != nil {
		t.Fatalf("nil lister must yield nil: %v", got)
	}
	p = &Provider{mcpBindings: &fakeMCPBindingLister{err: errors.New(`relation "mcp_catalog_bindings" does not exist`)}}
	if got := p.loadAPIMCPBindings(context.Background()); got != nil {
		t.Fatalf("missing table must be tolerated: %v", got)
	}
	rows := []gatewayconfig.GuardMCPBinding{
		{ApplicationID: "a1", EndpointPath: "/mcp/pay", CatalogName: "pay-mcp", Mode: "OBSERVE", ResponseGuardMode: "OBSERVE"},
		{ApplicationID: "a2", EndpointPath: "/mcp/refund", CatalogName: "pay-mcp", Mode: "PROTECT", ResponseGuardMode: "SANITIZE", RequireSessionBinding: true, OAuthResourceMetadataURL: "https://mcp.example.com/.well-known/oauth-protected-resource"},
	}
	p = &Provider{mcpBindings: &fakeMCPBindingLister{bindings: rows}}
	got := p.loadAPIMCPBindings(context.Background())
	if len(got) != 2 || got[0].Mode != "OBSERVE" || got[1].EndpointPath != "/mcp/refund" || got[1].Mode != "PROTECT" ||
		got[1].ResponseGuardMode != "SANITIZE" || !got[1].RequireSessionBinding ||
		got[1].OAuthResourceMetadataURL != "https://mcp.example.com/.well-known/oauth-protected-resource" {
		t.Fatalf("绑定段透传: %+v", got)
	}
}

// TestMCPEndpointCoveredByJWTTrust 覆盖谓词两态（§1.5 组合要求）：
// 覆盖 = 应用存在策略 && mode≠OFF && selector 覆盖路径（exact 相等或 prefix 段边界）。
func TestMCPEndpointCoveredByJWTTrust(t *testing.T) {
	appID := "11111111-1111-1111-1111-111111111111"
	policies := map[string]*gatewayconfig.GuardJWTTrustPolicy{
		"pay": {
			ApplicationID: appID,
			Mode:          "PROTECT",
			Selectors: []gatewayconfig.GuardJWTSelector{
				{Methods: []string{"POST"}, PathPrefix: "/mcp", TokenRequired: true},
				{Methods: []string{"POST"}, PathExact: "/rpc/health"},
			},
		},
		"off": {
			ApplicationID: "22222222-2222-2222-2222-222222222222",
			Mode:          "OFF",
			Selectors:     []gatewayconfig.GuardJWTSelector{{Methods: []string{"POST"}, PathPrefix: "/mcp"}},
		},
	}
	cases := []struct {
		name    string
		pols    map[string]*gatewayconfig.GuardJWTTrustPolicy
		app, ep string
		covered bool
	}{
		{"prefix 段边界覆盖", policies, appID, "/mcp/pay", true},
		{"prefix 自身相等覆盖", policies, appID, "/mcp", true},
		{"exact 覆盖", policies, appID, "/rpc/health", true},
		{"段边界不误配（/mcpx 不算 /mcp）", policies, appID, "/mcpx", false},
		{"未覆盖路径", policies, appID, "/other/api", false},
		{"应用无策略", policies, "33333333-3333-3333-3333-333333333333", "/mcp/pay", false},
		{"策略 OFF 不算覆盖", policies, "22222222-2222-2222-2222-222222222222", "/mcp/pay", false},
		{"空策略表", map[string]*gatewayconfig.GuardJWTTrustPolicy{}, appID, "/mcp/pay", false},
		{"nil 策略表", nil, appID, "/mcp/pay", false},
	}
	for _, c := range cases {
		if got := mcpEndpointCoveredByJWTTrust(c.pols, c.app, c.ep); got != c.covered {
			t.Fatalf("%s: covered=%t, want %t", c.name, got, c.covered)
		}
	}
}

// TestWarnMCPJWTTrustCoverage 警示函数形态：OBSERVE 绑定与已覆盖 PROTECT 不警示；
// 未覆盖 PROTECT 警示（非阻断——函数无返回值/不 panic；nil 配置安全）。
func TestWarnMCPJWTTrustCoverage(t *testing.T) {
	warnMCPJWTTrustCoverage(nil) // nil 安全
	appID := "11111111-1111-1111-1111-111111111111"
	cfg := &gatewayconfig.GuardConfig{
		APIMCPBindings: []gatewayconfig.GuardMCPBinding{
			{ApplicationID: appID, EndpointPath: "/mcp/pay", CatalogName: "pay-mcp", Mode: "OBSERVE"},
			{ApplicationID: appID, EndpointPath: "/mcp/covered", CatalogName: "pay-mcp", Mode: "PROTECT"},
			{ApplicationID: appID, EndpointPath: "/uncovered", CatalogName: "pay-mcp", Mode: "PROTECT"},
		},
		JWTTrust: map[string]*gatewayconfig.GuardJWTTrustPolicy{
			"pay": {ApplicationID: appID, Mode: "PROTECT",
				Selectors: []gatewayconfig.GuardJWTSelector{{Methods: []string{"POST"}, PathPrefix: "/mcp"}}},
		},
	}
	// 不 panic 即非阻断形态成立；警示内容谓词已由 TestMCPEndpointCoveredByJWTTrust 锚定
	warnMCPJWTTrustCoverage(cfg)
	if mcpEndpointCoveredByJWTTrust(cfg.JWTTrust, appID, "/uncovered") {
		t.Fatal("/uncovered 不应被判定覆盖")
	}
	if !mcpEndpointCoveredByJWTTrust(cfg.JWTTrust, appID, "/mcp/covered") {
		t.Fatal("/mcp/covered 应被判定覆盖")
	}
}
