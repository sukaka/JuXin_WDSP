package apiruntime

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/server/internal/apiassets"
)

func TestCollectOnce_FiltersStaticAndNonAPIButKeepsAlertsAndGRPC(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	cpPath := filepath.Join(dir, "checkpoint")
	now := time.Now().UTC()

	records := []Record{
		// 1) 非 API 的 HTML 页面（仅带 Cookie INFO 明细）：既不入资产表也不入主事件表
		{
			RequestID: "r-html", EndpointKey: "GET /products", Method: "GET", PathTemplate: "/products",
			IsAPI: false, APIConfidence: 0, FinalAction: "ALLOW", RiskLevel: "NONE",
			Details:    []dsctx.DetectorMatch{{Detector: "identity", RuleID: "identity.cookie_present", Category: "INFO", Severity: "INFO"}},
			OccurredAt: now,
		},
		// 2) 静态 JS 资源即使误标 IsAPI=true，也被默认静态规则挡在资产表外
		{
			RequestID: "r-js", EndpointKey: "GET /astro/page.BsuiZEAU.js", Method: "GET", PathTemplate: "/astro/page.BsuiZEAU.js",
			IsAPI: true, APIConfidence: 0.5, FinalAction: "ALLOW", RiskLevel: "NONE", OccurredAt: now,
		},
		// 3) 静态图片带攻击命中 WAF：主事件照常入库，但绝不写入 API 资产表
		{
			RequestID: "r-png-attack", EndpointKey: "GET /备案图标.png", Method: "GET", PathTemplate: "/备案图标.png",
			IsAPI: false, APIConfidence: 0, FinalAction: "BLOCK", RiskLevel: "HIGH", RiskScore: 50,
			Details:    []dsctx.DetectorMatch{{Detector: "waf", RuleID: "942100", Category: "BLOCK", Severity: "CRITICAL", ScoreDelta: 50}},
			OccurredAt: now,
		},
		// 4) 静态压缩包下载直链：不写入 API 资产表
		{
			RequestID: "r-zip", EndpointKey: "GET /downloads/app.tar.gz", Method: "GET", PathTemplate: "/downloads/app.tar.gz",
			IsAPI: true, APIConfidence: 0.4, FinalAction: "ALLOW", RiskLevel: "NONE", OccurredAt: now,
		},
		// 5) 真实 JSON API：正常发现入库
		{
			RequestID: "r-api", EndpointKey: "GET /orders/list", Method: "GET", PathTemplate: "/orders/list",
			IsAPI: true, APIConfidence: 0.35, Protocol: "REST_JSON", FinalAction: "ALLOW", RiskLevel: "NONE", OccurredAt: now,
		},
		// 6) gRPC 结构性协议（即使 IsAPI=false）：自动按有效 API 发现入库
		{
			RequestID: "r-grpc", EndpointKey: "POST /pkg.OrderService/GetOrder", Method: "POST", PathTemplate: "/pkg.OrderService/GetOrder",
			IsAPI: false, APIConfidence: 0, Protocol: "GRPC", FinalAction: "ALLOW", RiskLevel: "NONE", OccurredAt: now,
		},
	}

	lines := make([]string, 0, len(records))
	for _, r := range records {
		lines = append(lines, mustJSON(t, r))
	}
	writeLines(t, logPath, lines)

	saver := &fakeSaver{}
	disc := &fakeDiscovery{}
	c := NewCollector(saver, "test-filter", logPath, cpPath, "node-1")
	c.SetDiscoveryUpserter(disc)

	if _, err := c.CollectOnce(context.Background()); err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}

	// 资产表仅允许 r-api 和 r-grpc 两条
	if len(disc.calls) != 2 {
		t.Fatalf("want 2 discovered API endpoints, got %d: %+v", len(disc.calls), disc.calls)
	}
	if disc.calls[0].in.PathTemplate != "/orders/list" || !disc.calls[0].in.IsAPI {
		t.Fatalf("unexpected 1st discovery: %+v", disc.calls[0].in)
	}
	if disc.calls[1].in.PathTemplate != "/pkg.OrderService/GetOrder" || !disc.calls[1].in.IsAPI || disc.calls[1].in.ProtocolType != "GRPC" {
		t.Fatalf("unexpected 2nd discovery (gRPC): %+v", disc.calls[1].in)
	}

	// 主事件表应保留 r-png-attack（不因静态过滤丢失安全告警），且不写入纯 Cookie INFO 的 r-html
	if len(saver.saved) != 1 || saver.saved[0].RequestID != "r-png-attack" {
		t.Fatalf("want only r-png-attack in primary events, got %+v", saver.saved)
	}
}

func TestCollectOnce_CustomDiscoveryFilterPrefixAndWhitelist(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	cpPath := filepath.Join(dir, "checkpoint")
	now := time.Now().UTC()

	writeLines(t, logPath, []string{
		mustJSON(t, Record{
			RequestID: "r-astro", EndpointKey: "GET /astro/chunk", Method: "GET", PathTemplate: "/astro/chunk",
			IsAPI: true, APIConfidence: 0.5, FinalAction: "ALLOW", OccurredAt: now,
		}),
		mustJSON(t, Record{
			RequestID: "r-white", EndpointKey: "GET /api/public/logo.png", Method: "GET", PathTemplate: "/api/public/logo.png",
			IsAPI: true, APIConfidence: 0.6, FinalAction: "ALLOW", OccurredAt: now,
		}),
	})

	saver := &fakeSaver{}
	disc := &fakeDiscovery{}
	c := NewCollector(saver, "test-custom", logPath, cpPath, "node-1")
	c.SetDiscoveryUpserter(disc)
	c.SetDiscoveryFilter(func(context.Context) apiassets.DiscoveryFilterConfig {
		cfg := apiassets.DefaultDiscoveryFilterConfig()
		cfg.ExcludePathPrefixes = []string{"/astro"}
		cfg.IncludePathPrefixes = []string{"/api/public"}
		return cfg
	})

	if _, err := c.CollectOnce(context.Background()); err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if len(disc.calls) != 1 || disc.calls[0].in.PathTemplate != "/api/public/logo.png" {
		t.Fatalf("custom filter mismatch, got: %+v", disc.calls)
	}
}
