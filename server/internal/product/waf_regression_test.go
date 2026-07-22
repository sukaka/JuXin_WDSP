package product

import (
	"net/http"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/pipeline"
)

// TestAPIOffLeavesLegacyWAFPath 当 API 动态防护关闭时，统一管线跳过，调用方仍可按遗留 WAF 匹配阻断。
func TestAPIOffLeavesLegacyWAFPath(t *testing.T) {
	t.Setenv("PRODUCT_EDITION", "waf")
	t.Setenv("API_DYNAMIC_PROTECTION_ENABLED", "")
	s := Load()
	if s.APIDynamicProtection {
		t.Fatal("waf must keep API off")
	}
	r, _ := http.NewRequest(http.MethodGet, "http://h/attack?q=1", nil)
	res, err := pipeline.Process(r, pipeline.Config{Enabled: s.APIDynamicProtection}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Skipped {
		t.Fatal("pipeline must skip when API off")
	}
	// legacy WAF simulation: external block without pipeline decision
	legacy := dsctx.New("legacy-1", dsctx.DefaultParseLimits())
	legacy.AddMatch(dsctx.DetectorMatch{Detector: "waf", Severity: "HIGH", ScoreDelta: 50, Category: "BLOCK"})
	// without unified pipeline, caller decides from match — prove match recorded
	if legacy.MatchCount() != 1 {
		t.Fatal("legacy waf match missing")
	}
	// when API on, same match goes through decision
	r2, _ := http.NewRequest(http.MethodPost, "http://h/v1/x", strings.NewReader(`{"a":1}`))
	r2.Header.Set("Content-Type", "application/json")
	res2, err := pipeline.Process(r2, pipeline.Config{Enabled: true}, []dsctx.DetectorMatch{
		{Detector: "waf", Severity: "HIGH", ScoreDelta: 50, Category: "BLOCK"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res2.FinalAction != dsctx.ActionBlock {
		t.Fatalf("api-on decision=%s", res2.FinalAction)
	}
}
