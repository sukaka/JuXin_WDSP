package jiuzhang_guard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func TestRiskPolicyApplicationOverrideUsesScopedThreshold(t *testing.T) {
	appID := "app-risk-override"
	g := provisionIBHTestGuard(t, Guard{
		AppID: appID, EventsLog: filepath.Join(t.TempDir(), "events.log"), IdentitySalt: "test-salt",
		RiskPolicy: &riskPolicyJSON{Enabled: true, Mode: "OBSERVE", BlockThreshold: 80, RateLimitThreshold: 40},
		RiskPolicyOverrides: []riskPolicyOverrideJSON{{
			ApplicationID: appID,
			Policy:        riskPolicyJSON{Enabled: true, Mode: "PROTECT", Version: 11, BlockThreshold: 10, RateLimitThreshold: 5, RateLimitRPS: 10, SignalWindowSeconds: 3600},
		}},
	})
	eng := g.riskEngineForApp()
	if eng == nil || eng.Config().BlockThreshold != 10 || eng.Config().Version != 11 {
		t.Fatalf("override engine=%+v", eng)
	}
	req := httptest.NewRequest(http.MethodGet, "http://waf-test.local/", nil)
	req.RemoteAddr = "203.0.113.50:1234"
	g.feedRiskSignals(req, []dsctx.DetectorMatch{{Detector: "WAF", Category: "OBSERVE", ScoreDelta: 15}})
	rec, called, err := riskServe(t, g, req.RemoteAddr, "http://waf-test.local/", "", http.StatusOK)
	var handlerErr caddyhttp.HandlerError
	if !errors.As(err, &handlerErr) || handlerErr.StatusCode != http.StatusForbidden || called {
		t.Fatalf("override must block without calling upstream: code=%d err=%v called=%v", rec.Code, err, called)
	}
	events := riskEvents(t, g.EventsLog)
	if len(events) != 1 {
		t.Fatalf("risk events=%d", len(events))
	}
	risk, ok := events[0]["risk"].(map[string]any)
	if !ok || risk["policy_version"] != float64(11) || risk["score"] != float64(15) {
		t.Fatalf("risk event=%+v", events[0])
	}
}

func TestRiskPolicyApplicationOverrideIsolationAndDefault(t *testing.T) {
	overrideApp := "app-risk-override"
	otherApp := "app-risk-other"
	g := provisionIBHTestGuard(t, Guard{
		AppID: otherApp, EventsLog: filepath.Join(t.TempDir(), "events.log"), IdentitySalt: "test-salt",
		RiskPolicy: &riskPolicyJSON{Enabled: true, Mode: "OBSERVE", BlockThreshold: 80, RateLimitThreshold: 40},
		RiskPolicyOverrides: []riskPolicyOverrideJSON{{
			ApplicationID: overrideApp, Policy: riskPolicyJSON{Enabled: true, Mode: "PROTECT", BlockThreshold: 10, RateLimitThreshold: 5},
		}},
	})
	if g.riskEngineForApp() != g.risk {
		t.Fatal("application without override must inherit global engine")
	}
	if g.riskIdentityKey("base-key") != "base-key" {
		t.Fatal("default identity key changed")
	}
	req := httptest.NewRequest(http.MethodGet, "http://waf-test.local/", nil)
	req.RemoteAddr = "203.0.113.51:1234"
	g.feedRiskSignals(req, []dsctx.DetectorMatch{{Detector: "WAF", Category: "OBSERVE", ScoreDelta: 15}})
	_, called, err := riskServe(t, g, req.RemoteAddr, "http://waf-test.local/", "", http.StatusOK)
	if err != nil || !called {
		t.Fatalf("other application must retain global OBSERVE behavior: err=%v called=%v", err, called)
	}
}

func TestRiskPolicyApplicationOverrideExplicitlyDisabled(t *testing.T) {
	appID := "app-risk-disabled"
	g := provisionIBHTestGuard(t, Guard{
		AppID: appID, EventsLog: filepath.Join(t.TempDir(), "events.log"), IdentitySalt: "test-salt",
		RiskPolicy:          &riskPolicyJSON{Enabled: true, Mode: "PROTECT", BlockThreshold: 10, RateLimitThreshold: 5},
		RiskPolicyOverrides: []riskPolicyOverrideJSON{{ApplicationID: appID, Policy: riskPolicyJSON{Enabled: false}}},
	})
	if g.riskEngineForApp() != nil {
		t.Fatal("explicitly disabled override must not inherit global enforcement")
	}
	req := httptest.NewRequest(http.MethodGet, "http://waf-test.local/", nil)
	req.RemoteAddr = "203.0.113.52:1234"
	g.feedRiskSignals(req, []dsctx.DetectorMatch{{Detector: "WAF", Category: "OBSERVE", ScoreDelta: 50}})
	_, called, err := riskServe(t, g, req.RemoteAddr, "http://waf-test.local/", "", http.StatusOK)
	if err != nil || !called {
		t.Fatalf("disabled override must pass without enforcement: err=%v called=%v", err, called)
	}
}
