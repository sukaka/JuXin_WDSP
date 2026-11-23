package jiuzhang_guard

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/l7rules"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/temporaryblock"
)

func TestURLWhitelistBypassesBlacklistL7CCButNotManualBan(t *testing.T) {
	g := newTestGuard(t, Guard{
		AppID:   "app1",
		AppCode: "shop",
		GlobalDeny: []ruleJSON{
			{ID: "deny-ip", Address: "203.0.113.10", Priority: 1},
		},
		GlobalURLAllow: []urlAllowRuleJSON{
			{ID: "url-allow-health", MatchType: "EXACT", URIPattern: "/healthz", Priority: 10},
			{ID: "url-allow-cb", MatchType: "PREFIX", URIPattern: "/api/callback", Methods: []string{"POST"}, Priority: 20},
		},
		L7Rules: &l7rules.Config{
			Rules: []l7rules.RuleJSON{{
				ID:       "l7-block-all",
				Name:     "全路径阻断",
				Priority: 1,
				Enabled:  true,
				Conditions: []l7rules.ConditionJSON{
					{Type: "uri", Op: "prefix", Value: "/"},
				},
				Action: "block",
			}},
		},
		RateLimits: []policyJSON{{
			ID: "cc-strict", Dimension: "CLIENT_IP", Algorithm: "TOKEN_BUCKET",
			URIMatchType: "ALL", RequestsLimit: 1, WindowSeconds: 60, BurstCapacity: 1,
			Action: "REJECT", Priority: 1,
		}},
	})

	// 1. 黑名单 IP 访问 URL 白名单路径 /healthz：跳过黑名单、L7 与 CC，进入下游 next（模拟 WAF/源站）
	r1 := httptest.NewRequest(http.MethodGet, "http://shop.example.com/healthz?probe=1", nil)
	r1.RemoteAddr = "203.0.113.10:1234"
	r1.Header.Set("X-Request-Id", "req-url-allow-1")
	called := false
	if err := g.ServeHTTP(httptest.NewRecorder(), r1, nextHandler{&called}); err != nil || !called {
		t.Fatalf("whitelisted URL should bypass IP deny/L7/CC and reach next: err=%v called=%v", err, called)
	}

	// 2. 方法限定：POST /api/callback/order 放行，GET /api/callback/order 不命中 URL 白名单（被黑名单拒绝）
	r2 := httptest.NewRequest(http.MethodPost, "http://shop.example.com/api/callback/order", nil)
	r2.RemoteAddr = "203.0.113.10:1234"
	r2.Header.Set("X-Request-Id", "req-url-allow-2")
	called = false
	if err := g.ServeHTTP(httptest.NewRecorder(), r2, nextHandler{&called}); err != nil || !called {
		t.Fatalf("POST /api/callback/order should pass: err=%v called=%v", err, called)
	}

	r3 := httptest.NewRequest(http.MethodGet, "http://shop.example.com/api/callback/order", nil)
	r3.RemoteAddr = "203.0.113.10:1234"
	r3.Header.Set("X-Request-Id", "req-url-deny-3")
	called = false
	if err := g.ServeHTTP(httptest.NewRecorder(), r3, nextHandler{&called}); err == nil || called {
		t.Fatalf("GET /api/callback/order should be denied by IP blacklist: err=%v called=%v", err, called)
	}

	// 3. 路径穿越不得借前缀白名单逃逸：POST /api/callback/../admin/reset 被黑名单拒绝
	r4 := httptest.NewRequest(http.MethodPost, "http://shop.example.com/api/callback/../admin/reset", nil)
	r4.RemoteAddr = "203.0.113.10:1234"
	r4.Header.Set("X-Request-Id", "req-url-traversal-4")
	called = false
	if err := g.ServeHTTP(httptest.NewRecorder(), r4, nextHandler{&called}); err == nil || called {
		t.Fatalf("traversal out of prefix must not bypass blacklist: err=%v called=%v", err, called)
	}

	// 4. 人工临时封禁优先于 URL 白名单（安全底线）
	g.engine.blockCache.PutLocal(reqCtx(), temporaryblock.Block{
		ID: "manual-ban-1", ClientIP: "203.0.113.20", AppID: "app1",
		ExpiresAt: time.Now().Add(time.Hour), Auto: false,
	})
	r5 := httptest.NewRequest(http.MethodGet, "http://shop.example.com/healthz", nil)
	r5.RemoteAddr = "203.0.113.20:1234"
	r5.Header.Set("X-Request-Id", "req-manual-ban-5")
	called = false
	if err := g.ServeHTTP(httptest.NewRecorder(), r5, nextHandler{&called}); err == nil || called {
		t.Fatalf("manual ban must NOT be bypassed by URL whitelist: err=%v called=%v", err, called)
	}

	// 5. 自动 CC 封禁可由 URL 白名单绕过
	g.engine.blockCache.PutLocal(reqCtx(), temporaryblock.Block{
		ID: "auto-ban-1", ClientIP: "203.0.113.30", AppID: "app1",
		ExpiresAt: time.Now().Add(time.Hour), Auto: true,
	})
	r6 := httptest.NewRequest(http.MethodGet, "http://shop.example.com/healthz", nil)
	r6.RemoteAddr = "203.0.113.30:1234"
	r6.Header.Set("X-Request-Id", "req-auto-ban-bypass-6")
	called = false
	if err := g.ServeHTTP(httptest.NewRecorder(), r6, nextHandler{&called}); err != nil || !called {
		t.Fatalf("auto CC ban should be bypassed by URL whitelist: err=%v called=%v", err, called)
	}

	// 6. 验证事件日志：URL_ALLOW_MATCH 携带 AccessRuleID 且不挂 FinalDecision（放行非终止）
	var allowEvents int
	for _, ev := range g.readEvents(t) {
		if ev.EventType == events.URLAllowMatch {
			allowEvents++
			if ev.Action != "ALLOW" || ev.AccessRuleID == "" {
				t.Errorf("unexpected URL_ALLOW_MATCH event: %+v", ev)
			}
			if len(ev.FinalDecision) != 0 {
				t.Errorf("URL_ALLOW_MATCH should not attach final_decision: %s", ev.FinalDecision)
			}
		}
	}
	if allowEvents != 3 {
		t.Fatalf("expected 3 URL_ALLOW_MATCH events, got %d", allowEvents)
	}
}
