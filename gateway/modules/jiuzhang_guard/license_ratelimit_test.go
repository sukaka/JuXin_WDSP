package jiuzhang_guard

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
)

// 授权配额全局限速：限额内请求放行。
func TestLicenseRateLimitAllowsWithinLimit(t *testing.T) {
	g := newTestGuard(t, Guard{AppID: "app1", LicenseMaxQPS: 3})
	for i := 0; i < 3; i++ {
		called := false
		if err := g.ServeHTTP(httptest.NewRecorder(), req("203.0.113.120:1", nil), nextHandler{&called}); err != nil || !called {
			t.Fatalf("req %d within limit should pass: %v", i, err)
		}
	}
}

// 授权配额全局限速：超限 429（Retry-After + Request ID），全局共享桶不按来源区分，且不产生 CC 事件。
func TestLicenseRateLimitExceeded429(t *testing.T) {
	g := newTestGuard(t, Guard{AppID: "app1", LicenseMaxQPS: 2})
	for i := 0; i < 2; i++ {
		called := false
		if err := g.ServeHTTP(httptest.NewRecorder(), req("203.0.113.121:1", nil), nextHandler{&called}); err != nil || !called {
			t.Fatalf("req %d should pass", i)
		}
	}
	// 第三个请求即使换来源 IP 也被同一全局桶拒绝
	rec := httptest.NewRecorder()
	called := false
	if err := g.ServeHTTP(rec, req("203.0.113.122:1", nil), nextHandler{&called}); err != nil || called {
		t.Fatalf("over-limit request should be 429: %v", err)
	}
	if rec.Code != 429 || rec.Header().Get("Retry-After") == "" || rec.Header().Get("X-Jiuzhang-Request-ID") == "" {
		t.Fatalf("429 response headers: %v %v", rec.Code, rec.Header())
	}
	// 响应不泄露授权限速内部信息
	for _, leak := range []string{"license", "global"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Fatalf("429 body leaks internals: %q contains %q", rec.Body.String(), leak)
		}
	}
	// 不产生 CC 事件（避免污染 CC 统计）
	for _, e := range g.readEvents(t) {
		if e.EventType == events.CCRequestRejected || e.EventType == events.CCThresholdExceeded || e.EventType == events.CCTempBlockCreated {
			t.Fatalf("license rate limit must not emit CC events: %+v", e)
		}
	}
}

// 授权配额全局限速：0=关闭（缺省），零行为变化。
func TestLicenseRateLimitDisabled(t *testing.T) {
	g := newTestGuard(t, Guard{AppID: "app1"})
	for i := 0; i < 10; i++ {
		called := false
		if err := g.ServeHTTP(httptest.NewRecorder(), req("203.0.113.123:1", nil), nextHandler{&called}); err != nil || !called {
			t.Fatalf("disabled limit must pass: %v", err)
		}
	}
}

// Provision 校验：license_max_qps 负数拒绝加载，不静默吞错。
func TestProvisionRejectsNegativeLicenseMaxQPS(t *testing.T) {
	g := &Guard{
		AppID:         "app1",
		EventsLog:     filepath.Join(t.TempDir(), "events.log"),
		LicenseMaxQPS: -1,
	}
	err := g.Provision(caddy.Context{Context: context.Background()})
	if err == nil || !strings.Contains(err.Error(), "license_max_qps") {
		t.Fatalf("negative license_max_qps must fail provision: %v", err)
	}
}
