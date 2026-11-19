package gatewayconfig

import (
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/applications"
)

func TestVersionDisclosureResponseHeadersAlwaysHidden(t *testing.T) {
	cases := []struct {
		name string
		cfg  *AppHeaderConfig
	}{
		{name: "default"},
		{name: "legacy keep", cfg: &AppHeaderConfig{ServerAction: "keep", XPoweredByAction: "keep"}},
		{name: "legacy replace and custom readd", cfg: &AppHeaderConfig{
			ServerAction: "replace", ServerValue: "nginx/1.27.0",
			XPoweredByAction: "replace", XPoweredByValue: "PHP/8.4.0",
			CustomResponseRules: []HeaderRule{
				{Name: "Via", Method: "set", Value: "1.1 Caddy"},
				{Name: "x-postgresql-version", Method: "add", Value: "16.4"},
				{Name: "X-Safe", Method: "set", Value: "ok"},
			},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := buildHeaderHandler(tc.cfg)
			response := handler["response"].(mapT)
			if deferred, ok := response["deferred"].(bool); !ok || !deferred {
				t.Fatal("版本头清理必须在响应写出前执行")
			}
			deleted := make(map[string]bool)
			for _, name := range response["delete"].([]string) {
				deleted[strings.ToLower(name)] = true
			}
			for _, name := range versionDisclosureResponseHeaders {
				if !deleted[strings.ToLower(name)] {
					t.Errorf("缺少固定删除头 %s", name)
				}
			}
			for _, operation := range []string{"set", "add"} {
				values, ok := response[operation].(map[string][]string)
				if !ok {
					continue
				}
				for name := range values {
					if isVersionDisclosureResponseHeader(name) {
						t.Errorf("%s 不应重新设置版本头 %s", operation, name)
					}
				}
			}
		})
	}
}

func TestHeaderHandlerKeepsNonVersionCustomRules(t *testing.T) {
	cfg := &AppHeaderConfig{
		XAuthorAction: "replace", XAuthorValue: "security-team",
		CustomResponseRules: []HeaderRule{{Name: "X-Safe", Method: "set", Value: "ok"}},
	}
	response := buildHeaderHandler(cfg)["response"].(mapT)
	set := response["set"].(map[string][]string)
	if got := set["X-Author"]; len(got) != 1 || got[0] != "security-team" {
		t.Fatalf("X-Author 自定义行为被改变: %v", got)
	}
	if got := set["X-Safe"]; len(got) != 1 || got[0] != "ok" {
		t.Fatalf("普通自定义响应头被改变: %v", got)
	}
}

func TestH15StripPrefixPlacedAfterGuardAndWAFBeforeReverseProxy(t *testing.T) {
	app := AppData{
		AppID:          "app-1",
		Code:           "portal",
		ProtectionMode: applications.ModeProtect,
		PathRoutes: []AppPathRoute{
			{
				PathPrefix:     "/admin",
				UpstreamScheme: "http",
				UpstreamHost:   "2001:db8::10",
				UpstreamPort:   8080,
				StripPrefix:    true,
				Priority:       10,
			},
		},
	}
	entries := pathRouteEntries(GenerateInput{Guard: testGuardConfig()}, app, []string{"portal.example.com"}, 80)
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	handles, ok := entries[0].route["handle"].([]interface{})
	if !ok {
		t.Fatalf("handle type = %T, want []interface{}", entries[0].route["handle"])
	}
	var guardIdx, wafIdx, rewriteIdx, proxyIdx = -1, -1, -1, -1
	for i, raw := range handles {
		h := raw.(mapT)
		switch h["handler"] {
		case "jiuzhang_guard":
			guardIdx = i
		case "waf":
			wafIdx = i
		case "rewrite":
			rewriteIdx = i
			if h["strip_path_prefix"] != "/admin" {
				t.Fatalf("strip_path_prefix = %v, want /admin", h["strip_path_prefix"])
			}
		case "reverse_proxy":
			proxyIdx = i
			ups := h["upstreams"].([]interface{})
			dial := ups[0].(mapT)["dial"].(string)
			if dial != "[2001:db8::10]:8080" {
				t.Fatalf("IPv6 upstream dial = %q, want [2001:db8::10]:8080", dial)
			}
		}
	}
	if guardIdx < 0 || wafIdx < 0 || rewriteIdx < 0 || proxyIdx < 0 {
		t.Fatalf("missing handlers: guard=%d waf=%d rewrite=%d proxy=%d", guardIdx, wafIdx, rewriteIdx, proxyIdx)
	}
	if !(guardIdx < wafIdx && wafIdx < rewriteIdx && rewriteIdx+1 == proxyIdx) {
		t.Fatalf("invalid middleware order: guard=%d waf=%d rewrite=%d proxy=%d", guardIdx, wafIdx, rewriteIdx, proxyIdx)
	}

	// 软件旁路模式：rewrite 必须在 jiuzhang_software_bypass 选择器之后、reverse_proxy 正前方
	guardWithSB := testGuardConfig()
	guardWithSB.SoftwareBypass = &GuardSoftwareBypass{Enabled: true, CPUThresholdPercent: 90, MemoryThresholdPercent: 90, MinHoldSeconds: 30}
	sbEntries := pathRouteEntries(GenerateInput{Guard: guardWithSB}, app, []string{"portal.example.com"}, 80)
	sbHandles := sbEntries[0].route["handle"].([]interface{})
	if len(sbHandles) != 3 ||
		sbHandles[0].(mapT)["handler"] != "jiuzhang_software_bypass" ||
		sbHandles[1].(mapT)["handler"] != "rewrite" ||
		sbHandles[2].(mapT)["handler"] != "reverse_proxy" {
		t.Fatalf("software bypass strip_prefix order invalid: %+v", sbHandles)
	}
}
