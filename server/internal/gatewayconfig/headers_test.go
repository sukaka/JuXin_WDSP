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

func TestResponseCompressionDisabledOmitsEncodeHandler(t *testing.T) {
	if got := buildEncodeHandler(nil); got != nil {
		t.Fatalf("nil header config must not emit encode handler: %+v", got)
	}
	if got := buildEncodeHandler(&AppHeaderConfig{ResponseCompressionEnabled: false, ResponseCompressionEncodings: "gzip"}); got != nil {
		t.Fatalf("disabled response compression must not emit encode handler: %+v", got)
	}
	app := AppData{
		AppID:          "app-no-comp",
		Code:           "portal",
		ProtectionMode: applications.ModeProtect,
		HeaderConfig:   &AppHeaderConfig{ResponseCompressionEnabled: false},
	}
	handles := buildChainHandles(GenerateInput{Guard: testGuardConfig()}, app, mapT{"handler": "reverse_proxy"}, 80)
	for _, raw := range handles {
		if raw.(mapT)["handler"] == "encode" {
			t.Fatalf("disabled compression unexpectedly inserted encode handler: %+v", handles)
		}
	}
}

func TestResponseCompressionModesAndMiddlewareOrder(t *testing.T) {
	cases := []struct {
		name          string
		encodings     string
		wantEncKeys   []string
		wantPrefer    []string
		forbidEncKeys []string
	}{
		{
			name:        "default empty falls back to zstd,gzip",
			encodings:   "",
			wantEncKeys: []string{"zstd", "gzip"},
			wantPrefer:  []string{"zstd", "gzip"},
		},
		{
			name:        "zstd and gzip",
			encodings:   "zstd,gzip",
			wantEncKeys: []string{"zstd", "gzip"},
			wantPrefer:  []string{"zstd", "gzip"},
		},
		{
			name:          "gzip only",
			encodings:     "gzip",
			wantEncKeys:   []string{"gzip"},
			wantPrefer:    []string{"gzip"},
			forbidEncKeys: []string{"zstd"},
		},
		{
			name:          "zstd only",
			encodings:     "zstd",
			wantEncKeys:   []string{"zstd"},
			wantPrefer:    []string{"zstd"},
			forbidEncKeys: []string{"gzip"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enc := buildEncodeHandler(&AppHeaderConfig{
				ResponseCompressionEnabled:   true,
				ResponseCompressionEncodings: tc.encodings,
			})
			if enc == nil {
				t.Fatal("expected encode handler")
			}
			if enc["handler"] != "encode" {
				t.Fatalf("handler = %v, want encode", enc["handler"])
			}
			if enc["minimum_length"] != ResponseCompressionMinLength {
				t.Fatalf("minimum_length = %v, want %d", enc["minimum_length"], ResponseCompressionMinLength)
			}
			encMap := enc["encodings"].(mapT)
			for _, k := range tc.wantEncKeys {
				if _, ok := encMap[k]; !ok {
					t.Errorf("encodings missing %q: %+v", k, encMap)
				}
			}
			for _, k := range tc.forbidEncKeys {
				if _, ok := encMap[k]; ok {
					t.Errorf("encodings should not contain %q: %+v", k, encMap)
				}
			}
			prefer := enc["prefer"].([]string)
			if strings.Join(prefer, ",") != strings.Join(tc.wantPrefer, ",") {
				t.Errorf("prefer = %v, want %v", prefer, tc.wantPrefer)
			}
			matchHeaders := enc["match"].(mapT)["headers"].(mapT)
			contentTypes := matchHeaders["Content-Type"].([]string)
			hasHTML, hasJSON, hasJS, hasCSS := false, false, false, false
			for _, ct := range contentTypes {
				if ct == "text/*" || strings.Contains(ct, "event-stream") {
					t.Fatalf("content-type matcher must exclude SSE / wildcard text/*, got %q", ct)
				}
				switch ct {
				case "text/html*":
					hasHTML = true
				case "application/json*":
					hasJSON = true
				case "application/javascript*":
					hasJS = true
				case "text/css*":
					hasCSS = true
				}
			}
			if !hasHTML || !hasJSON || !hasJS || !hasCSS {
				t.Fatalf("missing common web/api MIME types: html=%v json=%v js=%v css=%v", hasHTML, hasJSON, hasJS, hasCSS)
			}
		})
	}

	// 验证中间件链顺序：requestID -> encode -> jiuzhang_guard -> waf -> headerHandler -> [rewrite] -> reverse_proxy
	// 同时开启 AcceptEncodingOff：回源请求强制 identity 明文，WAF/guard 完整检查明文后由 encode 压缩给客户端。
	app := AppData{
		AppID:          "app-comp",
		Code:           "portal",
		ProtectionMode: applications.ModeProtect,
		HeaderConfig: &AppHeaderConfig{
			AcceptEncodingOff:            true,
			ResponseCompressionEnabled:   true,
			ResponseCompressionEncodings: "zstd,gzip",
		},
		PathRoutes: []AppPathRoute{
			{
				PathPrefix:     "/api",
				UpstreamScheme: "http",
				UpstreamHost:   "10.0.0.20",
				UpstreamPort:   8080,
				StripPrefix:    true,
				Priority:       10,
			},
		},
	}

	checkNormalOrder := func(t *testing.T, handles []interface{}, wantRewrite bool) {
		t.Helper()
		var reqIDIdx, encodeIdx, guardIdx, wafIdx, respHdrIdx, rewriteIdx, proxyIdx = -1, -1, -1, -1, -1, -1, -1
		for i, raw := range handles {
			h := raw.(mapT)
			switch h["handler"] {
			case "headers":
				if reqIDIdx < 0 {
					reqIDIdx = i
				} else {
					respHdrIdx = i
				}
			case "encode":
				encodeIdx = i
			case "jiuzhang_guard":
				guardIdx = i
			case "waf":
				wafIdx = i
			case "rewrite":
				rewriteIdx = i
			case "reverse_proxy":
				proxyIdx = i
			}
		}
		if !(reqIDIdx == 0 && encodeIdx == 1 && encodeIdx < guardIdx && guardIdx < wafIdx && wafIdx < respHdrIdx && respHdrIdx < proxyIdx) {
			t.Fatalf("invalid compression chain order: reqID=%d encode=%d guard=%d waf=%d respHdr=%d rewrite=%d proxy=%d",
				reqIDIdx, encodeIdx, guardIdx, wafIdx, respHdrIdx, rewriteIdx, proxyIdx)
		}
		if wantRewrite && !(respHdrIdx < rewriteIdx && rewriteIdx+1 == proxyIdx) {
			t.Fatalf("invalid rewrite placement with compression: respHdr=%d rewrite=%d proxy=%d", respHdrIdx, rewriteIdx, proxyIdx)
		}
	}

	proxy := applyProxyOptions(mapT{"handler": "reverse_proxy"}, app.HeaderConfig)
	reqSet := proxy["headers"].(mapT)["request"].(mapT)["set"].(map[string][]string)
	if got := reqSet["Accept-Encoding"]; len(got) != 1 || got[0] != "identity" {
		t.Fatalf("AcceptEncodingOff must still force upstream identity: %v", got)
	}
	checkNormalOrder(t, buildChainHandles(GenerateInput{Guard: testGuardConfig()}, app, proxy, 80), false)

	// 路径转发路由同样挂接 encode 且顺序正确
	entries := pathRouteEntries(GenerateInput{Guard: testGuardConfig()}, app, []string{"portal.example.com"}, 80)
	if len(entries) != 1 {
		t.Fatalf("path route entries = %d, want 1", len(entries))
	}
	checkNormalOrder(t, entries[0].route["handle"].([]interface{}), true)

	// 手工 BYPASS 模式：requestID -> encode -> headerHandler -> reverse_proxy（无 guard/waf）
	bypassApp := app
	bypassApp.ProtectionMode = applications.ModeBypass
	bypassHandles := buildChainHandles(GenerateInput{Guard: testGuardConfig()}, bypassApp, proxy, 80)
	if len(bypassHandles) != 4 ||
		bypassHandles[0].(mapT)["handler"] != "headers" ||
		bypassHandles[1].(mapT)["handler"] != "encode" ||
		bypassHandles[2].(mapT)["handler"] != "headers" ||
		bypassHandles[3].(mapT)["handler"] != "reverse_proxy" {
		t.Fatalf("BYPASS compression chain invalid: %+v", bypassHandles)
	}

	// SoftwareBypass 模式：normal/bypass 子链均挂载 encode，外层仍为 [selector, rewrite, reverse_proxy]
	guardWithSB := testGuardConfig()
	guardWithSB.SoftwareBypass = &GuardSoftwareBypass{Enabled: true, CPUThresholdPercent: 90, MemoryThresholdPercent: 90, MinHoldSeconds: 30}
	sbEntries := pathRouteEntries(GenerateInput{Guard: guardWithSB}, app, []string{"portal.example.com"}, 80)
	sbHandles := sbEntries[0].route["handle"].([]interface{})
	if len(sbHandles) != 3 ||
		sbHandles[0].(mapT)["handler"] != "jiuzhang_software_bypass" ||
		sbHandles[1].(mapT)["handler"] != "rewrite" ||
		sbHandles[2].(mapT)["handler"] != "reverse_proxy" {
		t.Fatalf("software bypass outer chain invalid: %+v", sbHandles)
	}
	selector := sbHandles[0].(mapT)
	normalSub := selector["normal"].(mapT)["routes"].([]interface{})[0].(mapT)["handle"].([]interface{})
	bypassSub := selector["bypass"].(mapT)["routes"].([]interface{})[0].(mapT)["handle"].([]interface{})
	if len(normalSub) < 4 || normalSub[1].(mapT)["handler"] != "encode" || normalSub[2].(mapT)["handler"] != "jiuzhang_guard" {
		t.Fatalf("software bypass normal subchain invalid: %+v", normalSub)
	}
	if len(bypassSub) != 3 || bypassSub[1].(mapT)["handler"] != "encode" {
		t.Fatalf("software bypass pure proxy subchain invalid: %+v", bypassSub)
	}
}
