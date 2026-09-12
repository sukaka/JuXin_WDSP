package gatewayconfig

import (
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/applications"
)

// block_response 组设置 → GuardBlockResponse 组装（纯函数）：
// 空串/未知键不下发；全空返回 nil（网关内置默认模板）；超上限/非法错误码如实报错。
func TestBlockResponseFromSettings(t *testing.T) {
	// 全空（含种子行的空串）→ nil 不下发
	br, err := blockResponseFromSettings(map[string]string{
		"html_title": "", "html_body": "", "json_code": "", "json_message": "",
	})
	if err != nil || br != nil {
		t.Fatalf("all-empty should be nil: %v %+v", err, br)
	}
	// 未知键忽略（前向兼容）
	br, err = blockResponseFromSettings(map[string]string{"future_key": "x"})
	if err != nil || br != nil {
		t.Fatalf("unknown key should be ignored: %v %+v", err, br)
	}
	// 部分配置
	br, err = blockResponseFromSettings(map[string]string{
		"html_title": "访问受限", "json_code": "rate_limited.v2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if br == nil || br.HTMLTitle != "访问受限" || br.JSONCode != "rate_limited.v2" ||
		br.HTMLBody != "" || br.JSONMessage != "" {
		t.Fatalf("partial config: %+v", br)
	}
	// 超上限逐项拒绝
	oversize := []struct {
		name string
		kv   map[string]string
	}{
		{"html_title", map[string]string{"html_title": strings.Repeat("a", maxBlockResponseTitleBytes+1)}},
		{"html_body", map[string]string{"html_body": strings.Repeat("p", maxBlockResponseBodyBytes+1)}},
		{"json_code_len", map[string]string{"json_code": strings.Repeat("c", maxBlockResponseJSONCode+1)}},
		{"json_message", map[string]string{"json_message": strings.Repeat("m", maxBlockResponseJSONMsgBytes+1)}},
		{"json_code_charset", map[string]string{"json_code": "bad code!"}},
	}
	for _, tc := range oversize {
		if _, err := blockResponseFromSettings(tc.kv); err == nil {
			t.Fatalf("%s: expected error", tc.name)
		}
	}
	// 边界值通过
	if _, err := blockResponseFromSettings(map[string]string{
		"html_title":   strings.Repeat("a", maxBlockResponseTitleBytes),
		"html_body":    strings.Repeat("p", maxBlockResponseBodyBytes),
		"json_code":    strings.Repeat("c", maxBlockResponseJSONCode),
		"json_message": strings.Repeat("m", maxBlockResponseJSONMsgBytes),
	}); err != nil {
		t.Fatalf("boundary values should pass: %v", err)
	}
}

// 自定义阻断响应下发：Guard.BlockResponse 非 nil 时 guard JSON 携带 block_response 段
// （全产品形态，不受 WDSP 门控——APIDynamicProtection=false 同样下发）；
// nil 时不下发，JSON 与历史版本一致。
func TestGenerateGuardBlockResponse(t *testing.T) {
	newApp := func() AppData {
		return AppData{
			AppID: "app-uuid-1", Code: "shop", ProtectionMode: applications.ModeProtect,
			Domains:   []applications.Domain{{NormalizedHostname: "shop.example.com", HTTPEnabled: true, HTTPPort: intPtr(8080), Status: "ACTIVE"}},
			Upstreams: []applications.Upstream{{NormalizedHost: "127.0.0.1", Port: 9001, Status: "ACTIVE", Weight: 1}},
		}
	}

	// 非 nil：注入 guard JSON（纯 WAF 形态同样下发）
	cfg := testGuardConfig()
	cfg.BlockResponse = &GuardBlockResponse{
		HTMLTitle: "访问受限", HTMLBody: "<p>系统繁忙</p>",
		JSONCode: "rate_limited", JSONMessage: "触发频率限制",
	}
	gen, err := Generate(GenerateInput{
		Apps:        []AppData{newApp()},
		AdminSocket: "/var/run/caddy/admin.sock",
		Guard:       cfg,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gen.JSON, `"block_response"`) ||
		!strings.Contains(gen.JSON, `"html_title":"访问受限"`) ||
		!strings.Contains(gen.JSON, `"json_code":"rate_limited"`) {
		t.Error("block_response must be injected into guard JSON when configured")
	}
	if cfg.APIDynamicProtection {
		t.Fatal("test precondition: WDSP off")
	}

	// nil（缺省）：不下发，JSON 与历史版本一致
	gen, err = Generate(GenerateInput{
		Apps:        []AppData{newApp()},
		AdminSocket: "/var/run/caddy/admin.sock",
		Guard:       testGuardConfig(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(gen.JSON, "block_response") {
		t.Error("block_response must be omitted when nil")
	}
}
