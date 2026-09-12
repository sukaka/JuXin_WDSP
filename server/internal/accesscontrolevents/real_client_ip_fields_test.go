package accesscontrolevents

import (
	"strings"
	"testing"
)

// TestParseEventLineRealClientIPFields 阶段5 §6.5：client_ip_source /
// trusted_proxy_used / forwarded_chain_summary 三字段解析（缺失容忍、超长截断）。
func TestParseEventLineRealClientIPFields(t *testing.T) {
	// 可信代理链事件：三字段全量带出
	evt, err := ParseEventLine(validLine(t, map[string]interface{}{
		"client_ip_source":        "X_FORWARDED_FOR",
		"trusted_proxy_used":      "lb-1",
		"forwarded_chain_summary": "198.51.100.9, 10.0.0.1",
	}), "n")
	if err != nil {
		t.Fatalf("valid line rejected: %v", err)
	}
	if evt.ClientIPSource != "X_FORWARDED_FOR" || evt.TrustedProxyUsed != "lb-1" ||
		evt.ForwardedChainSummary != "198.51.100.9, 10.0.0.1" {
		t.Errorf("real client ip fields: %+v", evt)
	}

	// 旧版网关事件无三键 → 缺失容忍（空串，落库为 NULL）
	evt, err = ParseEventLine(validLine(t, nil), "n")
	if err != nil {
		t.Fatal(err)
	}
	if evt.ClientIPSource != "" || evt.TrustedProxyUsed != "" || evt.ForwardedChainSummary != "" {
		t.Errorf("missing keys must default to empty: %+v", evt)
	}

	// 超长字段截断（防注入）
	evt, err = ParseEventLine(validLine(t, map[string]interface{}{
		"client_ip_source":        strings.Repeat("S", 64),
		"trusted_proxy_used":      strings.Repeat("p", 200),
		"forwarded_chain_summary": strings.Repeat("9.9.9.9, ", 100),
	}), "n")
	if err != nil {
		t.Fatal(err)
	}
	if len(evt.ClientIPSource) != 32 {
		t.Errorf("client_ip_source not truncated: len=%d", len(evt.ClientIPSource))
	}
	if len(evt.TrustedProxyUsed) != 128 {
		t.Errorf("trusted_proxy_used not truncated: len=%d", len(evt.TrustedProxyUsed))
	}
	if len(evt.ForwardedChainSummary) != 256 {
		t.Errorf("forwarded_chain_summary not truncated: len=%d", len(evt.ForwardedChainSummary))
	}
}
