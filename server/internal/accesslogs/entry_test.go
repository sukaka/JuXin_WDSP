package accesslogs

import (
	"strings"
	"testing"
	"time"
)

func TestParseLine(t *testing.T) {
	valid := `{"occurred_at":"2026-07-23T10:00:00Z","request_id":"req-1","application_id":"1b4e28ba-2fa1-11d2-883f-0016d3cca427",` +
		`"domain":"waf-s5.local","gateway_node_id":"gateway-stage5-01","client_ip":"203.0.113.10","client_port":4321,` +
		`"request_method":"POST","request_uri":"/login?token=masked","request_path":"/login","query_summary":"token=masked",` +
		`"http_version":"HTTP/1.1","content_type":"application/json","user_agent_summary":"curl/8.0","referer_summary":"",` +
		`"response_status":200,"bytes_in":42,"bytes_out":128,"duration_ms":15,"waf_action":"",` +
		`"request_headers":{"Cookie":["masked"],"Accept":["*/*"]},"request_body":"{\"password\":\"masked\"}","request_body_truncated":false,` +
		`"response_headers":{"Content-Type":["application/json"]},"response_body":"{\"ok\":true}","response_body_truncated":false}`

	cases := []struct {
		name    string
		line    string
		wantErr bool
		check   func(t *testing.T, e *LogEntry)
	}{
		{
			name: "valid full line",
			line: valid,
			check: func(t *testing.T, e *LogEntry) {
				if e.RequestID != "req-1" || e.ResponseStatus != 200 || e.BytesIn != 42 || e.BytesOut != 128 {
					t.Errorf("basic fields wrong: %+v", e)
				}
				if e.RequestHeaders["Cookie"][0] != "masked" {
					t.Errorf("headers wrong: %v", e.RequestHeaders)
				}
				if e.DurationMS != 15 || e.ClientPort != 4321 {
					t.Errorf("duration/port wrong: %+v", e)
				}
			},
		},
		{name: "empty line", line: "  \n", wantErr: true},
		{name: "bad json", line: "{not json", wantErr: true},
		{name: "missing occurred_at", line: `{"request_id":"req-2"}`, wantErr: true},
		{name: "oversize line", line: `{"occurred_at":"2026-07-23T10:00:00Z","request_body":"` + strings.Repeat("a", 1<<20) + `"}`, wantErr: true},
		{
			name: "oversize fields truncated",
			line: `{"occurred_at":"2026-07-23T10:00:00Z","request_id":"` + strings.Repeat("r", 200) +
				`","domain":"` + strings.Repeat("d", 300) + `"}`,
			check: func(t *testing.T, e *LogEntry) {
				if len(e.RequestID) != maxRequestIDLen {
					t.Errorf("request_id not truncated: %d", len(e.RequestID))
				}
				if len(e.Domain) != maxDomainLen {
					t.Errorf("domain not truncated: %d", len(e.Domain))
				}
			},
		},
		{
			name: "NUL stripped from body",
			line: `{"occurred_at":"2026-07-23T10:00:00Z","request_id":"req-3","request_body":"a\u0000b","response_body":"x\u0000y"}`,
			check: func(t *testing.T, e *LogEntry) {
				if strings.Contains(e.RequestBody, "\x00") || strings.Contains(e.ResponseBody, "\x00") {
					t.Errorf("NUL not stripped: %q %q", e.RequestBody, e.ResponseBody)
				}
			},
		},
		{
			name: "minimal line defaults",
			line: `{"occurred_at":"2026-07-23T10:00:00Z"}`,
			check: func(t *testing.T, e *LogEntry) {
				if e.RequestID != "" || e.ResponseStatus != 0 || e.WAFAction != "" {
					t.Errorf("defaults wrong: %+v", e)
				}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e, err := ParseLine([]byte(c.line))
			if c.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.check != nil {
				c.check(t, e)
			}
		})
	}
}

func TestParseLineOccurredAtPreserved(t *testing.T) {
	e, err := ParseLine([]byte(`{"occurred_at":"2026-07-23T10:00:00Z"}`))
	if err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC)
	if !e.OccurredAt.Equal(want) {
		t.Errorf("occurred_at = %v, want %v", e.OccurredAt, want)
	}
}

// TestParseLineAPMFields APM 阶段1 字段合同（ADR D6/D7/D8，WP2 网关侧产出）：
// 新格式行携带 trace_id/span_id/endpoint_key/path_template/ttfb_ms，旧格式行
// 全部缺省（空串/nil），两种行都必须可解析。
func TestParseLineAPMFields(t *testing.T) {
	t.Run("new format with apm fields", func(t *testing.T) {
		line := `{"occurred_at":"2026-08-30T10:00:00Z","request_id":"req-apm-1",` +
			`"trace_id":"0123456789abcdef0123456789abcdef","span_id":"0123456789abcdef",` +
			`"endpoint_key":"GET /api/users/{id}","path_template":"/api/users/{id}",` +
			`"ttfb_ms":42,"response_status":200,"duration_ms":58,"waf_action":"OBSERVE"}`
		e, err := ParseLine([]byte(line))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if e.TraceID != "0123456789abcdef0123456789abcdef" || e.SpanID != "0123456789abcdef" {
			t.Errorf("trace/span wrong: %+v", e)
		}
		if e.EndpointKey != "GET /api/users/{id}" || e.PathTemplate != "/api/users/{id}" {
			t.Errorf("endpoint fields wrong: %+v", e)
		}
		if e.TTFBMs == nil || *e.TTFBMs != 42 {
			t.Errorf("ttfb_ms = %v, want 42", e.TTFBMs)
		}
		if e.WAFAction != "OBSERVE" {
			t.Errorf("waf_action = %q, want OBSERVE", e.WAFAction)
		}
	})
	t.Run("old format without apm fields", func(t *testing.T) {
		e, err := ParseLine([]byte(`{"occurred_at":"2026-08-30T10:00:00Z","request_id":"req-old-1","response_status":403,"waf_action":"BLOCK"}`))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if e.TraceID != "" || e.SpanID != "" || e.EndpointKey != "" || e.PathTemplate != "" || e.TTFBMs != nil {
			t.Errorf("old line must leave apm fields empty: %+v", e)
		}
	})
	t.Run("dirty ttfb nulled", func(t *testing.T) {
		for _, v := range []string{"-5", "9999999999999"} {
			e, err := ParseLine([]byte(`{"occurred_at":"2026-08-30T10:00:00Z","ttfb_ms":` + v + `}`))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if e.TTFBMs != nil {
				t.Errorf("ttfb_ms %s must be nulled (integer 列防溢出), got %d", v, *e.TTFBMs)
			}
		}
	})
	t.Run("apm fields truncated", func(t *testing.T) {
		line := `{"occurred_at":"2026-08-30T10:00:00Z","trace_id":"` + strings.Repeat("t", 100) +
			`","endpoint_key":"` + strings.Repeat("e", 300) + `"}`
		e, err := ParseLine([]byte(line))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(e.TraceID) != maxTraceIDLen {
			t.Errorf("trace_id not truncated: %d", len(e.TraceID))
		}
		if len(e.EndpointKey) != maxEndpointKeyLen {
			t.Errorf("endpoint_key not truncated: %d", len(e.EndpointKey))
		}
	})
}

// TestParseLineRealClientIPFields 阶段5 §6.5 字段合同：新格式行携带
// client_ip_source/trusted_proxy_used/forwarded_chain_summary；旧格式行全部缺省
// （空串，入库为 NULL），两种行都必须可解析；超长字段截断、NUL 剥离。
func TestParseLineRealClientIPFields(t *testing.T) {
	t.Run("new format with real client ip fields", func(t *testing.T) {
		line := `{"occurred_at":"2026-09-10T10:00:00Z","request_id":"req-ip-1",` +
			`"client_ip":"198.51.100.9","client_ip_source":"X_FORWARDED_FOR",` +
			`"trusted_proxy_used":"lb-1","forwarded_chain_summary":"198.51.100.9, 10.0.0.1"}`
		e, err := ParseLine([]byte(line))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if e.ClientIPSource != "X_FORWARDED_FOR" || e.TrustedProxyUsed != "lb-1" ||
			e.ForwardedChainSummary != "198.51.100.9, 10.0.0.1" {
			t.Errorf("real client ip fields wrong: %+v", e)
		}
	})
	t.Run("old format without real client ip fields", func(t *testing.T) {
		e, err := ParseLine([]byte(`{"occurred_at":"2026-09-10T10:00:00Z","request_id":"req-old-ip"}`))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if e.ClientIPSource != "" || e.TrustedProxyUsed != "" || e.ForwardedChainSummary != "" {
			t.Errorf("old line must leave real client ip fields empty: %+v", e)
		}
	})
	t.Run("overlong truncated", func(t *testing.T) {
		// NUL 剥离不在此断言：原始 NUL 即非法 JSON，在解码期即被拒（网关写盘前已剥离）
		line := `{"occurred_at":"2026-09-10T10:00:00Z","request_id":"req-ip-2",` +
			`"client_ip_source":"` + strings.Repeat("S", 64) + `",` +
			`"trusted_proxy_used":"` + strings.Repeat("p", 200) + `",` +
			`"forwarded_chain_summary":"` + strings.Repeat("9.9.9.9, ", 60) + `"}`
		e, err := ParseLine([]byte(line))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(e.ClientIPSource) != 32 {
			t.Errorf("client_ip_source not truncated: len=%d", len(e.ClientIPSource))
		}
		if len(e.TrustedProxyUsed) != 128 {
			t.Errorf("trusted_proxy_used not truncated: len=%d", len(e.TrustedProxyUsed))
		}
		if len(e.ForwardedChainSummary) != 256 {
			t.Errorf("forwarded_chain_summary not truncated: len=%d", len(e.ForwardedChainSummary))
		}
	})
}

// TestParseLineTLSFields 加密会话分析扩展字段合同（迁移 000241）：
// 新格式行携带 tls_protocol/tls_cipher_suite/tls_is_gm/tls_ja3/client_hello_version；
// 旧格式行缺失这 5 个字段时安全回落空串/false；超长字段截断、NUL 剥离。
func TestParseLineTLSFields(t *testing.T) {
	t.Run("new format with GM TLCP fields", func(t *testing.T) {
		line := `{"occurred_at":"2026-11-25T10:00:00Z","request_id":"req-tls-gm-1",` +
			`"tls_protocol":"TLCP1.1","tls_cipher_suite":"TLCP_ECC_SM4_GCM_SM3",` +
			`"tls_is_gm":true,"tls_ja3":"0123456789abcdef0123456789abcdef","client_hello_version":"TLCP1.1"}`
		e, err := ParseLine([]byte(line))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if e.TLSProtocol != "TLCP1.1" || e.TLSCipherSuite != "TLCP_ECC_SM4_GCM_SM3" ||
			!e.TLSIsGM || e.TLSJA3 != "0123456789abcdef0123456789abcdef" || e.ClientHelloVersion != "TLCP1.1" {
			t.Errorf("TLS fields mismatch: %+v", e)
		}
	})

	t.Run("legacy line without TLS fields remains backwards compatible", func(t *testing.T) {
		line := `{"occurred_at":"2026-11-25T10:00:00Z","request_id":"req-tls-legacy","request_method":"GET","response_status":200}`
		e, err := ParseLine([]byte(line))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if e.TLSProtocol != "" || e.TLSCipherSuite != "" || e.TLSIsGM || e.TLSJA3 != "" || e.ClientHelloVersion != "" {
			t.Errorf("legacy line must default TLS fields to empty/false: %+v", e)
		}
	})

	t.Run("overlong TLS fields truncated and NUL stripped", func(t *testing.T) {
		line := `{"occurred_at":"2026-11-25T10:00:00Z","request_id":"req-tls-trunc",` +
			`"tls_protocol":"T\u0000` + strings.Repeat("p", 40) + `",` +
			`"tls_cipher_suite":"C\u0000` + strings.Repeat("c", 100) + `",` +
			`"tls_ja3":"J\u0000` + strings.Repeat("j", 100) + `",` +
			`"client_hello_version":"V\u0000` + strings.Repeat("v", 40) + `"}`
		e, err := ParseLine([]byte(line))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(e.TLSProtocol) != maxTLSProtocolLen || strings.Contains(e.TLSProtocol, "\x00") {
			t.Errorf("tls_protocol not sanitized/truncated: len=%d", len(e.TLSProtocol))
		}
		if len(e.TLSCipherSuite) != maxTLSCipherSuiteLen || strings.Contains(e.TLSCipherSuite, "\x00") {
			t.Errorf("tls_cipher_suite not sanitized/truncated: len=%d", len(e.TLSCipherSuite))
		}
		if len(e.TLSJA3) != maxTLSJA3Len || strings.Contains(e.TLSJA3, "\x00") {
			t.Errorf("tls_ja3 not sanitized/truncated: len=%d", len(e.TLSJA3))
		}
		if len(e.ClientHelloVersion) != maxClientHelloVerLen || strings.Contains(e.ClientHelloVersion, "\x00") {
			t.Errorf("client_hello_version not sanitized/truncated: len=%d", len(e.ClientHelloVersion))
		}
	})
}
