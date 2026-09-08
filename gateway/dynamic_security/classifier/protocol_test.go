package classifier

import (
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func TestClassifyGraphQL(t *testing.T) {
	tests := []struct {
		name string
		p    *parser.Parsed
		want bool
	}{
		{"nil", nil, false},
		{"query 操作", &parser.Parsed{GraphQLOperation: "query"}, true},
		{"mutation 操作", &parser.Parsed{GraphQLOperation: "mutation"}, true},
		{"unknown 操作（解析层已确认 GraphQL 形态）", &parser.Parsed{GraphQLOperation: "unknown"}, true},
		{"普通 REST JSON", &parser.Parsed{IsJSON: true, JSONFields: map[string]string{"a": "string"}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyGraphQL(tc.p); got != tc.want {
				t.Fatalf("ClassifyGraphQL = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestClassifySOAP(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		headers     map[string]string
		want        bool
	}{
		{"soap+xml 裸类型", "application/soap+xml", nil, true},
		{"soap+xml 带 charset 与 action 参数", `application/soap+xml; charset=utf-8; action="urn:x"`, nil, true},
		{"text/xml + SOAPAction", "text/xml", map[string]string{"soapaction": `"urn:GetUser"`}, true},
		{"text/xml + SOAPAction 空串不算", "text/xml", map[string]string{"soapaction": ""}, false},
		{"text/xml 无 SOAPAction（普通 XML API）", "text/xml", nil, false},
		{"application/xml + SOAPAction", "application/xml", map[string]string{"soapaction": "urn:x"}, true},
		{"application/xml 无 SOAPAction", "application/xml", nil, false},
		{"畸形头部降级前缀仍可判 soap+xml", "application/soap+xml;;;", nil, true},
		{"JSON 误标", "application/json", map[string]string{"soapaction": "urn:x"}, false},
		{"nil", "", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &parser.Parsed{ContentType: tc.contentType, Headers: tc.headers}
			if got := ClassifySOAP(p); got != tc.want {
				t.Fatalf("ClassifySOAP(%q) = %v, want %v", tc.contentType, got, tc.want)
			}
		})
	}
}

func TestClassifyWebSocket(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    bool
	}{
		{"标准握手", map[string]string{"upgrade": "websocket", "connection": "Upgrade"}, true},
		{"connection 令牌列表", map[string]string{"upgrade": "websocket", "connection": "keep-alive, Upgrade"}, true},
		{"全小写", map[string]string{"upgrade": "websocket", "connection": "upgrade"}, true},
		{"upgrade 大写值", map[string]string{"upgrade": "WebSocket", "connection": "upgrade"}, true},
		{"缺 connection", map[string]string{"upgrade": "websocket"}, false},
		{"connection 不含 upgrade 令牌", map[string]string{"upgrade": "websocket", "connection": "keep-alive"}, false},
		{"connection 子串不等于令牌（upgradex 误判防护）", map[string]string{"upgrade": "websocket", "connection": "upgradex"}, false},
		{"缺 upgrade", map[string]string{"connection": "upgrade"}, false},
		{"普通请求", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &parser.Parsed{Headers: tc.headers}
			if got := ClassifyWebSocket(p); got != tc.want {
				t.Fatalf("ClassifyWebSocket(%v) = %v, want %v", tc.headers, got, tc.want)
			}
		})
	}
}
