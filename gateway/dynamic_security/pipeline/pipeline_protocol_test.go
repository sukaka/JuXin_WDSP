// pipeline_protocol_test.go GraphQL / SOAP / WebSocket 协议打标管线测试：
// 三类流量经 Process 后 api.protocol 扩展落值；普通 REST 不带扩展（已有
// TestProcessNonGRPCUntouched 覆盖 JSON 形态，这里补 query-only GET）。
package pipeline

import (
	"net/http"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
)

func protocolOf(t *testing.T, r *http.Request) string {
	t.Helper()
	res, err := Process(r, Config{Enabled: true, Mode: decision.ModeProtect}, nil)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := res.Context.GetExtension("api.protocol")
	s, _ := v.(string)
	return s
}

// GraphQL：application/graphql 原始查询与 /graphql+JSON query 两种形态均打标；
// 端点键按路径归一化（不按 operation 拆，本波不做）。
func TestProcessGraphQLProtocol(t *testing.T) {
	r, _ := http.NewRequest(http.MethodPost, "http://h/graphql", strings.NewReader(`query { user { id } }`))
	r.Header.Set("Content-Type", "application/graphql")
	if got := protocolOf(t, r); got != "GRAPHQL" {
		t.Fatalf("application/graphql protocol = %q, want GRAPHQL", got)
	}

	r2, _ := http.NewRequest(http.MethodPost, "http://h/graphql", strings.NewReader(`{"query":"mutation { createUser(id: 1) { id } }","operationName":"createUser"}`))
	r2.Header.Set("Content-Type", "application/json")
	if got := protocolOf(t, r2); got != "GRAPHQL" {
		t.Fatalf("/graphql+json query protocol = %q, want GRAPHQL", got)
	}
	if res, _ := Process(r2, Config{Enabled: true, Mode: decision.ModeProtect}, nil); res.EndpointKey != "POST /graphql" {
		t.Fatalf("graphql endpoint key must stay path-normalized: %q", res.EndpointKey)
	}

	// 反例：普通 JSON POST 到非 graphql 路径不打标
	r3, _ := http.NewRequest(http.MethodPost, "http://h/v1/users", strings.NewReader(`{"query":"not graphql path"}`))
	r3.Header.Set("Content-Type", "application/json")
	if got := protocolOf(t, r3); got != "" {
		t.Fatalf("plain json must not carry api.protocol, got %q", got)
	}
}

// SOAP：soap+xml 直接打标；text/xml 需 SOAPAction 头双重确认。
func TestProcessSOAPProtocol(t *testing.T) {
	body := `<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Body><m:GetUser xmlns:m="urn:x"><m:id>1</m:id></m:GetUser></soap:Body></soap:Envelope>`

	r, _ := http.NewRequest(http.MethodPost, "http://h/soap/user-service", strings.NewReader(body))
	r.Header.Set("Content-Type", `application/soap+xml; charset=utf-8`)
	if got := protocolOf(t, r); got != "SOAP" {
		t.Fatalf("soap+xml protocol = %q, want SOAP", got)
	}

	r2, _ := http.NewRequest(http.MethodPost, "http://h/soap/user-service", strings.NewReader(body))
	r2.Header.Set("Content-Type", "text/xml")
	r2.Header.Set("SOAPAction", `"urn:GetUser"`)
	if got := protocolOf(t, r2); got != "SOAP" {
		t.Fatalf("text/xml+SOAPAction protocol = %q, want SOAP", got)
	}

	// 反例：text/xml 无 SOAPAction（普通 XML API）不打标
	r3, _ := http.NewRequest(http.MethodPost, "http://h/v1/xml-export", strings.NewReader(`<x><a>1</a></x>`))
	r3.Header.Set("Content-Type", "text/xml")
	if got := protocolOf(t, r3); got != "" {
		t.Fatalf("plain xml must not carry api.protocol, got %q", got)
	}
}

// WebSocket：升级握手双头确认打标；缺一头均不打标。
func TestProcessWebSocketProtocol(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "http://h/ws/notify", nil)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	r.Header.Set("Sec-WebSocket-Version", "13")
	if got := protocolOf(t, r); got != "WEBSOCKET" {
		t.Fatalf("ws handshake protocol = %q, want WEBSOCKET", got)
	}

	// 反例：仅 Upgrade 头缺 Connection 令牌
	r2, _ := http.NewRequest(http.MethodGet, "http://h/ws/notify", nil)
	r2.Header.Set("Upgrade", "websocket")
	if got := protocolOf(t, r2); got != "" {
		t.Fatalf("missing connection token must not tag, got %q", got)
	}
}
