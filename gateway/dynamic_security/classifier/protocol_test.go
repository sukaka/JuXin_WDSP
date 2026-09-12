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

func TestClassifyJSONRPC(t *testing.T) {
	tests := []struct {
		name string
		p    *parser.Parsed
		want bool
	}{
		{"nil", nil, false},
		{"jsonrpc+method 契约字段", &parser.Parsed{IsJSON: true, JSONFields: map[string]string{"jsonrpc": "string", "method": "string", "id": "number"}}, true},
		{"仅 jsonrpc 无 method 不打标", &parser.Parsed{IsJSON: true, JSONFields: map[string]string{"jsonrpc": "string"}}, false},
		{"仅 method 无 jsonrpc 不打标", &parser.Parsed{IsJSON: true, JSONFields: map[string]string{"method": "string"}}, false},
		{"非 JSON 体带同名字段不算", &parser.Parsed{IsJSON: false, JSONFields: map[string]string{"jsonrpc": "string", "method": "string"}}, false},
		{"普通 JSON", &parser.Parsed{IsJSON: true, JSONFields: map[string]string{"a": "string"}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyJSONRPC(tc.p); got != tc.want {
				t.Fatalf("ClassifyJSONRPC = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestClassifyXMLRPC(t *testing.T) {
	tests := []struct {
		name string
		p    *parser.Parsed
		want bool
	}{
		{"nil", nil, false},
		{"methodCall.methodName 叶子", &parser.Parsed{XMLFields: map[string]string{"methodCall.methodName": "string", "methodCall.params": "string"}}, true},
		{"methodResponse（响应侧）不判", &parser.Parsed{XMLFields: map[string]string{"methodResponse.params": "string"}}, false},
		{"普通 XML", &parser.Parsed{XMLFields: map[string]string{"order.id": "number"}}, false},
		{"无 XML 体", &parser.Parsed{IsJSON: true}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyXMLRPC(tc.p); got != tc.want {
				t.Fatalf("ClassifyXMLRPC = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestClassifySSE(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    bool
	}{
		{"标准 Accept", map[string]string{"accept": "text/event-stream"}, true},
		{"Accept 列表含 event-stream", map[string]string{"accept": "text/html, text/event-stream"}, true},
		{"大小写容忍", map[string]string{"accept": "Text/Event-Stream"}, true},
		{"application/json", map[string]string{"accept": "application/json"}, false},
		{"无 Accept", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &parser.Parsed{Headers: tc.headers}
			if got := ClassifySSE(p); got != tc.want {
				t.Fatalf("ClassifySSE(%v) = %v, want %v", tc.headers, got, tc.want)
			}
		})
	}
}

func TestClassifyWebhook(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		headers map[string]string
		want    bool
	}{
		{"GitHub 事件头", "POST", map[string]string{"x-github-event": "push"}, true},
		{"GitHub 签名头", "POST", map[string]string{"x-hub-signature-256": "sha256=abc"}, true},
		{"Stripe 签名头", "POST", map[string]string{"x-stripe-signature": "t=1,v1=x"}, true},
		{"GET 带事件头不判（投递方恒 POST）", "GET", map[string]string{"x-github-event": "push"}, false},
		{"POST 无签名头", "POST", nil, false},
		{"头存在但空值不算", "POST", map[string]string{"x-github-event": ""}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &parser.Parsed{Method: tc.method, Headers: tc.headers}
			if got := ClassifyWebhook(p); got != tc.want {
				t.Fatalf("ClassifyWebhook(%s %v) = %v, want %v", tc.method, tc.headers, got, tc.want)
			}
		})
	}
}

func TestClassifyFileUpload(t *testing.T) {
	if !ClassifyFileUpload(&parser.Parsed{HasFiles: true, MultipartParts: []parser.PartMeta{{FileName: "a.png"}}}) {
		t.Fatal("multipart with file part must classify as upload")
	}
	if ClassifyFileUpload(&parser.Parsed{HasFiles: false}) {
		t.Fatal("multipart without file part must not classify as upload")
	}
	if ClassifyFileUpload(nil) {
		t.Fatal("nil must not classify")
	}
}

func TestClassifyFileDownloadRequest(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		headers map[string]string
		want    bool
	}{
		{"GET + Range bytes", "GET", map[string]string{"range": "bytes=0-1023"}, true},
		{"HEAD + Range bytes", "HEAD", map[string]string{"range": "bytes=0-"}, true},
		{"Range 大小写容忍", "GET", map[string]string{"range": " Bytes=0-1 "}, true},
		{"非 bytes 单位不判", "GET", map[string]string{"range": "items=0-10"}, false},
		{"POST 带 Range 不判", "POST", map[string]string{"range": "bytes=0-1"}, false},
		{"普通 GET 不判", "GET", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &parser.Parsed{Method: tc.method, Headers: tc.headers}
			if got := ClassifyFileDownloadRequest(p); got != tc.want {
				t.Fatalf("ClassifyFileDownloadRequest(%s %v) = %v, want %v", tc.method, tc.headers, got, tc.want)
			}
		})
	}
}

// ClassifyProtocol 统一入口：词表逐值正例 + 优先级 + IsAPI 门控。
func TestClassifyProtocol(t *testing.T) {
	tests := []struct {
		name  string
		p     *parser.Parsed
		isAPI bool
		want  string
	}{
		{"nil", nil, true, ""},
		{"ws 握手", &parser.Parsed{Method: "GET", Headers: map[string]string{"upgrade": "websocket", "connection": "upgrade"}}, false, ProtocolWebsocketHandshake},
		{"graphql", &parser.Parsed{Method: "POST", GraphQLOperation: "query", IsJSON: true}, false, ProtocolGraphQL},
		{"soap", &parser.Parsed{Method: "POST", ContentType: "application/soap+xml"}, false, ProtocolSOAP},
		{"xml-rpc", &parser.Parsed{Method: "POST", ContentType: "text/xml", XMLFields: map[string]string{"methodCall.methodName": "string"}}, false, ProtocolXMLRPC},
		{"json-rpc", &parser.Parsed{Method: "POST", IsJSON: true, JSONFields: map[string]string{"jsonrpc": "string", "method": "string"}}, false, ProtocolJSONRPC},
		{"sse", &parser.Parsed{Method: "GET", Headers: map[string]string{"accept": "text/event-stream"}}, false, ProtocolSSE},
		{"文件上传", &parser.Parsed{Method: "POST", HasFiles: true}, false, ProtocolFileUpload},
		{"range 下载", &parser.Parsed{Method: "GET", Headers: map[string]string{"range": "bytes=0-1"}}, false, ProtocolFileDownload},
		{"webhook", &parser.Parsed{Method: "POST", IsJSON: true, Headers: map[string]string{"x-github-event": "push"}}, false, ProtocolWebhook},
		// 优先级：SOAP 先于 XML-RPC；GraphQL 先于 JSON-RPC
		{"soap 优先于 xml-rpc", &parser.Parsed{Method: "POST", ContentType: "text/xml", Headers: map[string]string{"soapaction": "urn:x"}, XMLFields: map[string]string{"methodCall.methodName": "string"}}, false, ProtocolSOAP},
		{"graphql 优先于 json-rpc", &parser.Parsed{Method: "POST", GraphQLOperation: "query", IsJSON: true, JSONFields: map[string]string{"jsonrpc": "string", "method": "string"}}, false, ProtocolGraphQL},
		// 通用 REST 族：仅 API 分类命中时打标
		{"form api（API）", &parser.Parsed{Method: "POST", ContentType: "application/x-www-form-urlencoded", FormFields: map[string]string{"a": "string"}}, true, ProtocolFormAPI},
		{"form 非 API 不打标", &parser.Parsed{Method: "POST", ContentType: "application/x-www-form-urlencoded", FormFields: map[string]string{"a": "string"}}, false, ""},
		{"rest xml（API）", &parser.Parsed{Method: "POST", ContentType: "application/xml"}, true, ProtocolRESTXML},
		{"rest xml 非 API 不打标", &parser.Parsed{Method: "POST", ContentType: "application/xml"}, false, ""},
		{"+xml 后缀媒体类型", &parser.Parsed{Method: "POST", ContentType: "application/atom+xml"}, true, ProtocolRESTXML},
		{"rest json（API）", &parser.Parsed{Method: "GET", ContentType: "application/json", IsJSON: true}, true, ProtocolRESTJSON},
		{"rest json 非 API 不打标", &parser.Parsed{Method: "GET", ContentType: "application/json", IsJSON: true}, false, ""},
		{"vendor json 媒体类型", &parser.Parsed{Method: "GET", ContentType: "application/vnd.api+json"}, true, ProtocolRESTJSON},
		{"无形态信号（API）", &parser.Parsed{Method: "GET", ContentType: "text/plain"}, true, ProtocolUnknownHTTPAPI},
		{"无形态信号非 API", &parser.Parsed{Method: "GET", ContentType: "text/html"}, false, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyProtocol(tc.p, tc.isAPI); got != tc.want {
				t.Fatalf("ClassifyProtocol = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIsGenericProtocol(t *testing.T) {
	for _, v := range []any{ProtocolRESTJSON, ProtocolRESTXML, ProtocolFormAPI, ProtocolUnknownHTTPAPI} {
		if !IsGenericProtocol(v) {
			t.Fatalf("%v must be generic", v)
		}
	}
	for _, v := range []any{ProtocolGRPC, ProtocolGraphQL, ProtocolSOAP, ProtocolFileDownload, "REST", nil, 42} {
		if IsGenericProtocol(v) {
			t.Fatalf("%v must not be generic", v)
		}
	}
}
