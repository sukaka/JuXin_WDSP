// pipeline_protocol_test.go 协议打标管线测试（任务书 §9 词表）：
// 各协议形态经 Process 后 api.protocol 扩展落值；非 API 普通流量不带扩展
// （采集端缺省 REST 口径），API 分类命中的通用族按 REST_JSON/REST_XML/FORM_API/
// UNKNOWN_HTTP_API 打标。
package pipeline

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
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

	// 普通 JSON POST 到非 graphql 路径：不打 GRAPHQL；§9 词表扩展后按通用族打 REST_JSON
	//（原断言为不带扩展，API 分类命中的 JSON 流量打标为扩展后的新行为）。
	r3, _ := http.NewRequest(http.MethodPost, "http://h/v1/users", strings.NewReader(`{"query":"not graphql path"}`))
	r3.Header.Set("Content-Type", "application/json")
	if got := protocolOf(t, r3); got != "REST_JSON" {
		t.Fatalf("plain json api protocol = %q, want REST_JSON", got)
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

// WebSocket：升级握手双头确认打标 WEBSOCKET_HANDSHAKE（§9 词表值；原 WEBSOCKET
// 断言随词表对齐更名）；缺一头均不打标。
func TestProcessWebSocketProtocol(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "http://h/ws/notify", nil)
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	r.Header.Set("Sec-WebSocket-Version", "13")
	if got := protocolOf(t, r); got != "WEBSOCKET_HANDSHAKE" {
		t.Fatalf("ws handshake protocol = %q, want WEBSOCKET_HANDSHAKE", got)
	}

	// 反例：仅 Upgrade 头缺 Connection 令牌
	r2, _ := http.NewRequest(http.MethodGet, "http://h/ws/notify", nil)
	r2.Header.Set("Upgrade", "websocket")
	if got := protocolOf(t, r2); got != "" {
		t.Fatalf("missing connection token must not tag, got %q", got)
	}
}

// §9 词表扩展管线打标：JSON_RPC / XML_RPC / SSE / WEBHOOK / FILE_UPLOAD /
// FILE_DOWNLOAD（请求侧 Range）/ FORM_API / UNKNOWN_HTTP_API 逐值正例与边界。
func TestProcessProtocolVocabulary(t *testing.T) {
	// JSON-RPC：jsonrpc+method 契约字段
	r, _ := http.NewRequest(http.MethodPost, "http://h/rpc", strings.NewReader(`{"jsonrpc":"2.0","method":"getUser","id":1}`))
	r.Header.Set("Content-Type", "application/json")
	if got := protocolOf(t, r); got != "JSON_RPC" {
		t.Fatalf("json-rpc protocol = %q", got)
	}
	// 边界：仅 method 字段的普通 JSON → REST_JSON（不乱标 JSON_RPC）
	r, _ = http.NewRequest(http.MethodPost, "http://h/v1/users", strings.NewReader(`{"method":"getUser"}`))
	r.Header.Set("Content-Type", "application/json")
	if got := protocolOf(t, r); got != "REST_JSON" {
		t.Fatalf("plain json with method field protocol = %q, want REST_JSON", got)
	}

	// XML-RPC：text/xml + methodCall.methodName
	r, _ = http.NewRequest(http.MethodPost, "http://h/xmlrpc", strings.NewReader(`<?xml version="1.0"?><methodCall><methodName>getUser</methodName><params/></methodCall>`))
	r.Header.Set("Content-Type", "text/xml")
	if got := protocolOf(t, r); got != "XML_RPC" {
		t.Fatalf("xml-rpc protocol = %q", got)
	}

	// SSE：Accept: text/event-stream（结构性信号，不挂 IsAPI 门槛）
	r, _ = http.NewRequest(http.MethodGet, "http://h/events/stream", nil)
	r.Header.Set("Accept", "text/event-stream")
	if got := protocolOf(t, r); got != "SERVER_SENT_EVENTS" {
		t.Fatalf("sse protocol = %q", got)
	}

	// Webhook：POST + X-GitHub-Event
	r, _ = http.NewRequest(http.MethodPost, "http://h/hooks/github", strings.NewReader(`{"ref":"main"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-GitHub-Event", "push")
	if got := protocolOf(t, r); got != "WEBHOOK" {
		t.Fatalf("webhook protocol = %q", got)
	}

	// 文件上传：multipart 含文件 part
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", "a.png")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte("png-bytes")); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	r, _ = http.NewRequest(http.MethodPost, "http://h/upload", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	if got := protocolOf(t, r); got != "FILE_UPLOAD" {
		t.Fatalf("file upload protocol = %q", got)
	}

	// 文件下载（请求侧弱信号）：GET + Range: bytes=
	r, _ = http.NewRequest(http.MethodGet, "http://h/files/report.pdf", nil)
	r.Header.Set("Range", "bytes=0-1023")
	if got := protocolOf(t, r); got != "FILE_DOWNLOAD" {
		t.Fatalf("range download protocol = %q", got)
	}
	// 边界：普通 GET 无 Range 不打 FILE_DOWNLOAD；非 API 静态资源不带扩展
	r, _ = http.NewRequest(http.MethodGet, "http://h/assets/logo.png", nil)
	if got := protocolOf(t, r); got != "" {
		t.Fatalf("static asset must not carry api.protocol, got %q", got)
	}

	// FORM_API：urlencoded + API 分类命中（/api/v1 前缀凑足判定线）
	r, _ = http.NewRequest(http.MethodPost, "http://h/api/v1/login", strings.NewReader(`u=a&p=b`))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if got := protocolOf(t, r); got != "FORM_API" {
		t.Fatalf("form api protocol = %q", got)
	}
	// 边界：普通页面表单（非 API 分类）不打标
	r, _ = http.NewRequest(http.MethodPost, "http://h/login", strings.NewReader(`u=a&p=b`))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if got := protocolOf(t, r); got != "" {
		t.Fatalf("plain page form must not carry api.protocol, got %q", got)
	}

	// UNKNOWN_HTTP_API：API 分类命中但无任何具体协议形态信号
	r, _ = http.NewRequest(http.MethodGet, "http://h/api/v1/health", nil)
	if got := protocolOf(t, r); got != "UNKNOWN_HTTP_API" {
		t.Fatalf("unknown http api protocol = %q", got)
	}
}

// §8.2 四级识别标签与 0-100 置信度随 Process 落扩展（与 IsAPI 同源）。
func TestProcessClassificationExtension(t *testing.T) {
	r, _ := http.NewRequest(http.MethodPost, "http://h/v1/orders", strings.NewReader(`{"id":1}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	res, err := Process(r, Config{Enabled: true, Mode: decision.ModeProtect}, nil)
	if err != nil {
		t.Fatal(err)
	}
	lv, _ := res.Context.GetExtension("api.classification")
	if lv != "CONFIRMED_API" || res.API.Level != "CONFIRMED_API" {
		t.Fatalf("classification = %v / %q, want CONFIRMED_API", lv, res.API.Level)
	}
	c100, _ := res.Context.GetExtension("api.confidence100")
	if c100 != 100 || res.API.Confidence100 != 100 {
		t.Fatalf("confidence100 = %v / %d, want 100", c100, res.API.Confidence100)
	}
	// 非 API：NON_API/0 如实落扩展
	r2, _ := http.NewRequest(http.MethodGet, "http://h/docs", nil)
	r2.Header.Set("Content-Type", "text/html")
	res2, err := Process(r2, Config{Enabled: true, Mode: decision.ModeProtect}, nil)
	if err != nil {
		t.Fatal(err)
	}
	lv2, _ := res2.Context.GetExtension("api.classification")
	if lv2 != "NON_API" || res2.API.IsAPI {
		t.Fatalf("non-api classification = %v, IsAPI=%v", lv2, res2.API.IsAPI)
	}
}

// FILE_DOWNLOAD 响应侧升级：Content-Disposition 附件下载覆盖请求相位通用族标签；
// 结构性协议标签不覆盖；无 filename 的响应不改标签。
func TestProcessResponseFileDownloadProtocol(t *testing.T) {
	newCtx := func(proto string) *dsctx.RequestContext {
		ctx := dsctx.New("rid-dl", dsctx.DefaultParseLimits())
		if proto != "" {
			ctx.SetExtension("api.protocol", proto)
		}
		return ctx
	}
	download := ResponseInput{
		Status:             200,
		ContentType:        "application/zip",
		ContentDisposition: `attachment; filename="report.zip"`,
		BodySize:           1024,
	}

	// 通用族标签被升级
	ctx := newCtx("REST_JSON")
	if _, err := ProcessResponse(ctx, download, ResponseConfig{Mode: decision.ModeProtect}); err != nil {
		t.Fatal(err)
	}
	if v, _ := ctx.GetExtension("api.protocol"); v != "FILE_DOWNLOAD" {
		t.Fatalf("generic tag must upgrade to FILE_DOWNLOAD, got %v", v)
	}
	// 无标签请求（非 API 路径不常态进入本相位，防御性覆盖）同样打标
	ctx = newCtx("")
	if _, err := ProcessResponse(ctx, download, ResponseConfig{Mode: decision.ModeProtect}); err != nil {
		t.Fatal(err)
	}
	if v, _ := ctx.GetExtension("api.protocol"); v != "FILE_DOWNLOAD" {
		t.Fatalf("untagged ctx must tag FILE_DOWNLOAD, got %v", v)
	}
	// 结构性协议标签不覆盖
	ctx = newCtx("GRAPHQL")
	if _, err := ProcessResponse(ctx, download, ResponseConfig{Mode: decision.ModeProtect}); err != nil {
		t.Fatal(err)
	}
	if v, _ := ctx.GetExtension("api.protocol"); v != "GRAPHQL" {
		t.Fatalf("structural tag must stay, got %v", v)
	}
	// 无 filename 的响应不改标签
	ctx = newCtx("REST_JSON")
	plain := ResponseInput{Status: 200, ContentType: "application/json", Body: []byte(`{"ok":true}`), BodySize: 11}
	if _, err := ProcessResponse(ctx, plain, ResponseConfig{Mode: decision.ModeProtect}); err != nil {
		t.Fatal(err)
	}
	if v, _ := ctx.GetExtension("api.protocol"); v != "REST_JSON" {
		t.Fatalf("non-download response must not change tag, got %v", v)
	}
}
