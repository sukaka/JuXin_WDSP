// protocol.go 协议类型打标（任务书 §9 词表）。
//
// 与 grpc.go 同一纪律：保守精确、只做打标（protocol 进事件与端点发现），
// 不参与 API 分类打分；结构性协议（WS 握手/GraphQL/SOAP/RPC/SSE/文件传输/Webhook）
// 不挂 api.IsAPI 分类门槛（分类漏判不应关掉协议标注），通用 REST 族
// （REST_JSON/REST_XML/FORM_API/UNKNOWN_HTTP_API）仅 API 分类命中时打标——
// 非 API 普通 Web 流量保持零事件变化（采集端缺省 REST 口径）。
// 拿不准的一律不标/回落 REST 族，禁止乱标。
package classifier

import (
	"mime"
	"strings"

	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// 协议类型词表（任务书 §9，13 值 + 历史值 GRPC；与 api_endpoints.protocol_type 一致）。
const (
	ProtocolRESTJSON           = "REST_JSON"           // JSON 请求体的通用 REST 接口
	ProtocolRESTXML            = "REST_XML"            // XML 请求体且非 SOAP/XML-RPC 的通用接口
	ProtocolFormAPI            = "FORM_API"            // application/x-www-form-urlencoded 表单接口
	ProtocolSOAP               = "SOAP"                // application/soap+xml，或 xml + SOAPAction
	ProtocolGraphQL            = "GRAPHQL"             // 解析层双重确认（application/graphql 或 /graphql+query）
	ProtocolJSONRPC            = "JSON_RPC"            // JSON 体顶层同含 jsonrpc 与 method 字段
	ProtocolXMLRPC             = "XML_RPC"             // XML 体根元素 methodCall（含 methodCall.methodName 叶子）
	ProtocolWebhook            = "WEBHOOK"             // POST + 已知 Webhook 投递方签名/事件头
	ProtocolFileUpload         = "FILE_UPLOAD"         // multipart/form-data 且含文件 part
	ProtocolFileDownload       = "FILE_DOWNLOAD"       // 请求侧 Range 分段；响应侧 Content-Disposition 附件可升级
	ProtocolWebsocketHandshake = "WEBSOCKET_HANDSHAKE" // RFC 6455 升级握手（Upgrade+Connection 双头）
	ProtocolSSE                = "SERVER_SENT_EVENTS"  // Accept: text/event-stream
	ProtocolUnknownHTTPAPI     = "UNKNOWN_HTTP_API"    // 判定为 API 但无任何具体协议形态信号
	// ProtocolGRPC 历史词表值（§9 之外保留）：gRPC 由 ClassifyGRPC 单独识别，
	// 管线侧另有端点键全保留/帧校验等附加处理，不经 ClassifyProtocol。
	ProtocolGRPC = "GRPC"
)

// ClassifyGraphQL 识别 GraphQL 流量：解析层已产出操作类型即确认
// （application/graphql 原始查询文档，或 /graphql 路径 + JSON body 含 query 字段）。
func ClassifyGraphQL(p *parser.Parsed) bool {
	return p != nil && p.GraphQLOperation != ""
}

// ClassifySOAP 识别 SOAP 流量：
//   - 媒体类型 application/soap+xml（SOAP 1.2 注册类型）；或
//   - text/xml / application/xml + 存在 SOAPAction 请求头（SOAP 1.1 惯例）。
func ClassifySOAP(p *parser.Parsed) bool {
	if p == nil {
		return false
	}
	mt, _, err := mime.ParseMediaType(p.ContentType)
	if err != nil {
		// 头部畸形降级为 ';' 前缀小写（与 parser.splitMediaType 同一纪律）
		mt = strings.ToLower(strings.TrimSpace(strings.SplitN(p.ContentType, ";", 2)[0]))
	}
	mt = strings.ToLower(mt)
	if mt == "application/soap+xml" {
		return true
	}
	if (mt == "text/xml" || mt == "application/xml") && p.Headers["soapaction"] != "" {
		return true
	}
	return false
}

// ClassifyWebSocket 识别 WebSocket 升级握手（RFC 6455 §4.1）：
// Upgrade: websocket 且 Connection 令牌列表含 upgrade（容忍逗号分隔/大小写/空格）。
// 仅标注握手请求；升级后的帧不是 HTTP，不在本管线覆盖范围。
func ClassifyWebSocket(p *parser.Parsed) bool {
	if p == nil {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(p.Headers["upgrade"]), "websocket") {
		return false
	}
	for _, token := range strings.Split(p.Headers["connection"], ",") {
		if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
			return true
		}
	}
	return false
}

// ClassifyJSONRPC 识别 JSON-RPC：JSON 请求体顶层同时存在 jsonrpc 与 method 字段
// （JSON-RPC 2.0 请求/通知的契约字段；仅有其一不打标，防普通业务字段误判）。
func ClassifyJSONRPC(p *parser.Parsed) bool {
	if p == nil || !p.IsJSON {
		return false
	}
	if _, ok := p.JSONFields["jsonrpc"]; !ok {
		return false
	}
	_, ok := p.JSONFields["method"]
	return ok
}

// ClassifyXMLRPC 识别 XML-RPC：XML 请求体根元素 methodCall
// （解析层叶子路径 methodCall.methodName 存在即确认；响应侧 methodResponse 不在请求相位出现）。
func ClassifyXMLRPC(p *parser.Parsed) bool {
	if p == nil {
		return false
	}
	_, ok := p.XMLFields["methodCall.methodName"]
	return ok
}

// ClassifySSE 识别 Server-Sent Events 入口：Accept 头含 text/event-stream（RFC/HTML 标准媒体类型）。
func ClassifySSE(p *parser.Parsed) bool {
	if p == nil {
		return false
	}
	return strings.Contains(strings.ToLower(p.Headers["accept"]), "text/event-stream")
}

// webhookSignatureHeaders 已知 Webhook 投递方签名/事件头（存在即强信号；
// 只放专有头名，普通业务不会携带）。
var webhookSignatureHeaders = []string{
	"x-github-event",        // GitHub
	"x-hub-signature-256",   // GitHub 签名
	"x-gitlab-event",        // GitLab
	"x-stripe-signature",    // Stripe
	"x-slack-signature",     // Slack
	"x-shopify-hmac-sha256", // Shopify
	"x-shopify-topic",       // Shopify
}

// ClassifyWebhook 识别入站 Webhook：POST + 任一已知投递方签名/事件头。
// 限定 POST：上述投递方均以 POST 投递，收窄方法防普通请求带同名头误判。
func ClassifyWebhook(p *parser.Parsed) bool {
	if p == nil || p.Method != "POST" {
		return false
	}
	for _, h := range webhookSignatureHeaders {
		if p.Headers[h] != "" {
			return true
		}
	}
	return false
}

// ClassifyFileUpload 识别文件上传接口：multipart/form-data 且解析层确认含文件 part。
func ClassifyFileUpload(p *parser.Parsed) bool {
	return p != nil && p.HasFiles
}

// ClassifyFileDownloadRequest 请求侧下载形态（弱信号）：GET/HEAD + Range: bytes= 分段请求。
// 主信号在响应侧（Content-Disposition 附件，pipeline 响应相位据下载观测升级打标）；
// 无 Range 的普通 GET 不打标，宁可回落 REST 族。
func ClassifyFileDownloadRequest(p *parser.Parsed) bool {
	if p == nil || (p.Method != "GET" && p.Method != "HEAD") {
		return false
	}
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(p.Headers["range"])), "bytes=")
}

// IsGenericProtocol 判定扩展值是否为通用 REST 族协议标签
// （响应相位遇到 Content-Disposition 附件下载等强信号时仅允许覆盖通用族，
// 结构性协议标签不覆盖）。
func IsGenericProtocol(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	switch s {
	case ProtocolRESTJSON, ProtocolRESTXML, ProtocolFormAPI, ProtocolUnknownHTTPAPI:
		return true
	}
	return false
}

// mediaType 取 Content-Type 媒体类型小写（畸形头部降级为 ';' 前缀，与 parser 同一纪律）。
func mediaType(contentType string) string {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mt = strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0])
	}
	return strings.ToLower(mt)
}

// isXMLMedia 判断 XML 族媒体类型（text/xml、application/xml、application/*+xml 不含 soap——
// SOAP 已在 ClassifyProtocol 链前置判定）。
func isXMLMedia(mt string) bool {
	if mt == "text/xml" || mt == "application/xml" {
		return true
	}
	return strings.HasPrefix(mt, "application/") && strings.HasSuffix(mt, "+xml") &&
		!strings.Contains(mt, "soap")
}

// ClassifyProtocol 协议类型统一打标入口（任务书 §9；gRPC 除外——管线单独处理）。
// 返回 "" 表示不打标（非 API 且无结构性协议形态的普通流量，事件保持零变化）。
// 判定顺序即优先级：结构性协议优先于通用 REST 族，同请求只落一个值。
func ClassifyProtocol(p *parser.Parsed, isAPI bool) string {
	if p == nil {
		return ""
	}
	switch {
	case ClassifyWebSocket(p):
		return ProtocolWebsocketHandshake
	case ClassifyGraphQL(p):
		return ProtocolGraphQL
	case ClassifySOAP(p):
		return ProtocolSOAP
	case ClassifyXMLRPC(p):
		return ProtocolXMLRPC
	case ClassifyJSONRPC(p):
		return ProtocolJSONRPC
	case ClassifySSE(p):
		return ProtocolSSE
	case ClassifyFileUpload(p):
		return ProtocolFileUpload
	case ClassifyFileDownloadRequest(p):
		return ProtocolFileDownload
	case ClassifyWebhook(p):
		return ProtocolWebhook
	}
	if !isAPI {
		return ""
	}
	mt := mediaType(p.ContentType)
	switch {
	case mt == "application/x-www-form-urlencoded":
		return ProtocolFormAPI
	case isXMLMedia(mt):
		return ProtocolRESTXML
	case p.IsJSON || strings.Contains(mt, "json"):
		return ProtocolRESTJSON
	default:
		return ProtocolUnknownHTTPAPI
	}
}
