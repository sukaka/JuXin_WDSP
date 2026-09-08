// protocol.go GraphQL / SOAP / WebSocket 流量识别（协议词表补全）。
//
// 与 grpc.go 同一纪律：保守精确、只做打标（protocol 进事件与端点发现），
// 不参与 API 分类打分、不挂 api.IsAPI 分类门槛（分类漏判不应关掉协议标注）。
// 判定原料全部来自 parser.Parsed（GraphQL 已由解析层双重确认：
// application/graphql 原始查询，或 /graphql 路径 + JSON body 含 query 字段）。
package classifier

import (
	"mime"
	"strings"

	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
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
