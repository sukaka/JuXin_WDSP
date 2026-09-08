// 受控适配器脱敏复用出口（P1-03 §3.1：新来源不得绕过统一脱敏）。
//
// Nginx mirror / Envoy tap 等适配器在 Agent 内自行完成传输层接收与解析后，
// 必须经本函数构造 HTTP 请求消息——与被动 HTTP/1 传感器共用同一脱敏与
// Body 后处理出口（maskHeaders / maskURI / processBody），不存在第二条
// 脱敏路径。输入视为不可信线上数据，本函数内联完成全部脱敏。
package httpsensor

import (
	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
)

// MaskedRequestInput 适配器已解析的请求素材（全部视为不可信输入）。
// Headers 键必须已小写规范化；RawBody 为已按上限截断的捕获字节，
// WireSize 为线上原始 Body 长度（0 表示无 Body 或长度未知——配合 Truncated
// 表达），Truncated 表示线上 Body 超出捕获上限。
type MaskedRequestInput struct {
	Method    string
	Host      string
	URI       string
	Headers   map[string]string
	RawBody   []byte
	WireSize  int64
	Truncated bool
}

// MaskedRequestMessage 构造脱敏后的请求消息（与 conn.emit → buildRequest
// 完全同路径：Header 规则脱敏 + URI query 参数脱敏 + Body 等级门控/解码/
// 内容类型白名单/一级参数脱敏）。stats 可为 nil；masked 指标照常累加。
func MaskedRequestMessage(in MaskedRequestInput, pol *Policy, stats *Stats) *events.HTTPMessage {
	if pol == nil {
		p := Policy{Level: config.LevelL1}
		pol = &p
	}
	req := &requestInfo{
		method:    in.Method,
		uri:       in.URI,
		host:      in.Host,
		headers:   in.Headers,
		rawBody:   in.RawBody,
		wireSize:  in.WireSize,
		truncated: in.Truncated,
	}
	return buildRequest(req, pol, stats)
}
