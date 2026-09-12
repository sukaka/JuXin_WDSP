// HTTP 记录构造与脱敏唯一出口（Phase 3 契约 §3/§5）。
//
// 红线：包内所有 HTTP 记录均由 conn.emit 发出 → buildRequest/buildResponse
// 内联完成脱敏（headers/query/Body 一级参数），不存在任何绕过脱敏的发送路径。
package httpsensor

import (
	"strconv"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
)

// emit 一对请求/响应关联完成后的唯一上报出口（resp=nil 表示响应未捕获/超时）。
func (c *conn) emit(req *requestInfo, resp *responseInfo, respTS time.Time) {
	s := c.sensor
	pol := s.policy.Load()
	// Phase 4：Body 门控按本连接生效等级（按流调制）；全局等级为回落
	if lvl := c.getLevel(); lvl != "" && lvl != pol.Level {
		eff := *pol
		eff.Level = lvl
		pol = &eff
	}
	rec := events.HTTPRecord{
		FlowID:        c.key.flowID(s.agentID, c.start),
		RequestTS:     tsSeconds(req.ts),
		SrcIP:         c.key.srcIP,
		SrcPort:       c.key.srcPort,
		DstIP:         c.key.dstIP,
		DstPort:       c.key.dstPort,
		Direction:     c.dir,
		TLSVisibility: events.VisibilityPlaintext, // 仅明文流产出 HTTP 记录
		Request:       buildRequest(req, pol, &s.Stats),
	}
	if resp != nil {
		rec.Response = buildResponse(resp, pol, &s.Stats)
		ts := tsSeconds(respTS)
		rec.ResponseTS = &ts
		lat := respTS.Sub(req.ts).Milliseconds()
		if lat < 0 {
			lat = 0
		}
		rec.LatencyMs = &lat
	}
	s.Stats.RecordsEmitted.Add(1)
	if s.onRecord != nil {
		s.onRecord(rec)
	}
}

// buildRequest 构造请求消息（脱敏内联：Header 规则 + URI query 参数规则）。
// 实际脱敏的字段数累加进 stats.MaskedFields（masked 指标，P1-03 §5.7）。
func buildRequest(req *requestInfo, pol *Policy, stats *Stats) *events.HTTPMessage {
	masked := 0
	headers := cloneHeaders(req.headers)
	masked += maskHeaders(headers, pol.Masking.Headers)
	body := processBody(req.rawBody, req.wireSize, req.truncated, req.headers, pol, &masked)
	uri, n := maskURI(req.uri, pol.Masking.Params)
	masked += n
	if stats != nil && masked > 0 {
		stats.MaskedFields.Add(uint64(masked))
	}
	return &events.HTTPMessage{
		Method:            req.method,
		Scheme:            "http",
		Host:              req.host,
		URI:               uri,
		Headers:           headers,
		Body:              body.body,
		BodyTruncated:     body.truncated,
		OriginalBodySize:  body.origSize,
		BodySkippedReason: body.skipped,
	}
}

// buildResponse 构造响应消息（脱敏内联：Header 规则 + Body 一级参数规则）。
func buildResponse(resp *responseInfo, pol *Policy, stats *Stats) *events.HTTPMessage {
	masked := 0
	headers := cloneHeaders(resp.headers)
	masked += maskHeaders(headers, pol.Masking.Headers)
	body := processBody(resp.rawBody, resp.wireSize, resp.truncated, resp.headers, pol, &masked)
	if stats != nil && masked > 0 {
		stats.MaskedFields.Add(uint64(masked))
	}
	return &events.HTTPMessage{
		Status:            resp.status,
		Headers:           headers,
		Body:              body.body,
		BodyTruncated:     body.truncated,
		OriginalBodySize:  body.origSize,
		BodySkippedReason: body.skipped,
	}
}

// cloneHeaders 复制 Header map（脱敏就地修改，不得污染解析态）。
func cloneHeaders(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// tsSeconds Unix 秒浮点（毫秒精度，契约 §3）。
func tsSeconds(t time.Time) float64 {
	return float64(t.UnixMilli()) / 1000
}

// flowID 与 flow 包一致的 flow_id 格式（契约 §3.4）。
func (k connKey) flowID(agentID string, start time.Time) string {
	return agentID + "-" + k.srcIP + "-" + strconv.Itoa(int(k.srcPort)) + "-" +
		k.dstIP + "-" + strconv.Itoa(int(k.dstPort)) + "-" + strconv.FormatInt(start.Unix(), 10)
}
