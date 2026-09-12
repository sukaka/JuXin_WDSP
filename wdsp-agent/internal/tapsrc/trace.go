// Envoy tap TraceWrapper（JSON_BODY_AS_BYTES）→ v2 记录规范化。
//
// 口径（契约附录 B；全部如实，不造假值）：
//   - 缓冲输出不含时间戳/地址/连接/流 ID：时间戳取 tap 消息接收时间
//     （request_ts=response_ts=collection_ts，latency_ms=0 不表达业务延迟）；
//     五元组以 127.0.0.1:0 占位；capture_stream_id=null（不可获得）；
//   - 请求/响应配对由 Envoy 按流缓冲完成（一条 HttpBufferedTrace = 一个
//     HTTP/2 流），适配器不做跨消息配对；
//   - 协议版本：tap 中 HTTP/1 与 HTTP/2 呈现同一伪头形态，观测协议只能
//     来自 channel 部署断言（listener 维度），缺省 UNKNOWN；tap 位于下游
//     侧时原协议=观测协议（断言有效时），否则 null——不回填不推断；
//   - 伪头映射：:method/:path/:scheme/:authority → 请求行四元组；authority
//     与 host 头冲突时 authority 为准，冲突 host 头移除（不静默覆盖语义：
//     以权威值为准并剥离歧义头，与 mirrorsrc 同口径）；
//   - 正文：Envoy 按 max_buffered_*_bytes 截断时 truncated=true 且
//     original_total_size=null（截断后总大小不可确认，契约 V1.1）；
//     未截断时 original_total_size=实际缓冲长度；gRPC 正文默认不采集
//     （content_type 跳过，不解析 Protobuf）；WebSocket 升级流正文（帧）
//     不驻留；
//   - trailers：响应 trailers 保序保留（gRPC grpc-status 来源）；请求侧
//     同理；缺失（null）=来源不可见，空对象=确认无 trailer；
//   - gRPC：content-type application/grpc* 判定；service/method 由 :path
//     可信解析；grpc_status 取自响应 trailers grpc-status（0~16，非法值
//     视为不可见=null，不伪造 0）；stream_state：获得 grpc-status → CLOSED，
//     否则 UNKNOWN（取消/未完成/不可见如实 UNKNOWN）。
package tapsrc

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
	"github.com/jiuzhang-waf/wdsp-agent/internal/httpsensor"
)

// headerControlPrefix 控制命名空间前缀：采集前整体剥离，永不入记录。
const headerControlPrefix = "x-wdsp-"

// traceWrapper envoy.data.tap.v3.TraceWrapper JSON（仅 HTTP 缓冲 trace；
// 其余字段/类型忽略）。
type traceWrapper struct {
	HTTPBufferedTrace *httpBufferedTrace `json:"http_buffered_trace"`
}

type httpBufferedTrace struct {
	Request  *tapMessage `json:"request"`
	Response *tapMessage `json:"response"`
}

type tapMessage struct {
	Headers  []tapHeader `json:"headers"`
	Body     *tapBody    `json:"body"`
	Trailers []tapHeader `json:"trailers"`
}

type tapHeader struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type tapBody struct {
	AsBytes   string `json:"as_bytes"`
	AsString  string `json:"as_string"`
	Truncated bool   `json:"truncated"`
}

// headerSet 伪头提取后的头部集合（保序多值 + 存储总量钳）。
type headerSet struct {
	values    events.HTTPHeaderValues // 常规头（小写名 → 保序值数组）
	method    string
	path      string
	scheme    string
	authority string
	status    int // :status（响应侧；0=无）
	clamped   bool
}

// splitHeaders 拆分伪头与常规头：小写规范化、剥离 x-wdsp-* 控制命名空间、
// 同名多值保序保留、存储总量 ≤16KB（超出钳断计数）。输入视为不可信线上数据。
func splitHeaders(hs []tapHeader) headerSet {
	out := headerSet{values: events.HTTPHeaderValues{}}
	stored := 0
	for _, h := range hs {
		name := strings.ToLower(strings.TrimSpace(h.Key))
		if name == "" || strings.HasPrefix(name, headerControlPrefix) {
			continue
		}
		if strings.HasPrefix(name, ":") {
			switch name {
			case ":method":
				if out.method == "" {
					out.method = h.Value
				}
			case ":path":
				if out.path == "" {
					out.path = h.Value
				}
			case ":scheme":
				if out.scheme == "" {
					out.scheme = h.Value
				}
			case ":authority":
				if out.authority == "" {
					out.authority = h.Value
				}
			case ":status":
				if out.status == 0 {
					if v, err := strconv.Atoi(strings.TrimSpace(h.Value)); err == nil {
						out.status = v
					}
				}
			}
			continue
		}
		need := len(name) + len(h.Value) + 4
		if stored+need > maxHeaderStoreBytes {
			out.clamped = true
			continue
		}
		stored += need
		out.values[name] = append(out.values[name], h.Value)
	}
	return out
}

// joined 多值集 → 单值 map（httpsensor 出口入参形态；内容类型判断等用，
// 同名多值 ", " 连接——与 mirrorsrc/httpsensor 契约 §3 口径一致）。
func (s headerSet) joined() map[string]string {
	out := make(map[string]string, len(s.values))
	for k, vs := range s.values {
		out[k] = strings.Join(vs, ", ")
	}
	return out
}

// decodeBody 解码 tap 正文（JSON_BODY_AS_BYTES：as_bytes 为 base64）。
// 返回捕获字节与原始总大小是否可确认（Envoy 截断后总大小不可确认）。
// 防御性再钳制到 limit（Envoy 已按 max_buffered_* 截断，此处为纵深防御）。
func (m *tapMessage) decodeBody(limit int) (raw []byte, total int64, knownTotal, truncated bool) {
	if m.Body == nil {
		return nil, 0, true, false // 确认无正文
	}
	truncated = m.Body.Truncated
	var data []byte
	switch {
	case m.Body.AsBytes != "":
		d, err := base64.StdEncoding.DecodeString(m.Body.AsBytes)
		if err != nil {
			// 非法 base64：视为不可解码，正文跳过（不造假）
			return nil, 0, !truncated, truncated
		}
		data = d
	case m.Body.AsString != "":
		data = []byte(m.Body.AsString)
	}
	if len(data) > limit {
		data = data[:limit]
		truncated = true
	}
	if truncated {
		return data, 0, false, true // 截断后原始总大小不可确认（契约 V1.1：null）
	}
	return data, int64(len(data)), true, false
}

// normalize 一条 HttpBufferedTrace → v2 记录（脱敏经 httpsensor 同一出口）。
func (s *Source) normalize(tr *httpBufferedTrace, now time.Time) events.HTTPRecordV2 {
	pol := s.policy.Load()
	req := tr.Request
	rhs := splitHeaders(req.Headers)
	if rhs.clamped {
		s.Stats.HeaderClamped.Add(1)
	}

	isGRPC := strings.HasPrefix(mediaType(rhs.values["content-type"]), "application/grpc")
	isWSUpgrade := headerHasToken(rhs.values["upgrade"], "websocket")

	host := rhs.authority
	if host == "" {
		if hv := rhs.values["host"]; len(hv) > 0 {
			host = hv[0]
		}
	} else if hv := rhs.values["host"]; len(hv) > 0 && !strings.EqualFold(hv[0], host) {
		// authority 与 host 头冲突：authority 为准，冲突 host 头移除（不静默覆盖）
		delete(rhs.values, "host")
	}
	scheme := rhs.scheme
	if scheme != "http" && scheme != "https" {
		// 伪头缺失/非法：按终止点断言取默认（TLS 终止 listener → https）
		if s.cfg.TLSTerminated {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	uri := rhs.path
	if i := strings.IndexByte(uri, '#'); i >= 0 {
		uri = uri[:i] // fragment 不属于线上请求（防御性剔除）
	}

	rawReq, reqTotal, reqKnown, reqTrunc := req.decodeBody(s.cfg.MaxBodyBytes)
	if !s.cfg.BodyEnabled || isGRPC || isWSUpgrade {
		rawReq = nil // 默认仅元数据；gRPC 消息正文默认不采集；WS 帧不驻留
	}
	reqMsg := httpsensor.MaskedRequestMessage(httpsensor.MaskedRequestInput{
		Method:    rhs.method,
		Host:      host,
		URI:       uri,
		Headers:   rhs.joined(),
		RawBody:   rawReq,
		WireSize:  reqTotal,
		Truncated: reqTrunc,
	}, pol, &s.Stats.sensorStats)

	// 多值头逐值脱敏（保序保留重复值；禁止隐式逗号合并 Set-Cookie）
	maskedReqHeaders, n := httpsensor.MaskedHeaderValues(rhs.values, pol.Masking.Headers)
	if n > 0 {
		s.Stats.sensorStats.MaskedFields.Add(uint64(n))
	}

	ts := float64(now.UnixMilli()) / 1000
	v1 := events.HTTPRecord{
		FlowID: fmt.Sprintf("%s-tap-%s-%s-%d-%d",
			s.agentID, s.cfg.SourceInstance, s.cfg.ConfigID, now.UnixMilli(), s.seq.Add(1)),
		RequestTS:     ts,
		SrcIP:         "127.0.0.1", // tap 缓冲输出不含地址：回环占位，不伪造
		SrcPort:       0,
		DstIP:         "127.0.0.1",
		DstPort:       0,
		Direction:     "ingress",
		TLSVisibility: visibilityOf(s.cfg.TLSTerminated),
		Request:       reqMsg,
	}

	var respMsg *events.HTTPMessage
	var maskedRespHeaders events.HTTPHeaderValues
	var respStatus int
	var respTrunc bool
	var respKnown bool
	var respTotal int64
	if tr.Response != nil {
		rhs2 := splitHeaders(tr.Response.Headers)
		if rhs2.clamped {
			s.Stats.HeaderClamped.Add(1)
		}
		respStatus = rhs2.status
		var rawResp []byte
		rawResp, respTotal, respKnown, respTrunc = tr.Response.decodeBody(s.cfg.MaxBodyBytes)
		if !s.cfg.BodyEnabled || isGRPC || isWSUpgrade {
			rawResp = nil
		}
		respMsg = httpsensor.MaskedResponseMessage(httpsensor.MaskedResponseInput{
			Status:    respStatus,
			Headers:   rhs2.joined(),
			RawBody:   rawResp,
			WireSize:  respTotal,
			Truncated: respTrunc,
		}, pol, &s.Stats.sensorStats)
		maskedRespHeaders, n = httpsensor.MaskedHeaderValues(rhs2.values, pol.Masking.Headers)
		if n > 0 {
			s.Stats.sensorStats.MaskedFields.Add(uint64(n))
		}
		v1.Response = respMsg
		// tap 缓冲输出不含时间戳：响应时间=消息接收时间，latency 恒 0
		// （不表达业务延迟——口径见契约附录 B；同步 null 规则要求非 null）
		v1.ResponseTS = &ts
		zero := int64(0)
		v1.LatencyMs = &zero
	}

	out := events.NewHTTPRecordV2(s.agentID, v1, events.SourceRef{
		Type:                events.SourceEnvoyTap,
		Instance:            s.cfg.SourceInstance,
		Epoch:               s.epoch,
		CapabilitiesVersion: CapabilitiesVersion,
		ObservedHTTPVersion: s.cfg.ObservedHTTPVersion,
		// tap 位于下游侧：原协议=观测协议（断言有效时）；UNKNOWN 时
		// 不可确认 → null（不回填观测值）
		OriginalHTTPVersion: originalOf(s.cfg.ObservedHTTPVersion),
	})

	// 响应缺失：流异常结束（取消/重置/断连）时 Envoy 仍可能冲刷请求侧
	// ——如实 REQUEST_ONLY/DISCONNECT，不自称 COMPLETE
	if tr.Response == nil {
		out.AssociationState = events.AssocRequestOnly
		out.AssociationReason = events.AssocReasonDisconnect
	}

	// 覆盖多值头/trailer（v2 数组形态；NewHTTPRecordV2 的默认映射为单值展开）
	out.Request.Scheme = scheme
	out.Request.Headers = maskedReqHeaders
	out.Request.Trailers = s.maskTrailers(req.Trailers, pol)
	fixBodyQuality(&out.Request.BodyQuality, reqTrunc, reqKnown, reqTotal)
	// tap 缓冲输出不含连接/流标识：capture_stream_id=null（不造假；
	// NewHTTPRecordV2 默认以 flow_id 填充，对 tap 来源不适用）
	out.CaptureStreamID = nil
	if (isGRPC || isWSUpgrade) && bodyExisted(req) {
		// gRPC 消息正文/WS 帧默认不采集：content_type 跳过（captured=0）
		out.Request.Body = ""
		out.Request.BodyQuality.CapturedBytes = 0
		out.Request.BodyQuality.SkippedReason = "content_type"
	}
	if out.Response != nil {
		out.Response.Headers = maskedRespHeaders
		out.Response.Trailers = s.maskTrailers(tr.Response.Trailers, pol)
		fixBodyQuality(&out.Response.BodyQuality, respTrunc, respKnown, respTotal)
		if (isGRPC || isWSUpgrade) && bodyExisted(tr.Response) {
			out.Response.Body = ""
			out.Response.BodyQuality.CapturedBytes = 0
			out.Response.BodyQuality.SkippedReason = "content_type"
		}
	}

	// gRPC 元数据（HTTP 200 ≠ RPC 成功；不解析 Protobuf 正文）
	if isGRPC {
		out.GRPC = grpcInfoOf(uri, tr.Response)
	}
	return out
}

// maskTrailers trailer 列表 → 脱敏多值形态；null（未携带）=来源不可见，
// 空对象=确认无 trailer。grpc-status/grpc-message 不在默认脱敏名单，
// 由策略规则照常处理（敏感 trailer 名可经策略追加）。
func (s *Source) maskTrailers(ts []tapHeader, pol *httpsensor.Policy) events.HTTPHeaderValues {
	if ts == nil {
		return nil
	}
	set := splitHeaders(ts)
	if set.clamped {
		s.Stats.HeaderClamped.Add(1)
	}
	masked, n := httpsensor.MaskedHeaderValues(set.values, pol.Masking.Headers)
	if n > 0 {
		s.Stats.sensorStats.MaskedFields.Add(uint64(n))
	}
	return masked
}

// fixBodyQuality tap 截断语义修正（契约 V1.1）：Envoy 截断 → truncated=true
// 且 original_total_size=null（总大小不可确认）；未截断 → original_total_size
// =实际缓冲长度（已知）。
func fixBodyQuality(q *events.BodyQuality, tapTruncated, knownTotal bool, total int64) {
	switch {
	case tapTruncated || !knownTotal:
		q.Truncated = true
		q.OriginalTotalSize = nil
	case total > 0:
		q.OriginalTotalSize = &total
	}
}

// grpcInfoOf gRPC 元数据（service/method 由 :path 可信解析；grpc_status
// 取自响应 trailers，trailers-only 响应（错误快捷路径）时在响应 headers 中；
// 取消/未完成/不可见如实 UNKNOWN，不伪造 0）。
func grpcInfoOf(uri string, resp *tapMessage) *events.GRPCInfo {
	info := &events.GRPCInfo{StreamState: "UNKNOWN"}
	path := uri
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	if strings.HasPrefix(path, "/") {
		if i := strings.LastIndexByte(path, '/'); i > 0 {
			info.Service = path[1:i]
			info.Method = path[i+1:]
		}
	}
	if resp == nil {
		return info // 流未结束/不可见：grpc_status=null, stream_state=UNKNOWN
	}
	// trailers 优先；trailers-only 响应的 grpc-status 出现在 headers（实测：
	// Envoy 对 trailers-only 响应把状态头并入响应 headers 呈现）
	for _, hs := range [][]tapHeader{resp.Trailers, resp.Headers} {
		for _, h := range hs {
			if !strings.EqualFold(strings.TrimSpace(h.Key), "grpc-status") {
				continue
			}
			if v, err := strconv.Atoi(strings.TrimSpace(h.Value)); err == nil && v >= 0 && v <= 16 {
				vv := v
				info.GRPCStatus = &vv
				info.StreamState = "CLOSED"
			}
			// 非法 grpc-status 值：视为不可见（保持 null/UNKNOWN），不伪造
			return info
		}
	}
	return info
}

// visibilityOf TLS 可见性（部署断言：可信终止点 listener → DECRYPTED；
// 不由外部 Header 决定）。
func visibilityOf(tlsTerminated bool) string {
	if tlsTerminated {
		return "DECRYPTED"
	}
	return events.VisibilityPlaintext
}

// originalOf tap 位于下游侧：原协议=观测断言（UNKNOWN → 空，NewHTTPRecordV2
// 映射为 null；不回填不推断）。
func originalOf(observed string) string {
	return observed
}

// bodyExisted tap 消息是否携带正文（含截断但无字节的情形）。
func bodyExisted(m *tapMessage) bool {
	return m.Body != nil && (m.Body.AsBytes != "" || m.Body.AsString != "" || m.Body.Truncated)
}

// mediaType content-type 首值媒体类型（小写、去参数）。
func mediaType(vs []string) string {
	if len(vs) == 0 {
		return ""
	}
	ct := vs[0]
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.ToLower(strings.TrimSpace(ct))
}

// headerHasToken 逗号分隔头值含指定 token（大小写不敏感；Connection/Upgrade 判断用）。
func headerHasToken(vs []string, token string) bool {
	for _, v := range vs {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}
