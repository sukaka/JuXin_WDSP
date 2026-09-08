// HTTP 事件 v2 记录构造与发送线格式（契约 docs/agents/WDSP_AGENT_HTTP_EVENT_V2_CONTRACT.md
// §1/§2 冻结；P1-03 G1 接通发送路径）。
//
// 红线：
//   - event_id 必须稳定（重试/重启不变）且不含敏感正文：由
//     SHA-256(agent_id ‖ flow_id ‖ request_ts) 派生，不接触 Body/Header；
//   - 记录进入本构造前必须已完成脱敏（同 v1 红线，本包不做二次脱敏）；
//   - 观测协议与可确认原协议分别表达；无法确认的一律 UNKNOWN/null，不推断；
//   - 线格式逐字段对齐契约 §2：headers/trailers 数组形态（保序保留重复值）、
//     body_quality 内嵌 request/response（original_total_size 未知必须 null）、
//     协议枚举 1.0/1.1/2/3/UNKNOWN、关联原因词表 SOURCE_REQUEST_ONLY/TIMEOUT/
//     DISCONNECT/TRUNCATED/CORRELATION_MISS——仅冻结字段不造假值。
package events

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"

	"github.com/jiuzhang-waf/wdsp-agent/internal/k8smeta"
)

// HTTPRecordSchemaVersion v2 事件 schema 版本（批次包络 schema_version 判别值）。
const HTTPRecordSchemaVersion = 2

// source_type 冻结枚举（契约 §2；NGINX_MIRROR/ENVOY_TAP 由 G2/G3 适配器产生）。
const (
	SourcePassiveHTTP1 = "PASSIVE_HTTP1"
	SourceNginxMirror  = "NGINX_MIRROR"
	SourceEnvoyTap     = "ENVOY_TAP"
)

// association_state 冻结枚举（契约 §2）。
const (
	AssocComplete     = "COMPLETE"
	AssocRequestOnly  = "REQUEST_ONLY"
	AssocPartial      = "PARTIAL"
	AssocUncorrelated = "UNCORRELATED"
)

// association_reason 冻结词表（契约 §2：state=COMPLETE 时必须为空串，其余必须非空）。
const (
	AssocReasonSourceRequestOnly = "SOURCE_REQUEST_ONLY" // 单向源（如 Nginx mirror）
	AssocReasonTimeout           = "TIMEOUT"             // 响应未捕获/超时
	AssocReasonDisconnect        = "DISCONNECT"
	AssocReasonTruncated         = "TRUNCATED"
	AssocReasonCorrelationMiss   = "CORRELATION_MISS"
)

// HTTP 版本冻结枚举（契约 §2；UNKNOWN=无法确认，不得从 User-Agent 推断）。
const (
	HTTPVersion10      = "1.0"
	HTTPVersion11      = "1.1"
	HTTPVersion2       = "2"
	HTTPVersion3       = "3"
	HTTPVersionUnknown = "UNKNOWN"
)

// SourceRef 采集来源身份（受控来源实例与重启代次；不替代 Agent 机器身份）。
type SourceRef struct {
	Type                string // SourceXxx 枚举
	Instance            string // 受控来源实例标识（配置指定，缺省 "default"）
	Epoch               int64  // 来源进程重启代次（Unix 秒，单调递增）
	CapabilitiesVersion string // 采集源能力版本（与 policy_version/Agent build 分开；空=无独立版本）
	ObservedHTTPVersion string // 观测协议（空按来源类型取默认；取值限 HTTPVersionXxx 枚举）
	OriginalHTTPVersion string // 可确认原协议（空/UNKNOWN=不可确认 → null，不回填观测值）
	RequestOnly         bool   // 单向来源（仅请求可见，如 Nginx mirror）
}

// HTTPHeaderValues v2 headers/trailers 线格式（契约 §2：数组形态保序保留重复值，
// 禁止隐式逗号合并——尤其 Set-Cookie；名小写规范化由 Agent 完成）。
type HTTPHeaderValues map[string][]string

// GRPCInfo gRPC 可空元数据（契约 §2.2 [冻结]，G3 产生；本期仅元数据，不解码
// Protobuf 正文；HTTP 200 ≠ RPC 成功）。
type GRPCInfo struct {
	Service     string `json:"service"`
	Method      string `json:"method"`
	GRPCStatus  *int   `json:"grpc_status"` // null=流未结束/不可见（不伪造 0）
	StreamState string `json:"stream_state"`
}

// BodyQuality 正文采集质量（契约 §2.1：内嵌 request/response；original_total_size
// 未知必须 null，0 仅表示确认为空报文体）。
type BodyQuality struct {
	CapturedBytes     int64  `json:"captured_bytes"`
	OriginalTotalSize *int64 `json:"original_total_size"`
	Truncated         bool   `json:"truncated"`
	SkippedReason     string `json:"skipped_reason"` // "" / content_type / encoding
}

// HTTPRequestPartV2 v2 请求侧（请求行四元组必填同 v1；trailers null=来源不可见）。
type HTTPRequestPartV2 struct {
	Method      string           `json:"method"`
	Scheme      string           `json:"scheme"`
	Host        string           `json:"host"`
	URI         string           `json:"uri"`
	Headers     HTTPHeaderValues `json:"headers"`
	Trailers    HTTPHeaderValues `json:"trailers"`
	Body        string           `json:"body"`
	BodyQuality BodyQuality      `json:"body_quality"`
}

// HTTPResponsePartV2 v2 响应侧（record.response 可为 null——未捕获/超时/单向源）。
type HTTPResponsePartV2 struct {
	Status      int              `json:"status"`
	Headers     HTTPHeaderValues `json:"headers"`
	Trailers    HTTPHeaderValues `json:"trailers"`
	Body        string           `json:"body"`
	BodyQuality BodyQuality      `json:"body_quality"`
}

// HTTPRecordV2 HTTP 事件 v2 记录线格式（契约 §2：v1 超集；schema_version 仅在
// 批次包络，记录级不重复携带）。
type HTTPRecordV2 struct {
	EventID       string   `json:"event_id"`
	FlowID        string   `json:"flow_id"`
	RequestTS     float64  `json:"request_ts"`
	ResponseTS    *float64 `json:"response_ts"` // response 为 null 时同步为 null
	LatencyMS     *int64   `json:"latency_ms"`  // 同上
	CollectionTS  float64  `json:"collection_ts"`
	SrcIP         string   `json:"src_ip"`
	SrcPort       int      `json:"src_port"`
	DstIP         string   `json:"dst_ip"`
	DstPort       int      `json:"dst_port"`
	Direction     string   `json:"direction"`
	TLSVisibility string   `json:"tls_visibility"`

	SourceType                string  `json:"source_type"`
	SourceInstance            string  `json:"source_instance"`
	SourceEpoch               int64   `json:"source_epoch"`
	SourceCapabilitiesVersion string  `json:"source_capabilities_version"`
	ObservedHTTPVersion       string  `json:"observed_http_version"`
	OriginalHTTPVersion       *string `json:"original_http_version"` // null=不可确认，不回填观测值
	AssociationState          string  `json:"association_state"`
	AssociationReason         string  `json:"association_reason"`
	CaptureStreamID           *string `json:"capture_stream_id"`
	ApplicationBindingID      *string `json:"application_binding_id"` // 与 binding_version 同有同无
	BindingVersion            *int64  `json:"binding_version"`

	Request  HTTPRequestPartV2   `json:"request"`
	Response *HTTPResponsePartV2 `json:"response"`
	GRPC     *GRPCInfo           `json:"grpc"`
	K8s      *k8smeta.Metadata   `json:"k8s,omitempty"`
}

// HTTPRequestV2 v2 批次包络（契约 §1：schema_version=2 判别）。
type HTTPRequestV2 struct {
	SchemaVersion int            `json:"schema_version"`
	Records       []HTTPRecordV2 `json:"records"`
}

// HTTPV2Response v2 批次 202 响应（契约 §4.3：accepted_count+duplicate_count==len(records)）。
type HTTPV2Response struct {
	AcceptedCount  int `json:"accepted_count"`
	DuplicateCount int `json:"duplicate_count"`
}

// InvalidRecord 服务端 400 永久非法记录定位（契约 §4.4：全部非法记录的索引与原因；
// 批次级错误 index=-1）。
type InvalidRecord struct {
	Index  int    `json:"index"`
	Reason string `json:"reason"`
}

// StableEventID 生成 Agent 范围内稳定事件 ID：SHA-256(agent_id ‖ flow_id ‖
// request_ts毫秒) 十六进制，ev- 前缀。同一记录重试/重启后 ID 不变（服务端
// 按 (agent_id, event_id) 幂等去重）；输入不含正文/Header，不泄漏敏感内容。
func StableEventID(agentID string, rec HTTPRecord) string {
	h := sha256.New()
	h.Write([]byte(agentID))
	h.Write([]byte{0})
	h.Write([]byte(rec.FlowID))
	h.Write([]byte{0})
	h.Write([]byte(strconv.FormatFloat(rec.RequestTS, 'f', 3, 64)))
	return "ev-" + hex.EncodeToString(h.Sum(nil))
}

// NewHTTPBatchV2 由已脱敏的 v1 记录构造 v2 批次（统一来源身份；契约 §1 包络）。
func NewHTTPBatchV2(agentID string, recs []HTTPRecord, src SourceRef) HTTPRequestV2 {
	out := HTTPRequestV2{SchemaVersion: HTTPRecordSchemaVersion, Records: make([]HTTPRecordV2, 0, len(recs))}
	for _, rec := range recs {
		out.Records = append(out.Records, NewHTTPRecordV2(agentID, rec, src))
	}
	return out
}

// NewHTTPRecordV2 由已脱敏的 v1 记录构造 v2 记录（被动 HTTP/1 采集的默认映射；
// Nginx/Envoy 适配器在 G2/G3 落地时提供各自的 SourceRef 与关联状态）。
func NewHTTPRecordV2(agentID string, rec HTTPRecord, src SourceRef) HTTPRecordV2 {
	if src.Instance == "" {
		src.Instance = "default"
	}
	out := HTTPRecordV2{
		EventID:                   StableEventID(agentID, rec),
		FlowID:                    rec.FlowID,
		RequestTS:                 rec.RequestTS,
		ResponseTS:                rec.ResponseTS,
		LatencyMS:                 rec.LatencyMs,
		CollectionTS:              rec.RequestTS, // 被动采集：采集时间≈请求时间
		SrcIP:                     rec.SrcIP,
		SrcPort:                   int(rec.SrcPort),
		DstIP:                     rec.DstIP,
		DstPort:                   int(rec.DstPort),
		Direction:                 rec.Direction,
		TLSVisibility:             rec.TLSVisibility,
		SourceType:                src.Type,
		SourceInstance:            src.Instance,
		SourceEpoch:               src.Epoch,
		SourceCapabilitiesVersion: src.CapabilitiesVersion,
		ObservedHTTPVersion:       src.ObservedHTTPVersion,
		K8s:                       rec.K8s,
	}
	if out.TLSVisibility == "" {
		out.TLSVisibility = VisibilityPlaintext // 密文流不产生 HTTP 记录（fail-closed 不变）
	}
	if out.ObservedHTTPVersion == "" {
		// 各来源默认观测协议；适配器可显式覆盖（契约枚举，非 "HTTP/x" 字面量）
		switch src.Type {
		case SourcePassiveHTTP1, SourceNginxMirror:
			out.ObservedHTTPVersion = HTTPVersion11
		default:
			out.ObservedHTTPVersion = HTTPVersionUnknown
		}
	}
	// 原协议不可确认时为 null，不从 User-Agent 推断、不以观测值回填
	if v := src.OriginalHTTPVersion; v != "" && v != HTTPVersionUnknown {
		out.OriginalHTTPVersion = &v
	}
	// 被动源作用域内连接标识（flow_id；不替代 Agent 身份或业务 Request ID）
	if rec.FlowID != "" {
		sid := rec.FlowID
		out.CaptureStreamID = &sid
	}
	if rec.Request != nil {
		out.Request = HTTPRequestPartV2{
			Method:      rec.Request.Method,
			Scheme:      rec.Request.Scheme,
			Host:        rec.Request.Host,
			URI:         rec.Request.URI,
			Headers:     headerValuesOf(rec.Request.Headers),
			Body:        rec.Request.Body,
			BodyQuality: bodyQualityOf(rec.Request),
		}
	} else {
		out.Request = HTTPRequestPartV2{Headers: HTTPHeaderValues{}}
	}
	if rec.Response != nil {
		out.Response = &HTTPResponsePartV2{
			Status:      rec.Response.Status,
			Headers:     headerValuesOf(rec.Response.Headers),
			Body:        rec.Response.Body,
			BodyQuality: bodyQualityOf(rec.Response),
		}
	}
	// 关联状态：响应成对 → COMPLETE（reason 恒空串）；单向源 → REQUEST_ONLY/
	// SOURCE_REQUEST_ONLY；响应缺失（超时/未捕获）→ REQUEST_ONLY/TIMEOUT
	switch {
	case rec.Response != nil && rec.ResponseTS != nil:
		out.AssociationState = AssocComplete
	case src.RequestOnly:
		out.AssociationState = AssocRequestOnly
		out.AssociationReason = AssocReasonSourceRequestOnly
	default:
		out.AssociationState = AssocRequestOnly
		out.AssociationReason = AssocReasonTimeout
	}
	return out
}

// headerValuesOf v1 单值 map → v2 数组形态（契约 §2：保序保留重复值的线格式；
// v1 采集侧同名 Header 已先行合并，此处每名展开为单元素数组；恒非 nil——
// headers 不允许 null，空对象 = 无头部）。
func headerValuesOf(h map[string]string) HTTPHeaderValues {
	out := make(HTTPHeaderValues, len(h))
	for k, v := range h {
		out[k] = []string{v}
	}
	return out
}

// bodyQualityOf 由 v1 消息的正文字段导出 v2 采集质量（契约 §2.1 一致性约束：
// skipped 时 captured=0；truncated 要求原始总大小已知且 ≥ captured）。
func bodyQualityOf(m *HTTPMessage) BodyQuality {
	q := BodyQuality{
		Truncated:     m.BodyTruncated,
		SkippedReason: m.BodySkippedReason,
		CapturedBytes: int64(len(m.Body)),
	}
	// 批次预算缩减标记 budget_exceeded 不在 v2 skipped_reason 枚举内；其语义即
	// "因预算截断"，如实转写为 truncated=true / skipped_reason=""。
	if q.SkippedReason == BodySkippedBudgetExceeded {
		q.SkippedReason = ""
		q.Truncated = true
	}
	switch {
	case m.OriginalBodySize > 0:
		orig := m.OriginalBodySize // 被动采集 wireSize 恒照记（httpsensor）
		q.OriginalTotalSize = &orig
	case m.Body == "" && !q.Truncated:
		zero := int64(0) // 确认为空报文体（契约 §2.1：0 仅表示确认空）
		q.OriginalTotalSize = &zero
	default:
		// 截断但原始总大小未知：被动采集不可达（截断发生时 wireSize 必大于
		// 已采字节）。保持 null 不造假值；若上游不变量被破坏，服务端校验会
		// 拒绝该条并由发送路径按索引隔离丢弃。
	}
	return q
}
