// http_events_v2.go HTTP 事件 schema v2（契约 docs/agents/WDSP_AGENT_HTTP_EVENT_V2_CONTRACT.md
// §1/§2；任务书 P1-03 §4.1/§4.2，G0+G1）：
//
//   - v2 记录为 v1 超集：既有字段类型/必填性/同步 null 语义不变，新增 event_id（幂等键）、
//     来源三元组（source_type/source_instance/source_epoch）、协议观测（observed/original
//     _http_version）、tls_visibility 扩展 DECRYPTED、关联状态（association_state/reason）、
//     流标识（capture_stream_id）、来源绑定（application_binding_id/binding_version）、
//     headers/trailers 数组形态（保序保留重复值）、grpc 元数据子对象、body_quality、
//     collection_ts（ingestion_ts 由服务端生成，不在上报报文中）；
//   - 批次顶层 schema_version=2 判别；全量校验（收集全部非法记录的索引+原因）后单事务
//     写入，按 (agent_id, event_id) 幂等去重——重复确认但不重复入库、不扩大资产计数。
package agents

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

// HTTPEventSchemaV2 v2 批次判别值（包络 schema_version 字段）。
const HTTPEventSchemaV2 = 2

// v2 字段上限（契约 §2）。
const (
	maxHTTPEventIDLen        = 128
	maxHTTPSourceInstanceLen = 255
	maxHTTPSourceCapsVerLen  = 64
	maxHTTPCaptureStreamLen  = 255
	maxHTTPAssocReasonLen    = 64
	maxHTTPGRPCFieldLen      = 255
)

// eventIDPattern event_id 线格式（契约 §2：不得含敏感正文，随机或哈希派生）。
var eventIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// 来源类型枚举（契约 §2；NGINX_MIRROR/ENVOY_TAP 由 G2/G3 适配器产生）。
const (
	SourceTypePassiveHTTP1 = "PASSIVE_HTTP1"
	SourceTypeNginxMirror  = "NGINX_MIRROR"
	SourceTypeEnvoyTap     = "ENVOY_TAP"
)

// 关联状态枚举（契约 §2）。
const (
	AssocStateComplete     = "COMPLETE"
	AssocStateRequestOnly  = "REQUEST_ONLY"
	AssocStatePartial      = "PARTIAL"
	AssocStateUncorrelated = "UNCORRELATED"
)

// 关联原因枚举（契约 §2；state=COMPLETE 时必须为空串，其余必须非空）。
const (
	AssocReasonSourceRequestOnly = "SOURCE_REQUEST_ONLY"
	AssocReasonTimeout           = "TIMEOUT"
	AssocReasonDisconnect        = "DISCONNECT"
	AssocReasonTruncated         = "TRUNCATED"
	AssocReasonCorrelationMiss   = "CORRELATION_MISS"
)

// HTTP 版本枚举（契约 §2；UNKNOWN=无法确认，不从 User-Agent 推断）。
const (
	HTTPVersion10      = "1.0"
	HTTPVersion11      = "1.1"
	HTTPVersion2       = "2"
	HTTPVersion3       = "3"
	HTTPVersionUnknown = "UNKNOWN"
)

// tls_visibility v2 取值（v1 端点仍 fail-closed 只收 PLAINTEXT）。
const (
	TLSPlaintext = "PLAINTEXT"
	TLSDecrypted = "DECRYPTED"
	TLSUnknown   = "UNKNOWN"
)

// gRPC 流状态枚举（契约 §2.2）。
const (
	GRPCStreamOpen      = "OPEN"
	GRPCStreamClosed    = "CLOSED"
	GRPCStreamCancelled = "CANCELLED"
	GRPCStreamUnknown   = "UNKNOWN"
)

// 资产关联状态枚举（契约 §5，agent_http_asset_sources.association_state）。
const (
	AssetLinkLinked        = "LINKED"         // 端点 upsert 成功
	AssetLinkUnassigned    = "UNASSIGNED"     // v2 记录未声明来源绑定，待管理面确认
	AssetLinkQuotaRejected = "QUOTA_REJECTED" // 授权端点配额拒绝
	AssetLinkFailed        = "FAILED"         // 其他关联失败（last_error 记类别原因）
)

// HTTPHeaderValues v2 headers/trailers 形态（契约 §2：数组保序保留重复值，
// 禁止隐式逗号合并——尤其 Set-Cookie；名小写规范化由 Agent 完成）。
type HTTPHeaderValues map[string][]string

// HTTPBodyQuality 报文体质量（契约 §2.1：未知长度 original_total_size 必须 null，
// 不得填 0；captured_bytes 为脱敏前测量的实际捕获字节数）。
type HTTPBodyQuality struct {
	CapturedBytes     int64  `json:"captured_bytes"`
	OriginalTotalSize *int64 `json:"original_total_size"`
	Truncated         bool   `json:"truncated"`
	SkippedReason     string `json:"skipped_reason"`
}

// GRPCMeta gRPC 元数据子对象（契约 §2.2；本期仅元数据，不解析 Protobuf 正文；
// HTTP 200 ≠ RPC 成功——grpc_status 来自 trailers，流未结束/不可见为 null，不得伪造 0）。
type GRPCMeta struct {
	Service     string `json:"service"`
	Method      string `json:"method"`
	GRPCStatus  *int   `json:"grpc_status"`
	StreamState string `json:"stream_state"`
}

// HTTPRequestPartV2 v2 请求侧（请求行四元组必填同 v1；trailers 可空——
// null=来源不可见，空对象=确认无 trailer）。
type HTTPRequestPartV2 struct {
	Method      string           `json:"method"`
	Scheme      string           `json:"scheme"`
	Host        string           `json:"host"`
	URI         string           `json:"uri"`
	Headers     HTTPHeaderValues `json:"headers"`
	Trailers    HTTPHeaderValues `json:"trailers"`
	Body        string           `json:"body"`
	BodyQuality HTTPBodyQuality  `json:"body_quality"`
}

// HTTPResponsePartV2 v2 响应侧（record.response 可为 null——未捕获/超时/单向源）。
type HTTPResponsePartV2 struct {
	Status      int              `json:"status"`
	Headers     HTTPHeaderValues `json:"headers"`
	Trailers    HTTPHeaderValues `json:"trailers"`
	Body        string           `json:"body"`
	BodyQuality HTTPBodyQuality  `json:"body_quality"`
}

// HTTPRecordV2 单条 v2 HTTP 事件。
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
	OriginalHTTPVersion       *string `json:"original_http_version"`
	AssociationState          string  `json:"association_state"`
	AssociationReason         string  `json:"association_reason"`
	CaptureStreamID           *string `json:"capture_stream_id"`
	ApplicationBindingID      *string `json:"application_binding_id"`
	BindingVersion            *int64  `json:"binding_version"`

	Request  HTTPRequestPartV2   `json:"request"`
	Response *HTTPResponsePartV2 `json:"response"`
	GRPC     *GRPCMeta           `json:"grpc"`
	K8s      *K8sMetadata        `json:"k8s,omitempty"`
}

// HTTPRecordsRequestV2 v2 批量上报入参（包络 schema_version 恒为 2）。
type HTTPRecordsRequestV2 struct {
	SchemaVersion int            `json:"schema_version"`
	Records       []HTTPRecordV2 `json:"records"`
}

// InvalidRecord 永久非法记录定位（契约 §4.4：返回全部非法记录的索引与原因，
// 整批不部分提交；客户端隔离后重建剩余批次重发）。
type InvalidRecord struct {
	Index  int    `json:"index"`
	Reason string `json:"reason"`
}

// Validate 全量校验（契约 §4.1：逐条校验、收集全部非法记录——不再首错即返）。
// 返回 nil 表示整批合法；非 nil 切片为全部非法记录索引+原因（批次级错误放 index=-1）。
func (req *HTTPRecordsRequestV2) Validate() []InvalidRecord {
	if req.SchemaVersion != HTTPEventSchemaV2 {
		return []InvalidRecord{{Index: -1, Reason: fmt.Sprintf("schema_version 须为 %d", HTTPEventSchemaV2)}}
	}
	if len(req.Records) == 0 {
		return []InvalidRecord{{Index: -1, Reason: "records 不能为空"}}
	}
	if len(req.Records) > MaxHTTPRecordsPerBatch {
		return []InvalidRecord{{Index: -1, Reason: fmt.Sprintf(
			"records 每批上限 %d 条（当前 %d 条，请分批上报）", MaxHTTPRecordsPerBatch, len(req.Records))}}
	}
	var out []InvalidRecord
	for i := range req.Records {
		if err := req.Records[i].validate(); err != nil {
			out = append(out, InvalidRecord{Index: i, Reason: fmt.Sprintf("records[%d]: %v", i, err)})
		}
	}
	return out
}

func (rec *HTTPRecordV2) validate() error {
	if !validK8sMetadata(rec.K8s) {
		rec.K8s = nil
	}
	rec.EventID = strings.TrimSpace(rec.EventID)
	if !eventIDPattern.MatchString(rec.EventID) {
		return fmt.Errorf("event_id 缺失或非法（1~%d 字符，字母数字开头，可含 . _ : -）", maxHTTPEventIDLen)
	}
	rec.FlowID = strings.TrimSpace(rec.FlowID)
	if rec.FlowID == "" || len(rec.FlowID) > 255 {
		return errors.New("flow_id 缺失或超过 255 字符")
	}
	if math.IsNaN(rec.RequestTS) || math.IsInf(rec.RequestTS, 0) || rec.RequestTS <= 0 {
		return errors.New("request_ts 须为正 Unix 秒（浮点，毫秒精度）")
	}
	if math.IsNaN(rec.CollectionTS) || math.IsInf(rec.CollectionTS, 0) || rec.CollectionTS <= 0 {
		return errors.New("collection_ts 须为正 Unix 秒（浮点，毫秒精度）")
	}
	// response 与 response_ts/latency_ms 同步 null（沿用 v1 契约 §3）。
	if rec.Response == nil {
		if rec.ResponseTS != nil || rec.LatencyMS != nil {
			return errors.New("response 为 null 时 response_ts/latency_ms 须同步为 null")
		}
	} else {
		if rec.ResponseTS == nil || rec.LatencyMS == nil {
			return errors.New("response 存在时 response_ts/latency_ms 必填")
		}
		if math.IsNaN(*rec.ResponseTS) || math.IsInf(*rec.ResponseTS, 0) || *rec.ResponseTS < rec.RequestTS {
			return errors.New("response_ts 须 ≥ request_ts")
		}
		if *rec.LatencyMS < 0 || *rec.LatencyMS > math.MaxInt32 {
			return errors.New("latency_ms 须在 0~2^31-1")
		}
	}
	if _, err := netip.ParseAddr(rec.SrcIP); err != nil {
		return errors.New("src_ip 缺失或不是合法 IP 地址")
	}
	if _, err := netip.ParseAddr(rec.DstIP); err != nil {
		return errors.New("dst_ip 缺失或不是合法 IP 地址")
	}
	if rec.SrcPort < 0 || rec.SrcPort > 65535 || rec.DstPort < 0 || rec.DstPort > 65535 {
		return errors.New("端口须在 0~65535")
	}
	switch rec.Direction {
	case "ingress", "egress", "both":
	default:
		return errors.New("direction 须为 ingress/egress/both 之一")
	}
	if err := rec.validateSource(); err != nil {
		return err
	}
	if err := rec.Request.validate(); err != nil {
		return err
	}
	if rec.Response != nil {
		if err := rec.Response.validate(); err != nil {
			return fmt.Errorf("response: %w", err)
		}
	}
	return rec.validateGRPC()
}

// validateSource 来源/协议观测/关联状态/绑定字段校验（契约 §2）。
func (rec *HTTPRecordV2) validateSource() error {
	switch rec.SourceType {
	case SourceTypePassiveHTTP1, SourceTypeNginxMirror, SourceTypeEnvoyTap:
	default:
		return errors.New("source_type 须为 PASSIVE_HTTP1/NGINX_MIRROR/ENVOY_TAP 之一")
	}
	rec.SourceInstance = strings.TrimSpace(rec.SourceInstance)
	if rec.SourceInstance == "" || len(rec.SourceInstance) > maxHTTPSourceInstanceLen {
		return fmt.Errorf("source_instance 缺失或超过 %d 字符", maxHTTPSourceInstanceLen)
	}
	if rec.SourceEpoch < 0 {
		return errors.New("source_epoch 不能为负")
	}
	if len(rec.SourceCapabilitiesVersion) > maxHTTPSourceCapsVerLen {
		return fmt.Errorf("source_capabilities_version 超过 %d 字符", maxHTTPSourceCapsVerLen)
	}
	if !validHTTPVersion(rec.ObservedHTTPVersion) {
		return errors.New("observed_http_version 须为 1.0/1.1/2/3/UNKNOWN 之一")
	}
	if rec.OriginalHTTPVersion != nil {
		v := strings.TrimSpace(*rec.OriginalHTTPVersion)
		if !validHTTPVersion(v) {
			return errors.New("original_http_version 须为 1.0/1.1/2/3/UNKNOWN 或 null")
		}
		rec.OriginalHTTPVersion = &v
	}
	switch rec.TLSVisibility {
	case TLSPlaintext, TLSDecrypted, TLSUnknown:
	default:
		return errors.New("tls_visibility 须为 PLAINTEXT/DECRYPTED/UNKNOWN 之一（v2）")
	}
	switch rec.AssociationState {
	case AssocStateComplete, AssocStateRequestOnly, AssocStatePartial, AssocStateUncorrelated:
	default:
		return errors.New("association_state 须为 COMPLETE/REQUEST_ONLY/PARTIAL/UNCORRELATED 之一")
	}
	if len(rec.AssociationReason) > maxHTTPAssocReasonLen {
		return fmt.Errorf("association_reason 超过 %d 字符", maxHTTPAssocReasonLen)
	}
	if rec.AssociationState == AssocStateComplete {
		if rec.AssociationReason != "" {
			return errors.New("association_state=COMPLETE 时 association_reason 须为空串")
		}
	} else {
		switch rec.AssociationReason {
		case AssocReasonSourceRequestOnly, AssocReasonTimeout, AssocReasonDisconnect,
			AssocReasonTruncated, AssocReasonCorrelationMiss:
		default:
			return errors.New("association_state 非 COMPLETE 时 association_reason 须为 SOURCE_REQUEST_ONLY/TIMEOUT/DISCONNECT/TRUNCATED/CORRELATION_MISS 之一")
		}
	}
	// response 整体缺失（未捕获/单向源）时不得自称 COMPLETE。
	if rec.Response == nil && rec.AssociationState == AssocStateComplete {
		return errors.New("response 为 null 时 association_state 不得为 COMPLETE")
	}
	if rec.CaptureStreamID != nil {
		v := strings.TrimSpace(*rec.CaptureStreamID)
		if v == "" || len(v) > maxHTTPCaptureStreamLen {
			return fmt.Errorf("capture_stream_id 为 null 或 1~%d 字符", maxHTTPCaptureStreamLen)
		}
		rec.CaptureStreamID = &v
	}
	// 绑定字段同有同无（契约 §2）；服务端不因自报 binding 授予跨应用写入。
	if (rec.ApplicationBindingID == nil) != (rec.BindingVersion == nil) {
		return errors.New("application_binding_id 与 binding_version 须同时为 null 或同时携带")
	}
	if rec.ApplicationBindingID != nil {
		if _, err := uuid.Parse(strings.TrimSpace(*rec.ApplicationBindingID)); err != nil {
			return errors.New("application_binding_id 不是合法 UUID")
		}
		if *rec.BindingVersion < 0 {
			return errors.New("binding_version 不能为负")
		}
	}
	return nil
}

func validHTTPVersion(v string) bool {
	switch v {
	case HTTPVersion10, HTTPVersion11, HTTPVersion2, HTTPVersion3, HTTPVersionUnknown:
		return true
	}
	return false
}

func (p *HTTPRequestPartV2) validate() error {
	p.Method = strings.ToUpper(strings.TrimSpace(p.Method))
	if p.Method == "" || len(p.Method) > 16 || strings.ContainsAny(p.Method, "\r\n\t\x00 ") {
		return errors.New("request.method 缺失或非法")
	}
	p.Scheme = strings.ToLower(strings.TrimSpace(p.Scheme))
	if p.Scheme != "http" && p.Scheme != "https" {
		return errors.New("request.scheme 须为 http/https 之一")
	}
	if p.Host == "" || len(p.Host) > maxHTTPHostLen || strings.ContainsAny(p.Host, "\r\n\x00") {
		return fmt.Errorf("request.host 缺失或超过 %d 字符或含控制字符", maxHTTPHostLen)
	}
	if p.URI == "" || len(p.URI) > maxHTTPURILen || strings.ContainsAny(p.URI, "\r\n\x00") {
		return fmt.Errorf("request.uri 缺失或超过 %d 字节或含控制字符", maxHTTPURILen)
	}
	if err := p.Headers.validate("request.headers"); err != nil {
		return err
	}
	if err := p.Trailers.validate("request.trailers"); err != nil {
		return err
	}
	if strings.IndexByte(p.Body, 0) >= 0 {
		return errors.New("request.body 含非法 NUL 字符")
	}
	return p.BodyQuality.validate("request")
}

func (p *HTTPResponsePartV2) validate() error {
	if p.Status < 100 || p.Status > 999 {
		return errors.New("status 须在 100~999")
	}
	if err := p.Headers.validate("response.headers"); err != nil {
		return err
	}
	if err := p.Trailers.validate("response.trailers"); err != nil {
		return err
	}
	if strings.IndexByte(p.Body, 0) >= 0 {
		return errors.New("response.body 含非法 NUL 字符")
	}
	return p.BodyQuality.validate("response")
}

// validate headers/trailers 数组形态（上限与 v1 一致；nil=未携带合法——trailers 可空，
// headers 由调用方语义决定：请求/响应 headers 均可为空对象；数组每项至少一个值）。
func (h HTTPHeaderValues) validate(field string) error {
	if len(h) > maxHTTPHeadersPerMessage {
		return fmt.Errorf("%s 最多 %d 条", field, maxHTTPHeadersPerMessage)
	}
	for name, values := range h {
		if name == "" || len(name) > maxHTTPHeaderNameLen || strings.ContainsAny(name, "\r\n\x00:") {
			return fmt.Errorf("%s 含非法 Header 名", field)
		}
		if len(values) == 0 {
			return fmt.Errorf("%s[%q] 值数组不能为空", field, name)
		}
		for _, value := range values {
			if len(value) > maxHTTPHeaderValueLen || strings.ContainsAny(value, "\r\n\x00") {
				return fmt.Errorf("%s[%q] 值超过 %d 字节或含控制字符", field, name, maxHTTPHeaderValueLen)
			}
		}
	}
	return nil
}

// validate body_quality 一致性（契约 §2.1）。
func (q *HTTPBodyQuality) validate(side string) error {
	if q.CapturedBytes < 0 {
		return fmt.Errorf("%s.body_quality.captured_bytes 不能为负", side)
	}
	if q.OriginalTotalSize != nil && *q.OriginalTotalSize < 0 {
		return fmt.Errorf("%s.body_quality.original_total_size 不能为负（未知须为 null）", side)
	}
	switch q.SkippedReason {
	case "", SkipReasonContentType, SkipReasonEncoding:
	default:
		return fmt.Errorf("%s.body_quality.skipped_reason 须为 content_type/encoding 之一（或空）", side)
	}
	if q.SkippedReason != "" && q.CapturedBytes != 0 {
		return fmt.Errorf("%s.body_quality.skipped_reason 非空时 captured_bytes 须为 0", side)
	}
	// 契约 V1.1 修订：truncated=true 允许 original_total_size=null（原始总大小未知，
	// 如流式/tap 截断）；非 null 时必须 ≥ captured_bytes。
	if q.Truncated && q.OriginalTotalSize != nil && *q.OriginalTotalSize < q.CapturedBytes {
		return fmt.Errorf("%s.body_quality.truncated=true 且 original_total_size 非 null 时须 ≥ captured_bytes", side)
	}
	return nil
}

// validateGRPC gRPC 子对象（契约 §2.2；grpc_status null=流未结束/不可见，不得伪造 0）。
func (rec *HTTPRecordV2) validateGRPC() error {
	g := rec.GRPC
	if g == nil {
		return nil
	}
	if len(g.Service) > maxHTTPGRPCFieldLen || len(g.Method) > maxHTTPGRPCFieldLen {
		return fmt.Errorf("grpc.service/method 超过 %d 字符", maxHTTPGRPCFieldLen)
	}
	if strings.ContainsAny(g.Service, "\r\n\x00") || strings.ContainsAny(g.Method, "\r\n\x00") {
		return errors.New("grpc.service/method 含控制字符")
	}
	if g.GRPCStatus != nil && (*g.GRPCStatus < 0 || *g.GRPCStatus > 16) {
		return errors.New("grpc.grpc_status 须在 0~16 或为 null")
	}
	switch g.StreamState {
	case GRPCStreamOpen, GRPCStreamClosed, GRPCStreamCancelled, GRPCStreamUnknown:
	default:
		return errors.New("grpc.stream_state 须为 OPEN/CLOSED/CANCELLED/UNKNOWN 之一")
	}
	return nil
}

// SupportsHTTPEventV2 该 Agent 能力协商生效集是否包含 v2（契约 §3）。
func (a *Agent) SupportsHTTPEventV2() bool {
	for _, v := range a.HTTPEventSchemas {
		if v == HTTPEventSchemaV2 {
			return true
		}
	}
	return false
}

const APIObservationSchemaV1 = 1

// AgentCapabilities 能力声明（既有 HTTP 能力保持不变；API Observation 未声明即不支持）。
type AgentCapabilities struct {
	HTTPEventSchemaVersions      []int `json:"http_event_schema_versions"`
	APIObservationSchemaVersions []int `json:"api_observation_schema_versions"`
}

var serverHTTPEventSchemas = []int{1, HTTPEventSchemaV2}

func (c *AgentCapabilities) Validate() error {
	if c == nil {
		return nil
	}
	if len(c.HTTPEventSchemaVersions) > 8 {
		return errors.New("capabilities.http_event_schema_versions 最多 8 个元素")
	}
	seen := map[int]bool{}
	for _, v := range c.HTTPEventSchemaVersions {
		if v != 1 && v != HTTPEventSchemaV2 {
			return fmt.Errorf("capabilities.http_event_schema_versions 含不支持取值 %d", v)
		}
		if seen[v] {
			return errors.New("capabilities.http_event_schema_versions 含重复取值")
		}
		seen[v] = true
	}
	if len(c.APIObservationSchemaVersions) > 2 {
		return errors.New("capabilities.api_observation_schema_versions 最多 2 个元素")
	}
	seen = map[int]bool{}
	for _, v := range c.APIObservationSchemaVersions {
		if v != APIObservationSchemaV1 {
			return fmt.Errorf("capabilities.api_observation_schema_versions 含不支持取值 %d", v)
		}
		if seen[v] {
			return errors.New("capabilities.api_observation_schema_versions 含重复取值")
		}
		seen[v] = true
	}
	return nil
}

func schemasToInt16(vs []int) []int16 {
	out := make([]int16, 0, len(vs))
	for _, v := range vs {
		out = append(out, int16(v))
	}
	return out
}

func NegotiateHTTPEventSchemas(c *AgentCapabilities) []int {
	if c == nil || len(c.HTTPEventSchemaVersions) == 0 {
		return []int{1}
	}
	out := []int{}
	for _, supported := range serverHTTPEventSchemas {
		for _, v := range c.HTTPEventSchemaVersions {
			if v == supported {
				out = append(out, v)
				break
			}
		}
	}
	if len(out) == 0 {
		return []int{1}
	}
	return out
}

func NegotiateAPIObservationSchemas(c *AgentCapabilities) []int {
	if c == nil {
		return []int{}
	}
	for _, v := range c.APIObservationSchemaVersions {
		if v == APIObservationSchemaV1 {
			return []int{APIObservationSchemaV1}
		}
	}
	return []int{}
}

func (a *Agent) SupportsAPIObservationV1() bool {
	for _, v := range a.APIObservationSchemas {
		if v == APIObservationSchemaV1 {
			return true
		}
	}
	return false
}
