// http_events.go Full HTTP 事件（Phase 3，契约 docs/agents/WDSP_AGENT_PHASE3_CONTRACT.md
// §3 上报格式 / §4 Body 约束 / §6 存储）：机器端批量上报类型与校验、管理端行结构。
//
// 关键口径：
//   - 每批 ≤ 100 条且请求体 ≤ 8MB（machineHTTPMaxBody，见 machine_http.go），超限由
//     Agent 分批；response 可为 null（响应未捕获/超时），此时 response_ts/latency_ms
//     必须同步为 null（契约 §3 冻结）；
//   - v1 批次仅 tls_visibility=PLAINTEXT 产生 HTTP 记录——密文流只走 flow 事件通道
//     （契约 §3），v1 路径拒绝其他取值（fail-closed）；v2 批次按 v2 契约 §2 接受
//     PLAINTEXT/DECRYPTED/UNKNOWN（见 http_events_v2.go，DECRYPTED 需可信终止点证据）；
//   - headers/body 已是 Agent 离主机前脱敏后的内容（契约 §5），服务端不二次脱敏，
//     但仍按既有纪律做长度/控制字符边界校验（防索引行宽/存储放大）；
//   - uri 上限 2048 字节：(host, uri) 复合索引受 btree 索引行宽约 2704 字节硬限制
//     （迁移 000112 注释），校验期拒绝避免插入期整批 500。
package agents

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"time"

	"encoding/json"
	"github.com/google/uuid"
)

// HTTP 事件批量与字段上限（契约 §3/§4 与索引行宽安全，详见包注释）。
const (
	// MaxHTTPRecordsPerBatch 每批记录上限（契约 §3：≤100 条）。
	MaxHTTPRecordsPerBatch = 100
	// maxHTTPURILen URI 上限（字节）——(host, uri) 索引行宽安全（迁移 000112 注释）。
	maxHTTPURILen = 2048
	// maxHTTPHostLen Host 上限（与列宽一致）。
	maxHTTPHostLen = 255
	// maxHTTPHeadersPerMessage 单方向 Header 条目上限。
	maxHTTPHeadersPerMessage = 64
	// maxHTTPHeaderNameLen Header 名上限（字节）。
	maxHTTPHeaderNameLen = 255
	// maxHTTPHeaderValueLen Header 值上限（字节）。
	maxHTTPHeaderValueLen = 8192
)

// body_skipped_reason 枚举（契约 §4：内容类型白名单外/解压失败）。
const (
	SkipReasonContentType = "content_type"
	SkipReasonEncoding    = "encoding"
)

// HTTPBodyFields 请求/响应共享的报文体字段（headers 为脱敏后扁平键值——契约 §3
// 示例冻结为 string map；body 为已截断/已摘要内容，原始长度记 original_body_size）。
type HTTPBodyFields struct {
	Headers           map[string]string `json:"headers"`
	Body              string            `json:"body"`
	BodyTruncated     bool              `json:"body_truncated"`
	OriginalBodySize  int64             `json:"original_body_size"`
	BodySkippedReason string            `json:"body_skipped_reason"`
}

// HTTPRequestPart 请求侧（method/scheme/host/uri 请求行四元组必填——L0 语义之上
// L1/L2 增加 headers/body）。
type HTTPRequestPart struct {
	Method string `json:"method"`
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	URI    string `json:"uri"`
	HTTPBodyFields
}

// HTTPResponsePart 响应侧（record.response 可为 null——响应未捕获/超时）。
type HTTPResponsePart struct {
	Status int `json:"status"`
	HTTPBodyFields
}

// HTTPRecord 单条 HTTP 事件（一对请求/响应关联完成后只上报一次——契约 §3）。
type HTTPRecord struct {
	FlowID        string            `json:"flow_id"`
	RequestTS     float64           `json:"request_ts"`  // Unix 秒浮点（毫秒精度）
	ResponseTS    *float64          `json:"response_ts"` // response 为 null 时同步为 null
	LatencyMS     *int64            `json:"latency_ms"`  // 同上
	SrcIP         string            `json:"src_ip"`
	SrcPort       int               `json:"src_port"`
	DstIP         string            `json:"dst_ip"`
	DstPort       int               `json:"dst_port"`
	Direction     string            `json:"direction"`
	TLSVisibility string            `json:"tls_visibility"`
	Request       HTTPRequestPart   `json:"request"`
	Response      *HTTPResponsePart `json:"response"`
	K8s           *K8sMetadata      `json:"k8s,omitempty"`
}

// HTTPRecordsRequest http 批量上报入参（schema_version 为 v2 契约 §1 包络判别字段——
// v1 批次缺省或显式 1；2 走 v2 路径，见 machine_http.go）。
type HTTPRecordsRequest struct {
	SchemaVersion int          `json:"schema_version,omitempty"`
	Records       []HTTPRecord `json:"records"`
}

// Validate 批量校验（≤100 条——契约 §3；逐记录必填/枚举/一致性校验；
// schema_version 仅允许缺省/1——v2 批次由 v2 类型校验）。
func (req *HTTPRecordsRequest) Validate() error {
	if req.SchemaVersion != 0 && req.SchemaVersion != 1 {
		return fmt.Errorf("schema_version 非法（v1 批次须缺省或为 1，当前 %d）", req.SchemaVersion)
	}
	if len(req.Records) == 0 {
		return errors.New("records 不能为空")
	}
	if len(req.Records) > MaxHTTPRecordsPerBatch {
		return fmt.Errorf("records 每批上限 %d 条（当前 %d 条，请分批上报）", MaxHTTPRecordsPerBatch, len(req.Records))
	}
	for i := range req.Records {
		if err := req.Records[i].validate(); err != nil {
			return fmt.Errorf("records[%d]: %w", i, err)
		}
	}
	return nil
}

func (rec *HTTPRecord) validate() error {
	if !validK8sMetadata(rec.K8s) {
		rec.K8s = nil
	}
	rec.FlowID = strings.TrimSpace(rec.FlowID)
	if rec.FlowID == "" || len(rec.FlowID) > 255 {
		return errors.New("flow_id 缺失或超过 255 字符")
	}
	if math.IsNaN(rec.RequestTS) || math.IsInf(rec.RequestTS, 0) || rec.RequestTS <= 0 {
		return errors.New("request_ts 须为正 Unix 秒（浮点，毫秒精度）")
	}
	// response 与 response_ts/latency_ms 同步 null（契约 §3）：同有同无。
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
	// 契约 §3：密文流不产生 HTTP 记录（仍走 flow 事件通道）——fail-closed 只收 PLAINTEXT。
	if rec.TLSVisibility != "PLAINTEXT" {
		return errors.New("tls_visibility 仅接受 PLAINTEXT（密文流不产生 HTTP 记录）")
	}
	if err := rec.Request.validate(); err != nil {
		return err
	}
	if rec.Response != nil {
		if err := rec.Response.validate(); err != nil {
			return fmt.Errorf("response: %w", err)
		}
	}
	return nil
}

func (p *HTTPRequestPart) validate() error {
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
	return p.HTTPBodyFields.validate("request")
}

func (p *HTTPResponsePart) validate() error {
	if p.Status < 100 || p.Status > 999 {
		return errors.New("status 须在 100~999")
	}
	return p.HTTPBodyFields.validate("response")
}

func (b *HTTPBodyFields) validate(side string) error {
	if len(b.Headers) > maxHTTPHeadersPerMessage {
		return fmt.Errorf("%s.headers 最多 %d 条", side, maxHTTPHeadersPerMessage)
	}
	for name, value := range b.Headers {
		if name == "" || len(name) > maxHTTPHeaderNameLen || strings.ContainsAny(name, "\r\n\x00:") {
			return fmt.Errorf("%s.headers 含非法 Header 名", side)
		}
		if len(value) > maxHTTPHeaderValueLen || strings.ContainsAny(value, "\r\n\x00") {
			return fmt.Errorf("%s.headers[%q] 值超过 %d 字节或含控制字符", side, name, maxHTTPHeaderValueLen)
		}
	}
	if b.OriginalBodySize < 0 {
		return fmt.Errorf("%s.original_body_size 不能为负", side)
	}
	switch b.BodySkippedReason {
	case "", SkipReasonContentType, SkipReasonEncoding:
	default:
		return fmt.Errorf("%s.body_skipped_reason 须为 content_type/encoding 之一（或空）", side)
	}
	return nil
}

// ---------- 管理端行结构 ----------

// HTTPEventRow HTTP 事件行（管理端；列表不含 headers/body——对应字段为 null，
// 详情 GET .../http-events/{id} 全量返回——契约 §6）。
type HTTPEventRow struct {
	ID               int64           `json:"id"`
	AgentID          uuid.UUID       `json:"agent_id"`
	FlowID           string          `json:"flow_id"`
	Ts               time.Time       `json:"ts"`
	LatencyMS        *int            `json:"latency_ms"`
	SrcIP            string          `json:"src_ip"`
	SrcPort          int             `json:"src_port"`
	DstIP            string          `json:"dst_ip"`
	DstPort          int             `json:"dst_port"`
	Direction        string          `json:"direction"`
	TLSVisibility    string          `json:"tls_visibility"`
	Method           string          `json:"method"`
	Scheme           string          `json:"scheme"`
	Host             string          `json:"host"`
	URI              string          `json:"uri"`
	Status           *int            `json:"status"`
	RequestHeaders   json.RawMessage `json:"request_headers"`
	ResponseHeaders  json.RawMessage `json:"response_headers"`
	RequestBody      *string         `json:"request_body"`
	ResponseBody     *string         `json:"response_body"`
	ReqTruncated     bool            `json:"req_truncated"`
	RespTruncated    bool            `json:"resp_truncated"`
	ReqOriginalSize  int64           `json:"req_original_size"`
	RespOriginalSize int64           `json:"resp_original_size"`
	// Req/RespSkippedReason body 未采集原因（000113 起持久化；''=正常采集，
	// content_type/encoding——与机器端上报 body_skipped_reason 同口径）。
	ReqSkippedReason  string          `json:"req_skipped_reason"`
	RespSkippedReason string          `json:"resp_skipped_reason"`
	CreatedAt         time.Time       `json:"created_at"`
	K8s               json.RawMessage `json:"k8s,omitempty"`

	// ---- 000133 v2 列（管理端展示，任务书 P1-03 §4.3） ----
	// v1 存量行取库默认值（schema_version=1 / source_type=PASSIVE_HTTP1 /
	// observed=UNKNOWN / 可空列 NULL），如实表达"旧采集无来源/协议观测信息"。
	SchemaVersion             int             `json:"schema_version"`
	EventID                   *string         `json:"event_id"`
	SourceType                string          `json:"source_type"`
	SourceInstance            string          `json:"source_instance"`
	SourceEpoch               int64           `json:"source_epoch"`
	SourceCapabilitiesVersion string          `json:"source_capabilities_version"`
	ObservedHTTPVersion       string          `json:"observed_http_version"`
	OriginalHTTPVersion       *string         `json:"original_http_version"`
	AssociationState          *string         `json:"association_state"`
	AssociationReason         string          `json:"association_reason"`
	CaptureStreamID           *string         `json:"capture_stream_id"`
	ApplicationBindingID      *uuid.UUID      `json:"application_binding_id"`
	BindingVersion            *int64          `json:"binding_version"`
	GRPC                      json.RawMessage `json:"grpc"`
	RequestTrailers           json.RawMessage `json:"request_trailers"`
	ResponseTrailers          json.RawMessage `json:"response_trailers"`
	ReqBodyQuality            json.RawMessage `json:"req_body_quality"`
	RespBodyQuality           json.RawMessage `json:"resp_body_quality"`
	CollectionTS              *time.Time      `json:"collection_ts"`
	IngestionTS               *time.Time      `json:"ingestion_ts"`
}

// HTTPEventFilter 管理端 http-events 列表过滤（host 精确匹配大小写不敏感；
// method 精确匹配大小写不敏感）。
type HTTPEventFilter struct {
	Host   string
	Method string
	Page   PageParams
}

// ---------- 管理端输出（契约 §3 嵌套结构 + v2 增量字段） ----------

// HTTPEventMessageJSON 管理端输出消息体（请求/响应共用）：
//   - Headers 为 json.RawMessage 双形态——v1 行 string map、v2 行数组 map
//     （{"name":["v1","v2"]}，保序保留重复值；同列双形态按 schema_version 区分解读，
//     v2 契约 §6）；v2 行还原失败（非数组形态）回落空对象，不静默吞成 null；
//   - Trailers/BodyQuality 仅 v2 行有值（v1 行输出 null——来源无此概念，不伪造）。
type HTTPEventMessageJSON struct {
	Headers           json.RawMessage `json:"headers"`
	Body              string          `json:"body"`
	BodyTruncated     bool            `json:"body_truncated"`
	OriginalBodySize  int64           `json:"original_body_size"`
	BodySkippedReason string          `json:"body_skipped_reason"`
	Trailers          json.RawMessage `json:"trailers"`
	BodyQuality       json.RawMessage `json:"body_quality"`
}

// HTTPEventRequestJSON 管理端输出请求侧。
type HTTPEventRequestJSON struct {
	Method string `json:"method"`
	Scheme string `json:"scheme"`
	Host   string `json:"host"`
	URI    string `json:"uri"`
	HTTPEventMessageJSON
}

// HTTPEventResponseJSON 管理端输出响应侧。
type HTTPEventResponseJSON struct {
	Status int `json:"status"`
	HTTPEventMessageJSON
}

// HTTPEventJSON 管理端输出记录（契约 §3 嵌套结构 + 顶层 id/agent_id——前后端统一形状；
// 机器端上报同为该嵌套结构，管理端仅追加存储主键与归属）。
//
// 字段口径：
//   - request_ts/response_ts 为 Unix 秒浮点（毫秒精度——time.Time 经 UnixMilli 转换，
//     避免二进制浮点尾差）；response_ts 由 request_ts + latency_ms 派生
//     （§6 表结构未单列 response_ts 列，latency_ms 为 Agent 实测关联时延）；
//   - response 为 NULL（响应未捕获/超时）时输出 "response": null 且
//     response_ts/latency_ms 同步为 null（与机器端上报口径一致）；
//   - body_skipped_reason 自迁移 000113 起持久化（content_type/encoding），
//     输出真实值——采集完整性信号（设计 §34/§35/§65），不再恒空串；
//   - v2 增量（v2 契约 §2/§6，任务书 §4.3）：schema_version/event_id/来源三元组与
//     能力版本/观测与原协议/关联状态与原因/流标识/来源绑定/grpc/trailers/body_quality/
//     collection_ts/ingestion_ts；v1 存量行如实输出库默认值或 null，不回填伪造；
//   - collection_ts（来源采集）与 ingestion_ts（服务端接收）分列——两者差值为
//     采集→入库延迟（缓存补传可辨），均不混入业务延迟（业务延迟仅 latency_ms）。
type HTTPEventJSON struct {
	ID            int64                  `json:"id"`
	AgentID       uuid.UUID              `json:"agent_id"`
	FlowID        string                 `json:"flow_id"`
	RequestTS     float64                `json:"request_ts"`
	ResponseTS    *float64               `json:"response_ts"`
	LatencyMS     *int64                 `json:"latency_ms"`
	SrcIP         string                 `json:"src_ip"`
	SrcPort       int                    `json:"src_port"`
	DstIP         string                 `json:"dst_ip"`
	DstPort       int                    `json:"dst_port"`
	Direction     string                 `json:"direction"`
	TLSVisibility string                 `json:"tls_visibility"`
	Request       HTTPEventRequestJSON   `json:"request"`
	Response      *HTTPEventResponseJSON `json:"response"`
	K8s           json.RawMessage        `json:"k8s,omitempty"`

	// ---- v2 增量（000133 列；v1 行为库默认值/null） ----
	SchemaVersion             int             `json:"schema_version"`
	EventID                   *string         `json:"event_id"`
	SourceType                string          `json:"source_type"`
	SourceInstance            string          `json:"source_instance"`
	SourceEpoch               int64           `json:"source_epoch"`
	SourceCapabilitiesVersion string          `json:"source_capabilities_version"`
	ObservedHTTPVersion       string          `json:"observed_http_version"`
	OriginalHTTPVersion       *string         `json:"original_http_version"`
	AssociationState          *string         `json:"association_state"`
	AssociationReason         string          `json:"association_reason"`
	CaptureStreamID           *string         `json:"capture_stream_id"`
	ApplicationBindingID      *uuid.UUID      `json:"application_binding_id"`
	BindingVersion            *int64          `json:"binding_version"`
	GRPC                      json.RawMessage `json:"grpc"`
	CollectionTS              *float64        `json:"collection_ts"`
	IngestionTS               *float64        `json:"ingestion_ts"`
}

// headersFromJSON jsonb → v1 string map（nil/空一律给非 nil 空对象——嵌套结构 headers
// 不输出 null）。仅适用于 v1 行；v2 行（数组形态）须走 headerValuesFromJSON。
func headersFromJSON(raw json.RawMessage) map[string]string {
	out := map[string]string{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil || out == nil {
			return map[string]string{}
		}
	}
	return out
}

// headerValuesFromJSON v2 行 jsonb → 数组形态 RawMessage 还原（v2 契约 §2：
// {"name":["v1","v2"]} 保序保留重复值）。nil/空 → "{}"；非数组形态（损坏/越版本数据）
// 回落 "{}"——不输出 null，不把非法形态原样透传给前端。
func headerValuesFromJSON(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage(`{}`)
	}
	var probe HTTPHeaderValues
	if err := json.Unmarshal(raw, &probe); err != nil || probe == nil {
		return json.RawMessage(`{}`)
	}
	return raw
}

// headersAdminJSON 按 schema_version 还原 headers 输出形态（同列双形态，v2 契约 §6）：
// v1 → string map 原样；v2 → 数组 map 还原。full=false（列表）一律 "{}"。
func headersAdminJSON(schemaVersion int, raw json.RawMessage, full bool) json.RawMessage {
	if !full {
		return json.RawMessage(`{}`)
	}
	if schemaVersion == HTTPEventSchemaV2 {
		return headerValuesFromJSON(raw)
	}
	out, err := json.Marshal(headersFromJSON(raw))
	if err != nil { // map[string]string 理论上不会失败；防御性兜底
		return json.RawMessage(`{}`)
	}
	return out
}

// unixFloat time.Time → Unix 秒浮点（毫秒精度，与 request_ts 口径一致）。
func unixFloat(t time.Time) float64 {
	return float64(t.UnixMilli()) / 1000.0
}

// unixFloatPtr 可空时间戳 → 可空 Unix 秒浮点。
func unixFloatPtr(t *time.Time) *float64 {
	if t == nil {
		return nil
	}
	v := unixFloat(*t)
	return &v
}

// ToNestedJSON 转换管理端输出（契约 §3 嵌套结构 + v2 增量字段）。
// full=false（列表）保持轻量：request/response 的 headers 置空对象、body 置空串，
// body_truncated/original_body_size 标志如实保留（前端列表需截断标记）；
// full=true（详情）给全量 headers/body，并还原 v2 trailers/body_quality 子对象。
// v2 标量字段（来源/协议/关联/绑定/时间戳）列表与详情均返回——列表需独立状态展示
// （任务书 §4.3/§8 AGT-026）；JSONB 子对象（grpc/trailers/body_quality）仅详情返回
// （与 headers/body 同纪律，列表行保持轻量）。
func (e *HTTPEventRow) ToNestedJSON(full bool) *HTTPEventJSON {
	// 零值归一：直构行（单测）未走库默认值时与存量 v1 行口径对齐。
	schemaVersion := e.SchemaVersion
	if schemaVersion == 0 {
		schemaVersion = 1
	}
	sourceType := e.SourceType
	if sourceType == "" {
		sourceType = SourceTypePassiveHTTP1
	}
	observed := e.ObservedHTTPVersion
	if observed == "" {
		observed = HTTPVersionUnknown
	}
	out := &HTTPEventJSON{
		ID:            e.ID,
		AgentID:       e.AgentID,
		FlowID:        e.FlowID,
		RequestTS:     unixFloat(e.Ts),
		SrcIP:         e.SrcIP,
		SrcPort:       e.SrcPort,
		DstIP:         e.DstIP,
		DstPort:       e.DstPort,
		Direction:     e.Direction,
		TLSVisibility: e.TLSVisibility,
		K8s:           e.K8s,
		Request: HTTPEventRequestJSON{
			Method: e.Method,
			Scheme: e.Scheme,
			Host:   e.Host,
			URI:    e.URI,
			HTTPEventMessageJSON: HTTPEventMessageJSON{
				Headers:           headersAdminJSON(schemaVersion, e.RequestHeaders, full),
				BodyTruncated:     e.ReqTruncated,
				OriginalBodySize:  e.ReqOriginalSize,
				BodySkippedReason: e.ReqSkippedReason,
			},
		},
		SchemaVersion:             schemaVersion,
		EventID:                   e.EventID,
		SourceType:                sourceType,
		SourceInstance:            e.SourceInstance,
		SourceEpoch:               e.SourceEpoch,
		SourceCapabilitiesVersion: e.SourceCapabilitiesVersion,
		ObservedHTTPVersion:       observed,
		OriginalHTTPVersion:       e.OriginalHTTPVersion,
		AssociationState:          e.AssociationState,
		AssociationReason:         e.AssociationReason,
		CaptureStreamID:           e.CaptureStreamID,
		ApplicationBindingID:      e.ApplicationBindingID,
		BindingVersion:            e.BindingVersion,
		CollectionTS:              unixFloatPtr(e.CollectionTS),
		IngestionTS:               unixFloatPtr(e.IngestionTS),
	}
	if full {
		// v2 行还原 JSONB 子对象；v1 行保持 null（来源无此概念，不伪造）。
		// trailers 保留 null（来源不可见）与 {}（确认无 trailer）的语义区分——v2 契约 §2。
		if schemaVersion == HTTPEventSchemaV2 {
			if e.RequestTrailers != nil {
				out.Request.Trailers = headerValuesFromJSON(e.RequestTrailers)
			}
			out.Request.BodyQuality = e.ReqBodyQuality
			out.GRPC = e.GRPC
		}
		if e.RequestBody != nil {
			out.Request.Body = *e.RequestBody
		}
	}
	if e.Status != nil {
		if e.LatencyMS != nil {
			ms := int64(*e.LatencyMS)
			out.LatencyMS = &ms
			ts := out.RequestTS + float64(ms)/1000.0
			out.ResponseTS = &ts
		}
		resp := &HTTPEventResponseJSON{
			Status: *e.Status,
			HTTPEventMessageJSON: HTTPEventMessageJSON{
				Headers:           headersAdminJSON(schemaVersion, e.ResponseHeaders, full),
				BodyTruncated:     e.RespTruncated,
				OriginalBodySize:  e.RespOriginalSize,
				BodySkippedReason: e.RespSkippedReason,
			},
		}
		if full {
			if schemaVersion == HTTPEventSchemaV2 {
				if e.ResponseTrailers != nil {
					resp.Trailers = headerValuesFromJSON(e.ResponseTrailers)
				}
				resp.BodyQuality = e.RespBodyQuality
			}
			if e.ResponseBody != nil {
				resp.Body = *e.ResponseBody
			}
		}
		out.Response = resp
	}
	return out
}
