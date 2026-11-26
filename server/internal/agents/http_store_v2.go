// http_store_v2.go HTTP 事件 schema v2 仓储（契约 WDSP_AGENT_HTTP_EVENT_V2_CONTRACT.md
// §4/§5/§6）：
//   - InsertHTTPEventsV2：单事务逐条 INSERT ... ON CONFLICT (agent_id, event_id, ts)
//     WHERE event_id IS NOT NULL DO NOTHING——(agent_id, event_id, ts) 幂等去重（部分唯一
//     索引，迁移 000133/000244）；重复确认但不重复入库，返回新入库记录的输入下标与重复条数；
//     任何错误整批回滚（500 → Agent 有界重试/补传）；
//   - UpsertHTTPAssetSource：资产来源关系 upsert（唯一键 agent_id+host+method+
//     path_template+source_type+source_instance——多来源各自成行，不覆盖资产所有权）；
//   - ListHTTPAssetSources：管理端分页（association_state 过滤——配额拒绝/未绑定/
//     关联失败均可查询，不只 Warn）。
package agents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// httpEventV2Cols v2 入库列序（id/created_at 由库默认生成；v1 兼容列 + 000133 v2 列）。
var httpEventV2Cols = []string{
	"agent_id", "flow_id", "ts", "latency_ms",
	"src_ip", "src_port", "dst_ip", "dst_port", "direction", "tls_visibility",
	"method", "scheme", "host", "uri", "status",
	"request_headers", "response_headers", "request_body", "response_body",
	"req_truncated", "resp_truncated", "req_original_size", "resp_original_size",
	"req_skipped_reason", "resp_skipped_reason",
	"k8s",
	// ---- 000133 v2 列 ----
	"schema_version", "event_id",
	"source_type", "source_instance", "source_epoch", "source_capabilities_version",
	"observed_http_version", "original_http_version",
	"association_state", "association_reason", "capture_stream_id",
	"application_binding_id", "binding_version",
	"grpc", "request_trailers", "response_trailers",
	"req_body_quality", "resp_body_quality",
	"collection_ts", "ingestion_ts",
}

// marshalHTTPHeaderValues v2 headers/trailers 数组形态 → jsonb（nil → NULL——
// 仅 trailers 允许；headers 调用方保证非 nil）。
func marshalHTTPHeaderValues(h HTTPHeaderValues) []byte {
	if h == nil {
		return nil
	}
	raw, err := json.Marshal(h)
	if err != nil { // map[string][]string 理论上不会失败；防御性兜底
		return []byte(`{}`)
	}
	return raw
}

// marshalJSONOrNil 可选子对象 → jsonb（nil → NULL）。
func marshalJSONOrNil(v interface{}) []byte {
	if v == nil {
		return nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return raw
}

// httpEventV2Values v2 记录 → INSERT 值（列序同 httpEventV2Cols；body_quality 四要素
// 镜像到 v1 兼容列（截断/跳过/已知原始长度）保持管理端列表/详情可读，完整对象另存
// req/resp_body_quality——契约 §6）。
func httpEventV2Values(agentID uuid.UUID, rec *HTTPRecordV2, ingestionTS time.Time) []interface{} {
	var latency *int
	var status *int
	var respHeaders, respBodyQuality []byte
	var respBody *string
	respTruncated := false
	var respOriginalSize int64
	respSkipped := ""
	var respTrailers []byte
	if rec.Response != nil {
		ms := int(*rec.LatencyMS) // validate 已限 0~MaxInt32
		latency = &ms
		st := rec.Response.Status
		status = &st
		respHeaders = marshalHTTPHeaderValues(rec.Response.Headers)
		respTrailers = marshalHTTPHeaderValues(rec.Response.Trailers)
		if rec.Response.Body != "" {
			b := rec.Response.Body
			respBody = &b
		}
		respTruncated = rec.Response.BodyQuality.Truncated
		if rec.Response.BodyQuality.OriginalTotalSize != nil {
			respOriginalSize = *rec.Response.BodyQuality.OriginalTotalSize
		}
		respSkipped = rec.Response.BodyQuality.SkippedReason
		respBodyQuality = marshalJSONOrNil(&rec.Response.BodyQuality)
	}
	var reqBody *string
	if rec.Request.Body != "" {
		b := rec.Request.Body
		reqBody = &b
	}
	var reqOriginalSize int64
	if rec.Request.BodyQuality.OriginalTotalSize != nil {
		reqOriginalSize = *rec.Request.BodyQuality.OriginalTotalSize
	}
	var bindingID *uuid.UUID
	if rec.ApplicationBindingID != nil {
		if id, err := uuid.Parse(*rec.ApplicationBindingID); err == nil { // validate 已保证合法
			bindingID = &id
		}
	}
	return []interface{}{
		agentID, rec.FlowID, httpTS(rec.RequestTS), latency,
		rec.SrcIP, rec.SrcPort, rec.DstIP, rec.DstPort, rec.Direction, rec.TLSVisibility,
		rec.Request.Method, rec.Request.Scheme, rec.Request.Host, rec.Request.URI, status,
		marshalHTTPHeaderValues(nonNilHeaderValues(rec.Request.Headers)), respHeaders, reqBody, respBody,
		rec.Request.BodyQuality.Truncated, respTruncated, reqOriginalSize, respOriginalSize,
		rec.Request.BodyQuality.SkippedReason, respSkipped,
		marshalK8sMetadata(rec.K8s),
		HTTPEventSchemaV2, rec.EventID,
		rec.SourceType, rec.SourceInstance, rec.SourceEpoch, rec.SourceCapabilitiesVersion,
		rec.ObservedHTTPVersion, rec.OriginalHTTPVersion,
		rec.AssociationState, rec.AssociationReason, rec.CaptureStreamID,
		bindingID, rec.BindingVersion,
		marshalJSONOrNil(rec.GRPC), marshalHTTPHeaderValues(rec.Request.Trailers), respTrailers,
		marshalJSONOrNil(&rec.Request.BodyQuality), respBodyQuality,
		httpTS(rec.CollectionTS), ingestionTS.UTC(),
	}
}

// nonNilHeaderValues headers 列 NOT NULL 兜底（v2 校验允许空对象但不允许 null）。
func nonNilHeaderValues(h HTTPHeaderValues) HTTPHeaderValues {
	if h == nil {
		return HTTPHeaderValues{}
	}
	return h
}

func buildInsertHTTPEventV2SQL() string {
	return `INSERT INTO agent_http_events (` + joinCols(httpEventV2Cols) + `)
VALUES (` + placeholders(len(httpEventV2Cols)) + `)
ON CONFLICT (agent_id, event_id, ts) WHERE event_id IS NOT NULL DO NOTHING
RETURNING id`
}

// InsertHTTPEventsV2 v2 批次幂等入库（契约 §4：单事务；按 (agent_id, event_id, ts) 去重；
// 返回新入库记录的输入下标（供资产联动——重复记录不扩大资产计数）与重复条数）。
func (s *Store) InsertHTTPEventsV2(ctx context.Context, agentID uuid.UUID, records []HTTPRecordV2, ingestionTS time.Time) ([]int, int, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	insertSQL := buildInsertHTTPEventV2SQL()

	acceptedIdx := make([]int, 0, len(records))
	duplicates := 0
	for i := range records {
		var id int64
		err := tx.QueryRow(ctx, insertSQL, httpEventV2Values(agentID, &records[i], ingestionTS)...).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			duplicates++ // 同 (agent_id, event_id) 已存在——确认但不重复入库（含批内重复）
			continue
		}
		if err != nil {
			return nil, 0, err // 整批回滚
		}
		acceptedIdx = append(acceptedIdx, i)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, 0, err
	}
	return acceptedIdx, duplicates, nil
}

func joinCols(cols []string) string {
	out := ""
	for i, c := range cols {
		if i > 0 {
			out += ", "
		}
		out += c
	}
	return out
}

func placeholders(n int) string {
	out := ""
	for i := 1; i <= n; i++ {
		if i > 1 {
			out += ", "
		}
		out += "$" + strconv.Itoa(i)
	}
	return out
}

// ---------- 资产来源关系（契约 §5） ----------

// HTTPAssetClassification 来源观测时的 API 分类证据（不落敏感内容）。
type HTTPAssetClassification struct {
	IsAPI        bool      `json:"is_api"`
	Confidence   float64   `json:"confidence"`
	Level        string    `json:"level"`
	Signals      []string  `json:"signals"`
	ClassifiedAt time.Time `json:"classified_at"`
}

// HTTPAssetSourceInput 来源关系 upsert 输入。
type HTTPAssetSourceInput struct {
	AgentID              uuid.UUID
	EndpointID           *uuid.UUID // 关联成功的端点；未关联为 nil
	Host                 string
	Method               string
	PathTemplate         string
	SourceType           string
	SourceInstance       string
	SourceEpoch          int64
	ApplicationBindingID *uuid.UUID
	BindingVersion       *int64
	State                string // AssetLink* 枚举
	LastError            string // FAILED/QUOTA_REJECTED 的类别原因（≤255，截断）
	Classification       *HTTPAssetClassification
	Now                  time.Time
}

// HTTPAssetSourceRow 来源关系行（管理端查询输出）。
type HTTPAssetSourceRow struct {
	ID                   int64                    `json:"id"`
	AgentID              uuid.UUID                `json:"agent_id"`
	EndpointID           *uuid.UUID               `json:"endpoint_id"`
	Host                 string                   `json:"host"`
	Method               string                   `json:"method"`
	PathTemplate         string                   `json:"path_template"`
	SourceType           string                   `json:"source_type"`
	SourceInstance       string                   `json:"source_instance"`
	SourceEpoch          int64                    `json:"source_epoch"`
	ApplicationBindingID *uuid.UUID               `json:"application_binding_id"`
	BindingVersion       *int64                   `json:"binding_version"`
	AssociationState     string                   `json:"association_state"`
	LastError            string                   `json:"last_error"`
	FirstSeenAt          time.Time                `json:"first_seen_at"`
	LastSeenAt           time.Time                `json:"last_seen_at"`
	Classification       *HTTPAssetClassification `json:"classification,omitempty"`
}

// HTTPAssetSourceFilter 管理端过滤（state 精确匹配；空=全部）。
type HTTPAssetSourceFilter struct {
	State string
	Page  PageParams
}

// UpsertHTTPAssetSource 来源关系 upsert（多来源各自成行；重放仅推进 last_seen_at
// 与关联状态——endpoint_id 在关联成功时刷新，失败行不覆盖既有成功关联）。
func (s *Store) UpsertHTTPAssetSource(ctx context.Context, in HTTPAssetSourceInput) error {
	var classIsAPI *bool
	var classConfidence *float64
	classLevel := ""
	classSignals := []byte("[]")
	var classifiedAt *time.Time
	if c := in.Classification; c != nil {
		isAPI := c.IsAPI
		confidence := c.Confidence
		classified := c.ClassifiedAt.UTC()
		if classified.IsZero() {
			classified = in.Now.UTC()
		}
		classIsAPI = &isAPI
		classConfidence = &confidence
		classLevel = c.Level
		signals := c.Signals
		if signals == nil {
			signals = []string{}
		}
		if raw, err := json.Marshal(signals); err == nil {
			classSignals = raw
		}
		classifiedAt = &classified
	}
	_, err := s.db.Exec(ctx, `
INSERT INTO agent_http_asset_sources
(agent_id, endpoint_id, host, method, path_template,
 source_type, source_instance, source_epoch,
 application_binding_id, binding_version,
 association_state, last_error, first_seen_at, last_seen_at,
 classification_is_api, classification_confidence, classification_level,
 classification_signals, classified_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$13,$14,$15,$16,$17,$18)
ON CONFLICT (agent_id, host, method, path_template, source_type, source_instance)
DO UPDATE SET
  endpoint_id  = COALESCE(EXCLUDED.endpoint_id, agent_http_asset_sources.endpoint_id),
  source_epoch = EXCLUDED.source_epoch,
  application_binding_id = COALESCE(EXCLUDED.application_binding_id, agent_http_asset_sources.application_binding_id),
  binding_version = COALESCE(EXCLUDED.binding_version, agent_http_asset_sources.binding_version),
  association_state = EXCLUDED.association_state,
  last_error = EXCLUDED.last_error,
  last_seen_at = EXCLUDED.last_seen_at,
  classification_is_api = COALESCE(EXCLUDED.classification_is_api, agent_http_asset_sources.classification_is_api),
  classification_confidence = COALESCE(EXCLUDED.classification_confidence, agent_http_asset_sources.classification_confidence),
  classification_level = CASE WHEN EXCLUDED.classified_at IS NOT NULL THEN EXCLUDED.classification_level ELSE agent_http_asset_sources.classification_level END,
  classification_signals = CASE WHEN EXCLUDED.classified_at IS NOT NULL THEN EXCLUDED.classification_signals ELSE agent_http_asset_sources.classification_signals END,
  classified_at = COALESCE(EXCLUDED.classified_at, agent_http_asset_sources.classified_at)`,
		in.AgentID, in.EndpointID, in.Host, in.Method, in.PathTemplate,
		in.SourceType, in.SourceInstance, in.SourceEpoch,
		in.ApplicationBindingID, in.BindingVersion,
		in.State, in.LastError, in.Now.UTC(),
		classIsAPI, classConfidence, classLevel, classSignals, classifiedAt)
	return err
}

// ListHTTPAssetSources 管理端分页（last_seen_at 倒序；state 精确过滤）。
func (s *Store) ListHTTPAssetSources(ctx context.Context, agentID uuid.UUID, f HTTPAssetSourceFilter) ([]HTTPAssetSourceRow, int64, error) {
	where := `agent_id = $1`
	args := []interface{}{agentID}
	if f.State != "" {
		args = append(args, f.State)
		where += fmt.Sprintf(" AND association_state = $%d", len(args))
	}
	args = append(args, f.Page.PageSize, f.Page.Offset())
	rows, err := s.db.Query(ctx, `
SELECT id, agent_id, endpoint_id, host, method, path_template,
       source_type, source_instance, source_epoch,
       application_binding_id, binding_version,
       association_state, last_error, first_seen_at, last_seen_at,
       classification_is_api, classification_confidence, classification_level,
       classification_signals, classified_at,
       count(*) OVER () AS total
FROM agent_http_asset_sources
WHERE `+where+`
ORDER BY last_seen_at DESC, id DESC
LIMIT $`+strconv.Itoa(len(args)-1)+` OFFSET $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []HTTPAssetSourceRow{}
	var total int64
	for rows.Next() {
		var r HTTPAssetSourceRow
		var classIsAPI *bool
		var classConfidence *float64
		var classLevel string
		var classSignals []byte
		var classifiedAt *time.Time
		if err := rows.Scan(&r.ID, &r.AgentID, &r.EndpointID, &r.Host, &r.Method, &r.PathTemplate,
			&r.SourceType, &r.SourceInstance, &r.SourceEpoch,
			&r.ApplicationBindingID, &r.BindingVersion,
			&r.AssociationState, &r.LastError, &r.FirstSeenAt, &r.LastSeenAt,
			&classIsAPI, &classConfidence, &classLevel, &classSignals, &classifiedAt, &total); err != nil {
			return nil, 0, err
		}
		if classifiedAt != nil {
			classification := &HTTPAssetClassification{Level: classLevel, Signals: []string{}, ClassifiedAt: *classifiedAt}
			if classIsAPI != nil {
				classification.IsAPI = *classIsAPI
			}
			if classConfidence != nil {
				classification.Confidence = *classConfidence
			}
			if len(classSignals) > 0 {
				_ = json.Unmarshal(classSignals, &classification.Signals)
			}
			r.Classification = classification
		}
		out = append(out, r)
	}
	return out, total, rows.Err()
}
