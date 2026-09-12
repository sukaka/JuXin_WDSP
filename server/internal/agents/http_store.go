// http_store.go Agent HTTP 事件 PostgreSQL 仓储（Phase 3，契约 §6）：
// CopyFrom 批量入库（整批失败整体报错，Agent 转本地缓存补传）/ 管理端分页（host/method
// 过滤，ts 倒序）/ 单条全量 / 保留清理删除（sweeper 调用，created_at 早于 7 天）。
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

// ErrHTTPEventNotFound HTTP 事件不存在（或不属于该 Agent）。
var ErrHTTPEventNotFound = errors.New("agent http event not found")

// httpEventCols CopyFrom 列序（id/created_at 由库默认生成；
// req/resp_skipped_reason 为 000113 增量——body_skipped_reason 持久化）。
var httpEventCols = []string{
	"agent_id", "flow_id", "ts", "latency_ms",
	"src_ip", "src_port", "dst_ip", "dst_port", "direction", "tls_visibility",
	"method", "scheme", "host", "uri", "status",
	"request_headers", "response_headers", "request_body", "response_body",
	"req_truncated", "resp_truncated", "req_original_size", "resp_original_size",
	"req_skipped_reason", "resp_skipped_reason",
	"k8s",
}

// requestTS 转换 Unix 秒浮点（毫秒精度）为 time.Time（UTC）。
func httpTS(secFloat float64) time.Time {
	sec := int64(secFloat)
	nsec := int64((secFloat - float64(sec)) * 1e9)
	return time.Unix(sec, nsec).UTC()
}

// marshalHTTPHeaders 脱敏后 Header map → jsonb（nil map 落 '{}'——request_headers
// 列 NOT NULL；response 未捕获时调用方直接传 nil 走 NULL）。
func marshalHTTPHeaders(h map[string]string) []byte {
	if h == nil {
		h = map[string]string{}
	}
	raw, err := json.Marshal(h)
	if err != nil { // map[string]string 理论上不会失败；防御性兜底
		return []byte(`{}`)
	}
	return raw
}

// httpEventCopyRow 记录 → CopyFrom 行（response 为 null 时 latency/status/响应侧字段
// 同步 nil——契约 §3；body 空串落 NULL——未采集/跳过语义）。
func httpEventCopyRow(agentID uuid.UUID, rec *HTTPRecord) []interface{} {
	var latency *int
	var status *int
	var respHeaders []byte
	var respBody *string
	respTruncated := false
	var respOriginalSize int64
	respSkipped := ""
	if rec.Response != nil {
		ms := int(*rec.LatencyMS) // validate 已限 0~MaxInt32
		latency = &ms
		st := rec.Response.Status
		status = &st
		respHeaders = marshalHTTPHeaders(rec.Response.Headers)
		if rec.Response.Body != "" {
			b := rec.Response.Body
			respBody = &b
		}
		respTruncated = rec.Response.BodyTruncated
		respOriginalSize = rec.Response.OriginalBodySize
		respSkipped = rec.Response.BodySkippedReason
	}
	var reqBody *string
	if rec.Request.Body != "" {
		b := rec.Request.Body
		reqBody = &b
	}
	return []interface{}{
		agentID, rec.FlowID, httpTS(rec.RequestTS), latency,
		rec.SrcIP, rec.SrcPort, rec.DstIP, rec.DstPort, rec.Direction, rec.TLSVisibility,
		rec.Request.Method, rec.Request.Scheme, rec.Request.Host, rec.Request.URI, status,
		marshalHTTPHeaders(rec.Request.Headers), respHeaders, reqBody, respBody,
		rec.Request.BodyTruncated, respTruncated, rec.Request.OriginalBodySize, respOriginalSize,
		rec.Request.BodySkippedReason, respSkipped,
		marshalK8sMetadata(rec.K8s),
	}
}

// InsertHTTPEvents HTTP 事件批量入库（CopyFrom 单轮整批；失败整体报错——契约 §3：
// 入库失败整体 500，Agent 落本地缓存补传）。
func (s *Store) InsertHTTPEvents(ctx context.Context, agentID uuid.UUID, records []HTTPRecord) error {
	rows := make([][]interface{}, 0, len(records))
	for i := range records {
		rows = append(rows, httpEventCopyRow(agentID, &records[i]))
	}
	_, err := s.db.CopyFrom(ctx, pgx.Identifier{"agent_http_events"}, httpEventCols, pgx.CopyFromRows(rows))
	return err
}

// httpEventListCols 列表列（不含 headers/body——契约 §6 列表分页轻量，详情全量；
// skipped_reason 为采集完整性信号，列表同样带出——契约 §9 前端列表需明示 skipped 标记；
// 000133 v2 标量列（来源/协议/关联/绑定/collection_ts/ingestion_ts）列表同样带出——
// 任务书 §4.3/AGT-026 列表需来源/协议/数据质量独立状态展示；grpc/trailers/body_quality
// JSONB 子对象仅详情（与 headers/body 同纪律）。
const httpEventListCols = `id, agent_id, flow_id, ts, latency_ms, src_ip, src_port, dst_ip, dst_port,
	direction, tls_visibility, method, scheme, host, uri, status,
	req_truncated, resp_truncated, req_original_size, resp_original_size,
	req_skipped_reason, resp_skipped_reason, created_at, k8s,
	schema_version, event_id, source_type, source_instance, source_epoch,
	source_capabilities_version, observed_http_version, original_http_version,
	association_state, association_reason, capture_stream_id,
	application_binding_id, binding_version, collection_ts, ingestion_ts`

// scanHTTPEventListRow 按 httpEventListCols 列序扫描一行（count(*) OVER () 尾列）。
func scanHTTPEventListRow(rows pgx.Rows, e *HTTPEventRow, total *int64) error {
	return rows.Scan(&e.ID, &e.AgentID, &e.FlowID, &e.Ts, &e.LatencyMS,
		&e.SrcIP, &e.SrcPort, &e.DstIP, &e.DstPort, &e.Direction, &e.TLSVisibility,
		&e.Method, &e.Scheme, &e.Host, &e.URI, &e.Status,
		&e.ReqTruncated, &e.RespTruncated, &e.ReqOriginalSize, &e.RespOriginalSize,
		&e.ReqSkippedReason, &e.RespSkippedReason, &e.CreatedAt, &e.K8s,
		&e.SchemaVersion, &e.EventID, &e.SourceType, &e.SourceInstance, &e.SourceEpoch,
		&e.SourceCapabilitiesVersion, &e.ObservedHTTPVersion, &e.OriginalHTTPVersion,
		&e.AssociationState, &e.AssociationReason, &e.CaptureStreamID,
		&e.ApplicationBindingID, &e.BindingVersion, &e.CollectionTS, &e.IngestionTS,
		total)
}

// ListHTTPEvents 管理端分页（host/method 精确过滤大小写不敏感；ts 倒序——契约 §6）。
func (s *Store) ListHTTPEvents(ctx context.Context, agentID uuid.UUID, f HTTPEventFilter) ([]HTTPEventRow, int64, error) {
	where := `agent_id = $1`
	args := []interface{}{agentID}
	if f.Host != "" {
		args = append(args, f.Host)
		where += fmt.Sprintf(" AND lower(host) = lower($%d)", len(args))
	}
	if f.Method != "" {
		args = append(args, f.Method)
		where += fmt.Sprintf(" AND upper(method) = upper($%d)", len(args))
	}
	args = append(args, f.Page.PageSize, f.Page.Offset())
	rows, err := s.db.Query(ctx, `
SELECT `+httpEventListCols+`, count(*) OVER () AS total
FROM agent_http_events
WHERE `+where+`
ORDER BY ts DESC, id DESC
LIMIT $`+strconv.Itoa(len(args)-1)+` OFFSET $`+strconv.Itoa(len(args)), args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []HTTPEventRow{}
	var total int64
	for rows.Next() {
		var e HTTPEventRow
		if err := scanHTTPEventListRow(rows, &e, &total); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// GetHTTPEvent 单条全量（含 headers/body——契约 §6；v2 行还原 trailers/body_quality/
// grpc 子对象与数组形态 headers；不属于该 Agent 同样 404 防越权探测）。
func (s *Store) GetHTTPEvent(ctx context.Context, agentID uuid.UUID, id int64) (*HTTPEventRow, error) {
	row := s.db.QueryRow(ctx, `
SELECT id, agent_id, flow_id, ts, latency_ms, src_ip, src_port, dst_ip, dst_port,
       direction, tls_visibility, method, scheme, host, uri, status,
       request_headers, response_headers, request_body, response_body,
       req_truncated, resp_truncated, req_original_size, resp_original_size,
	       req_skipped_reason, resp_skipped_reason, created_at, k8s,
       schema_version, event_id, source_type, source_instance, source_epoch,
       source_capabilities_version, observed_http_version, original_http_version,
       association_state, association_reason, capture_stream_id,
       application_binding_id, binding_version, grpc,
       request_trailers, response_trailers, req_body_quality, resp_body_quality,
       collection_ts, ingestion_ts
FROM agent_http_events
WHERE agent_id = $1 AND id = $2`, agentID, id)
	var e HTTPEventRow
	if err := row.Scan(&e.ID, &e.AgentID, &e.FlowID, &e.Ts, &e.LatencyMS,
		&e.SrcIP, &e.SrcPort, &e.DstIP, &e.DstPort, &e.Direction, &e.TLSVisibility,
		&e.Method, &e.Scheme, &e.Host, &e.URI, &e.Status,
		&e.RequestHeaders, &e.ResponseHeaders, &e.RequestBody, &e.ResponseBody,
		&e.ReqTruncated, &e.RespTruncated, &e.ReqOriginalSize, &e.RespOriginalSize,
		&e.ReqSkippedReason, &e.RespSkippedReason, &e.CreatedAt, &e.K8s,
		&e.SchemaVersion, &e.EventID, &e.SourceType, &e.SourceInstance, &e.SourceEpoch,
		&e.SourceCapabilitiesVersion, &e.ObservedHTTPVersion, &e.OriginalHTTPVersion,
		&e.AssociationState, &e.AssociationReason, &e.CaptureStreamID,
		&e.ApplicationBindingID, &e.BindingVersion, &e.GRPC,
		&e.RequestTrailers, &e.ResponseTrailers, &e.ReqBodyQuality, &e.RespBodyQuality,
		&e.CollectionTS, &e.IngestionTS); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrHTTPEventNotFound
		}
		return nil, err
	}
	return &e, nil
}

// DeleteExpiredHTTPEvents 保留清理：删除 created_at 早于 before 的记录
// （契约 §6/设计 §68.9 硬上限；sweeper 每日调用，返回删除行数）。
func (s *Store) DeleteExpiredHTTPEvents(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.Exec(ctx, `DELETE FROM agent_http_events WHERE created_at < $1`, before.UTC())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected(), nil
}
