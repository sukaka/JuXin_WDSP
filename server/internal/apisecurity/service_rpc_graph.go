// service_rpc_graph.go 后端微服务真实 RPC / 服务间调用图谱（WDSP API 安全图谱主视图）。
//
// 数据源（全部来自真实运行态观测，绝不造假数据，各路独立降级不 500）：
//   1) OTel 分布式追踪（ClickHouse apm.otel_traces）：
//      - 优先按 (TraceId, Client.SpanId = Server.ParentSpanId) 做双端 Span 真实配对（OTEL_SPAN_PAIRED）；
//      - 未匹配到对端 Server Span 的客户端 Span 排除 DB/MQ 后提取 peer.service / rpc.service / server.address（OTEL_CLIENT_SPAN）；
//      - 协议优先识别 rpc.system（GRPC/DUBBO/THRIFT/JSONRPC 等），其次 HTTP。
//   2) 云 API Sensor 分布式数据流（ClickHouse wdsp.data_flow_contributions）：
//      - 提取去重后的 SERVICE → SERVICE（及可选 EXTERNAL）真实服务间调用，OBSERVED_TRACE 记为 AGENT_TRACE_PAIRED。
//   3) 分布式流量 Agent gRPC 观测（PostgreSQL agent_http_events WHERE grpc IS NOT NULL）：
//      - 即使未部署 ClickHouse，只要流量 Agent 捕获到 gRPC 流量也能呈现服务调用关系（AGENT_GRPC_OBSERVED）。
package apisecurity

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/apm"
	"github.com/jiuzhang-waf/server/internal/response"
)

const (
	serviceRPCDefaultWindow     = time.Hour
	serviceRPCMaxWindow         = 24 * time.Hour
	serviceRPCDefaultLimit      = 200
	serviceRPCMaxLimit          = 500
	serviceRPCSourceFetchLimit  = 501
	serviceRPCMaxOperations     = 20
	serviceRPCMaxSampleTraces   = 5
	serviceRPCMaxServiceNameLen = 128
	serviceRPCCHExecTimeoutSec  = 30
)

// validServiceRPCProtocols 允许的 protocol 过滤参数白名单。
var validServiceRPCProtocols = map[string]bool{
	"ALL":         true,
	"RPC":         true,
	"GRPC":        true,
	"HTTP":        true,
	"DUBBO":       true,
	"THRIFT":      true,
	"JSONRPC":     true,
	"CONNECT_RPC": true,
}

// ServiceRPCGraphFilter 微服务真实 RPC / 服务间调用图谱查询条件。
type ServiceRPCGraphFilter struct {
	Start           time.Time
	End             time.Time
	Protocol        string // ALL / RPC / GRPC / HTTP / DUBBO / THRIFT / JSONRPC / CONNECT_RPC
	Service         string // 可选：源或目标服务名关键字（大小写不敏感）
	PairedOnly      bool   // 仅保留双端 Span/Trace 确凿配对的真实调用
	IncludeExternal bool   // 是否包含未归属为内部服务的外部目标（默认 false）
	MinCalls        int64  // 最小调用次数
	Limit           int    // 返回边上限（默认 200，最大 500）
}

// ServiceRPCSourceStatus 单路遥测数据源的真实可用状态（如实返回，不静默伪造）。
type ServiceRPCSourceStatus struct {
	Source    string `json:"source"`
	Label     string `json:"label"`
	Status    string `json:"status"` // READY / EMPTY / NOT_CONFIGURED / UNAVAILABLE
	EdgeCount int    `json:"edge_count"`
	Message   string `json:"message,omitempty"`
}

// ServiceRPCNode 微服务调用图谱节点。
type ServiceRPCNode struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	NodeType        string   `json:"node_type"` // SERVICE / EXTERNAL
	Protocols       []string `json:"protocols"`
	InboundCalls    int64    `json:"inbound_calls"`
	OutboundCalls   int64    `json:"outbound_calls"`
	InboundEdges    int      `json:"inbound_edges"`
	OutboundEdges   int      `json:"outbound_edges"`
	ErrorCount      int64    `json:"error_count"`
	ErrorRate       float64  `json:"error_rate"`
	AvgMS           float64  `json:"avg_ms"`
	OperationsCount int      `json:"operations_count"`
}

// ServiceRPCEdge 微服务间真实调用边。
type ServiceRPCEdge struct {
	ID             string    `json:"id"`
	Source         string    `json:"source"`
	Target         string    `json:"target"`
	TargetType     string    `json:"target_type"`   // SERVICE / EXTERNAL
	Protocol       string    `json:"protocol"`      // GRPC / DUBBO / THRIFT / JSONRPC / RPC / HTTP ...
	CallCategory   string    `json:"call_category"` // RPC / HTTP
	EvidenceType   string    `json:"evidence_type"` // OTEL_SPAN_PAIRED / OTEL_CLIENT_SPAN / AGENT_TRACE_PAIRED / AGENT_CLIENT_OBSERVED / AGENT_GRPC_OBSERVED
	Paired         bool      `json:"paired"`
	DataSource     string    `json:"data_source"` // otel_traces / agent_dataflow / agent_grpc
	Calls          int64     `json:"calls"`
	ErrorCount     int64     `json:"error_count"`
	ErrorRate      float64   `json:"error_rate"`
	AvgMS          float64   `json:"avg_ms"`
	P95MS          float64   `json:"p95_ms"`
	Operations     []string  `json:"operations"`
	SampleTraceIDs []string  `json:"sample_trace_ids"`
	FirstSeenAt    time.Time `json:"first_seen_at"`
	LastSeenAt     time.Time `json:"last_seen_at"`
}

// ServiceRPCGraphSummary 微服务 RPC 图谱统计摘要。
type ServiceRPCGraphSummary struct {
	TotalNodes    int   `json:"total_nodes"`
	ServiceNodes  int   `json:"service_nodes"`
	ExternalNodes int   `json:"external_nodes"`
	TotalEdges    int   `json:"total_edges"`
	RPCEdges      int   `json:"rpc_edges"`
	HTTPEdges     int   `json:"http_edges"`
	PairedEdges   int   `json:"paired_edges"`
	ErrorEdges    int   `json:"error_edges"`
	TotalCalls    int64 `json:"total_calls"`
	TotalErrors   int64 `json:"total_errors"`
	Truncated     bool  `json:"truncated"`
}

// ServiceRPCGraph 后端微服务真实 RPC / 服务间调用图谱响应。
type ServiceRPCGraph struct {
	Start   time.Time                `json:"start"`
	End     time.Time                `json:"end"`
	Nodes   []ServiceRPCNode         `json:"nodes"`
	Edges   []ServiceRPCEdge         `json:"edges"`
	Summary ServiceRPCGraphSummary   `json:"summary"`
	Sources []ServiceRPCSourceStatus `json:"sources"`
	Note    string                   `json:"note,omitempty"`
}

// DefaultServiceRPCGraphReader 汇聚 ClickHouse（OTel + 数据流）与 PostgreSQL（流量 Agent gRPC）。
type DefaultServiceRPCGraphReader struct {
	db        *pgxpool.Pool
	resolveCH func(context.Context) apm.CHQuerier
}

// NewServiceRPCGraphReader 创建微服务真实调用图谱读实例；resolveCH 可为 nil（自动降级）。
func NewServiceRPCGraphReader(db *pgxpool.Pool, resolveCH func(context.Context) apm.CHQuerier) *DefaultServiceRPCGraphReader {
	return &DefaultServiceRPCGraphReader{db: db, resolveCH: resolveCH}
}

func withServiceRPCCHSettings(ctx context.Context) context.Context {
	return clickhouse.Context(ctx, clickhouse.WithSettings(clickhouse.Settings{
		"max_execution_time": serviceRPCCHExecTimeoutSec,
	}))
}

func roundRPCFloat(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0
	}
	return math.Round(v*1000) / 1000
}

func classifyServiceRPCProtocol(raw string) (protocol, category string) {
	p := strings.ToUpper(strings.TrimSpace(raw))
	if p == "" {
		return "RPC", "RPC"
	}
	switch p {
	case "HTTP", "HTTPS", "HTTP/1.1", "HTTP/2", "HTTP2":
		return "HTTP", "HTTP"
	case "GRPC", "GRPC_WEB", "GRPC-WEB":
		return "GRPC", "RPC"
	case "DUBBO", "THRIFT", "JSONRPC", "JSON-RPC", "CONNECT_RPC", "RPC", "MOTAN", "SOFARPC", "TARS":
		if p == "JSON-RPC" {
			return "JSONRPC", "RPC"
		}
		return p, "RPC"
	default:
		if strings.Contains(p, "RPC") {
			return p, "RPC"
		}
		if strings.HasPrefix(p, "HTTP") {
			return "HTTP", "HTTP"
		}
		return p, "RPC"
	}
}

func evidencePriority(ev string) int {
	switch ev {
	case "OTEL_SPAN_PAIRED":
		return 5
	case "AGENT_TRACE_PAIRED":
		return 4
	case "OTEL_CLIENT_SPAN":
		return 3
	case "AGENT_GRPC_OBSERVED":
		return 2
	case "AGENT_CLIENT_OBSERVED":
		return 1
	default:
		return 0
	}
}

// buildOTelServiceRPCQuery 构造 ClickHouse apm.otel_traces 微服务间调用查询：
// Client/Producer span 左连接同 TraceId 下匹配的 Server/Consumer span（s.ParentSpanId = c.SpanId），
// 排除 DB/MQ 基础设施 span，仅保留服务间 RPC / HTTP 与可选外部调用。
func buildOTelServiceRPCQuery(f ServiceRPCGraphFilter) (string, []any) {
	query := `SELECT
  c.ServiceName AS source,
  multiIf(
    s.server_service != '' AND s.server_service != c.ServiceName, s.server_service,
    c.SpanAttributes['peer.service'] != '', c.SpanAttributes['peer.service'],
    c.SpanAttributes['rpc.service'] != '', c.SpanAttributes['rpc.service'],
    c.SpanAttributes['server.address'] != '', c.SpanAttributes['server.address'],
    ''
  ) AS target,
  multiIf(
    s.server_service != '' AND s.server_service != c.ServiceName, 'SERVICE',
    c.SpanAttributes['peer.service'] != '' OR c.SpanAttributes['rpc.service'] != '', 'SERVICE',
    'EXTERNAL'
  ) AS target_type,
  multiIf(
    c.SpanAttributes['rpc.system'] != '', upper(c.SpanAttributes['rpc.system']),
    s.server_rpc_system != '', upper(s.server_rpc_system),
    c.SpanAttributes['http.request.method'] != '' OR c.SpanAttributes['http.method'] != '', 'HTTP',
    'RPC'
  ) AS protocol,
  if(s.server_service != '' AND s.server_service != c.ServiceName, 'OTEL_SPAN_PAIRED', 'OTEL_CLIENT_SPAN') AS evidence_type,
  count() AS calls,
  countIf(c.StatusCode = 'Error') AS error_count,
  avg(c.Duration) / 1000000.0 AS avg_ms,
  quantile(0.95)(c.Duration) / 1000000.0 AS p95_ms,
  groupUniqArray(` + strconv.Itoa(serviceRPCMaxOperations) + `)(
    multiIf(
      c.SpanAttributes['rpc.service'] != '' AND c.SpanAttributes['rpc.method'] != '',
        concat(c.SpanAttributes['rpc.service'], '/', c.SpanAttributes['rpc.method']),
      s.server_rpc_service != '' AND s.server_rpc_method != '',
        concat(s.server_rpc_service, '/', s.server_rpc_method),
      c.SpanName != '', c.SpanName,
      s.server_span_name
    )
  ) AS operations,
  groupUniqArray(` + strconv.Itoa(serviceRPCMaxSampleTraces) + `)(c.TraceId) AS sample_trace_ids,
  min(c.Timestamp) AS first_seen_at,
  max(c.Timestamp) AS last_seen_at
FROM apm.otel_traces AS c
LEFT JOIN (
  SELECT
    TraceId,
    ParentSpanId,
    any(ServiceName) AS server_service,
    any(SpanName) AS server_span_name,
    any(SpanAttributes['rpc.system']) AS server_rpc_system,
    any(SpanAttributes['rpc.service']) AS server_rpc_service,
    any(SpanAttributes['rpc.method']) AS server_rpc_method
  FROM apm.otel_traces
  WHERE Timestamp >= ? AND Timestamp < ?
    AND SpanKind IN ('Server', 'Consumer')
    AND ParentSpanId != ''
  GROUP BY TraceId, ParentSpanId
) AS s ON c.TraceId = s.TraceId AND c.SpanId = s.ParentSpanId
WHERE c.Timestamp >= ? AND c.Timestamp < ?
  AND c.SpanKind IN ('Client', 'Producer')
  AND c.SpanAttributes['db.system'] = ''
  AND c.SpanAttributes['messaging.system'] = ''
GROUP BY source, target, target_type, protocol, evidence_type
HAVING source != '' AND target != '' AND source != target
ORDER BY calls DESC, source ASC, target ASC
LIMIT ?`
	args := []any{f.Start, f.End, f.Start, f.End, serviceRPCSourceFetchLimit}
	return query, args
}

// buildDataflowServiceRPCQuery 构造 ClickHouse wdsp.data_flow_contributions 服务间调用查询。
func buildDataflowServiceRPCQuery(f ServiceRPCGraphFilter) (string, []any) {
	query := `SELECT
  latest_source_node AS source,
  latest_target_node AS target,
  latest_target_type AS target_type,
  latest_protocol AS protocol,
  if(argMax(latest_evidence_type, event_time) = 'OBSERVED_TRACE', 'AGENT_TRACE_PAIRED', 'AGENT_CLIENT_OBSERVED') AS evidence_type,
  sum(latest_count_weight) AS calls,
  sum(latest_error) AS error_count,
  sum(latest_latency_ms * latest_count_weight) / greatest(sum(latest_count_weight), 1) AS avg_ms,
  quantile(0.95)(latest_latency_ms) AS p95_ms,
  groupUniqArrayIf(` + strconv.Itoa(serviceRPCMaxOperations) + `)(
    trimBoth(concat(latest_method, ' ', latest_path_template)),
    latest_method != '' OR latest_path_template != ''
  ) AS operations,
  groupUniqArrayIf(` + strconv.Itoa(serviceRPCMaxSampleTraces) + `)(latest_trace_id, latest_trace_id != '') AS sample_trace_ids,
  min(event_time) AS first_seen_at,
  max(event_time) AS last_seen_at
FROM (
  SELECT agent_id, event_id, edge_id,
    argMax(occurred_at, received_at) AS event_time,
    argMax(source_node, received_at) AS latest_source_node,
    argMax(source_type, received_at) AS latest_source_type,
    argMax(target_node, received_at) AS latest_target_node,
    argMax(target_type, received_at) AS latest_target_type,
    argMax(protocol, received_at) AS latest_protocol,
    argMax(method, received_at) AS latest_method,
    argMax(path_template, received_at) AS latest_path_template,
    argMax(latency_ms, received_at) AS latest_latency_ms,
    argMax(error, received_at) AS latest_error,
    argMax(count_weight, received_at) AS latest_count_weight,
    argMax(evidence_type, received_at) AS latest_evidence_type,
    argMax(trace_id, received_at) AS latest_trace_id
  FROM wdsp.data_flow_contributions
  WHERE occurred_at >= ? AND occurred_at < ?
  GROUP BY agent_id, event_id, edge_id
)
WHERE latest_evidence_type NOT IN ('PAIRED_CLIENT', 'PAIRED_SERVER')
  AND latest_source_type = 'SERVICE'
  AND latest_target_type IN ('SERVICE', 'EXTERNAL')
  AND latest_source_node != ''
  AND latest_target_node != ''
  AND latest_source_node != latest_target_node
GROUP BY source, target, target_type, protocol
HAVING calls > 0
ORDER BY calls DESC, source ASC, target ASC
LIMIT ?`
	args := []any{f.Start, f.End, serviceRPCSourceFetchLimit}
	return query, args
}

func scanServiceRPCCHRows(rows apm.CHRows, dataSource string) ([]ServiceRPCEdge, error) {
	edges := []ServiceRPCEdge{}
	for rows.Next() {
		var source, target, targetType, rawProto, evidenceType string
		var calls, errCount uint64
		var avgMS, p95MS float64
		var ops, traces []string
		var firstSeen, lastSeen time.Time
		if err := rows.Scan(
			&source, &target, &targetType, &rawProto, &evidenceType,
			&calls, &errCount, &avgMS, &p95MS, &ops, &traces, &firstSeen, &lastSeen,
		); err != nil {
			return nil, err
		}
		proto, category := classifyServiceRPCProtocol(rawProto)
		tt := strings.ToUpper(strings.TrimSpace(targetType))
		if tt != "SERVICE" {
			tt = "EXTERNAL"
		}
		paired := evidenceType == "OTEL_SPAN_PAIRED" || evidenceType == "AGENT_TRACE_PAIRED"
		edges = append(edges, ServiceRPCEdge{
			Source:         strings.TrimSpace(source),
			Target:         strings.TrimSpace(target),
			TargetType:     tt,
			Protocol:       proto,
			CallCategory:   category,
			EvidenceType:   evidenceType,
			Paired:         paired,
			DataSource:     dataSource,
			Calls:          int64(calls),
			ErrorCount:     int64(errCount),
			AvgMS:          roundRPCFloat(avgMS),
			P95MS:          roundRPCFloat(p95MS),
			Operations:     cleanStringSlice(ops, serviceRPCMaxOperations),
			SampleTraceIDs: cleanStringSlice(traces, serviceRPCMaxSampleTraces),
			FirstSeenAt:    firstSeen.UTC(),
			LastSeenAt:     lastSeen.UTC(),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return edges, nil
}

func (r *DefaultServiceRPCGraphReader) queryOTelTraces(ctx context.Context, ch apm.CHQuerier, f ServiceRPCGraphFilter) ([]ServiceRPCEdge, ServiceRPCSourceStatus) {
	st := ServiceRPCSourceStatus{
		Source: "otel_traces",
		Label:  "OTel 分布式追踪",
	}
	if ch == nil {
		st.Status = "NOT_CONFIGURED"
		st.Message = "未配置 ClickHouse 数据面（APM_CLICKHOUSE_DSN），OTel 微服务调用链暂不可用"
		return nil, st
	}
	sqlText, args := buildOTelServiceRPCQuery(f)
	rows, err := ch.Query(withServiceRPCCHSettings(ctx), sqlText, args...)
	if err != nil {
		slog.Warn("service-rpc-graph: OTel ClickHouse 查询降级", "error", err)
		st.Status = "UNAVAILABLE"
		st.Message = "OTel 追踪表暂不可查（已降级为空）"
		return nil, st
	}
	defer rows.Close()
	edges, err := scanServiceRPCCHRows(rows, "otel_traces")
	if err != nil {
		slog.Warn("service-rpc-graph: OTel ClickHouse 扫描降级", "error", err)
		st.Status = "UNAVAILABLE"
		st.Message = "OTel 追踪数据读取失败（已降级为空）"
		return nil, st
	}
	st.EdgeCount = len(edges)
	if len(edges) == 0 {
		st.Status = "EMPTY"
		st.Message = "当前时间窗内暂无 OTel 微服务 Span 数据"
	} else {
		st.Status = "READY"
	}
	return edges, st
}

func (r *DefaultServiceRPCGraphReader) queryAgentDataflow(ctx context.Context, ch apm.CHQuerier, f ServiceRPCGraphFilter) ([]ServiceRPCEdge, ServiceRPCSourceStatus) {
	st := ServiceRPCSourceStatus{
		Source: "agent_dataflow",
		Label:  "云 API Sensor 数据流",
	}
	if ch == nil {
		st.Status = "NOT_CONFIGURED"
		st.Message = "未配置 ClickHouse 数据面，分布式数据流服务拓扑暂不可用"
		return nil, st
	}
	sqlText, args := buildDataflowServiceRPCQuery(f)
	rows, err := ch.Query(withServiceRPCCHSettings(ctx), sqlText, args...)
	if err != nil {
		slog.Warn("service-rpc-graph: Dataflow ClickHouse 查询降级", "error", err)
		st.Status = "UNAVAILABLE"
		st.Message = "数据流贡献表暂不可查（已降级为空）"
		return nil, st
	}
	defer rows.Close()
	edges, err := scanServiceRPCCHRows(rows, "agent_dataflow")
	if err != nil {
		slog.Warn("service-rpc-graph: Dataflow ClickHouse 扫描降级", "error", err)
		st.Status = "UNAVAILABLE"
		st.Message = "数据流数据读取失败（已降级为空）"
		return nil, st
	}
	st.EdgeCount = len(edges)
	if len(edges) == 0 {
		st.Status = "EMPTY"
		st.Message = "当前时间窗内暂无 Sensor 服务间调用记录"
	} else {
		st.Status = "READY"
	}
	return edges, st
}

func (r *DefaultServiceRPCGraphReader) queryAgentGRPC(ctx context.Context, f ServiceRPCGraphFilter) ([]ServiceRPCEdge, ServiceRPCSourceStatus) {
	st := ServiceRPCSourceStatus{
		Source: "agent_grpc",
		Label:  "流量 Agent gRPC 观测",
	}
	if r.db == nil {
		st.Status = "NOT_CONFIGURED"
		st.Message = "数据库未初始化"
		return nil, st
	}
	rows, err := r.db.Query(ctx, `
WITH grpc_rows AS (
  SELECT
    COALESCE(
      NULLIF(CASE WHEN e.k8s->>'side' = 'src' THEN COALESCE(NULLIF(e.k8s->>'service',''), NULLIF(e.k8s->>'workload',''), NULLIF(e.k8s->>'pod','')) END, ''),
      NULLIF(e.src_ip, ''),
      NULLIF(a.hostname, ''),
      e.agent_id::text
    ) AS source,
    COALESCE(
      NULLIF(CASE WHEN e.k8s->>'side' = 'dst' THEN COALESCE(NULLIF(e.k8s->>'service',''), NULLIF(e.k8s->>'workload',''), NULLIF(e.k8s->>'pod','')) END, ''),
      NULLIF(e.grpc->>'service', ''),
      NULLIF(e.host, ''),
      CASE WHEN e.dst_ip <> '' AND e.dst_port > 0 THEN e.dst_ip || ':' || e.dst_port::text
           WHEN e.dst_ip <> '' THEN e.dst_ip
           ELSE '' END
    ) AS target,
    CASE
      WHEN COALESCE(e.grpc->>'service','') <> '' AND COALESCE(e.grpc->>'method','') <> ''
        THEN (e.grpc->>'service') || '/' || (e.grpc->>'method')
      WHEN COALESCE(e.grpc->>'service','') <> ''
        THEN e.grpc->>'service'
      ELSE COALESCE(NULLIF(e.uri,''), 'gRPC')
    END AS op_name,
    CASE
      WHEN (e.grpc->>'grpc_status') ~ '^[0-9]+$' AND (e.grpc->>'grpc_status')::int > 0 THEN 1
      ELSE 0
    END AS is_err,
    e.latency_ms,
    e.ts
  FROM agent_http_events e
  LEFT JOIN agents a ON a.agent_id = e.agent_id
  WHERE e.grpc IS NOT NULL
    AND e.ts >= $1 AND e.ts < $2
)
SELECT
  source,
  target,
  COUNT(*)::bigint AS calls,
  SUM(is_err)::bigint AS error_count,
  COALESCE(AVG(latency_ms)::double precision, 0) AS avg_ms,
  COALESCE(percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms) FILTER (WHERE latency_ms IS NOT NULL), 0)::double precision AS p95_ms,
  (ARRAY_AGG(DISTINCT op_name ORDER BY op_name))[1:20] AS operations,
  MIN(ts) AS first_seen_at,
  MAX(ts) AS last_seen_at
FROM grpc_rows
WHERE source <> '' AND target <> '' AND source <> target
GROUP BY source, target
ORDER BY calls DESC, source ASC, target ASC
LIMIT $3`, f.Start, f.End, serviceRPCSourceFetchLimit)
	if err != nil {
		slog.Warn("service-rpc-graph: agent_http_events gRPC 查询降级", "error", err)
		st.Status = "UNAVAILABLE"
		st.Message = "流量 Agent gRPC 观测表暂不可查"
		return nil, st
	}
	defer rows.Close()
	edges := []ServiceRPCEdge{}
	for rows.Next() {
		var source, target string
		var calls, errCount int64
		var avgMS, p95MS float64
		var ops []string
		var firstSeen, lastSeen time.Time
		if err := rows.Scan(&source, &target, &calls, &errCount, &avgMS, &p95MS, &ops, &firstSeen, &lastSeen); err != nil {
			slog.Warn("service-rpc-graph: agent_http_events gRPC 扫描降级", "error", err)
			st.Status = "UNAVAILABLE"
			st.Message = "流量 Agent gRPC 数据读取失败"
			return nil, st
		}
		edges = append(edges, ServiceRPCEdge{
			Source:         strings.TrimSpace(source),
			Target:         strings.TrimSpace(target),
			TargetType:     "SERVICE",
			Protocol:       "GRPC",
			CallCategory:   "RPC",
			EvidenceType:   "AGENT_GRPC_OBSERVED",
			Paired:         false,
			DataSource:     "agent_grpc",
			Calls:          calls,
			ErrorCount:     errCount,
			AvgMS:          roundRPCFloat(avgMS),
			P95MS:          roundRPCFloat(p95MS),
			Operations:     cleanStringSlice(ops, serviceRPCMaxOperations),
			SampleTraceIDs: []string{},
			FirstSeenAt:    firstSeen.UTC(),
			LastSeenAt:     lastSeen.UTC(),
		})
	}
	if err := rows.Err(); err != nil {
		slog.Warn("service-rpc-graph: agent_http_events gRPC 遍历降级", "error", err)
		st.Status = "UNAVAILABLE"
		st.Message = "流量 Agent gRPC 数据遍历失败"
		return nil, st
	}
	st.EdgeCount = len(edges)
	if len(edges) == 0 {
		st.Status = "EMPTY"
		st.Message = "当前时间窗内暂无流量 Agent gRPC 记录"
	} else {
		st.Status = "READY"
	}
	return edges, st
}

// ServiceRPCGraph 汇聚三路真实微服务调用数据源，执行过滤、合并去重与节点派生。
func (r *DefaultServiceRPCGraphReader) ServiceRPCGraph(ctx context.Context, f ServiceRPCGraphFilter) (*ServiceRPCGraph, error) {
	var ch apm.CHQuerier
	if r.resolveCH != nil {
		ch = r.resolveCH(ctx)
	}
	otelEdges, otelStatus := r.queryOTelTraces(ctx, ch, f)
	dfEdges, dfStatus := r.queryAgentDataflow(ctx, ch, f)
	grpcEdges, grpcStatus := r.queryAgentGRPC(ctx, f)

	rawEdges := make([]ServiceRPCEdge, 0, len(otelEdges)+len(dfEdges)+len(grpcEdges))
	rawEdges = append(rawEdges, otelEdges...)
	rawEdges = append(rawEdges, dfEdges...)
	rawEdges = append(rawEdges, grpcEdges...)

	sources := []ServiceRPCSourceStatus{otelStatus, dfStatus, grpcStatus}
	return buildServiceRPCGraph(rawEdges, sources, f), nil
}

func cleanStringSlice(in []string, maxLen int) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
		if maxLen > 0 && len(out) >= maxLen {
			break
		}
	}
	return out
}

func mergeStringSlices(a, b []string, maxLen int) []string {
	combined := make([]string, 0, len(a)+len(b))
	combined = append(combined, a...)
	combined = append(combined, b...)
	out := cleanStringSlice(combined, 0)
	sort.Strings(out)
	if maxLen > 0 && len(out) > maxLen {
		out = out[:maxLen]
	}
	return out
}

// buildServiceRPCGraph 纯逻辑：按过滤条件筛选、按 (source, target, protocol) 合并去重并派生服务节点。
func buildServiceRPCGraph(rawEdges []ServiceRPCEdge, sources []ServiceRPCSourceStatus, f ServiceRPCGraphFilter) *ServiceRPCGraph {
	if f.Limit <= 0 || f.Limit > serviceRPCMaxLimit {
		f.Limit = serviceRPCDefaultLimit
	}
	protoFilter := strings.ToUpper(strings.TrimSpace(f.Protocol))
	if protoFilter == "" {
		protoFilter = "ALL"
	}
	svcFilter := strings.ToLower(strings.TrimSpace(f.Service))

	type edgeKey struct {
		source   string
		target   string
		protocol string
	}
	type edgeAcc struct {
		edge        ServiceRPCEdge
		weightedSum float64
	}
	merged := make(map[edgeKey]*edgeAcc, len(rawEdges))

	for _, e := range rawEdges {
		e.Source = strings.TrimSpace(e.Source)
		e.Target = strings.TrimSpace(e.Target)
		if e.Source == "" || e.Target == "" || e.Source == e.Target || e.Calls <= 0 {
			continue
		}
		e.Protocol, e.CallCategory = classifyServiceRPCProtocol(e.Protocol)
		if strings.ToUpper(strings.TrimSpace(e.TargetType)) == "SERVICE" {
			e.TargetType = "SERVICE"
		} else {
			e.TargetType = "EXTERNAL"
		}
		if f.PairedOnly && !e.Paired {
			continue
		}
		if !f.IncludeExternal && e.TargetType != "SERVICE" {
			continue
		}
		if protoFilter == "RPC" && e.CallCategory != "RPC" {
			continue
		}
		if protoFilter != "ALL" && protoFilter != "RPC" && e.Protocol != protoFilter {
			continue
		}
		if svcFilter != "" {
			if !strings.Contains(strings.ToLower(e.Source), svcFilter) &&
				!strings.Contains(strings.ToLower(e.Target), svcFilter) {
				continue
			}
		}

		k := edgeKey{source: e.Source, target: e.Target, protocol: e.Protocol}
		acc, ok := merged[k]
		if !ok {
			e.ID = fmt.Sprintf("%s->%s|%s", e.Source, e.Target, e.Protocol)
			e.Operations = cleanStringSlice(e.Operations, serviceRPCMaxOperations)
			sort.Strings(e.Operations)
			e.SampleTraceIDs = cleanStringSlice(e.SampleTraceIDs, serviceRPCMaxSampleTraces)
			merged[k] = &edgeAcc{
				edge:        e,
				weightedSum: e.AvgMS * float64(e.Calls),
			}
			continue
		}

		acc.edge.Calls += e.Calls
		acc.edge.ErrorCount += e.ErrorCount
		acc.weightedSum += e.AvgMS * float64(e.Calls)
		if e.P95MS > acc.edge.P95MS {
			acc.edge.P95MS = e.P95MS
		}
		if e.TargetType == "SERVICE" {
			acc.edge.TargetType = "SERVICE"
		}
		if e.Paired {
			acc.edge.Paired = true
		}
		if evidencePriority(e.EvidenceType) > evidencePriority(acc.edge.EvidenceType) {
			acc.edge.EvidenceType = e.EvidenceType
			acc.edge.DataSource = e.DataSource
		}
		acc.edge.Operations = mergeStringSlices(acc.edge.Operations, e.Operations, serviceRPCMaxOperations)
		acc.edge.SampleTraceIDs = mergeStringSlices(acc.edge.SampleTraceIDs, e.SampleTraceIDs, serviceRPCMaxSampleTraces)
		if !e.FirstSeenAt.IsZero() && (acc.edge.FirstSeenAt.IsZero() || e.FirstSeenAt.Before(acc.edge.FirstSeenAt)) {
			acc.edge.FirstSeenAt = e.FirstSeenAt
		}
		if !e.LastSeenAt.IsZero() && (acc.edge.LastSeenAt.IsZero() || e.LastSeenAt.After(acc.edge.LastSeenAt)) {
			acc.edge.LastSeenAt = e.LastSeenAt
		}
	}

	edges := make([]ServiceRPCEdge, 0, len(merged))
	for _, acc := range merged {
		if f.MinCalls > 0 && acc.edge.Calls < f.MinCalls {
			continue
		}
		if acc.edge.Calls > 0 {
			acc.edge.ErrorRate = roundRPCFloat(float64(acc.edge.ErrorCount) / float64(acc.edge.Calls))
			acc.edge.AvgMS = roundRPCFloat(acc.weightedSum / float64(acc.edge.Calls))
		}
		acc.edge.P95MS = roundRPCFloat(acc.edge.P95MS)
		edges = append(edges, acc.edge)
	}

	sort.Slice(edges, func(i, j int) bool {
		if edges[i].Calls != edges[j].Calls {
			return edges[i].Calls > edges[j].Calls
		}
		if edges[i].Paired != edges[j].Paired {
			return edges[i].Paired
		}
		if edges[i].Source != edges[j].Source {
			return edges[i].Source < edges[j].Source
		}
		if edges[i].Target != edges[j].Target {
			return edges[i].Target < edges[j].Target
		}
		return edges[i].Protocol < edges[j].Protocol
	})

	truncated := false
	if len(edges) > f.Limit {
		edges = edges[:f.Limit]
		truncated = true
	}

	type nodeAcc struct {
		node         ServiceRPCNode
		protoSet     map[string]struct{}
		opSet        map[string]struct{}
		totalCalls   int64
		weightedMS   float64
	}
	nodeMap := make(map[string]*nodeAcc, len(edges)*2)
	ensureNode := func(name, nodeType string) *nodeAcc {
		acc, ok := nodeMap[name]
		if !ok {
			acc = &nodeAcc{
				node: ServiceRPCNode{
					ID:        name,
					Name:      name,
					NodeType:  nodeType,
					Protocols: []string{},
				},
				protoSet: map[string]struct{}{},
				opSet:    map[string]struct{}{},
			}
			nodeMap[name] = acc
		} else if nodeType == "SERVICE" {
			acc.node.NodeType = "SERVICE"
		}
		return acc
	}

	summary := ServiceRPCGraphSummary{
		TotalEdges: len(edges),
		Truncated:  truncated,
	}
	for _, e := range edges {
		summary.TotalCalls += e.Calls
		summary.TotalErrors += e.ErrorCount
		if e.CallCategory == "RPC" {
			summary.RPCEdges++
		} else {
			summary.HTTPEdges++
		}
		if e.Paired {
			summary.PairedEdges++
		}
		if e.ErrorRate >= 0.05 {
			summary.ErrorEdges++
		}

		src := ensureNode(e.Source, "SERVICE")
		src.node.OutboundCalls += e.Calls
		src.node.OutboundEdges++
		src.protoSet[e.Protocol] = struct{}{}

		dst := ensureNode(e.Target, e.TargetType)
		dst.node.InboundCalls += e.Calls
		dst.node.InboundEdges++
		dst.node.ErrorCount += e.ErrorCount
		dst.totalCalls += e.Calls
		dst.weightedMS += e.AvgMS * float64(e.Calls)
		dst.protoSet[e.Protocol] = struct{}{}
		for _, op := range e.Operations {
			dst.opSet[op] = struct{}{}
		}
	}

	nodes := make([]ServiceRPCNode, 0, len(nodeMap))
	for _, acc := range nodeMap {
		for p := range acc.protoSet {
			acc.node.Protocols = append(acc.node.Protocols, p)
		}
		sort.Strings(acc.node.Protocols)
		acc.node.OperationsCount = len(acc.opSet)
		if acc.totalCalls > 0 {
			acc.node.ErrorRate = roundRPCFloat(float64(acc.node.ErrorCount) / float64(acc.totalCalls))
			acc.node.AvgMS = roundRPCFloat(acc.weightedMS / float64(acc.totalCalls))
		}
		if acc.node.NodeType == "SERVICE" {
			summary.ServiceNodes++
		} else {
			summary.ExternalNodes++
		}
		nodes = append(nodes, acc.node)
	}
	sort.Slice(nodes, func(i, j int) bool {
		ti := nodes[i].InboundCalls + nodes[i].OutboundCalls
		tj := nodes[j].InboundCalls + nodes[j].OutboundCalls
		if ti != tj {
			return ti > tj
		}
		return nodes[i].Name < nodes[j].Name
	})
	summary.TotalNodes = len(nodes)

	note := "基于 OTel 分布式追踪双端 Span 配对、云 API Sensor 服务间数据流与流量 Agent gRPC 观测汇聚生成；优先展示双端确凿配对（Client↔Server）的微服务间调用"
	if truncated {
		note += fmt.Sprintf("；结果已达上限 %d 条边，请按服务或协议缩小范围", f.Limit)
	}
	if sources == nil {
		sources = []ServiceRPCSourceStatus{}
	}

	return &ServiceRPCGraph{
		Start:   f.Start,
		End:     f.End,
		Nodes:   nodes,
		Edges:   edges,
		Summary: summary,
		Sources: sources,
		Note:    note,
	}
}

func parseServiceRPCGraphFilter(w http.ResponseWriter, r *http.Request, now time.Time) (ServiceRPCGraphFilter, bool) {
	q := r.URL.Query()
	end := now.UTC()
	if raw := strings.TrimSpace(q.Get("end")); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 end（需 RFC3339 时间）")
			return ServiceRPCGraphFilter{}, false
		}
		end = t.UTC()
	}
	start := end.Add(-serviceRPCDefaultWindow)
	if raw := strings.TrimSpace(q.Get("start")); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 start（需 RFC3339 时间）")
			return ServiceRPCGraphFilter{}, false
		}
		start = t.UTC()
	}
	if !start.Before(end) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "start 必须早于 end")
		return ServiceRPCGraphFilter{}, false
	}
	if end.Sub(start) > serviceRPCMaxWindow {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "微服务调用图谱查询窗口不能超过 24 小时")
		return ServiceRPCGraphFilter{}, false
	}

	proto := strings.ToUpper(strings.TrimSpace(q.Get("protocol")))
	if proto == "" {
		proto = "ALL"
	}
	if !validServiceRPCProtocols[proto] {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 protocol（支持 ALL/RPC/GRPC/HTTP/DUBBO/THRIFT/JSONRPC/CONNECT_RPC）")
		return ServiceRPCGraphFilter{}, false
	}

	svc := strings.TrimSpace(q.Get("service"))
	if len([]rune(svc)) > serviceRPCMaxServiceNameLen {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "service 长度不能超过 128 字符")
		return ServiceRPCGraphFilter{}, false
	}

	pairedOnly, ok := parseOptionalBoolParam(w, r, "paired_only")
	if !ok {
		return ServiceRPCGraphFilter{}, false
	}
	includeExternal, ok := parseOptionalBoolParam(w, r, "include_external")
	if !ok {
		return ServiceRPCGraphFilter{}, false
	}

	var minCalls int64
	if raw := strings.TrimSpace(q.Get("min_calls")); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 0 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 min_calls（需非负整数）")
			return ServiceRPCGraphFilter{}, false
		}
		minCalls = n
	}

	limit := serviceRPCDefaultLimit
	if raw := strings.TrimSpace(q.Get("limit")); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 || n > serviceRPCMaxLimit {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, fmt.Sprintf("无效的 limit（需 1~%d 整数）", serviceRPCMaxLimit))
			return ServiceRPCGraphFilter{}, false
		}
		limit = n
	}

	return ServiceRPCGraphFilter{
		Start:           start,
		End:             end,
		Protocol:        proto,
		Service:         svc,
		PairedOnly:      pairedOnly,
		IncludeExternal: includeExternal,
		MinCalls:        minCalls,
		Limit:           limit,
	}, true
}

// ServiceRPCGraph GET /api/v1/api-security/service-rpc-graph
// 返回后端微服务之间真实 RPC / 服务间调用图谱（权限 api_graph.read）。
func (h *Handler) ServiceRPCGraph(w http.ResponseWriter, r *http.Request) {
	f, ok := parseServiceRPCGraphFilter(w, r, time.Now().UTC())
	if !ok {
		return
	}
	reader := h.serviceRPCGraph
	if reader == nil {
		if h.store != nil {
			reader = NewServiceRPCGraphReader(h.store.db, nil)
		} else {
			reader = NewServiceRPCGraphReader(nil, nil)
		}
	}
	g, err := reader.ServiceRPCGraph(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, g)
}
