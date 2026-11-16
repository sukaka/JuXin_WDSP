// chstore.go APM 阶段2 下半：ClickHouse 数据面只读检索（apm.otel_traces，
// schema 以 deployment/apm/clickhouse/001_otel_traces.sql 为准，对齐
// opentelemetry-collector-contrib v0.154.0 clickhouse exporter DDL）。
//
// 纪律（任务书与 APM 设计 §12/§15.2/§21.3）：
//   - 全部查询参数化（? 占位由 clickhouse-go 绑定），表名/列名只出自本文件常量 SQL；
//   - 原始表扫描强制时间窗（trace-search 窗口上限 24h；trace 瀑布缺省对齐最长 TTL 层
//     14 天），LIMIT 强制上限；每条查询经 withCHSettings 设 max_execution_time；
//   - 遥测故障不影响管理面：CH 未配置（querier=nil）或查询失败一律降级为
//     data_source=agentless 的空数据，绝不上抛 500；
//   - SpanAttributes 只透传 spanAttrWhitelist 白名单键（数据最小化 §12.1：
//     db.statement / url.query / 请求正文类键严禁放出）。
package apm

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
)

const (
	// chMaxExecutionTimeSec 单条 CH 查询最大执行时间（秒，查询级 SETTINGS）。
	chMaxExecutionTimeSec = 30
	// maxTraceSpans 单 trace 返回 span 上限（超出截断并将 truncated 置 true）。
	maxTraceSpans = 1000
	// traceSpansDefaultWindow trace 瀑布 CH 侧缺省窗口（对齐原始表最长 TTL 层 14 天，
	// 避免出现"索引在、数据已删"的漏查窗口）。
	traceSpansDefaultWindow = 14 * 24 * time.Hour
	// requestIDTraceLimit request_id 解析 trace_id 集合上限（request_id 本应有唯一索引，
	// 上限仅防异常数据下放大的 IN 集合）。
	requestIDTraceLimit = 100
	// searchServicesCap 单 trace 返回的 services 列表上限（groupUniqArray 护栏）。
	searchServicesCap = 32
)

// spanAttrWhitelist span attributes 透传白名单（OTel 语义约定 + 九章自有键）。
// 新增键前评审数据最小化口径；db.statement、url.query、header/body 留痕类键严禁加入。
var spanAttrWhitelist = map[string]bool{
	// HTTP（新旧语义约定并存：1.x http.method / 2.x http.request.method）
	"http.method":               true,
	"http.request.method":       true,
	"http.route":                true,
	"http.status_code":          true,
	"http.response.status_code": true,
	"server.address":            true,
	"server.port":               true,
	"peer.service":              true,
	// DB（只放系统/操作/命名空间；语句与 bind values 严禁透传）
	"db.system":         true,
	"db.operation.name": true,
	"db.namespace":      true,
	// 消息与 RPC
	"messaging.system":           true,
	"messaging.destination.name": true,
	"messaging.operation.name":   true,
	"rpc.system":                 true,
	"rpc.service":                true,
	"rpc.method":                 true,
	// 九章自有（网关埋点写入，TTL 分层亦引用）
	"jiuzhang.waf_action": true,
}

// filterSpanAttributes 白名单过滤（nil 入返回空 map，保证 JSON 输出 {} 而非 null）。
func filterSpanAttributes(attrs map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range attrs {
		if spanAttrWhitelist[k] {
			out[k] = v
		}
	}
	return out
}

// CHRows 收窄的 ClickHouse 行集抽象（driver.Rows 满足；单测 fake）。
type CHRows interface {
	Next() bool
	Scan(dest ...any) error
	Close() error
	Err() error
}

// CHQuerier 收窄的 ClickHouse 查询抽象（生产为 chQuerier 适配 driver.Conn；单测 fake）。
type CHQuerier interface {
	Query(ctx context.Context, query string, args ...any) (CHRows, error)
}

// chQuerier driver.Conn → CHQuerier 适配器。
type chQuerier struct{ conn driver.Conn }

func (q chQuerier) Query(ctx context.Context, query string, args ...any) (CHRows, error) {
	return q.conn.Query(ctx, query, args...)
}

func (q chQuerier) Exec(ctx context.Context, query string, args ...any) error {
	return q.conn.Exec(ctx, query, args...)
}

// Close 关闭底层连接（CHManager DSN 热更新重建前回收旧连接）。
func (q chQuerier) Close() error { return q.conn.Close() }

// OpenClickHouse 解析 DSN、建立连接并 Ping（5s 超时）。失败由调用方 Warn 降级，
// 不得 panic——遥测故障不影响管理面。
func OpenClickHouse(dsn string) (CHQuerier, error) {
	opts, err := clickhouse.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse ClickHouse DSN: %w", err)
	}
	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("open ClickHouse: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping ClickHouse: %w", err)
	}
	return chQuerier{conn: conn}, nil
}

// withCHSettings 查询级护栏：max_execution_time。
func withCHSettings(ctx context.Context) context.Context {
	return clickhouse.Context(ctx, clickhouse.WithSettings(clickhouse.Settings{
		"max_execution_time": chMaxExecutionTimeSec,
	}))
}

// slogWarnCH CH 查询失败告警日志（遥测故障不影响管理面，仅 Warn 后降级）。
func slogWarnCH(op string, err error) {
	slog.Warn("APM ClickHouse 查询失败，OTel 数据降级为空", "op", op, "error", err)
}

// roundMS 纳秒/毫秒浮点统一保留 3 位小数（微秒精度，避免浮点长尾污染响应）。
func roundMS(ms float64) float64 { return math.Round(ms*1000) / 1000 }

// ---------- trace-search 查询构造 ----------

// traceSearchClauses 生成 WHERE/HAVING 条件片段与绑定参数（顺序与占位符一致）。
// 时间窗恒在 WHERE（原始表扫描必须限窗）；聚合条件（耗时/错误）落 HAVING。
// ServiceNames 非 nil 时强制 ServiceName IN 约束（P1-01 A2 应用约束下推）。
func traceSearchClauses(f TraceSearchFilter) (where []string, having []string, args []any) {
	where = []string{"Timestamp >= ?", "Timestamp < ?"}
	args = append(args, f.Start, f.End)
	if f.Service != "" {
		where = append(where, "ServiceName = ?")
		args = append(args, f.Service)
	}
	if f.ServiceNames != nil {
		where = append(where, "ServiceName IN (?)")
		args = append(args, f.ServiceNames)
	}
	if len(f.TraceIDs) > 0 {
		where = append(where, "TraceId IN (?)")
		args = append(args, f.TraceIDs)
	}
	if f.MinDurationMS > 0 {
		having = append(having, "wall_ms >= ?")
		args = append(args, f.MinDurationMS)
	}
	if f.ErrorOnly {
		having = append(having, "error_count > 0")
	}
	return where, having, args
}

// traceSearchGroupBy trace 检索公共聚合体（list 与 count 共用，保证口径一致）。
// 耗时口径：duration_ms = trace 墙钟耗时（max(span 结束) − min(span 开始)，毫秒）；
// 根 span 取 ParentSpanId=” 且 SpanKind='Server' 中耗时最长者，无 Server 根退化为
// 任一 ParentSpanId=” 根，仍无则如实返回空串（采集缺根，前端标注）。
func traceSearchGroupBy(f TraceSearchFilter) (string, []any) {
	where, having, args := traceSearchClauses(f)
	var b strings.Builder
	b.WriteString(`SELECT
  TraceId,
  min(Timestamp) AS start_time,
  (max(toUnixTimestamp64Nano(Timestamp) + toInt64(Duration)) - min(toUnixTimestamp64Nano(Timestamp))) / 1000000.0 AS wall_ms,
  count() AS span_count,
  countIf(StatusCode = 'Error') AS error_count,
  groupUniqArray(` + fmt.Sprintf("%d", searchServicesCap) + `)(ServiceName) AS services,
  argMaxIf(ServiceName, Duration, ParentSpanId = '' AND SpanKind = 'Server') AS root_server_service,
  argMaxIf(SpanName, Duration, ParentSpanId = '' AND SpanKind = 'Server') AS root_server_operation,
  argMaxIf(ServiceName, Duration, ParentSpanId = '') AS root_any_service,
  argMaxIf(SpanName, Duration, ParentSpanId = '') AS root_any_operation
FROM apm.otel_traces
WHERE ` + strings.Join(where, " AND ") + `
GROUP BY TraceId`)
	if len(having) > 0 {
		b.WriteString("\nHAVING " + strings.Join(having, " AND "))
	}
	return b.String(), args
}

// buildTraceSearchListQuery trace-search 列表查询（按开始时间倒序分页，LIMIT/OFFSET 强制）。
func buildTraceSearchListQuery(f TraceSearchFilter) (string, []any) {
	body, args := traceSearchGroupBy(f)
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	return body + `
ORDER BY start_time DESC, TraceId ASC
LIMIT ? OFFSET ?`, args
}

// buildTraceSearchCountQuery trace-search 总数查询（子查询计数，与列表同口径）。
func buildTraceSearchCountQuery(f TraceSearchFilter) (string, []any) {
	body, args := traceSearchGroupBy(f)
	return "SELECT count() FROM (\n" + body + "\n)", args
}

// buildTraceSpansQuery trace 瀑布查询（trace_id 精确 + 强制时间窗 + 上限 maxTraceSpans+1
// 用于探测截断；按开始时间正序，前端按 parent 关系组织瀑布）。
func buildTraceSpansQuery(traceID string, start, end time.Time) (string, []any) {
	return `SELECT SpanId, ParentSpanId, ServiceName, SpanName, SpanKind,
  Timestamp, Duration, StatusCode, SpanAttributes
FROM apm.otel_traces
WHERE TraceId = ? AND Timestamp >= ? AND Timestamp < ?
ORDER BY Timestamp ASC, SpanId ASC
LIMIT ?`, []any{traceID, start, end, maxTraceSpans + 1}
}

// ---------- 行映射 ----------

// scanTraceSearchRow 单行扫描（拆出便于单测；services 为 CH Array(String)，
// count()/countIf() 为 UInt64，扫入后转 int64——量级远低于溢出阈值）。
func scanTraceSearchRow(rows CHRows) (*TraceSearchItem, error) {
	var it TraceSearchItem
	var wallMS float64
	var spanCount, errorCount uint64
	var rootServerSvc, rootServerOp, rootAnySvc, rootAnyOp string
	var services []string
	if err := rows.Scan(&it.TraceID, &it.StartTime, &wallMS, &spanCount, &errorCount,
		&services, &rootServerSvc, &rootServerOp, &rootAnySvc, &rootAnyOp); err != nil {
		return nil, err
	}
	it.SpanCount, it.ErrorCount = int64(spanCount), int64(errorCount)
	it.DurationMS = roundMS(wallMS)
	it.Services = services
	if it.Services == nil {
		it.Services = []string{}
	}
	it.RootService, it.RootOperation = rootServerSvc, rootServerOp
	if it.RootService == "" && it.RootOperation == "" {
		it.RootService, it.RootOperation = rootAnySvc, rootAnyOp
	}
	return &it, nil
}

// scanOTelSpanRow 单 span 扫描与映射（Duration 纳秒 → 毫秒 3 位小数；attributes 白名单过滤）。
func scanOTelSpanRow(rows CHRows) (*OTelSpan, error) {
	var sp OTelSpan
	var durNS uint64
	var attrs map[string]string
	if err := rows.Scan(&sp.SpanID, &sp.ParentSpanID, &sp.ServiceName, &sp.OperationName,
		&sp.SpanKind, &sp.StartTime, &durNS, &sp.StatusCode, &attrs); err != nil {
		return nil, err
	}
	sp.DurationMS = roundMS(float64(durNS) / 1e6)
	sp.Attributes = filterSpanAttributes(attrs)
	return &sp, nil
}

// ---------- Store 的 CH 侧查询 ----------

// degradedTraceSearch CH 未配置/不可用时的降级响应（空页 + agentless + 提示 +
// availability UNAVAILABLE，不 500）。P1-01 A2：availability 由真实降级原因构建。
func (s *Store) degradedTraceSearch(ctx context.Context, f TraceSearchFilter, message string, status chQueryStatus) *TraceSearchData {
	return &TraceSearchData{
		List:       []TraceSearchItem{},
		Total:      0,
		Page:       f.Page,
		PageSize:   f.PageSize,
		DataSource: dataSourceAgentless,
		Message:    message,
		Availability: s.chAvailability(ctx, status, false, f.Start, f.End, f.IngestLagThreshold,
			accessLogDisabledReason(f)...),
	}
}

// accessLogDisabledReason request_id 检索且访问日志关闭时的原因码（有证据才填）。
func accessLogDisabledReason(f TraceSearchFilter) []string {
	if f.RequestID != "" && !f.AccessLogEnabled {
		return []string{reasonAccessLogDisabled}
	}
	return nil
}

// SearchTraces trace 检索（CH 数据面；request_id 先经 access_logs 解析 trace_id 集合）。
// CH 未配置或查询失败一律降级为空页（data_source=agentless + message + availability
// UNAVAILABLE），不返回错误。
// P1-01 A2：application_id 按应用约束（apm_services 服务名集合下推 CH、access_logs
// 解析下推 application_id）；request_id 检索返回 correlation 关联判定（五态 + UNKNOWN，
// 判定矩阵见 availability.go correlateRequestIDTrace）。
func (s *Store) SearchTraces(ctx context.Context, f TraceSearchFilter) (*TraceSearchData, error) {
	// 应用约束解析（PG）：服务名集合下推 CH；空集合 = 约束不可满足（不静默放弃约束）
	appConstrained := f.ApplicationID != nil
	if appConstrained {
		names, err := s.serviceNamesByApplication(ctx, *f.ApplicationID)
		if err != nil {
			return nil, err
		}
		f.ServiceNames = names
	}

	// trace_id 直达优先；否则 request_id 解析（access_logs 唯一索引点查，应用约束下推）
	requestIDMode := len(f.TraceIDs) == 0 && f.RequestID != ""
	var resolveRows []requestIDResolveRow
	if requestIDMode {
		rows, err := s.resolveRequestID(ctx, f.RequestID, f.ApplicationID, f.Start, f.End)
		if err != nil {
			return nil, err
		}
		resolveRows = rows
		ids := []string{}
		seen := map[string]bool{}
		for _, r := range rows {
			if r.TraceID != "" && !seen[r.TraceID] {
				seen[r.TraceID] = true
				ids = append(ids, r.TraceID)
			}
		}
		f.TraceIDs = ids
	}

	// correlation 构建闭包：汇聚本次真实证据（CH 状态/水位/解析行/事件证据）。
	// 安全事件证据仅在关联判定需要时查询（无命中路径的阻断/存在性判定）。
	buildCorrelation := func(chStatus chQueryStatus, found []TraceSearchItem) (*Correlation, error) {
		if !requestIDMode {
			return nil, nil
		}
		evAny, evBlock := false, false
		if len(resolveRows) == 0 || len(f.TraceIDs) == 0 || len(found) == 0 {
			var err error
			evAny, evBlock, err = s.securityEventEvidence(ctx, f.RequestID)
			if err != nil {
				return nil, err
			}
		}
		wmLatest, wmHasData, wmKnown := time.Time{}, false, false
		if chStatus == chQueryOK {
			wmLatest, wmHasData, wmKnown = s.latestIngest(ctx)
		}
		return correlateRequestIDTrace(correlationFacts{
			AccessLogEnabled: f.AccessLogEnabled,
			Rows:             resolveRows,
			ResolvedIDs:      f.TraceIDs,
			EventAny:         evAny,
			EventBlock:       evBlock,
			Found:            found,
			CHStatus:         chStatus,
			WMKnown:          wmKnown,
			WMHasData:        wmHasData,
			WMLatest:         wmLatest,
			Now:              s.now(),
			WindowEnd:        f.End,
		}), nil
	}

	ch := s.conn(ctx)
	if ch == nil {
		out := s.degradedTraceSearch(ctx, f, "APM_CLICKHOUSE_DSN 未配置：OTel 数据面未接入，当前仅支持无 Agent 网关侧数据（已知 trace_id 可用 /apm/traces/{trace_id} 检索）", chQueryNotConfigured)
		corr, err := buildCorrelation(chQueryNotConfigured, nil)
		if err != nil {
			return nil, err
		}
		out.Correlation = corr
		return out, nil
	}

	// 无需查 CH 的如实空页（数据面在线口径）：
	// 1) request_id 无关联 trace（解析为空）；
	// 2) 应用约束不可满足（无映射服务 / service 不在映射集合内）。
	emptyOnline := func(message string) (*TraceSearchData, error) {
		out := &TraceSearchData{
			List: []TraceSearchItem{}, Total: 0, Page: f.Page, PageSize: f.PageSize,
			DataSource: dataSourceOTel,
			Message:    message,
			Availability: s.chAvailability(ctx, chQueryOK, false, f.Start, f.End, f.IngestLagThreshold,
				accessLogDisabledReason(f)...),
		}
		corr, err := buildCorrelation(chQueryOK, nil)
		if err != nil {
			return nil, err
		}
		out.Correlation = corr
		return out, nil
	}
	if requestIDMode && len(f.TraceIDs) == 0 {
		return emptyOnline("")
	}
	if appConstrained {
		if len(f.ServiceNames) == 0 {
			return emptyOnline("该应用无已映射的 OTel 服务（apm_services 无记录），按应用约束检索无候选 Span")
		}
		if f.Service != "" {
			found := false
			for _, n := range f.ServiceNames {
				if n == f.Service {
					found = true
					break
				}
			}
			if !found {
				return emptyOnline("service 不在该应用已映射的 OTel 服务集合内，约束后无候选")
			}
		}
	}

	countSQL, countArgs := buildTraceSearchCountQuery(f)
	var total uint64
	countRows, err := ch.Query(withCHSettings(ctx), countSQL, countArgs...)
	if err != nil {
		slogWarnCH("trace-search count", err)
		out := s.degradedTraceSearch(ctx, f, "ClickHouse 数据面暂不可用，已降级为空结果（agentless 数据不受影响）", chQueryFailed)
		corr, cerr := buildCorrelation(chQueryFailed, nil)
		if cerr != nil {
			return nil, cerr
		}
		out.Correlation = corr
		return out, nil
	}
	if countRows.Next() {
		if err := countRows.Scan(&total); err != nil {
			countRows.Close()
			slogWarnCH("trace-search count scan", err)
			out := s.degradedTraceSearch(ctx, f, "ClickHouse 数据面暂不可用，已降级为空结果（agentless 数据不受影响）", chQueryFailed)
			corr, cerr := buildCorrelation(chQueryFailed, nil)
			if cerr != nil {
				return nil, cerr
			}
			out.Correlation = corr
			return out, nil
		}
	}
	if err := countRows.Err(); err != nil {
		countRows.Close()
		slogWarnCH("trace-search count iterate", err)
		out := s.degradedTraceSearch(ctx, f, "ClickHouse 数据面暂不可用，已降级为空结果（agentless 数据不受影响）", chQueryFailed)
		corr, cerr := buildCorrelation(chQueryFailed, nil)
		if cerr != nil {
			return nil, cerr
		}
		out.Correlation = corr
		return out, nil
	}
	countRows.Close()

	out := &TraceSearchData{
		List: []TraceSearchItem{}, Total: int64(total), Page: f.Page, PageSize: f.PageSize,
		DataSource: dataSourceOTel,
	}
	if total == 0 {
		out.Availability = s.chAvailability(ctx, chQueryOK, false, f.Start, f.End, f.IngestLagThreshold,
			accessLogDisabledReason(f)...)
		corr, err := buildCorrelation(chQueryOK, nil)
		if err != nil {
			return nil, err
		}
		out.Correlation = corr
		return out, nil
	}

	listSQL, listArgs := buildTraceSearchListQuery(f)
	rows, err := ch.Query(withCHSettings(ctx), listSQL, listArgs...)
	if err != nil {
		slogWarnCH("trace-search list", err)
		out := s.degradedTraceSearch(ctx, f, "ClickHouse 数据面暂不可用，已降级为空结果（agentless 数据不受影响）", chQueryFailed)
		corr, cerr := buildCorrelation(chQueryFailed, nil)
		if cerr != nil {
			return nil, cerr
		}
		out.Correlation = corr
		return out, nil
	}
	defer rows.Close()
	for rows.Next() {
		it, err := scanTraceSearchRow(rows)
		if err != nil {
			slogWarnCH("trace-search list scan", err)
			out := s.degradedTraceSearch(ctx, f, "ClickHouse 数据面暂不可用，已降级为空结果（agentless 数据不受影响）", chQueryFailed)
			corr, cerr := buildCorrelation(chQueryFailed, nil)
			if cerr != nil {
				return nil, cerr
			}
			out.Correlation = corr
			return out, nil
		}
		out.List = append(out.List, *it)
	}
	if err := rows.Err(); err != nil {
		slogWarnCH("trace-search list iterate", err)
		out := s.degradedTraceSearch(ctx, f, "ClickHouse 数据面暂不可用，已降级为空结果（agentless 数据不受影响）", chQueryFailed)
		corr, cerr := buildCorrelation(chQueryFailed, nil)
		if cerr != nil {
			return nil, cerr
		}
		out.Correlation = corr
		return out, nil
	}
	out.Availability = s.chAvailability(ctx, chQueryOK, true, f.Start, f.End, f.IngestLagThreshold,
		accessLogDisabledReason(f)...)
	corr, err := buildCorrelation(chQueryOK, out.List)
	if err != nil {
		return nil, err
	}
	out.Correlation = corr
	return out, nil
}

// queryTraceSpans 查询单 trace 的 OTel span（强制时间窗 + 上限截断探测）。
// 返回本次查询真实状态（P1-01 A2：availability 判定证据）——未配置/失败返回
// (空, false, 对应状态)，调用方如实标注 data_source/availability，不 500。
func (s *Store) queryTraceSpans(ctx context.Context, traceID string, start, end time.Time) ([]OTelSpan, bool, chQueryStatus) {
	ch := s.conn(ctx)
	if ch == nil {
		return []OTelSpan{}, false, chQueryNotConfigured
	}
	sql, args := buildTraceSpansQuery(traceID, start, end)
	rows, err := ch.Query(withCHSettings(ctx), sql, args...)
	if err != nil {
		slogWarnCH("trace spans", err)
		return []OTelSpan{}, false, chQueryFailed
	}
	defer rows.Close()
	spans := []OTelSpan{}
	truncated := false
	for rows.Next() {
		if len(spans) >= maxTraceSpans {
			// 第 maxTraceSpans+1 行仅作截断探测，不再扫描下放
			truncated = true
			break
		}
		sp, err := scanOTelSpanRow(rows)
		if err != nil {
			slogWarnCH("trace spans scan", err)
			return []OTelSpan{}, false, chQueryFailed
		}
		spans = append(spans, *sp)
	}
	if err := rows.Err(); err != nil {
		slogWarnCH("trace spans iterate", err)
		return []OTelSpan{}, false, chQueryFailed
	}
	return spans, truncated, chQueryOK
}

// resolveRequestID request_id 在 access_logs 的命中行（唯一索引点查，时间窗随检索窗
// 一并下推；application_id 非空时同步下推应用约束——跨应用碰撞 ID 不得串联）。
// trace_id 非法格式行归一为空串（写入侧已校验，此处纵深防御；调用方按空串=无 trace
// 上下文处理，不编造关联键）。
func (s *Store) resolveRequestID(ctx context.Context, requestID string, appID *uuid.UUID, start, end time.Time) ([]requestIDResolveRow, error) {
	where := "request_id = $1 AND occurred_at >= $2 AND occurred_at < $3"
	args := []interface{}{requestID, start, end}
	if appID != nil {
		args = append(args, *appID)
		where += fmt.Sprintf(" AND application_id = $%d", len(args))
	}
	args = append(args, requestIDTraceLimit)
	rows, err := s.db.Query(ctx, `
SELECT COALESCE(trace_id, ''), occurred_at, COALESCE(NULLIF(waf_action, ''), 'ALLOW')
FROM access_logs WHERE `+where+fmt.Sprintf(" ORDER BY occurred_at DESC LIMIT $%d", len(args)), args...)
	if err != nil {
		return nil, fmt.Errorf("resolve request_id: %w", err)
	}
	defer rows.Close()
	out := []requestIDResolveRow{}
	for rows.Next() {
		var r requestIDResolveRow
		if err := rows.Scan(&r.TraceID, &r.OccurredAt, &r.WAFAction); err != nil {
			return nil, fmt.Errorf("resolve request_id scan: %w", err)
		}
		if traceIDPattern.MatchString(r.TraceID) {
			r.TraceID = strings.ToLower(r.TraceID)
		} else {
			r.TraceID = ""
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
