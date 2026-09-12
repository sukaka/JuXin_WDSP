// chstore_aggregates.go APM 阶段3 第一批查询：SQL 指纹聚合、异常指纹聚合、服务依赖边。
//
// 数据源口径（schema 以 deployment/apm/clickhouse/001_otel_traces.sql 与
// 002_aggregates.sql 为准；设计 docs/BUSINESS_PERFORMANCE_APM_DESIGN.md §11.1/§16.1）：
//
//   - SQL 指纹：主数据源为 002 的 apm.apm_sql_minutes 分钟聚合表（calls/error_count/
//     avg_ms）。该表按 §13.3 基数预算只保留计数与耗时总量/最大值，不含分位数、
//     db.namespace、db.operation.name 与示例 trace——这些由 apm.otel_traces 同窗
//     派生（p95 用 quantile(0.95)，示例 trace 用 groupUniqArray(3)），两侧以
//     DbSystem + hex(MD5(db.statement)) 指纹等值 JOIN（指纹公式与物化视图一致）。
//     全程不出现原始 statement（§11.1：首期只存/只出指纹）。
//   - 异常指纹：002 的 apm.apm_exception_fingerprints（AggregatingMergeTree，
//     ARRAY JOIN Events 的 exception 事件）粒度足够支撑契约行（类型+指纹+计数+
//     首末出现+影响服务+示例 trace），无需 otel_traces 兜底；first/last_seen 为
//     分钟聚合桶粒度（±1 分钟），如实标注。示例 trace ≤3 需两级聚合：
//     内层按物化视图排序键 countMerge/anyMerge 出每桶示例，外层 groupUniqArray(3) 收集。
//   - 服务依赖：002 无依赖聚合表，从 apm.otel_traces 的 CLIENT/PRODUCER span 单视角
//     派生（ServiceName → peer.service / db.system[/namespace] /
//     messaging.system[/destination] / server.address），无对端 SERVER span 配对，
//     note 如实标注；未标注 peer.service 的 HTTP 调用按目标地址归类为 external。
//
// 纪律与 chstore.go 一致：全部参数化、强制时间窗（≤24h）与 LIMIT、withCHSettings
// max_execution_time、CH 未配置/失败一律降级空数据（data_source=agentless）不 500。
package apm

import (
	"context"
	"strconv"
	"strings"
)

const (
	// sqlSampleTraceCap SQL 指纹示例 trace 上限（groupUniqArray 护栏）。
	sqlSampleTraceCap = 3
	// exceptionSampleTraceCap 异常指纹示例 trace 上限。
	exceptionSampleTraceCap = 3
	// exceptionServicesCap 异常指纹影响服务列表上限（groupUniqArray 护栏）。
	exceptionServicesCap = 16
	// maxDependencyEdges 依赖边返回上限（+1 行探测截断，超限时 note 如实标注）。
	maxDependencyEdges = 500
)

// sqlSortColumns sort 白名单 → ORDER BY 列（常量映射，用户输入不直接拼 SQL）。
var sqlSortColumns = map[string]string{
	"calls":  "calls",
	"avg_ms": "avg_ms",
	"p95_ms": "p95_ms",
}

// dependenciesDerivedNote 依赖边派生口径说明（正常返回时如实标注单视角派生）。
const dependenciesDerivedNote = "基于客户端 span（CLIENT/PRODUCER）单视角派生，无对端 SERVER span 配对；" +
	"未标注 peer.service 的 HTTP 调用按 server.address 归类为 external"

// ---------- SQL 指纹聚合查询构造 ----------

// sqlAggSubquery 002 SQL 指纹分钟聚合表子查询（SummingMergeTree 按分组合并 sum）。
// 返回 WHERE 片段追加与参数顺序：窗口 → [service] → [db_system]。
func sqlAggSubquery(f SQLFilter) (string, []any) {
	where := []string{"Minute >= ?", "Minute < ?"}
	args := []any{f.Start, f.End}
	if f.Service != "" {
		where = append(where, "ServiceName = ?")
		args = append(args, f.Service)
	}
	if f.DBSystem != "" {
		where = append(where, "DbSystem = ?")
		args = append(args, f.DBSystem)
	}
	return `SELECT DbSystem, SqlFingerprint,
  sum(CallCount) AS calls,
  sum(ErrorCount) AS error_count,
  sum(TotalDurationNs) / 1000000.0 / greatest(sum(CallCount), 1) AS avg_ms
FROM apm.apm_sql_minutes
WHERE ` + strings.Join(where, " AND ") + `
GROUP BY DbSystem, SqlFingerprint`, args
}

// sqlRawSubquery otel_traces 同窗派生子查询：p95/namespace/operation/示例 trace。
// WHERE 与物化视图口径一致（Client + db.statement 非空），指纹公式相同保证 JOIN 键匹配。
// 参数顺序：窗口 → [service] → [db_system]（与聚合子查询独立绑定）。
func sqlRawSubquery(f SQLFilter) (string, []any) {
	where := []string{
		"SpanKind = 'Client'", "SpanAttributes['db.statement'] != ''",
		"Timestamp >= ?", "Timestamp < ?",
	}
	args := []any{f.Start, f.End}
	if f.Service != "" {
		where = append(where, "ServiceName = ?")
		args = append(args, f.Service)
	}
	if f.DBSystem != "" {
		where = append(where, "SpanAttributes['db.system'] = ?")
		args = append(args, f.DBSystem)
	}
	return `SELECT SpanAttributes['db.system'] AS DbSystem,
  hex(MD5(SpanAttributes['db.statement'])) AS SqlFingerprint,
  quantile(0.95)(Duration) / 1000000.0 AS p95_ms,
  any(SpanAttributes['db.namespace']) AS namespace,
  any(SpanAttributes['db.operation.name']) AS operation,
  groupUniqArray(` + strconv.Itoa(sqlSampleTraceCap) + `)(TraceId) AS sample_trace_ids
FROM apm.otel_traces
WHERE ` + strings.Join(where, " AND ") + `
GROUP BY DbSystem, SqlFingerprint`, args
}

// buildSQLListQuery SQL 指纹列表：聚合表 LEFT JOIN 原始表派生列（聚合行全保留；
// 原始表侧缺失时 p95_ms=0、namespace/operation 为空串——LEFT JOIN 默认填零值）。
// sort 经 sqlSortColumns 白名单映射（未知值回退 p95_ms），分页 LIMIT/OFFSET 强制。
func buildSQLListQuery(f SQLFilter) (string, []any) {
	agg, aggArgs := sqlAggSubquery(f)
	raw, rawArgs := sqlRawSubquery(f)
	sortCol, ok := sqlSortColumns[f.Sort]
	if !ok {
		sortCol = sqlSortColumns["p95_ms"]
	}
	args := append(append([]any{}, aggArgs...), rawArgs...)
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	return `SELECT
  agg.DbSystem AS db_system,
  agg.SqlFingerprint AS sql_fingerprint,
  raw.namespace AS namespace,
  raw.operation AS operation,
  agg.calls AS calls,
  agg.error_count AS error_count,
  agg.avg_ms AS avg_ms,
  raw.p95_ms AS p95_ms,
  raw.sample_trace_ids AS sample_trace_ids
FROM (
` + agg + `
) agg
LEFT JOIN (
` + raw + `
) raw ON agg.DbSystem = raw.DbSystem AND agg.SqlFingerprint = raw.SqlFingerprint
ORDER BY ` + sortCol + ` DESC, sql_fingerprint ASC
LIMIT ? OFFSET ?`, args
}

// buildSQLCountQuery SQL 指纹总数（聚合表分组计数，与列表同过滤口径）。
func buildSQLCountQuery(f SQLFilter) (string, []any) {
	agg, args := sqlAggSubquery(f)
	return "SELECT count() FROM (\n" + agg + "\n)", args
}

// ---------- SQL trace 级定位查询构造（P1-01 A2） ----------

// sqlTraceWhere trace 级定位的 WHERE 片段与参数（单 trace 精确 + 强制时间窗；
// service/db_system 过滤同步下推到该 trace 的 span 集合）。
func sqlTraceWhere(f SQLFilter) (string, []any) {
	where := []string{
		"TraceId = ?", "SpanKind = 'Client'", "SpanAttributes['db.statement'] != ''",
		"Timestamp >= ?", "Timestamp < ?",
	}
	args := []any{f.TraceID, f.Start, f.End}
	if f.Service != "" {
		where = append(where, "ServiceName = ?")
		args = append(args, f.Service)
	}
	if f.DBSystem != "" {
		where = append(where, "SpanAttributes['db.system'] = ?")
		args = append(args, f.DBSystem)
	}
	return strings.Join(where, " AND "), args
}

// buildSQLTraceListQuery trace 级 SQL 定位：仅该 trace 的 Client DB span 直接派生
// 指纹行（精确语义：行即该 trace 实际执行的 SQL 指纹，非窗口候选；指纹公式与
// 物化视图一致保证可与聚合行对照）。列序与 scanSQLRow 一致（复用行映射）。
// 全程不出现原始 statement（§11.1 纪律同窗口聚合模式）。
func buildSQLTraceListQuery(f SQLFilter) (string, []any) {
	w, args := sqlTraceWhere(f)
	sortCol, ok := sqlSortColumns[f.Sort]
	if !ok {
		sortCol = sqlSortColumns["p95_ms"]
	}
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	return `SELECT
  SpanAttributes['db.system'] AS db_system,
  hex(MD5(SpanAttributes['db.statement'])) AS sql_fingerprint,
  any(SpanAttributes['db.namespace']) AS namespace,
  any(SpanAttributes['db.operation.name']) AS operation,
  count() AS calls,
  countIf(StatusCode = 'Error') AS error_count,
  avg(Duration) / 1000000.0 AS avg_ms,
  quantile(0.95)(Duration) / 1000000.0 AS p95_ms,
  groupUniqArray(` + strconv.Itoa(sqlSampleTraceCap) + `)(TraceId) AS sample_trace_ids
FROM apm.otel_traces
WHERE ` + w + `
GROUP BY db_system, sql_fingerprint
ORDER BY ` + sortCol + ` DESC, sql_fingerprint ASC
LIMIT ? OFFSET ?`, args
}

// buildSQLTraceCountQuery trace 级定位指纹总数（与列表同过滤口径）。
func buildSQLTraceCountQuery(f SQLFilter) (string, []any) {
	w, args := sqlTraceWhere(f)
	return `SELECT count() FROM (
SELECT SpanAttributes['db.system'] AS db_system,
  hex(MD5(SpanAttributes['db.statement'])) AS sql_fingerprint
FROM apm.otel_traces
WHERE ` + w + `
GROUP BY db_system, sql_fingerprint
)`, args
}

// ---------- 异常指纹聚合查询构造 ----------

// exceptionsGroupBy 异常指纹公共聚合体（list 与 count 共用，保证口径一致）。
// 两级聚合：内层按物化视图排序键合并聚合状态（countMerge/anyMerge），外层按
// （类型+指纹）汇总并收集去重服务/示例 trace。
func exceptionsGroupBy(f ExceptionsFilter) (string, []any) {
	where := []string{"Minute >= ?", "Minute < ?"}
	args := []any{f.Start, f.End}
	if f.Service != "" {
		where = append(where, "ServiceName = ?")
		args = append(args, f.Service)
	}
	return `SELECT ExceptionType, Fingerprint,
  sum(cnt) AS count,
  min(minute) AS first_seen_at,
  max(minute) AS last_seen_at,
  groupUniqArray(` + strconv.Itoa(exceptionServicesCap) + `)(svc) AS affected_services,
  groupUniqArray(` + strconv.Itoa(exceptionSampleTraceCap) + `)(example) AS sample_trace_ids
FROM (
  SELECT Minute AS minute, ServiceName AS svc, ExceptionType, Fingerprint,
    countMerge(SampleCount) AS cnt,
    anyMerge(ExampleTraceId) AS example
  FROM apm.apm_exception_fingerprints
  WHERE ` + strings.Join(where, " AND ") + `
  GROUP BY Minute, ServiceName, ExceptionType, Fingerprint
)
GROUP BY ExceptionType, Fingerprint`, args
}

// buildExceptionsListQuery 异常指纹列表（按事件数倒序分页，LIMIT/OFFSET 强制）。
func buildExceptionsListQuery(f ExceptionsFilter) (string, []any) {
	body, args := exceptionsGroupBy(f)
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	return body + `
ORDER BY count DESC, Fingerprint ASC
LIMIT ? OFFSET ?`, args
}

// buildExceptionsCountQuery 异常指纹总数（子查询计数，与列表同口径）。
func buildExceptionsCountQuery(f ExceptionsFilter) (string, []any) {
	body, args := exceptionsGroupBy(f)
	return "SELECT count() FROM (\n" + body + "\n)", args
}

// ---------- 异常 trace 级定位查询构造（P1-01 A2） ----------

// exceptionsTraceWhere trace 级异常定位的 WHERE 片段与参数
// （单 trace 精确 + exception 事件 + 强制时间窗；service 过滤下推到该 trace 的 span）。
func exceptionsTraceWhere(f ExceptionsFilter) (string, []any) {
	where := []string{"TraceId = ?", "Events.Name = 'exception'", "Timestamp >= ?", "Timestamp < ?"}
	args := []any{f.TraceID, f.Start, f.End}
	if f.Service != "" {
		where = append(where, "ServiceName = ?")
		args = append(args, f.Service)
	}
	return strings.Join(where, " AND "), args
}

// buildExceptionsTraceListQuery trace 级异常定位：该 trace 的 exception 事件逐条返回
// （精确语义：事件即该 trace span 实际携带的异常；指纹与聚合表同式——
// hex(MD5(stacktrace 原文))，可与窗口聚合行对照）。
// message/stacktrace 原文经掩码+截断后在 Go 侧处理（见 scanExceptionTraceItem），
// SQL 侧仍取出原文——传输面为进程内，接口面只出处理后纯文本。
func buildExceptionsTraceListQuery(f ExceptionsFilter) (string, []any) {
	w, args := exceptionsTraceWhere(f)
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	return `SELECT TraceId, SpanId, ServiceName,
  Events.Timestamp AS event_ts,
  Events.Attributes['exception.type'] AS exception_type,
  Events.Attributes['exception.message'] AS exception_message,
  Events.Attributes['exception.stacktrace'] AS exception_stacktrace,
  hex(MD5(Events.Attributes['exception.stacktrace'])) AS fingerprint
FROM apm.otel_traces
ARRAY JOIN Events
WHERE ` + w + `
ORDER BY event_ts ASC, SpanId ASC
LIMIT ? OFFSET ?`, args
}

// buildExceptionsTraceCountQuery trace 级异常事件总数（与列表同过滤口径）。
func buildExceptionsTraceCountQuery(f ExceptionsFilter) (string, []any) {
	w, args := exceptionsTraceWhere(f)
	return `SELECT count()
FROM apm.otel_traces
ARRAY JOIN Events
WHERE ` + w, args
}

// ---------- 服务依赖查询构造 ----------

// buildDependenciesQuery 依赖边派生（otel_traces CLIENT/PRODUCER span 单视角）。
// target/target_type 由属性优先级链推导（db > messaging > peer.service > server.address）；
// 无任何对端属性的 span 无法成边（HAVING 剔除）。LIMIT 取上限+1 用于截断探测。
func buildDependenciesQuery(f DependenciesFilter) (string, []any) {
	where := []string{
		"SpanKind IN ('Client', 'Producer')",
		"Timestamp >= ?", "Timestamp < ?",
	}
	args := []any{f.Start, f.End}
	if f.Service != "" {
		where = append(where, "ServiceName = ?")
		args = append(args, f.Service)
	}
	args = append(args, maxDependencyEdges+1)
	return `SELECT
  ServiceName AS source,
  multiIf(
    SpanAttributes['db.system'] != '',
      SpanAttributes['db.system'] || if(SpanAttributes['db.namespace'] != '', '/' || SpanAttributes['db.namespace'], ''),
    SpanAttributes['messaging.system'] != '',
      SpanAttributes['messaging.system'] || if(SpanAttributes['messaging.destination.name'] != '', '/' || SpanAttributes['messaging.destination.name'], ''),
    SpanAttributes['peer.service'] != '', SpanAttributes['peer.service'],
    SpanAttributes['server.address'] != '', SpanAttributes['server.address'],
    ''
  ) AS target,
  multiIf(
    SpanAttributes['db.system'] != '', 'db',
    SpanAttributes['messaging.system'] != '', 'messaging',
    SpanAttributes['peer.service'] != '', 'service',
    'external'
  ) AS target_type,
  count() AS calls,
  countIf(StatusCode = 'Error') / toFloat64(count()) AS error_rate,
  avg(Duration) / 1000000.0 AS avg_ms
FROM apm.otel_traces
WHERE ` + strings.Join(where, " AND ") + `
GROUP BY source, target, target_type
HAVING target != ''
ORDER BY calls DESC, source ASC, target ASC
LIMIT ?`, args
}

// ---------- 行映射 ----------

// scanSQLRow SQL 指纹行扫描（UInt64 → int64；耗时已是毫秒浮点，统一 3 位小数）。
func scanSQLRow(rows CHRows) (*SQLRow, error) {
	var it SQLRow
	var calls, errorCount uint64
	if err := rows.Scan(&it.DBSystem, &it.SQLFingerprint, &it.Namespace, &it.Operation,
		&calls, &errorCount, &it.AvgMS, &it.P95MS, &it.SampleTraceIDs); err != nil {
		return nil, err
	}
	it.Calls, it.ErrorCount = int64(calls), int64(errorCount)
	it.AvgMS, it.P95MS = roundMS(it.AvgMS), roundMS(it.P95MS)
	if it.SampleTraceIDs == nil {
		it.SampleTraceIDs = []string{}
	}
	return &it, nil
}

// scanExceptionRow 异常指纹行扫描。
func scanExceptionRow(rows CHRows) (*ExceptionRow, error) {
	var it ExceptionRow
	var count uint64
	if err := rows.Scan(&it.ExceptionType, &it.Fingerprint, &count,
		&it.FirstSeenAt, &it.LastSeenAt, &it.AffectedServices, &it.SampleTraceIDs); err != nil {
		return nil, err
	}
	it.Count = int64(count)
	if it.AffectedServices == nil {
		it.AffectedServices = []string{}
	}
	if it.SampleTraceIDs == nil {
		it.SampleTraceIDs = []string{}
	}
	return &it, nil
}

// scanExceptionTraceItem trace 级异常事件行扫描（P1-01 A2）：message/stacktrace
// 出接口前凭据形态掩码 + rune 上限截断（纯文本，截断标记如实返回）。
func scanExceptionTraceItem(rows CHRows) (*ExceptionTraceItem, error) {
	var it ExceptionTraceItem
	var message, stack string
	if err := rows.Scan(&it.TraceID, &it.SpanID, &it.ServiceName, &it.OccurredAt,
		&it.ExceptionType, &message, &stack, &it.Fingerprint); err != nil {
		return nil, err
	}
	it.OccurredAt = it.OccurredAt.UTC()
	it.ExceptionMessage, it.MessageTruncated = capRunes(maskExceptionText(message), exceptionMessageMaxRunes)
	it.Stacktrace, it.StacktraceTruncated = capRunes(maskExceptionText(stack), exceptionStacktraceMaxRunes)
	return &it, nil
}

// scanDependencyEdge 依赖边行扫描（错误率/耗时统一 3 位小数）。
func scanDependencyEdge(rows CHRows) (*DependencyEdge, error) {
	var e DependencyEdge
	var calls uint64
	if err := rows.Scan(&e.Source, &e.Target, &e.TargetType, &calls, &e.ErrorRate, &e.AvgMS); err != nil {
		return nil, err
	}
	e.Calls = int64(calls)
	e.ErrorRate, e.AvgMS = roundMS(e.ErrorRate), roundMS(e.AvgMS)
	return &e, nil
}

// ---------- Store 的 CH 侧查询（降级纪律同 SearchTraces） ----------

const chDegradedMessage = "ClickHouse 数据面暂不可用，已降级为空结果（agentless 数据不受影响）"

// matchNote 匹配语义说明（P1-01 A2：无法精确关联时明确标注候选语义）。
const (
	// matchNoteWindowAggregate 窗口聚合模式：行与特定请求无精确关系（不将全时间窗
	// SQL 排名标为"该请求慢 SQL"——任务书 §4.2）。
	matchNoteWindowAggregate = "窗口级聚合：仅 sample_trace_ids 为示例锚点，不构成特定请求的精确定位（同时间窗候选）"
	// matchNoteTraceExactSQL trace 级精确定位（仅该 trace 的 DB span 派生）。
	matchNoteTraceExactSQL = "trace 级精确定位：仅含该 trace 的 DB Span 派生指纹"
	// matchNoteTraceExactExceptions trace 级精确定位（仅该 trace 的 exception 事件）。
	matchNoteTraceExactExceptions = "trace 级精确定位：仅含该 trace 的 exception 事件（文本已掩码截断）"
)

// degradedSQL CH 未配置/不可用时的降级响应（空页 + agentless + 提示 +
// availability UNAVAILABLE，不 500）。P1-01 A2：match 语义字段在降级时同样回显。
func (s *Store) degradedSQL(ctx context.Context, f SQLFilter, message string, status chQueryStatus) *SQLData {
	out := &SQLData{
		List: []SQLRow{}, Total: 0, Page: f.Page, PageSize: f.PageSize,
		DataSource: dataSourceAgentless, Message: message,
		TraceID: f.TraceID,
	}
	if f.TraceID != "" {
		out.MatchMode, out.MatchNote = matchModeTraceExact, matchNoteTraceExactSQL
	} else {
		out.MatchMode, out.MatchNote = matchModeWindowAggregate, matchNoteWindowAggregate
	}
	out.Availability = s.chAvailability(ctx, status, false, f.Start, f.End, f.IngestLagThreshold)
	return out
}

// ListSQLFingerprints SQL 指纹聚合列表（CH 数据面；未配置/故障降级为空页不报错）。
// P1-01 A2：trace_id 非空时切换 trace 级精确定位（仅从该 trace 的 DB span 派生指纹，
// match_mode=trace_exact）；窗口聚合模式 match_mode=window_aggregate（候选语义，
// 不标为特定请求的慢 SQL）。
func (s *Store) ListSQLFingerprints(ctx context.Context, f SQLFilter) (*SQLData, error) {
	ch := s.conn(ctx)
	if ch == nil {
		return s.degradedSQL(ctx, f, "APM_CLICKHOUSE_DSN 未配置：OTel 数据面未接入，SQL 指纹聚合不可用", chQueryNotConfigured), nil
	}
	countSQL, countArgs := buildSQLCountQuery(f)
	listSQLBuilder := buildSQLListQuery
	if f.TraceID != "" {
		countSQL, countArgs = buildSQLTraceCountQuery(f)
		listSQLBuilder = buildSQLTraceListQuery
	}
	var total uint64
	countRows, err := ch.Query(withCHSettings(ctx), countSQL, countArgs...)
	if err != nil {
		slogWarnCH("sql-fingerprints count", err)
		return s.degradedSQL(ctx, f, chDegradedMessage, chQueryFailed), nil
	}
	if countRows.Next() {
		if err := countRows.Scan(&total); err != nil {
			countRows.Close()
			slogWarnCH("sql-fingerprints count scan", err)
			return s.degradedSQL(ctx, f, chDegradedMessage, chQueryFailed), nil
		}
	}
	if err := countRows.Err(); err != nil {
		countRows.Close()
		slogWarnCH("sql-fingerprints count iterate", err)
		return s.degradedSQL(ctx, f, chDegradedMessage, chQueryFailed), nil
	}
	countRows.Close()

	out := &SQLData{
		List: []SQLRow{}, Total: int64(total), Page: f.Page, PageSize: f.PageSize,
		DataSource: dataSourceOTel, TraceID: f.TraceID,
	}
	if f.TraceID != "" {
		out.MatchMode, out.MatchNote = matchModeTraceExact, matchNoteTraceExactSQL
	} else {
		out.MatchMode, out.MatchNote = matchModeWindowAggregate, matchNoteWindowAggregate
	}
	if total == 0 {
		out.Availability = s.chAvailability(ctx, chQueryOK, false, f.Start, f.End, f.IngestLagThreshold)
		return out, nil
	}

	listSQL, listArgs := listSQLBuilder(f)
	rows, err := ch.Query(withCHSettings(ctx), listSQL, listArgs...)
	if err != nil {
		slogWarnCH("sql-fingerprints list", err)
		return s.degradedSQL(ctx, f, chDegradedMessage, chQueryFailed), nil
	}
	defer rows.Close()
	for rows.Next() {
		it, err := scanSQLRow(rows)
		if err != nil {
			slogWarnCH("sql-fingerprints list scan", err)
			return s.degradedSQL(ctx, f, chDegradedMessage, chQueryFailed), nil
		}
		out.List = append(out.List, *it)
	}
	if err := rows.Err(); err != nil {
		slogWarnCH("sql-fingerprints list iterate", err)
		return s.degradedSQL(ctx, f, chDegradedMessage, chQueryFailed), nil
	}
	out.Availability = s.chAvailability(ctx, chQueryOK, true, f.Start, f.End, f.IngestLagThreshold)
	return out, nil
}

// degradedExceptions CH 未配置/不可用时的降级响应。
func (s *Store) degradedExceptions(ctx context.Context, f ExceptionsFilter, message string, status chQueryStatus) *ExceptionsData {
	out := &ExceptionsData{
		List: []ExceptionRow{}, Total: 0, Page: f.Page, PageSize: f.PageSize,
		DataSource: dataSourceAgentless, Message: message,
		TraceID: f.TraceID, TraceExceptions: []ExceptionTraceItem{},
	}
	if f.TraceID != "" {
		out.MatchMode, out.MatchNote = matchModeTraceExact, matchNoteTraceExactExceptions
	} else {
		out.MatchMode, out.MatchNote = matchModeWindowAggregate, matchNoteWindowAggregate
	}
	out.Availability = s.chAvailability(ctx, status, false, f.Start, f.End, f.IngestLagThreshold)
	return out
}

// ListExceptions 异常指纹聚合列表（CH 数据面；未配置/故障降级为空页不报错）。
// P1-01 A2：trace_id 非空时切换 trace 级精确定位（直读该 trace 的 exception 事件，
// 结果在 trace_exceptions，list 为空数组；message/stacktrace 掩码+截断纯文本）。
func (s *Store) ListExceptions(ctx context.Context, f ExceptionsFilter) (*ExceptionsData, error) {
	ch := s.conn(ctx)
	if ch == nil {
		return s.degradedExceptions(ctx, f, "APM_CLICKHOUSE_DSN 未配置：OTel 数据面未接入，异常指纹聚合不可用", chQueryNotConfigured), nil
	}

	countSQL, countArgs := buildExceptionsCountQuery(f)
	if f.TraceID != "" {
		countSQL, countArgs = buildExceptionsTraceCountQuery(f)
	}
	var total uint64
	countRows, err := ch.Query(withCHSettings(ctx), countSQL, countArgs...)
	if err != nil {
		slogWarnCH("exceptions count", err)
		return s.degradedExceptions(ctx, f, chDegradedMessage, chQueryFailed), nil
	}
	if countRows.Next() {
		if err := countRows.Scan(&total); err != nil {
			countRows.Close()
			slogWarnCH("exceptions count scan", err)
			return s.degradedExceptions(ctx, f, chDegradedMessage, chQueryFailed), nil
		}
	}
	if err := countRows.Err(); err != nil {
		countRows.Close()
		slogWarnCH("exceptions count iterate", err)
		return s.degradedExceptions(ctx, f, chDegradedMessage, chQueryFailed), nil
	}
	countRows.Close()

	out := &ExceptionsData{
		List: []ExceptionRow{}, Total: int64(total), Page: f.Page, PageSize: f.PageSize,
		DataSource: dataSourceOTel, TraceID: f.TraceID, TraceExceptions: []ExceptionTraceItem{},
	}
	if f.TraceID != "" {
		out.MatchMode, out.MatchNote = matchModeTraceExact, matchNoteTraceExactExceptions
	} else {
		out.MatchMode, out.MatchNote = matchModeWindowAggregate, matchNoteWindowAggregate
	}
	if total == 0 {
		out.Availability = s.chAvailability(ctx, chQueryOK, false, f.Start, f.End, f.IngestLagThreshold)
		return out, nil
	}

	if f.TraceID != "" {
		// trace 级定位：直读 exception 事件（掩码+截断在 scanExceptionTraceItem）
		listSQL, listArgs := buildExceptionsTraceListQuery(f)
		rows, err := ch.Query(withCHSettings(ctx), listSQL, listArgs...)
		if err != nil {
			slogWarnCH("exceptions trace list", err)
			return s.degradedExceptions(ctx, f, chDegradedMessage, chQueryFailed), nil
		}
		defer rows.Close()
		for rows.Next() {
			it, err := scanExceptionTraceItem(rows)
			if err != nil {
				slogWarnCH("exceptions trace list scan", err)
				return s.degradedExceptions(ctx, f, chDegradedMessage, chQueryFailed), nil
			}
			out.TraceExceptions = append(out.TraceExceptions, *it)
		}
		if err := rows.Err(); err != nil {
			slogWarnCH("exceptions trace list iterate", err)
			return s.degradedExceptions(ctx, f, chDegradedMessage, chQueryFailed), nil
		}
		out.Availability = s.chAvailability(ctx, chQueryOK, true, f.Start, f.End, f.IngestLagThreshold)
		return out, nil
	}

	listSQL, listArgs := buildExceptionsListQuery(f)
	rows, err := ch.Query(withCHSettings(ctx), listSQL, listArgs...)
	if err != nil {
		slogWarnCH("exceptions list", err)
		return s.degradedExceptions(ctx, f, chDegradedMessage, chQueryFailed), nil
	}
	defer rows.Close()
	for rows.Next() {
		it, err := scanExceptionRow(rows)
		if err != nil {
			slogWarnCH("exceptions list scan", err)
			return s.degradedExceptions(ctx, f, chDegradedMessage, chQueryFailed), nil
		}
		out.List = append(out.List, *it)
	}
	if err := rows.Err(); err != nil {
		slogWarnCH("exceptions list iterate", err)
		return s.degradedExceptions(ctx, f, chDegradedMessage, chQueryFailed), nil
	}
	out.Availability = s.chAvailability(ctx, chQueryOK, true, f.Start, f.End, f.IngestLagThreshold)
	return out, nil
}

// ListDependencies 服务依赖边列表（CH 数据面客户端 span 单视角派生；
// 未配置/故障降级为空边列表不报错；返回边数达上限时 note 追加截断提示）。
func (s *Store) ListDependencies(ctx context.Context, f DependenciesFilter) (*DependenciesData, error) {
	ch := s.conn(ctx)
	if ch == nil {
		return &DependenciesData{
			Edges: []DependencyEdge{}, DataSource: dataSourceAgentless,
			Note: "APM_CLICKHOUSE_DSN 未配置：OTel 数据面未接入，服务依赖拓扑不可用",
		}, nil
	}
	sql, args := buildDependenciesQuery(f)
	rows, err := ch.Query(withCHSettings(ctx), sql, args...)
	if err != nil {
		slogWarnCH("dependencies", err)
		return &DependenciesData{
			Edges: []DependencyEdge{}, DataSource: dataSourceAgentless, Note: chDegradedMessage,
		}, nil
	}
	defer rows.Close()
	edges := []DependencyEdge{}
	truncated := false
	for rows.Next() {
		if len(edges) >= maxDependencyEdges {
			// 第 maxDependencyEdges+1 行仅作截断探测，不再扫描下放
			truncated = true
			break
		}
		e, err := scanDependencyEdge(rows)
		if err != nil {
			slogWarnCH("dependencies scan", err)
			return &DependenciesData{
				Edges: []DependencyEdge{}, DataSource: dataSourceAgentless, Note: chDegradedMessage,
			}, nil
		}
		edges = append(edges, *e)
	}
	if err := rows.Err(); err != nil {
		slogWarnCH("dependencies iterate", err)
		return &DependenciesData{
			Edges: []DependencyEdge{}, DataSource: dataSourceAgentless, Note: chDegradedMessage,
		}, nil
	}
	note := dependenciesDerivedNote
	if truncated {
		note += "；结果已达单页上限 " + strconv.Itoa(maxDependencyEdges) + " 条，请缩小时间窗或按 service 过滤"
	}
	return &DependenciesData{Edges: edges, DataSource: dataSourceOTel, Note: note}, nil
}
