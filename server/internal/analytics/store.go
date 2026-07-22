// store.go 统计分析查询仓储：聚合表读 + 业务表实时分布/排行。
package analytics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/aggregations"
	"github.com/jiuzhang-waf/server/internal/metrics"
)

// Store 统计分析仓储。
type Store struct {
	db  *pgxpool.Pool
	agg *aggregations.Store
}

// NewStore 创建统计仓储。
func NewStore(db *pgxpool.Pool, agg *aggregations.Store) *Store {
	return &Store{db: db, agg: agg}
}

// ErrApplicationNotFound 应用不存在（或已删除）。
var ErrApplicationNotFound = errors.New("应用不存在")

// TrendData 通用时间序列响应（times 与每个 series 数组等长对齐）。
type TrendData struct {
	Start       time.Time            `json:"start"`
	End         time.Time            `json:"end"`
	Granularity string               `json:"granularity"`
	Times       []time.Time          `json:"times"`
	Series      map[string][]float64 `json:"series"`
}

// CountPoint 计数趋势点。
type CountPoint struct {
	Time  time.Time `json:"time"`
	Count int64     `json:"count"`
}

// SourceIPStat 源 IP 排行项。
type SourceIPStat struct {
	IP     string `json:"ip"`
	Events int64  `json:"events"`
	Blocks int64  `json:"blocks"`
}

// AppStat 应用排行项。
type AppStat struct {
	Code   string  `json:"code"`
	Name   string  `json:"name"`
	Events float64 `json:"events"`
}

// RuleStat 规则命中排行项。
type RuleStat struct {
	RuleID         int   `json:"rule_id"`
	Hits           int64 `json:"hits"`
	FalsePositives int64 `json:"false_positives"`
}

// URIStat URI 排行项。
type URIStat struct {
	Path   string `json:"path"`
	Events int64  `json:"events"`
	Blocks int64  `json:"blocks"`
}

// CCOverviewData CC 防护统计总览。
type CCOverviewData struct {
	Start               time.Time    `json:"start"`
	End                 time.Time    `json:"end"`
	ThresholdExceeded   int64        `json:"threshold_exceeded"`
	RequestsRejected    int64        `json:"requests_rejected"`
	TempBlocksCreated   int64        `json:"temp_blocks_created"`
	TempBlocksExpired   int64        `json:"temp_blocks_expired"`
	TempBlocksReleased  int64        `json:"temp_blocks_released"`
	IPAllowMatches      int64        `json:"ip_allow_matches"`
	IPDenyMatches       int64        `json:"ip_deny_matches"`
	GlobalRuleEvents    int64        `json:"global_rule_events"`
	AppRuleEvents       int64        `json:"app_rule_events"`
	InvalidProxyHeaders int64        `json:"invalid_proxy_headers"`
	EngineErrors        int64        `json:"engine_errors"`
	TempBlockTrend      []CountPoint `json:"temp_block_trend"`
}

// RuleHitStat 访问控制规则命中排行项。
type RuleHitStat struct {
	RuleID    string `json:"rule_id"`
	EventType string `json:"event_type"`
	Hits      int64  `json:"hits"`
}

// RuleStatusStat 访问控制规则启停统计项。
type RuleStatusStat struct {
	RuleType string `json:"rule_type"`
	Status   string `json:"status"`
	Count    int64  `json:"count"`
}

// ACOverviewData 访问控制统计总览。
type ACOverviewData struct {
	Start            time.Time        `json:"start"`
	End              time.Time        `json:"end"`
	AllowMatches     int64            `json:"allow_matches"`
	DenyMatches      int64            `json:"deny_matches"`
	RuleHits         []RuleHitStat    `json:"rule_hits"`
	RuleStatus       []RuleStatusStat `json:"rule_status"`
	ActiveTempBlocks int64            `json:"active_temp_blocks"`
	TempBlockTrend   []CountPoint     `json:"temp_block_trend"`
}

// StatusCount 处置状态分布项。
type StatusCount struct {
	Status string `json:"status"`
	Count  int64  `json:"count"`
}

// HandlerStat 处置人统计项。
type HandlerStat struct {
	Username string `json:"username"`
	Count    int64  `json:"count"`
}

// DispositionData 事件处置统计总览。
type DispositionData struct {
	Start                 time.Time     `json:"start"`
	End                   time.Time     `json:"end"`
	StatusDistribution    []StatusCount `json:"status_distribution"`
	AvgDispositionSeconds float64       `json:"avg_disposition_seconds"`
	Handlers              []HandlerStat `json:"handlers"`
}

// ResolveAppCode 解析应用 ID → code（聚合标签用 code 维度）。
func (s *Store) ResolveAppCode(ctx context.Context, id uuid.UUID) (string, error) {
	var code string
	err := s.db.QueryRow(ctx,
		`SELECT code FROM applications WHERE id = $1 AND deleted_at IS NULL`, id).Scan(&code)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrApplicationNotFound
	}
	if err != nil {
		return "", err
	}
	return code, nil
}

// ---------- 内部通用查询 ----------

// labelTotals 单指标按标签键汇总（无应用过滤时走聚合 store 的 TopLabels）。
func (s *Store) labelTotals(ctx context.Context, r Range, metric, labelKey, appCode string, limit int) ([]KV, error) {
	if appCode == "" {
		rows, err := s.agg.TopLabels(ctx, r.Table(), metric, labelKey, r.Start, r.End, limit)
		if err != nil {
			return nil, err
		}
		out := make([]KV, 0, len(rows))
		for _, row := range rows {
			out = append(out, KV{Key: row.Key, Value: row.Value})
		}
		return out, nil
	}
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	query := fmt.Sprintf(`
SELECT labels->>$4 AS k, SUM(value) AS v FROM %s
WHERE metric = $1 AND bucket_start >= $2 AND bucket_start < $3 AND labels->>'app' = $5
GROUP BY k ORDER BY v DESC LIMIT $6`, r.Table())
	rows, err := s.db.Query(ctx, query, metric, r.Start, r.End, labelKey, appCode, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []KV
	for rows.Next() {
		var k *string
		var v float64
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		if k != nil {
			out = append(out, KV{Key: *k, Value: v})
		}
	}
	return out, rows.Err()
}

// bucketSeries 单指标按桶 + 标签键的散点（pivotSeries 的输入）。
func (s *Store) bucketSeries(ctx context.Context, r Range, metric, labelKey, appCode string) ([]seriesPoint, error) {
	where := "metric = $1 AND bucket_start >= $2 AND bucket_start < $3"
	args := []interface{}{metric, r.Start, r.End}
	if appCode != "" {
		where += fmt.Sprintf(" AND labels->>'app' = $%d", len(args)+2)
		args = append(args, labelKey, appCode)
	} else {
		args = append(args, labelKey)
	}
	query := fmt.Sprintf(`
SELECT bucket_start, labels->>$4 AS k, SUM(value) FROM %s
WHERE %s GROUP BY 1, 2 ORDER BY 1`, r.Table(), where)
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []seriesPoint
	for rows.Next() {
		var t time.Time
		var k *string
		var v float64
		if err := rows.Scan(&t, &k, &v); err != nil {
			return nil, err
		}
		key := ""
		if k != nil {
			key = *k
		}
		out = append(out, seriesPoint{t: t, key: key, v: v})
	}
	return out, rows.Err()
}

// ---------- 请求趋势 ----------

// RequestTrend 请求量 + 状态分类 + P50/P95/P99 序列。
// series 键：requests / status_2xx / status_4xx / status_5xx / p50_ms / p95_ms / p99_ms。
func (s *Store) RequestTrend(ctx context.Context, r Range, appCode string) (*TrendData, error) {
	points, err := s.bucketSeries(ctx, r, metrics.HTTPRequestsTotal, "status_class", appCode)
	if err != nil {
		return nil, err
	}
	times, _, series := pivotSeries(points)
	out := &TrendData{
		Start: r.Start, End: r.End, Granularity: r.Granularity(),
		Times:  times,
		Series: map[string][]float64{},
	}
	sum := make([]float64, len(times))
	for key, vals := range series {
		out.Series["status_"+key] = vals
		for i, v := range vals {
			sum[i] += v
		}
	}
	out.Series["requests"] = sum

	// 分位数：合并每桶直方图后估算。
	p50, p95, p99, err := s.percentileSeries(ctx, r, appCode, times)
	if err != nil {
		return nil, err
	}
	out.Series["p50_ms"] = p50
	out.Series["p95_ms"] = p95
	out.Series["p99_ms"] = p99
	return out, nil
}

// percentileSeries 按 times 对齐的 P50/P95/P99（毫秒）。
func (s *Store) percentileSeries(ctx context.Context, r Range, appCode string, times []time.Time) ([]float64, []float64, []float64, error) {
	where := "metric = $1 AND bucket_start >= $2 AND bucket_start < $3"
	args := []interface{}{metrics.HTTPRequestDurationMs, r.Start, r.End}
	if appCode != "" {
		where += fmt.Sprintf(" AND labels->>'app' = $%d", len(args)+1)
		args = append(args, appCode)
	}
	query := fmt.Sprintf(`SELECT bucket_start, extra->'buckets' FROM %s WHERE %s`, r.Table(), where)
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, nil, nil, err
	}
	defer rows.Close()
	merged := map[time.Time][]int{}
	for rows.Next() {
		var t time.Time
		var raw []byte
		if err := rows.Scan(&t, &raw); err != nil {
			return nil, nil, nil, err
		}
		var counts []int
		if len(raw) > 0 && string(raw) != "null" {
			if err := json.Unmarshal(raw, &counts); err != nil {
				return nil, nil, nil, fmt.Errorf("duration buckets decode: %w", err)
			}
		}
		merged[t] = MergeCounts(merged[t], counts)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, nil, err
	}
	p50 := make([]float64, len(times))
	p95 := make([]float64, len(times))
	p99 := make([]float64, len(times))
	for i, t := range times {
		counts := normalizeCounts(merged[t])
		p50[i] = metrics.PercentileFromBuckets(counts, 0.50)
		p95[i] = metrics.PercentileFromBuckets(counts, 0.95)
		p99[i] = metrics.PercentileFromBuckets(counts, 0.99)
	}
	return p50, p95, p99, nil
}

// ---------- 安全事件趋势 ----------

// SecurityEventTrend WAF 事件/阻断/观察序列。
// series 键：events / blocks / observes。
func (s *Store) SecurityEventTrend(ctx context.Context, r Range, appCode string) (*TrendData, error) {
	where := "metric IN ($1, $2, $3) AND bucket_start >= $4 AND bucket_start < $5"
	args := []interface{}{metrics.WAFEventsTotal, metrics.WAFBlocksTotal, metrics.WAFObserveTotal, r.Start, r.End}
	if appCode != "" {
		where += fmt.Sprintf(" AND labels->>'app' = $%d", len(args)+1)
		args = append(args, appCode)
	}
	query := fmt.Sprintf(`SELECT bucket_start, metric, SUM(value) FROM %s WHERE %s GROUP BY 1, 2 ORDER BY 1`, r.Table(), where)
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keyOf := map[string]string{
		metrics.WAFEventsTotal:  "events",
		metrics.WAFBlocksTotal:  "blocks",
		metrics.WAFObserveTotal: "observes",
	}
	var points []seriesPoint
	for rows.Next() {
		var t time.Time
		var m string
		var v float64
		if err := rows.Scan(&t, &m, &v); err != nil {
			return nil, err
		}
		points = append(points, seriesPoint{t: t, key: keyOf[m], v: v})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	times, _, series := pivotSeries(points)
	return &TrendData{
		Start: r.Start, End: r.End, Granularity: r.Granularity(),
		Times:  times,
		Series: series,
	}, nil
}

// ---------- 分布与排行 ----------

// RiskLevels 风险等级分布（severity 降序排行）。
func (s *Store) RiskLevels(ctx context.Context, r Range, appCode string) ([]KV, error) {
	return s.labelTotals(ctx, r, metrics.WAFEventsTotal, "severity", appCode, 20)
}

// AttackTypes 攻击类型分布。
func (s *Store) AttackTypes(ctx context.Context, r Range, appCode string) ([]KV, error) {
	return s.labelTotals(ctx, r, metrics.WAFEventsTotal, "attack_type", appCode, 50)
}

// TopSourceIPs 攻击源 IP 排行（直接查事件表；IP 不是受控聚合标签）。
func (s *Store) TopSourceIPs(ctx context.Context, r Range, appID *uuid.UUID, limit int) ([]SourceIPStat, error) {
	if limit <= 0 || limit > 100 {
		limit = 10
	}
	where := "occurred_at >= $1 AND occurred_at < $2 AND client_ip IS NOT NULL"
	args := []interface{}{r.Start, r.End}
	if appID != nil {
		where += fmt.Sprintf(" AND application_id = $%d", len(args)+1)
		args = append(args, *appID)
	}
	args = append(args, limit)
	query := fmt.Sprintf(`
SELECT host(client_ip) AS ip, count(*) AS events, count(*) FILTER (WHERE action = 'BLOCK') AS blocks
FROM security_events WHERE %s
GROUP BY ip ORDER BY events DESC, ip LIMIT $%d`, where, len(args))
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SourceIPStat{}
	for rows.Next() {
		var it SourceIPStat
		if err := rows.Scan(&it.IP, &it.Events, &it.Blocks); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// TopApplications 应用事件排行（聚合表 app 标签 + 应用名补充）。
func (s *Store) TopApplications(ctx context.Context, r Range, limit int) ([]AppStat, error) {
	kvs, err := s.labelTotals(ctx, r, metrics.WAFEventsTotal, "app", "", limit)
	if err != nil {
		return nil, err
	}
	out := make([]AppStat, 0, len(kvs))
	codes := make([]string, 0, len(kvs))
	for _, kv := range kvs {
		out = append(out, AppStat{Code: kv.Key, Events: kv.Value})
		codes = append(codes, kv.Key)
	}
	if len(codes) == 0 {
		return out, nil
	}
	rows, err := s.db.Query(ctx,
		`SELECT code, name FROM applications WHERE code = ANY($1) AND deleted_at IS NULL`, codes)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	names := map[string]string{}
	for rows.Next() {
		var code, name string
		if err := rows.Scan(&code, &name); err != nil {
			return nil, err
		}
		names[code] = name
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Name = names[out[i].Code]
	}
	return out, nil
}

// TopRules 规则命中排行（含误报数）。
func (s *Store) TopRules(ctx context.Context, r Range, appID *uuid.UUID, limit int) ([]RuleStat, error) {
	if limit <= 0 || limit > 100 {
		limit = 10
	}
	// 命中数：聚合表 waf_rule_hits_total（policy 标签 = 规则ID）。
	rows, err := s.agg.TopLabels(ctx, r.Table(), "waf_rule_hits_total", "policy", r.Start, r.End, limit)
	if err != nil {
		return nil, err
	}
	out := make([]RuleStat, 0, len(rows))
	for _, row := range rows {
		rid, err := strconv.Atoi(row.Key)
		if err != nil {
			continue
		}
		out = append(out, RuleStat{RuleID: rid, Hits: int64(row.Value)})
	}
	// 误报数：确认为误报的事件其规则匹配明细。
	if len(out) > 0 {
		ids := make([]int, 0, len(out))
		for _, it := range out {
			ids = append(ids, it.RuleID)
		}
		where := `e.occurred_at >= $1 AND e.occurred_at < $2
  AND e.disposition_status = 'CONFIRMED_FALSE_POSITIVE' AND m.rule_id = ANY($3)`
		args := []interface{}{r.Start, r.End, ids}
		if appID != nil {
			where += fmt.Sprintf(" AND e.application_id = $%d", len(args)+1)
			args = append(args, *appID)
		}
		fpRows, err := s.db.Query(ctx, fmt.Sprintf(`
SELECT m.rule_id, count(*) FROM security_event_matches m
JOIN security_events e ON e.id = m.event_id
WHERE %s GROUP BY m.rule_id`, where), args...)
		if err != nil {
			return nil, err
		}
		fp := map[int]int64{}
		for fpRows.Next() {
			var rid int
			var c int64
			if err := fpRows.Scan(&rid, &c); err != nil {
				fpRows.Close()
				return nil, err
			}
			fp[rid] = c
		}
		fpRows.Close()
		if err := fpRows.Err(); err != nil {
			return nil, err
		}
		for i := range out {
			out[i].FalsePositives = fp[out[i].RuleID]
		}
	}
	return out, nil
}

// TopURIs 受攻击 URI 排行（直接查事件表）。
func (s *Store) TopURIs(ctx context.Context, r Range, appID *uuid.UUID, limit int) ([]URIStat, error) {
	if limit <= 0 || limit > 100 {
		limit = 10
	}
	where := "occurred_at >= $1 AND occurred_at < $2 AND request_path <> ''"
	args := []interface{}{r.Start, r.End}
	if appID != nil {
		where += fmt.Sprintf(" AND application_id = $%d", len(args)+1)
		args = append(args, *appID)
	}
	args = append(args, limit)
	query := fmt.Sprintf(`
SELECT request_path, count(*) AS events, count(*) FILTER (WHERE action = 'BLOCK') AS blocks
FROM security_events WHERE %s
GROUP BY request_path ORDER BY events DESC, request_path LIMIT $%d`, where, len(args))
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []URIStat{}
	for rows.Next() {
		var it URIStat
		if err := rows.Scan(&it.Path, &it.Events, &it.Blocks); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// ---------- CC / 访问控制总览 ----------

// tempBlockTrend 临时封禁创建趋势（事件表 date_trunc 分桶）。
func (s *Store) tempBlockTrend(ctx context.Context, r Range, appID *uuid.UUID) ([]CountPoint, error) {
	where := "event_type = 'CC_TEMP_BLOCK_CREATED' AND occurred_at >= $2 AND occurred_at < $3"
	args := []interface{}{r.TrendBucket(), r.Start, r.End}
	if appID != nil {
		where += fmt.Sprintf(" AND application_id = $%d", len(args)+1)
		args = append(args, *appID)
	}
	rows, err := s.db.Query(ctx, fmt.Sprintf(`
SELECT date_trunc($1, occurred_at) AS b, count(*) FROM access_control_events
WHERE %s GROUP BY b ORDER BY b`, where), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CountPoint{}
	for rows.Next() {
		var p CountPoint
		if err := rows.Scan(&p.Time, &p.Count); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// CC 类事件类型（全局/应用分布只统计这些）。
var ccEventTypes = map[string]bool{
	"CC_THRESHOLD_EXCEEDED":  true,
	"CC_REQUEST_REJECTED":    true,
	"CC_TEMP_BLOCK_CREATED":  true,
	"CC_TEMP_BLOCK_EXPIRED":  true,
	"CC_TEMP_BLOCK_RELEASED": true,
}

// CCOverview CC 防护统计。
func (s *Store) CCOverview(ctx context.Context, r Range, appID *uuid.UUID) (*CCOverviewData, error) {
	where := "occurred_at >= $1 AND occurred_at < $2"
	args := []interface{}{r.Start, r.End}
	if appID != nil {
		where += fmt.Sprintf(" AND application_id = $%d", len(args)+1)
		args = append(args, *appID)
	}
	rows, err := s.db.Query(ctx, fmt.Sprintf(`
SELECT event_type, count(*),
  count(*) FILTER (WHERE application_id IS NULL) AS global_n,
  count(*) FILTER (WHERE application_id IS NOT NULL) AS app_n
FROM access_control_events WHERE %s GROUP BY event_type`, where), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := &CCOverviewData{Start: r.Start, End: r.End, TempBlockTrend: []CountPoint{}}
	for rows.Next() {
		var et string
		var n, globalN, appN int64
		if err := rows.Scan(&et, &n, &globalN, &appN); err != nil {
			return nil, err
		}
		switch et {
		case "CC_THRESHOLD_EXCEEDED":
			out.ThresholdExceeded = n
		case "CC_REQUEST_REJECTED":
			out.RequestsRejected = n
		case "CC_TEMP_BLOCK_CREATED":
			out.TempBlocksCreated = n
		case "CC_TEMP_BLOCK_EXPIRED":
			out.TempBlocksExpired = n
		case "CC_TEMP_BLOCK_RELEASED":
			out.TempBlocksReleased = n
		case "IP_ALLOW_MATCH":
			out.IPAllowMatches = n
		case "IP_DENY_MATCH":
			out.IPDenyMatches = n
		case "TRUSTED_PROXY_INVALID", "FORWARDED_HEADER_INVALID", "FORWARDED_CHAIN_TOO_LONG":
			out.InvalidProxyHeaders += n
		case "RATE_LIMIT_ENGINE_ERROR":
			out.EngineErrors = n
		}
		if ccEventTypes[et] {
			out.GlobalRuleEvents += globalN
			out.AppRuleEvents += appN
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	trend, err := s.tempBlockTrend(ctx, r, appID)
	if err != nil {
		return nil, err
	}
	out.TempBlockTrend = trend
	return out, nil
}

// AccessControlOverview 黑白名单/规则/临时封禁统计。
func (s *Store) AccessControlOverview(ctx context.Context, r Range, appID *uuid.UUID) (*ACOverviewData, error) {
	out := &ACOverviewData{
		Start: r.Start, End: r.End,
		RuleHits: []RuleHitStat{}, RuleStatus: []RuleStatusStat{}, TempBlockTrend: []CountPoint{},
	}
	where := "occurred_at >= $1 AND occurred_at < $2 AND event_type IN ('IP_ALLOW_MATCH','IP_DENY_MATCH')"
	args := []interface{}{r.Start, r.End}
	if appID != nil {
		where += fmt.Sprintf(" AND application_id = $%d", len(args)+1)
		args = append(args, *appID)
	}
	// 命中分布
	rows, err := s.db.Query(ctx, fmt.Sprintf(`
SELECT event_type, count(*) FROM access_control_events WHERE %s GROUP BY event_type`, where), args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var et string
		var n int64
		if err := rows.Scan(&et, &n); err != nil {
			rows.Close()
			return nil, err
		}
		if et == "IP_ALLOW_MATCH" {
			out.AllowMatches = n
		} else {
			out.DenyMatches = n
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// 规则命中排行
	hitRows, err := s.db.Query(ctx, fmt.Sprintf(`
SELECT access_rule_id, event_type, count(*) AS hits FROM access_control_events
WHERE %s AND access_rule_id <> '' GROUP BY 1, 2 ORDER BY hits DESC LIMIT 10`, where), args...)
	if err != nil {
		return nil, err
	}
	for hitRows.Next() {
		var it RuleHitStat
		if err := hitRows.Scan(&it.RuleID, &it.EventType, &it.Hits); err != nil {
			hitRows.Close()
			return nil, err
		}
		out.RuleHits = append(out.RuleHits, it)
	}
	hitRows.Close()
	if err := hitRows.Err(); err != nil {
		return nil, err
	}
	// 规则启停统计（配置态，不限时间范围）
	stRows, err := s.db.Query(ctx, `
SELECT rule_type, status, count(*) FROM ip_access_rules
WHERE deleted_at IS NULL GROUP BY 1, 2 ORDER BY 1, 2`)
	if err != nil {
		return nil, err
	}
	for stRows.Next() {
		var it RuleStatusStat
		if err := stRows.Scan(&it.RuleType, &it.Status, &it.Count); err != nil {
			stRows.Close()
			return nil, err
		}
		out.RuleStatus = append(out.RuleStatus, it)
	}
	stRows.Close()
	if err := stRows.Err(); err != nil {
		return nil, err
	}
	// 封禁中数量（实时）
	if err := s.db.QueryRow(ctx, `
SELECT count(*) FROM temporary_blocks WHERE status = 'ACTIVE' AND block_expires_at > now()`).Scan(&out.ActiveTempBlocks); err != nil {
		return nil, err
	}
	// 临时封禁趋势
	trend, err := s.tempBlockTrend(ctx, r, appID)
	if err != nil {
		return nil, err
	}
	out.TempBlockTrend = trend
	return out, nil
}

// ---------- 处置统计 ----------

// DispositionOverview 处置状态分布、平均处置时长、处置人统计。
func (s *Store) DispositionOverview(ctx context.Context, r Range, appID *uuid.UUID) (*DispositionData, error) {
	out := &DispositionData{Start: r.Start, End: r.End, StatusDistribution: []StatusCount{}, Handlers: []HandlerStat{}}
	where := "occurred_at >= $1 AND occurred_at < $2"
	args := []interface{}{r.Start, r.End}
	if appID != nil {
		where += fmt.Sprintf(" AND application_id = $%d", len(args)+1)
		args = append(args, *appID)
	}
	rows, err := s.db.Query(ctx, fmt.Sprintf(`
SELECT disposition_status, count(*) FROM security_events WHERE %s GROUP BY 1 ORDER BY 2 DESC`, where), args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var it StatusCount
		if err := rows.Scan(&it.Status, &it.Count); err != nil {
			rows.Close()
			return nil, err
		}
		out.StatusDistribution = append(out.StatusDistribution, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// 平均处置时长（秒）
	var avg *float64
	if err := s.db.QueryRow(ctx, fmt.Sprintf(`
SELECT AVG(EXTRACT(EPOCH FROM (disposition_at - occurred_at)))
FROM security_events WHERE %s AND disposition_at IS NOT NULL`, where), args...).Scan(&avg); err != nil {
		return nil, err
	}
	if avg != nil {
		out.AvgDispositionSeconds = *avg
	}
	// 处置人统计
	hRows, err := s.db.Query(ctx, fmt.Sprintf(`
SELECT COALESCE(u.username, ''), count(*) FROM security_events e
LEFT JOIN users u ON u.id = e.disposition_user_id
WHERE %s AND e.disposition_user_id IS NOT NULL
GROUP BY 1 ORDER BY 2 DESC LIMIT 20`, where), args...)
	if err != nil {
		return nil, err
	}
	defer hRows.Close()
	for hRows.Next() {
		var it HandlerStat
		if err := hRows.Scan(&it.Username, &it.Count); err != nil {
			return nil, err
		}
		out.Handlers = append(out.Handlers, it)
	}
	return out, hRows.Err()
}
