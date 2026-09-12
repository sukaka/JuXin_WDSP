// store.go APM 查询仓储：聚合表读模型 + access_logs/security_events trace 关联。
// 所有 SQL 参数化；聚合表名仅来自 aggTableFor 的固定枚举，不接受任何外部输入。
package apm

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/aggregations"
	"github.com/jiuzhang-waf/server/internal/metrics"
)

// ErrNotFound 应用不存在（服务详情 404 分支）。
var ErrNotFound = errors.New("application not found")

// minuteTableWindow 分钟表适用窗口上限（≤6h 分钟桶，更长窗口走小时聚合表）。
const minuteTableWindow = 6 * time.Hour

// topN 排行截取长度（overview 各榜单与服务详情 top_endpoints）。
const topN = 5

// traceQueryLimit trace 检索单侧结果上限（trace_id 为 128 位随机精确匹配键，
// 走部分索引；上限防异常数据下放大的结果集）。
const traceQueryLimit = 100

// aggTableFor 按查询窗口选择聚合表（表名为固定枚举，非用户输入）。
func aggTableFor(start, end time.Time) string {
	if end.Sub(start) <= minuteTableWindow {
		return "metric_minute_aggregates"
	}
	return "metric_hour_aggregates"
}

// trendStep 趋势桶粒度（与所选聚合表桶一致）。
func trendStep(table string) time.Duration {
	if table == "metric_minute_aggregates" {
		return time.Minute
	}
	return time.Hour
}

// rate 安全除法（分母为 0 时返回 0）。
func rate(part, total float64) float64 {
	if total <= 0 {
		return 0
	}
	return part / total
}

// latencyFromBuckets 从合并直方图估算 p50/p95/p99。
func latencyFromBuckets(counts []int) Latency {
	return Latency{
		P50: metrics.PercentileFromBuckets(counts, 0.50),
		P95: metrics.PercentileFromBuckets(counts, 0.95),
		P99: metrics.PercentileFromBuckets(counts, 0.99),
	}
}

// splitEndpoint 拆分端点键 "METHOD /path/{id}" → (method, path_template)；
// 保留桶（__OTHER__/__UNCLASSIFIED__）与畸形键返回空 method/path_template，endpoint 原样保留。
func splitEndpoint(endpoint string) (method, pathTemplate string) {
	for i, c := range endpoint {
		if c == ' ' {
			return endpoint[:i], endpoint[i+1:]
		}
	}
	return "", ""
}

// Store APM 查询仓储。ClickHouse 数据面查询器经 resolveCH 逐次解析（生产由
// CHManager 供给，DSN 运行期热更新后新查询自动走重建后的连接；nil = 未配置/
// 不可用，OTel 检索类查询如实降级为空，见 chstore.go）。
// ch 为静态注入（仅单测与既有构造便利）；resolveCH 非 nil 时优先。
// wm* 为采集水位短 TTL 缓存（availability.last_ingested_at/estimated_lag_ms 来源，
// 见 availability.go latestIngest）；nowFunc 为时间源（单测注入，nil=time.Now）。
type Store struct {
	db        *pgxpool.Pool
	ch        CHQuerier
	resolveCH func(ctx context.Context) CHQuerier

	wmMu        sync.Mutex
	wmQuerier   CHQuerier // 缓存读数对应的查询器（DSN 热更新重建后按身份失效）
	wmFetchedAt time.Time
	wmLatest    time.Time
	wmHasData   bool
	wmValid     bool
	nowFunc     func() time.Time
}

// NewStore 创建 APM 查询仓储（resolveCH 为运行期连接解析函数，生产为
// CHManager.ResolveQuerier；解析出 nil 即纯无 Agent 模式）。
func NewStore(db *pgxpool.Pool, resolveCH func(ctx context.Context) CHQuerier) *Store {
	return &Store{db: db, resolveCH: resolveCH}
}

// conn 解析当前 ClickHouse 查询器（resolveCH 优先，回退静态注入的 ch；
// nil = 数据面未接入）。
func (s *Store) conn(ctx context.Context) CHQuerier {
	if s.resolveCH != nil {
		return s.resolveCH(ctx)
	}
	return s.ch
}

// ServicesFilter 服务列表查询条件（Page/PageSize 已由 handler 夹紧；
// AgentOfflineAfter 为 Agent 在线判定阈值，来自 APMConfig.AgentOfflineMinutes 夹紧值）。
type ServicesFilter struct {
	Keyword           string
	Page              int
	PageSize          int
	Start             time.Time
	End               time.Time
	AgentOfflineAfter time.Duration
}

// EndpointsFilter 端点列表查询条件（Sort 已白名单校验；AppCode 为 nil 表示全部应用）。
type EndpointsFilter struct {
	AppCode  *string
	Sort     string // p95 / requests / error_rate
	Page     int
	PageSize int
	Start    time.Time
	End      time.Time
}

// ---------- 内部聚合结构 ----------

// appAgg 单应用窗口聚合（byClass 按 status_class 的请求数；dur 为合并直方图）。
type appAgg struct {
	requests float64
	byClass  map[string]float64
	blocked  float64
	observed float64
	dur      []int
	lastSeen *time.Time
}

func newAppAgg() *appAgg {
	return &appAgg{byClass: map[string]float64{}, dur: make([]int, len(metrics.DurationBucketsMs)+1)}
}

func (a *appAgg) err5xx() float64 { return a.byClass["5xx"] }
func (a *appAgg) err4xx() float64 { return a.byClass["4xx"] }

// endpointAgg 单端点（app × endpoint 跨 status_class/action 合并）窗口聚合。
type endpointAgg struct {
	app      string
	endpoint string
	requests float64
	err5xx   float64
	blocked  float64
	dur      []int
	lastSeen *time.Time
}

// appIdentity 应用标识（聚合标签 app=code 反解 id/name）。
type appIdentity struct {
	ID   uuid.UUID
	Name string
}

// ---------- 通用查询构件 ----------

// appCond 生成可选的应用过滤子句与参数（codes 为空 = 全部应用）。
// 返回追加到 WHERE 的片段（含前导空格）与追加后的参数列表。
func appCond(codes []string, args []interface{}) (string, []interface{}) {
	if len(codes) == 0 {
		return "", args
	}
	return fmt.Sprintf(" AND labels->>'app' = ANY($%d)", len(args)+1), append(args, codes)
}

// loadAppAggs 窗口内按应用聚合请求/错误/阻断/观察/耗时直方图。
// codes 为空聚合全部应用；否则限定给定 code 集合。
func (s *Store) loadAppAggs(ctx context.Context, table string, start, end time.Time, codes []string) (map[string]*appAgg, error) {
	out := map[string]*appAgg{}
	get := func(code string) *appAgg {
		a := out[code]
		if a == nil {
			a = newAppAgg()
			out[code] = a
		}
		return a
	}

	// 请求数（按 app × status_class）+ last_seen
	args := []interface{}{metrics.HTTPRequestsTotal, start, end}
	cond, args := appCond(codes, args)
	rows, err := s.db.Query(ctx, fmt.Sprintf(`
SELECT labels->>'app', labels->>'status_class', SUM(value), MAX(bucket_start)
FROM %s WHERE metric = $1 AND bucket_start >= $2 AND bucket_start < $3%s
GROUP BY 1, 2`, table, cond), args...)
	if err != nil {
		return nil, fmt.Errorf("app requests: %w", err)
	}
	for rows.Next() {
		var code, class string
		var v float64
		var last *time.Time
		if err := rows.Scan(&code, &class, &v, &last); err != nil {
			rows.Close()
			return nil, fmt.Errorf("app requests scan: %w", err)
		}
		a := get(code)
		a.requests += v
		a.byClass[class] += v
		if last != nil && (a.lastSeen == nil || last.After(*a.lastSeen)) {
			a.lastSeen = last
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("app requests iterate: %w", err)
	}

	// 阻断/观察数（waf_blocks_total / waf_observes_total，仅 app 标签）
	args = []interface{}{[]string{metrics.WAFBlocksTotal, metrics.WAFObserveTotal}, start, end}
	cond, args = appCond(codes, args)
	rows, err = s.db.Query(ctx, fmt.Sprintf(`
SELECT metric, labels->>'app', SUM(value)
FROM %s WHERE metric = ANY($1) AND bucket_start >= $2 AND bucket_start < $3%s
GROUP BY 1, 2`, table, cond), args...)
	if err != nil {
		return nil, fmt.Errorf("app actions: %w", err)
	}
	for rows.Next() {
		var m, code string
		var v float64
		if err := rows.Scan(&m, &code, &v); err != nil {
			rows.Close()
			return nil, fmt.Errorf("app actions scan: %w", err)
		}
		a := get(code)
		if m == metrics.WAFBlocksTotal {
			a.blocked += v
		} else {
			a.observed += v
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("app actions iterate: %w", err)
	}

	// 耗时直方图（按 app 合并各桶计数；extra->'buckets' 缺失/NULL 时 lateral 为空集自动跳过）
	args = []interface{}{metrics.HTTPRequestDurationMs, start, end}
	cond, args = appCond(codes, args)
	rows, err = s.db.Query(ctx, fmt.Sprintf(`
SELECT labels->>'app', b.idx, SUM(b.cnt::int)
FROM %s, LATERAL jsonb_array_elements_text(extra->'buckets') WITH ORDINALITY AS b(cnt, idx)
WHERE metric = $1 AND bucket_start >= $2 AND bucket_start < $3%s
GROUP BY 1, 2`, table, cond), args...)
	if err != nil {
		return nil, fmt.Errorf("app duration: %w", err)
	}
	for rows.Next() {
		var code string
		var idx, cnt int
		if err := rows.Scan(&code, &idx, &cnt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("app duration scan: %w", err)
		}
		a := get(code)
		if idx >= 1 && idx <= len(a.dur) {
			a.dur[idx-1] += cnt
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("app duration iterate: %w", err)
	}
	return out, nil
}

// trend 窗口内按桶聚合请求/5xx/阻断/p95（零值桶补齐，时间轴连续）。
// codes 为空聚合全部应用（overview），否则单应用（服务详情）。
func (s *Store) trend(ctx context.Context, table string, start, end time.Time, codes []string) ([]TrendBucket, error) {
	step := trendStep(table)
	buckets := map[time.Time]*TrendBucket{}
	order := []time.Time{}
	for t := start.UTC().Truncate(step); t.Before(end); t = t.Add(step) {
		buckets[t] = &TrendBucket{BucketStart: t}
		order = append(order, t)
	}

	// 请求与 5xx（按桶 × status_class）
	args := []interface{}{metrics.HTTPRequestsTotal, start, end}
	cond, args := appCond(codes, args)
	rows, err := s.db.Query(ctx, fmt.Sprintf(`
SELECT bucket_start, labels->>'status_class', SUM(value)
FROM %s WHERE metric = $1 AND bucket_start >= $2 AND bucket_start < $3%s
GROUP BY 1, 2`, table, cond), args...)
	if err != nil {
		return nil, fmt.Errorf("trend requests: %w", err)
	}
	for rows.Next() {
		var ts time.Time
		var class string
		var v float64
		if err := rows.Scan(&ts, &class, &v); err != nil {
			rows.Close()
			return nil, fmt.Errorf("trend requests scan: %w", err)
		}
		if b, ok := buckets[ts.UTC().Truncate(step)]; ok {
			b.Requests += v
			if class == "5xx" {
				b.Errors += v
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("trend requests iterate: %w", err)
	}

	// 阻断（按桶）
	args = []interface{}{metrics.WAFBlocksTotal, start, end}
	cond, args = appCond(codes, args)
	rows, err = s.db.Query(ctx, fmt.Sprintf(`
SELECT bucket_start, SUM(value)
FROM %s WHERE metric = $1 AND bucket_start >= $2 AND bucket_start < $3%s
GROUP BY 1`, table, cond), args...)
	if err != nil {
		return nil, fmt.Errorf("trend blocks: %w", err)
	}
	for rows.Next() {
		var ts time.Time
		var v float64
		if err := rows.Scan(&ts, &v); err != nil {
			rows.Close()
			return nil, fmt.Errorf("trend blocks scan: %w", err)
		}
		if b, ok := buckets[ts.UTC().Truncate(step)]; ok {
			b.Blocked += v
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("trend blocks iterate: %w", err)
	}

	// p95（按桶合并直方图后估算）
	args = []interface{}{metrics.HTTPRequestDurationMs, start, end}
	cond, args = appCond(codes, args)
	rows, err = s.db.Query(ctx, fmt.Sprintf(`
SELECT bucket_start, b.idx, SUM(b.cnt::int)
FROM %s, LATERAL jsonb_array_elements_text(extra->'buckets') WITH ORDINALITY AS b(cnt, idx)
WHERE metric = $1 AND bucket_start >= $2 AND bucket_start < $3%s
GROUP BY 1, 2`, table, cond), args...)
	if err != nil {
		return nil, fmt.Errorf("trend duration: %w", err)
	}
	nb := len(metrics.DurationBucketsMs) + 1
	durByBucket := map[time.Time][]int{}
	for rows.Next() {
		var ts time.Time
		var idx, cnt int
		if err := rows.Scan(&ts, &idx, &cnt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("trend duration scan: %w", err)
		}
		k := ts.UTC().Truncate(step)
		d := durByBucket[k]
		if d == nil {
			d = make([]int, nb)
			durByBucket[k] = d
		}
		if idx >= 1 && idx <= nb {
			d[idx-1] += cnt
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("trend duration iterate: %w", err)
	}
	for k, d := range durByBucket {
		if b, ok := buckets[k]; ok {
			b.P95 = metrics.PercentileFromBuckets(d, 0.95)
		}
	}

	out := make([]TrendBucket, 0, len(order))
	for _, t := range order {
		out = append(out, *buckets[t])
	}
	return out, nil
}

// loadEndpointAggs 窗口内按端点聚合（app × endpoint，跨 status_class/action 合并）。
// 仅端点级指标（管道 A，access_log 开启时才有数据）。
func (s *Store) loadEndpointAggs(ctx context.Context, table string, start, end time.Time, codes []string) (map[string]*endpointAgg, error) {
	out := map[string]*endpointAgg{}
	get := func(app, endpoint string) *endpointAgg {
		k := app + "\x00" + endpoint
		e := out[k]
		if e == nil {
			e = &endpointAgg{app: app, endpoint: endpoint, dur: make([]int, len(metrics.DurationBucketsMs)+1)}
			out[k] = e
		}
		return e
	}

	// 请求/5xx/阻断（action='block'）+ last_seen
	args := []interface{}{metrics.HTTPEndpointRequestsTotal, start, end}
	cond, args := appCond(codes, args)
	rows, err := s.db.Query(ctx, fmt.Sprintf(`
SELECT labels->>'app', labels->>'endpoint', labels->>'status_class', labels->>'action', SUM(value), MAX(bucket_start)
FROM %s WHERE metric = $1 AND bucket_start >= $2 AND bucket_start < $3%s
GROUP BY 1, 2, 3, 4`, table, cond), args...)
	if err != nil {
		return nil, fmt.Errorf("endpoint requests: %w", err)
	}
	for rows.Next() {
		var app, endpoint, class, action string
		var v float64
		var last *time.Time
		if err := rows.Scan(&app, &endpoint, &class, &action, &v, &last); err != nil {
			rows.Close()
			return nil, fmt.Errorf("endpoint requests scan: %w", err)
		}
		e := get(app, endpoint)
		e.requests += v
		if class == "5xx" {
			e.err5xx += v
		}
		if action == "block" {
			e.blocked += v
		}
		if last != nil && (e.lastSeen == nil || last.After(*e.lastSeen)) {
			e.lastSeen = last
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("endpoint requests iterate: %w", err)
	}

	// 耗时直方图（duration_ms 按端点合并；TTFB 直方图当前响应面不暴露，不查询）
	args = []interface{}{metrics.HTTPEndpointDurationMs, start, end}
	cond, args = appCond(codes, args)
	rows, err = s.db.Query(ctx, fmt.Sprintf(`
SELECT labels->>'app', labels->>'endpoint', b.idx, SUM(b.cnt::int)
FROM %s, LATERAL jsonb_array_elements_text(extra->'buckets') WITH ORDINALITY AS b(cnt, idx)
WHERE metric = $1 AND bucket_start >= $2 AND bucket_start < $3%s
GROUP BY 1, 2, 3`, table, cond), args...)
	if err != nil {
		return nil, fmt.Errorf("endpoint duration: %w", err)
	}
	for rows.Next() {
		var app, endpoint string
		var idx, cnt int
		if err := rows.Scan(&app, &endpoint, &idx, &cnt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("endpoint duration scan: %w", err)
		}
		e := get(app, endpoint)
		if idx >= 1 && idx <= len(e.dur) {
			e.dur[idx-1] += cnt
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("endpoint duration iterate: %w", err)
	}
	return out, nil
}

// appIdentities 批量反解应用 code → id/name（已删除应用不出现在结果中）。
func (s *Store) appIdentities(ctx context.Context, codes []string) (map[string]appIdentity, error) {
	out := map[string]appIdentity{}
	if len(codes) == 0 {
		return out, nil
	}
	rows, err := s.db.Query(ctx,
		`SELECT id, code, name FROM applications WHERE code = ANY($1) AND deleted_at IS NULL`, codes)
	if err != nil {
		return nil, fmt.Errorf("app identities: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		var code, name string
		if err := rows.Scan(&id, &code, &name); err != nil {
			return nil, fmt.Errorf("app identities scan: %w", err)
		}
		out[code] = appIdentity{ID: id, Name: name}
	}
	return out, rows.Err()
}

// ---------- 对外查询 ----------

// Overview APM 概览（应用级聚合 + 端点级榜单；accessLogEnabled=false 时端点级为空）。
func (s *Store) Overview(ctx context.Context, start, end time.Time, accessLogEnabled bool) (*OverviewData, error) {
	table := aggTableFor(start, end)
	out := &OverviewData{
		DataSource:           "agentless",
		AccessLogEnabled:     accessLogEnabled,
		StartTime:            start,
		EndTime:              end,
		Trend:                []TrendBucket{},
		TopSlowApplications:  []AppRankItem{},
		TopErrorApplications: []AppRankItem{},
		TopSlowEndpoints:     []EndpointStat{},
	}

	aggs, err := s.loadAppAggs(ctx, table, start, end, nil)
	if err != nil {
		return nil, err
	}
	trend, err := s.trend(ctx, table, start, end, nil)
	if err != nil {
		return nil, err
	}
	out.Trend = trend

	totalDur := make([]int, len(metrics.DurationBucketsMs)+1)
	codes := make([]string, 0, len(aggs))
	var lastSeen *time.Time
	for code, a := range aggs {
		codes = append(codes, code)
		out.RequestsTotal += a.requests
		out.Error5xxTotal += a.err5xx()
		out.Error4xxTotal += a.err4xx()
		out.BlockedTotal += a.blocked
		for i := range totalDur {
			totalDur[i] += a.dur[i]
		}
		if a.lastSeen != nil && (lastSeen == nil || a.lastSeen.After(*lastSeen)) {
			lastSeen = a.lastSeen
		}
	}
	out.ErrorRate = rate(out.Error5xxTotal, out.RequestsTotal)
	out.Latency = latencyFromBuckets(totalDur)

	// availability（P1-01 A2）：网关侧聚合数据自述；access_log 关闭时端点级腿
	// （top_slow_endpoints/unclassified_requests）不可得，如实标注 partial + 原因码
	if !accessLogEnabled {
		out.Availability = gatewayAvailability(out.RequestsTotal > 0, out.RequestsTotal > 0, lastSeen, reasonAccessLogDisabled)
		out.Availability.Partial = true
	} else {
		out.Availability = gatewayAvailability(out.RequestsTotal > 0, out.RequestsTotal > 0, lastSeen)
	}

	identities, err := s.appIdentities(ctx, codes)
	if err != nil {
		return nil, err
	}
	rankOf := func(code string, a *appAgg) AppRankItem {
		it := AppRankItem{App: code, Requests: a.requests, ErrorRate: rate(a.err5xx(), a.requests),
			P95: metrics.PercentileFromBuckets(a.dur, 0.95)}
		if id, ok := identities[code]; ok {
			idCopy := id.ID
			it.ApplicationID = &idCopy
			it.Name = id.Name
		}
		return it
	}
	slow := make([]AppRankItem, 0, len(aggs))
	byErr := make([]AppRankItem, 0, len(aggs))
	for code, a := range aggs {
		if a.requests <= 0 {
			continue
		}
		slow = append(slow, rankOf(code, a))
		byErr = append(byErr, rankOf(code, a))
	}
	sort.Slice(slow, func(i, j int) bool {
		if slow[i].P95 != slow[j].P95 {
			return slow[i].P95 > slow[j].P95
		}
		return slow[i].App < slow[j].App
	})
	sort.Slice(byErr, func(i, j int) bool {
		if byErr[i].ErrorRate != byErr[j].ErrorRate {
			return byErr[i].ErrorRate > byErr[j].ErrorRate
		}
		return byErr[i].App < byErr[j].App
	})
	out.TopSlowApplications = headAppRank(slow, topN)
	out.TopErrorApplications = headAppRank(byErr, topN)

	// 端点级（管道 A 关闭时不产出数据，榜单与未归类计数如实为空/0）
	if accessLogEnabled {
		epAggs, err := s.loadEndpointAggs(ctx, table, start, end, nil)
		if err != nil {
			return nil, err
		}
		eps := make([]EndpointStat, 0, len(epAggs))
		for _, e := range epAggs {
			if e.endpoint == aggregations.EndpointUnclassified {
				out.UnclassifiedRequests += int64(e.requests)
			}
			if e.requests <= 0 {
				continue
			}
			eps = append(eps, EndpointStat{App: e.app, Endpoint: e.endpoint, Requests: e.requests,
				ErrorRate: rate(e.err5xx, e.requests), P95: metrics.PercentileFromBuckets(e.dur, 0.95)})
		}
		sort.Slice(eps, func(i, j int) bool {
			if eps[i].P95 != eps[j].P95 {
				return eps[i].P95 > eps[j].P95
			}
			if eps[i].App != eps[j].App {
				return eps[i].App < eps[j].App
			}
			return eps[i].Endpoint < eps[j].Endpoint
		})
		out.TopSlowEndpoints = headEndpointStat(eps, topN)
	}
	return out, nil
}

// ListServices 服务列表（applications 分页 + 窗口聚合回填）。
func (s *Store) ListServices(ctx context.Context, f ServicesFilter) ([]ServiceRow, int64, error) {
	where := "deleted_at IS NULL"
	args := []interface{}{}
	if f.Keyword != "" {
		args = append(args, "%"+f.Keyword+"%")
		where += fmt.Sprintf(" AND (code ILIKE $%d OR name ILIKE $%d)", len(args), len(args))
	}
	var total int64
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM applications WHERE `+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("services count: %w", err)
	}
	args = append(args, f.PageSize, (f.Page-1)*f.PageSize)
	rows, err := s.db.Query(ctx, fmt.Sprintf(`
SELECT id, code, name FROM applications WHERE %s
ORDER BY code ASC LIMIT $%d OFFSET $%d`, where, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("services list: %w", err)
	}
	type appRow struct {
		id   uuid.UUID
		code string
		name string
	}
	var apps []appRow
	var codes []string
	for rows.Next() {
		var a appRow
		if err := rows.Scan(&a.id, &a.code, &a.name); err != nil {
			rows.Close()
			return nil, 0, fmt.Errorf("services scan: %w", err)
		}
		apps = append(apps, a)
		codes = append(codes, a.code)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("services iterate: %w", err)
	}

	out := make([]ServiceRow, 0, len(apps))
	if len(apps) == 0 {
		return out, total, nil
	}
	aggs, err := s.loadAppAggs(ctx, aggTableFor(f.Start, f.End), f.Start, f.End, codes)
	if err != nil {
		return nil, 0, err
	}
	// Agent 覆盖（阶段2 下半）：apm_agents ⋈ apm_services 按应用统计在线/总数，
	// 有在线 Agent 的应用观测模式为 "agent"，否则 "agentless"（如实降级）。
	appIDs := make([]uuid.UUID, 0, len(apps))
	for _, a := range apps {
		appIDs = append(appIDs, a.id)
	}
	agentCounts, err := s.agentCountsByApplication(ctx, appIDs, time.Now().UTC().Add(-f.AgentOfflineAfter))
	if err != nil {
		return nil, 0, err
	}
	for _, a := range apps {
		row := ServiceRow{
			ApplicationID:   a.id,
			App:             a.code,
			Name:            a.name,
			ObservationMode: "agentless",
		}
		if ac := agentCounts[a.id]; ac != nil {
			row.AgentsOnline, row.AgentsTotal = ac.online, ac.total
			if ac.online > 0 {
				row.ObservationMode = "agent"
			}
		}
		if g := aggs[a.code]; g != nil {
			lat := latencyFromBuckets(g.dur)
			row.Requests = g.requests
			row.ErrorRate = rate(g.err5xx(), g.requests)
			row.Blocked = g.blocked
			row.P50, row.P95, row.P99 = lat.P50, lat.P95, lat.P99
			row.LastSeenAt = g.lastSeen
		}
		out = append(out, row)
	}
	return out, total, nil
}

// agentCounts 单应用 Agent 计数（total 不含 REVOKED；online 为心跳未超阈值者）。
type agentCounts struct {
	online int
	total  int
}

// agentCountsByApplication 按应用批量统计 Agent 在线/总数（REVOKED 不计；
// 在线 = COALESCE(last_heartbeat_at, registered_at) >= onlineSince，与
// DeriveAgentStatus 的 OFFLINE 推导口径一致）。
func (s *Store) agentCountsByApplication(ctx context.Context, appIDs []uuid.UUID, onlineSince time.Time) (map[uuid.UUID]*agentCounts, error) {
	out := map[uuid.UUID]*agentCounts{}
	if len(appIDs) == 0 {
		return out, nil
	}
	rows, err := s.db.Query(ctx, `
SELECT s.application_id,
       count(*) FILTER (WHERE a.status <> 'REVOKED'),
       count(*) FILTER (WHERE a.status <> 'REVOKED'
                        AND COALESCE(a.last_heartbeat_at, a.registered_at) >= $2)
FROM apm_agents a
JOIN apm_services s ON s.id = a.service_id
WHERE s.application_id = ANY($1)
GROUP BY s.application_id`, appIDs, onlineSince)
	if err != nil {
		return nil, fmt.Errorf("agent counts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var appID uuid.UUID
		var total, online int
		if err := rows.Scan(&appID, &total, &online); err != nil {
			return nil, fmt.Errorf("agent counts scan: %w", err)
		}
		out[appID] = &agentCounts{online: online, total: total}
	}
	return out, rows.Err()
}

// ServiceDetail 服务详情（应用不存在返回 ErrNotFound）。
func (s *Store) ServiceDetail(ctx context.Context, id uuid.UUID, start, end time.Time, accessLogEnabled bool) (*ServiceDetailData, error) {
	var appID uuid.UUID
	var code, name string
	err := s.db.QueryRow(ctx,
		`SELECT id, code, name FROM applications WHERE id = $1 AND deleted_at IS NULL`, id).
		Scan(&appID, &code, &name)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("service get: %w", err)
	}

	table := aggTableFor(start, end)
	out := &ServiceDetailData{
		ApplicationID:   appID,
		App:             code,
		Name:            name,
		ObservationMode: "agentless",
		Trend:           []TrendBucket{},
		StatusClasses:   []StatusClassCount{},
		Actions:         []ActionCount{},
		TopEndpoints:    []EndpointStat{},
	}
	aggs, err := s.loadAppAggs(ctx, table, start, end, []string{code})
	if err != nil {
		return nil, err
	}
	trend, err := s.trend(ctx, table, start, end, []string{code})
	if err != nil {
		return nil, err
	}
	out.Trend = trend

	a := aggs[code]
	if a == nil {
		a = newAppAgg()
	}
	out.RequestsTotal = a.requests
	out.ErrorRate = rate(a.err5xx(), a.requests)
	out.Latency = latencyFromBuckets(a.dur)
	classes := make([]string, 0, len(a.byClass))
	for c := range a.byClass {
		classes = append(classes, c)
	}
	sort.Strings(classes)
	for _, c := range classes {
		out.StatusClasses = append(out.StatusClasses, StatusClassCount{StatusClass: c, Count: a.byClass[c]})
	}
	// 动作分布（app 级派生口径：allow = requests − block − observe，下限 0）
	allow := a.requests - a.blocked - a.observed
	if allow < 0 {
		allow = 0
	}
	out.Actions = []ActionCount{
		{Action: "allow", Count: allow},
		{Action: "observe", Count: a.observed},
		{Action: "block", Count: a.blocked},
	}

	if accessLogEnabled {
		epAggs, err := s.loadEndpointAggs(ctx, table, start, end, []string{code})
		if err != nil {
			return nil, err
		}
		eps := make([]EndpointStat, 0, len(epAggs))
		for _, e := range epAggs {
			if e.requests <= 0 {
				continue
			}
			eps = append(eps, EndpointStat{Endpoint: e.endpoint, Requests: e.requests,
				ErrorRate: rate(e.err5xx, e.requests), P95: metrics.PercentileFromBuckets(e.dur, 0.95)})
		}
		sort.Slice(eps, func(i, j int) bool {
			if eps[i].P95 != eps[j].P95 {
				return eps[i].P95 > eps[j].P95
			}
			return eps[i].Endpoint < eps[j].Endpoint
		})
		out.TopEndpoints = headEndpointStat(eps, topN)
	}
	// availability（P1-01 A2）：access_log 关闭时端点级腿（top_endpoints）不可得
	if !accessLogEnabled {
		out.Availability = gatewayAvailability(out.RequestsTotal > 0, out.RequestsTotal > 0, a.lastSeen, reasonAccessLogDisabled)
		out.Availability.Partial = true
	} else {
		out.Availability = gatewayAvailability(out.RequestsTotal > 0, out.RequestsTotal > 0, a.lastSeen)
	}
	return out, nil
}

// ListEndpoints 端点列表（窗口内聚合后排序分页；保留桶 __OTHER__/__UNCLASSIFIED__ 原样返回）。
func (s *Store) ListEndpoints(ctx context.Context, f EndpointsFilter) ([]EndpointRow, int64, error) {
	var codes []string
	if f.AppCode != nil {
		codes = []string{*f.AppCode}
	}
	epAggs, err := s.loadEndpointAggs(ctx, aggTableFor(f.Start, f.End), f.Start, f.End, codes)
	if err != nil {
		return nil, 0, err
	}

	appCodes := make([]string, 0, len(epAggs))
	seen := map[string]bool{}
	for _, e := range epAggs {
		if !seen[e.app] {
			seen[e.app] = true
			appCodes = append(appCodes, e.app)
		}
	}
	identities, err := s.appIdentities(ctx, appCodes)
	if err != nil {
		return nil, 0, err
	}

	rows := make([]EndpointRow, 0, len(epAggs))
	for _, e := range epAggs {
		lat := latencyFromBuckets(e.dur)
		method, pathTemplate := splitEndpoint(e.endpoint)
		row := EndpointRow{
			App:          e.app,
			Endpoint:     e.endpoint,
			Method:       method,
			PathTemplate: pathTemplate,
			Requests:     e.requests,
			ErrorRate:    rate(e.err5xx, e.requests),
			Blocked:      e.blocked,
			P50:          lat.P50,
			P95:          lat.P95,
			P99:          lat.P99,
			LastSeenAt:   e.lastSeen,
		}
		if id, ok := identities[e.app]; ok {
			idCopy := id.ID
			row.ApplicationID = &idCopy
		}
		rows = append(rows, row)
	}

	sortFn := map[string]func(EndpointRow) float64{
		"p95":        func(r EndpointRow) float64 { return r.P95 },
		"requests":   func(r EndpointRow) float64 { return r.Requests },
		"error_rate": func(r EndpointRow) float64 { return r.ErrorRate },
	}[f.Sort]
	if sortFn == nil {
		sortFn = func(r EndpointRow) float64 { return r.P95 }
	}
	sort.Slice(rows, func(i, j int) bool {
		vi, vj := sortFn(rows[i]), sortFn(rows[j])
		if vi != vj {
			return vi > vj
		}
		if rows[i].App != rows[j].App {
			return rows[i].App < rows[j].App
		}
		return rows[i].Endpoint < rows[j].Endpoint
	})

	total := int64(len(rows))
	from := (f.Page - 1) * f.PageSize
	if from >= len(rows) {
		return []EndpointRow{}, total, nil
	}
	to := from + f.PageSize
	if to > len(rows) {
		to = len(rows)
	}
	return rows[from:to], total, nil
}

// AppCodeByID 解析应用 ID → code（过滤参数反解用；不存在返回 ErrNotFound）。
func (s *Store) AppCodeByID(ctx context.Context, id uuid.UUID) (string, error) {
	var code string
	err := s.db.QueryRow(ctx,
		`SELECT code FROM applications WHERE id = $1 AND deleted_at IS NULL`, id).Scan(&code)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("app code: %w", err)
	}
	return code, nil
}

// serviceNamesByApplication 应用映射的 OTel 服务名集合（apm_services，迁移 000089：
// OTel service.name ↔ application 映射表；trace-search 按应用约束检索的证据来源）。
// 应用无任何映射服务时返回空集合（约束不可满足，调用方如实空页，不静默放弃约束）。
func (s *Store) serviceNamesByApplication(ctx context.Context, appID uuid.UUID) ([]string, error) {
	rows, err := s.db.Query(ctx, `
SELECT service_name FROM apm_services
WHERE application_id = $1
ORDER BY service_name ASC LIMIT $2`, appID, appServicesCap)
	if err != nil {
		return nil, fmt.Errorf("app service names: %w", err)
	}
	defer rows.Close()
	names := []string{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, fmt.Errorf("app service names scan: %w", err)
		}
		names = append(names, n)
	}
	return names, rows.Err()
}

// securityEventEvidence request_id 的安全事件证据（存在性/阻断动作），
// 用于 access_logs 无命中或无 trace 上下文时 correlation 的 NOT_EXPECTED/UNKNOWN 判定
// （访问日志可关闭而安全事件独立入库，阻断事件是网关终止请求的现存证据来源）。
func (s *Store) securityEventEvidence(ctx context.Context, requestID string) (hasAny, hasBlock bool, err error) {
	err = s.db.QueryRow(ctx, `
SELECT count(*) > 0, count(*) FILTER (WHERE action = 'BLOCK') > 0
FROM security_events WHERE request_id = $1`, requestID).Scan(&hasAny, &hasBlock)
	if err != nil {
		return false, false, fmt.Errorf("security event evidence: %w", err)
	}
	return hasAny, hasBlock, nil
}

// TraceView trace 检索：access_logs 按 trace_id 精确匹配（部分索引），
// 再按命中记录的 request_id 关联 security_events。start/end 为 nil 时不限时间
// （128 位随机键点查 + LIMIT 上限兜底）；均无命中返回空数组而非错误。
// 阶段2 下半扩展：接入 ClickHouse 数据面后追加 otel_spans 瀑布（CH 侧强制时间窗——
// 入参窗口优先，缺省对齐原始表最长 TTL 层 14 天）；CH 未配置/不可用时降级为
// 纯 agentless 数据（otel_spans 空、data_source=agentless），不 500。
// P1-01 A2：availability/correlation 由双腿真实命中、阻断证据与采集水位判定
// （availability.go；accessLogEnabled/ingestLagThreshold 由 handler 从设置读入）。
func (s *Store) TraceView(ctx context.Context, traceID string, start, end *time.Time, accessLogEnabled bool, ingestLagThreshold time.Duration) (*TraceViewData, error) {
	out := &TraceViewData{
		TraceID:        traceID,
		AccessLogs:     []TraceAccessLog{},
		SecurityEvents: []TraceSecurityEvent{},
		OTelSpans:      []OTelSpan{},
		DataSource:     dataSourceAgentless,
		Partial:        true,
		Note:           dataSourceAgentless,
	}

	where := "trace_id = $1"
	args := []interface{}{traceID}
	if start != nil {
		args = append(args, *start)
		where += fmt.Sprintf(" AND occurred_at >= $%d", len(args))
	}
	if end != nil {
		args = append(args, *end)
		where += fmt.Sprintf(" AND occurred_at < $%d", len(args))
	}
	args = append(args, traceQueryLimit)
	rows, err := s.db.Query(ctx, `
SELECT id, occurred_at, request_id, application_id, domain, COALESCE(host(client_ip), ''),
  request_method, request_uri, request_path, response_status, duration_ms, ttfb_ms,
  COALESCE(NULLIF(waf_action, ''), 'ALLOW'), span_id, endpoint_key, path_template
FROM access_logs WHERE `+where+fmt.Sprintf(" ORDER BY occurred_at DESC LIMIT $%d", len(args)), args...)
	if err != nil {
		return nil, fmt.Errorf("trace access logs: %w", err)
	}
	requestIDs := []string{}
	seenReq := map[string]bool{}
	for rows.Next() {
		var e TraceAccessLog
		if err := rows.Scan(&e.ID, &e.OccurredAt, &e.RequestID, &e.ApplicationID, &e.Domain, &e.ClientIP,
			&e.RequestMethod, &e.RequestURI, &e.RequestPath, &e.ResponseStatus, &e.DurationMS, &e.TTFBMS,
			&e.WAFAction, &e.SpanID, &e.EndpointKey, &e.PathTemplate); err != nil {
			rows.Close()
			return nil, fmt.Errorf("trace access logs scan: %w", err)
		}
		out.AccessLogs = append(out.AccessLogs, e)
		if e.RequestID != "" && !seenReq[e.RequestID] {
			seenReq[e.RequestID] = true
			requestIDs = append(requestIDs, e.RequestID)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("trace access logs iterate: %w", err)
	}

	if len(requestIDs) > 0 {
		evRows, err := s.db.Query(ctx, `
SELECT id, occurred_at, request_id, application_id, attack_type, severity, action,
  COALESCE(response_status, 0), request_method, request_uri, rule_match_count, disposition_status
FROM security_events WHERE request_id = ANY($1)
ORDER BY occurred_at DESC LIMIT $2`, requestIDs, traceQueryLimit)
		if err != nil {
			return nil, fmt.Errorf("trace security events: %w", err)
		}
		defer evRows.Close()
		for evRows.Next() {
			var ev TraceSecurityEvent
			if err := evRows.Scan(&ev.ID, &ev.OccurredAt, &ev.RequestID, &ev.ApplicationID,
				&ev.AttackType, &ev.Severity, &ev.Action, &ev.ResponseStatus,
				&ev.RequestMethod, &ev.RequestURI, &ev.RuleMatchCount, &ev.DispositionStatus); err != nil {
				return nil, fmt.Errorf("trace security events scan: %w", err)
			}
			out.SecurityEvents = append(out.SecurityEvents, ev)
		}
		if err := evRows.Err(); err != nil {
			return nil, fmt.Errorf("trace security events iterate: %w", err)
		}
	}

	// OTel 瀑布（CH 数据面；未配置/不可用时 queryTraceSpans 返回空 + 状态，维持 agentless 口径）
	now := time.Now().UTC()
	chStart, chEnd := now.Add(-traceSpansDefaultWindow), now
	if start != nil && end != nil {
		chStart, chEnd = *start, *end
	}
	spans, truncated, chStatus := s.queryTraceSpans(ctx, traceID, chStart, chEnd)
	out.OTelSpans = spans
	out.SpanCount = len(spans)
	out.Truncated = truncated
	hasRoot := false
	if len(spans) > 0 {
		if len(out.AccessLogs) > 0 {
			out.DataSource = dataSourceMixed
		} else {
			out.DataSource = dataSourceOTel
		}
		// partial：被截断或无根 span（ParentSpanId 为空串者）视为可能不完整
		for _, sp := range spans {
			if sp.ParentSpanID == "" {
				hasRoot = true
				break
			}
		}
		out.Partial = truncated || !hasRoot
	}
	out.Note = out.DataSource

	// availability / correlation（P1-01 A2；判定证据见 availability.go）
	out.Availability = s.traceViewAvailability(ctx, chStatus, out.AccessLogs, out.SecurityEvents,
		spans, truncated, hasRoot, accessLogEnabled, end, ingestLagThreshold)
	wmLatest, wmHasData, wmKnown := time.Time{}, false, false
	if chStatus == chQueryOK {
		wmLatest, wmHasData, wmKnown = s.latestIngest(ctx)
	}
	spanServices := []string{}
	seenSvc := map[string]bool{}
	var spanStartMin time.Time
	for _, sp := range spans {
		if !seenSvc[sp.ServiceName] {
			seenSvc[sp.ServiceName] = true
			spanServices = append(spanServices, sp.ServiceName)
		}
		if spanStartMin.IsZero() || sp.StartTime.Before(spanStartMin) {
			spanStartMin = sp.StartTime
		}
	}
	out.Correlation = correlateTraceView(traceViewFacts{
		TraceID:       traceID,
		GatewayHit:    len(out.AccessLogs) > 0 || len(out.SecurityEvents) > 0,
		OTelHit:       len(spans) > 0,
		BlockEvidence: traceViewBlockEvidence(out.AccessLogs, out.SecurityEvents),
		OccurredMax:   traceViewLatestGatewayEvent(out.AccessLogs, out.SecurityEvents),
		SpanStartMin:  spanStartMin,
		SpanServices:  spanServices,
		CHStatus:      chStatus,
		WMKnown:       wmKnown,
		WMHasData:     wmHasData,
		WMLatest:      wmLatest,
		Now:           s.now(),
	})
	return out, nil
}

// traceViewBlockEvidence 网关腿阻断证据（access_logs waf_action 或 security_events
// action 为 BLOCK；P0-04 final_decision 落地前的可证据来源，合流点见 availability.go）。
func traceViewBlockEvidence(logs []TraceAccessLog, events []TraceSecurityEvent) bool {
	for _, l := range logs {
		if l.WAFAction == "BLOCK" {
			return true
		}
	}
	for _, e := range events {
		if e.Action == "BLOCK" {
			return true
		}
	}
	return false
}

// traceViewLatestGatewayEvent 网关腿最近事件时间（无命中为零值）。
func traceViewLatestGatewayEvent(logs []TraceAccessLog, events []TraceSecurityEvent) time.Time {
	var t time.Time
	for _, l := range logs {
		if l.OccurredAt.After(t) {
			t = l.OccurredAt
		}
	}
	for _, e := range events {
		if e.OccurredAt.After(t) {
			t = e.OccurredAt
		}
	}
	return t
}

func headAppRank(items []AppRankItem, n int) []AppRankItem {
	if len(items) > n {
		return items[:n]
	}
	return items
}

func headEndpointStat(items []EndpointStat, n int) []EndpointStat {
	if len(items) > n {
		return items[:n]
	}
	return items
}
