// endpoint_perf.go APM 阶段1（WP5）端点性能告警评估：周期读取端点级分钟聚合
// （metric_minute_aggregates 只读，生产方为 aggregations.RunEndpointRED 的 access_logs
// 全量访问日志聚合），按 system_settings 的 apm_alert 组阈值触发
// ENDPOINT_LATENCY_HIGH（端点 p95 持续超阈）/ ENDPOINT_ERROR_RATE_HIGH（端点 5xx
// 错误率持续超阈）；触发/合并/冷却/抖动/自动恢复全部复用引擎既有机制（Raise/AutoRecover）。
//
// 防误报护栏（设计依据 docs/BUSINESS_PERFORMANCE_APM_DESIGN.md §18.2「持续窗口 +
// 最小请求量，避免低流量端点因单次错误告警」）：
//   - 最小请求量：窗口内端点请求总数低于 min_requests（默认 60）不评估，
//     低流量端点单次错误不误报；
//   - 窗口级超阈 + 持续窗口：窗口整体指标（p95 / 错误率）须超阈，且最近
//     sustain_minutes（默认 3）个连续分钟桶各自超阈——单分钟毛刺与「早期大流量
//     干净桶 + 近期小流量脏桶」均不告警；分钟桶缺失（该分钟无流量）即中断连续；
//   - 窗口口径：仅取已完成且聚合任务已重算定稿的分钟桶——窗口整体上移 1 分钟
//     （RunEndpointRED 每分钟重算当前与上一分钟桶，当分钟内上一分钟桶仍是部分数据，
//     直接纳入会因部分计数抖动引发告警翻转）。
//
// 伪端点（保留桶 __OTHER__/__UNCLASSIFIED__，aggregations.EndpointOther/
// EndpointUnclassified）不评估：Top-N 合并桶/未归类治理桶不代表单一可处置端点。
// 告警详情只含 app/endpoint/指标值/窗口等聚合上下文，不含任何请求正文、参数或
// 原始路径（endpoint 为网关归一化后的 "METHOD /path/{id}" 模板）。
package systemalerts

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jiuzhang-waf/server/internal/aggregations"
	"github.com/jiuzhang-waf/server/internal/metrics"
)

// system_settings 的 apm_alert 组配置键与默认值（消费侧校验，非法值回退默认；
// 种子行见迁移 000089，可经系统设置 Update API 在线调整——键已登记 settings 白名单）。
const (
	apmAlertSettingsGroup = "apm_alert"

	apmAlertKeyEndpointP95Ms     = "endpoint_p95_ms"     // 端点 p95 阈值（毫秒）
	apmAlertKeyEndpointErrorRate = "endpoint_error_rate" // 端点 5xx 错误率阈值（0-1]
	apmAlertKeyMinRequests       = "min_requests"        // 窗口最小请求量护栏
	apmAlertKeySustainMinutes    = "sustain_minutes"     // 持续超阈分钟桶数护栏

	defaultEndpointP95Ms       = 2000
	defaultEndpointErrorRate   = 0.2
	defaultEndpointMinRequests = 60
	defaultEndpointSustainMin  = 3

	// 配置合法区间（超出回退默认，防误配导致告警风暴或永久静默）
	maxEndpointP95Ms       = 600000 // 10 分钟
	maxEndpointMinRequests = 1000000

	// endpointPerfWindow 评估窗口（固定 5 个分钟桶；sustain_minutes 不得超窗口）。
	endpointPerfWindow = 5 * time.Minute
	// endpointPerfWindowLag 窗口整体上移量：避开聚合任务在途重算的分钟桶。
	endpointPerfWindowLag = time.Minute

	// endpointComponentMaxLen 对应 system_alerts.component VARCHAR(40)。
	endpointComponentMaxLen = 40
)

// EndpointMinuteStat 是单端点单分钟桶的统计（跨 status_class/action 合并）。
type EndpointMinuteStat struct {
	App         string
	Endpoint    string
	BucketStart time.Time
	Requests    float64
	Err5xx      float64
	// DurBuckets 时长直方图桶计数（len = len(metrics.DurationBucketsMs)+1；无样本为 nil）。
	DurBuckets []int
}

// EndpointPerfStatsStore 提供端点级分钟聚合统计（metric_minute_aggregates 只读）。
type EndpointPerfStatsStore interface {
	// EndpointMinuteStats 返回窗口 [start, end) 内按端点 × 分钟桶的请求/5xx/时长直方图。
	EndpointMinuteStats(ctx context.Context, start, end time.Time) ([]EndpointMinuteStat, error)
}

// endpointPerfConfig 是一次评估生效的规则配置（每次评估时读取，运行期改配置即时生效）。
type endpointPerfConfig struct {
	P95Ms       float64
	ErrorRate   float64
	MinRequests int64
	Sustain     int
}

// loadEndpointPerfConfig 读取并校验 apm_alert 组配置：缺省/非法值一律回退默认，
// 不因误配放大或关闭告警。
func loadEndpointPerfConfig(ctx context.Context, s SettingsReader) endpointPerfConfig {
	cfg := endpointPerfConfig{
		P95Ms:       defaultEndpointP95Ms,
		ErrorRate:   defaultEndpointErrorRate,
		MinRequests: defaultEndpointMinRequests,
		Sustain:     defaultEndpointSustainMin,
	}
	if s == nil {
		return cfg
	}
	if v := s.GetInt(ctx, apmAlertSettingsGroup, apmAlertKeyEndpointP95Ms, defaultEndpointP95Ms); v > 0 && v <= maxEndpointP95Ms {
		cfg.P95Ms = float64(v)
	}
	if v := s.GetFloat(ctx, apmAlertSettingsGroup, apmAlertKeyEndpointErrorRate, defaultEndpointErrorRate); v > 0 && v <= 1 {
		cfg.ErrorRate = v
	}
	if v := s.GetInt(ctx, apmAlertSettingsGroup, apmAlertKeyMinRequests, defaultEndpointMinRequests); v > 0 && v <= maxEndpointMinRequests {
		cfg.MinRequests = int64(v)
	}
	// sustain 超窗口分钟数将永不满足（静默失效），视为非法回退默认
	if v := s.GetInt(ctx, apmAlertSettingsGroup, apmAlertKeySustainMinutes, defaultEndpointSustainMin); v >= 1 && v <= int(endpointPerfWindow/time.Minute) {
		cfg.Sustain = v
	}
	return cfg
}

// endpointMinuteDatum 单分钟桶数据。
type endpointMinuteDatum struct {
	requests float64
	err5xx   float64
	dur      []int
}

// endpointWindowStat 单端点（app × endpoint）窗口聚合：窗口总量/合并直方图 + 分钟桶序列。
type endpointWindowStat struct {
	app      string
	endpoint string
	requests float64
	err5xx   float64
	dur      []int
	minutes  map[time.Time]*endpointMinuteDatum
}

// buildEndpointWindowStats 分钟桶行 → 端点窗口聚合（跳过伪端点保留桶；
// 输出按 app/endpoint 升序，评估顺序确定）。
func buildEndpointWindowStats(rows []EndpointMinuteStat) []*endpointWindowStat {
	nb := len(metrics.DurationBucketsMs) + 1
	byKey := map[string]*endpointWindowStat{}
	for _, r := range rows {
		if r.Endpoint == aggregations.EndpointOther || r.Endpoint == aggregations.EndpointUnclassified {
			continue
		}
		key := r.App + "\x00" + r.Endpoint
		st := byKey[key]
		if st == nil {
			st = &endpointWindowStat{
				app: r.App, endpoint: r.Endpoint,
				dur: make([]int, nb), minutes: map[time.Time]*endpointMinuteDatum{},
			}
			byKey[key] = st
		}
		b := r.BucketStart.UTC().Truncate(time.Minute)
		m := st.minutes[b]
		if m == nil {
			m = &endpointMinuteDatum{dur: make([]int, nb)}
			st.minutes[b] = m
		}
		st.requests += r.Requests
		st.err5xx += r.Err5xx
		m.requests += r.Requests
		m.err5xx += r.Err5xx
		for i := 0; i < nb && i < len(r.DurBuckets); i++ {
			st.dur[i] += r.DurBuckets[i]
			m.dur[i] += r.DurBuckets[i]
		}
	}
	out := make([]*endpointWindowStat, 0, len(byKey))
	for _, st := range byKey {
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].app != out[j].app {
			return out[i].app < out[j].app
		}
		return out[i].endpoint < out[j].endpoint
	})
	return out
}

// sustainBreached 最近 sustain 个连续分钟桶（自窗口终点前一分钟回数）是否各自超阈；
// 桶缺失或桶内无请求即中断连续，视为不满足（流量消失不产生告警，由恢复路径收口）。
func sustainBreached(st *endpointWindowStat, end time.Time, sustain int, exceed func(*endpointMinuteDatum) bool) bool {
	for i := 1; i <= sustain; i++ {
		m := st.minutes[end.Add(-time.Duration(i)*time.Minute)]
		if m == nil || m.requests <= 0 || !exceed(m) {
			return false
		}
	}
	return true
}

// endpointLatencyBreached 慢端点判定：窗口请求量达护栏 + 窗口 p95 ≥ 阈值 +
// 最近 sustain 个连续分钟桶各自 p95 ≥ 阈值（≥ 口径与既有 spike 评估一致）。
func endpointLatencyBreached(st *endpointWindowStat, cfg endpointPerfConfig, end time.Time) bool {
	if st.requests < float64(cfg.MinRequests) {
		return false
	}
	if metrics.PercentileFromBuckets(st.dur, 0.95) < cfg.P95Ms {
		return false
	}
	return sustainBreached(st, end, cfg.Sustain, func(m *endpointMinuteDatum) bool {
		return metrics.PercentileFromBuckets(m.dur, 0.95) >= cfg.P95Ms
	})
}

// endpointErrorRateBreached 端点错误率判定：窗口请求量达护栏 + 窗口 5xx 错误率 ≥ 阈值 +
// 最近 sustain 个连续分钟桶各自错误率 ≥ 阈值。
func endpointErrorRateBreached(st *endpointWindowStat, cfg endpointPerfConfig, end time.Time) bool {
	if st.requests < float64(cfg.MinRequests) {
		return false
	}
	if st.err5xx/st.requests < cfg.ErrorRate {
		return false
	}
	return sustainBreached(st, end, cfg.Sustain, func(m *endpointMinuteDatum) bool {
		return m.err5xx/m.requests >= cfg.ErrorRate
	})
}

// truncatedAlertComponent 生成告警组件标识（去重键）：控制字符清洗为空格；
// 超 system_alerts.component VARCHAR(40) 时按字符截断并附 8 位 SHA-1 摘要后缀——
// 截断不同的长键不会碰撞成同一去重键。
func truncatedAlertComponent(raw string) string {
	raw = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, raw)
	if utf8.RuneCountInString(raw) <= endpointComponentMaxLen {
		return raw
	}
	sum := sha1.Sum([]byte(raw)) // #nosec G505 -- 仅作去重键摘要，非安全用途
	suffix := hex.EncodeToString(sum[:])[:8]
	return string([]rune(raw)[:endpointComponentMaxLen-9]) + "-" + suffix
}

// endpointPerfComponent 端点性能告警组件标识：app + "/" + endpoint（截断口径
// 见 truncatedAlertComponent）。
func endpointPerfComponent(app, endpoint string) string {
	return truncatedAlertComponent(app + "/" + endpoint)
}

// EvaluateEndpointPerf 评估端点性能告警（需配置 EndpointPerf；周期调用，装配层与
// Evaluate/EvaluateAPIFindings 同 ticker）。窗口内超阈端点逐组件 Raise（走合并/冷却/
// 抖动），本轮未触发但仍有未关闭告警的组件 AutoRecover（含窗口内已无流量的端点）。
// 读数失败整体中止（不清动既有告警）；单端点 Raise/恢复失败不阻断其他端点，错误聚合返回。
func (e *Engine) EvaluateEndpointPerf(ctx context.Context) error {
	if e.endpointPerf == nil {
		return nil
	}
	// APM 总开关关闭：空转（运行期热生效；不清动既有告警，开启后下轮自动恢复评估）
	if !e.apmEnabledNow(ctx) {
		return nil
	}
	cfg := loadEndpointPerfConfig(ctx, e.settings)
	end := e.now().UTC().Truncate(time.Minute).Add(-endpointPerfWindowLag)
	stats, err := e.endpointPerf.EndpointMinuteStats(ctx, end.Add(-endpointPerfWindow), end)
	if err != nil {
		return fmt.Errorf("endpoint minute stats: %w", err)
	}
	endpoints := buildEndpointWindowStats(stats)

	triggered := map[string]map[string]bool{}
	mark := func(comp, typ string) {
		m := triggered[comp]
		if m == nil {
			m = map[string]bool{}
			triggered[comp] = m
		}
		m[typ] = true
	}
	var errs []error
	for _, st := range endpoints {
		comp := endpointPerfComponent(st.app, st.endpoint)
		if endpointLatencyBreached(st, cfg, end) {
			mark(comp, TypeEndpointLatencyHigh) // 先标记再 Raise：Raise 失败不误恢复既有告警
			if _, err := e.Raise(ctx, RaiseRequest{
				AlertType: TypeEndpointLatencyHigh,
				Component: comp,
				Title:     "端点响应耗时过高",
				Message: fmt.Sprintf("应用 %s 端点 %s 最近 %d 分钟 p95 约 %.0fms（阈值 %.0fms），窗口请求 %d 次，连续 %d 分钟超阈",
					st.app, st.endpoint, int(endpointPerfWindow/time.Minute),
					metrics.PercentileFromBuckets(st.dur, 0.95), cfg.P95Ms, int64(st.requests), cfg.Sustain),
			}); err != nil {
				errs = append(errs, err)
			}
		}
		if endpointErrorRateBreached(st, cfg, end) {
			mark(comp, TypeEndpointErrorRateHigh)
			if _, err := e.Raise(ctx, RaiseRequest{
				AlertType: TypeEndpointErrorRateHigh,
				Component: comp,
				Title:     "端点错误率过高",
				Message: fmt.Sprintf("应用 %s 端点 %s 最近 %d 分钟 5xx 错误率 %.1f%%（阈值 %.1f%%），窗口请求 %d 次（5xx %d 次），连续 %d 分钟超阈",
					st.app, st.endpoint, int(endpointPerfWindow/time.Minute),
					st.err5xx/st.requests*100, cfg.ErrorRate*100, int64(st.requests), int64(st.err5xx), cfg.Sustain),
			}); err != nil {
				errs = append(errs, err)
			}
		}
	}

	// 自动恢复：仍有未关闭告警但本轮未触发的组件（一次查询避免逐端点扫库）。
	open, err := e.store.ListOpenByTypes(ctx, []string{TypeEndpointLatencyHigh, TypeEndpointErrorRateHigh})
	if err != nil {
		return errors.Join(append(errs, fmt.Errorf("list open endpoint alerts: %w", err))...)
	}
	for i := range open {
		a := &open[i]
		if triggered[a.Component][a.AlertType] {
			continue
		}
		if _, err := e.AutoRecover(ctx, a.Component, a.AlertType); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ---------- Store 实现（metric_minute_aggregates 只读统计） ----------

// EndpointMinuteStats 实现 EndpointPerfStatsStore：请求/5xx 与时长直方图两条查询
// 在 Go 侧按（桶 × app × endpoint）合并（与 apm 查询同一读模型口径）。
func (s *Store) EndpointMinuteStats(ctx context.Context, start, end time.Time) ([]EndpointMinuteStat, error) {
	type key struct {
		bucket   time.Time
		app      string
		endpoint string
	}
	nb := len(metrics.DurationBucketsMs) + 1
	byKey := map[key]*EndpointMinuteStat{}
	get := func(b time.Time, app, endpoint string) *EndpointMinuteStat {
		k := key{b, app, endpoint}
		st := byKey[k]
		if st == nil {
			st = &EndpointMinuteStat{App: app, Endpoint: endpoint, BucketStart: b}
			byKey[k] = st
		}
		return st
	}

	// 请求数与 5xx（端点级 requests 指标，跨 status_class/action 合并）
	rows, err := s.db.Query(ctx, `
SELECT bucket_start, labels->>'app', labels->>'endpoint',
       COALESCE(SUM(value), 0),
       COALESCE(SUM(value) FILTER (WHERE labels->>'status_class' = '5xx'), 0)
FROM metric_minute_aggregates
WHERE metric = $1 AND bucket_start >= $2 AND bucket_start < $3
GROUP BY 1, 2, 3`, metrics.HTTPEndpointRequestsTotal, start, end)
	if err != nil {
		return nil, fmt.Errorf("endpoint requests: %w", err)
	}
	for rows.Next() {
		var b time.Time
		var app, endpoint string
		var req, err5xx float64
		if err := rows.Scan(&b, &app, &endpoint, &req, &err5xx); err != nil {
			rows.Close()
			return nil, fmt.Errorf("endpoint requests scan: %w", err)
		}
		st := get(b.UTC(), app, endpoint)
		st.Requests = req
		st.Err5xx = err5xx
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("endpoint requests iterate: %w", err)
	}

	// 时长直方图（extra.buckets 按桶序合并；缺失/NULL 时 lateral 为空集自动跳过）
	rows, err = s.db.Query(ctx, `
SELECT bucket_start, labels->>'app', labels->>'endpoint', b.idx, SUM(b.cnt::int)
FROM metric_minute_aggregates,
     LATERAL jsonb_array_elements_text(extra->'buckets') WITH ORDINALITY AS b(cnt, idx)
WHERE metric = $1 AND bucket_start >= $2 AND bucket_start < $3
GROUP BY 1, 2, 3`, metrics.HTTPEndpointDurationMs, start, end)
	if err != nil {
		return nil, fmt.Errorf("endpoint duration: %w", err)
	}
	for rows.Next() {
		var b time.Time
		var app, endpoint string
		var idx, cnt int
		if err := rows.Scan(&b, &app, &endpoint, &idx, &cnt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("endpoint duration scan: %w", err)
		}
		st := get(b.UTC(), app, endpoint)
		if st.DurBuckets == nil {
			st.DurBuckets = make([]int, nb)
		}
		if idx >= 1 && idx <= nb {
			st.DurBuckets[idx-1] += cnt
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("endpoint duration iterate: %w", err)
	}

	out := make([]EndpointMinuteStat, 0, len(byKey))
	for _, st := range byKey {
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].BucketStart.Equal(out[j].BucketStart) {
			return out[i].BucketStart.Before(out[j].BucketStart)
		}
		if out[i].App != out[j].App {
			return out[i].App < out[j].App
		}
		return out[i].Endpoint < out[j].Endpoint
	})
	return out, nil
}
