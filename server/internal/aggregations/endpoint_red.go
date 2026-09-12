// endpoint_red.go APM 阶段1 端点级 RED 分钟聚合（决策：docs/APM_STAGE0_ADR.md D7/D8/D9）。
//
// 数据源为管道 A（guard 全量访问日志 access_logs 表；管道 B 应用级 RED 见 accesslog.go）。
// 每分钟任务随 RunMinute 同节奏回看重算当前分钟与上一分钟（迟到修正口径一致），
// 窗口整段重算后覆盖落库（delete+insert 同事务，重跑/重算不重复——Top-N 成员随迟到
// 数据漂移时不残留上一轮标签行，比裸 upsert 更严格，语义与既有分钟任务相同）。
//
// 维度：app（application_id join applications 反解 code；NULL → unknown，与管道 B 一致）、
// endpoint（endpoint_key，空 → __UNCLASSIFIED__ 治理桶，不按原始 path 聚合）、
// status_class（复用 accesslog.go statusClass 2xx/4xx/5xx 口径）、action（小写
// allow/observe/block；历史空串按 ALLOW 归一）。
// 基数护栏（ADR D7）：每应用每分钟桶按请求数取 Top-EndpointREDTopN 端点，其余并入
// __OTHER__；__UNCLASSIFIED__/__OTHER__ 为保留桶名，豁免 Top-N 竞争、始终保留。
// 标签值长护栏：endpoint 超 128 字符（metrics 标签值上限）直接并入 __OTHER__。
// 网关不会上报保留桶名（服务端保留字），同名 endpoint_key 按设计折叠进保留桶。
//
// 指标（metrics 包常量）：http_endpoint_requests_total（请求数）、
// http_endpoint_duration_ms（duration_ms 直方图，复用 DurationBucketsMs，
// extra.buckets）、http_endpoint_ttfb_ms（ttfb_ms 直方图，仅样本数>0 时产出，
// 旧网关无 ttfb_ms 字段时不产出该指标）。
// 小时/天 rollup（jobs.go rollup）按 (metric, labels) 通用合并 extra.buckets，
// 新指标无需登记即自动生效。
package aggregations

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jiuzhang-waf/server/internal/metrics"
)

// EndpointREDTopN 每应用每分钟桶保留的端点数上限（ADR D7，默认 200）。
const EndpointREDTopN = 200

// 端点保留桶名（服务端保留字，网关 endpoint_key 不会与之同名）。
const (
	EndpointOther        = "__OTHER__"        // Top-N 之外的尾端点与超长标签值合并桶
	EndpointUnclassified = "__UNCLASSIFIED__" // endpoint_key 缺失（未归类）治理桶
)

// endpointREDMetrics 本任务写出的三个指标名（窗口覆盖删除范围）。
var endpointREDMetrics = []string{
	metrics.HTTPEndpointRequestsTotal,
	metrics.HTTPEndpointDurationMs,
	metrics.HTTPEndpointTTFBMs,
}

// endpointBucketFilters 生成列 col 的直方图计数 FILTER 子句（桶界取
// metrics.DurationBucketsMs 代码常量，非用户输入；产出 len+1 个计数列，
// 末桶为 > 最大桶界；NULL 行比较为 NULL 自动落入无桶——ttfb_ms 可空语义由此保证）。
func endpointBucketFilters(col string) string {
	var b strings.Builder
	prev := 0
	for i, le := range metrics.DurationBucketsMs {
		if i > 0 {
			b.WriteString(", ")
		}
		if i == 0 {
			fmt.Fprintf(&b, "count(*) FILTER (WHERE %s <= %d)", col, le)
		} else {
			fmt.Fprintf(&b, "count(*) FILTER (WHERE %s > %d AND %s <= %d)", col, prev, col, le)
		}
		prev = le
	}
	fmt.Fprintf(&b, ", count(*) FILTER (WHERE %s > %d)", col, prev)
	return b.String()
}

// endpointREDQuery 分钟窗口端点分组查询（SQL 只做分组与桶计数，语义加工全部在
// buildEndpointREDRows 完成，便于纯逻辑单测）。GROUP BY 原始 response_status/waf_action
// 而非 SQL CASE：status_class 口径直接复用 accesslog.go statusClass，无双份实现。
var endpointREDQuery = `
SELECT COALESCE(a.code,'unknown'), COALESCE(l.endpoint_key,''), l.response_status, l.waf_action, count(*),
  ` + endpointBucketFilters("duration_ms") + `,
  ` + endpointBucketFilters("ttfb_ms") + `
FROM access_logs l LEFT JOIN applications a ON a.id = l.application_id
WHERE l.occurred_at >= $1 AND l.occurred_at < $2
GROUP BY 1,2,3,4`

// endpointREDRawRow SQL 分组原始行（dur/ttfb 长度 = len(DurationBucketsMs)+1）。
type endpointREDRawRow struct {
	app      string
	endpoint string // 原始 endpoint_key（空串 = 未归类）
	status   int
	action   string // 原始 waf_action（'' / 'ALLOW' / 'OBSERVE' / 'BLOCK'）
	count    int64
	dur      []int
	ttfb     []int
}

// endpointGroupKey 聚合维度键。
type endpointGroupKey struct {
	app, endpoint, statusClass, action string
}

// endpointGroupVal 组内累计值（dur/ttfb 为直方图桶计数）。
type endpointGroupVal struct {
	count     float64
	dur, ttfb []int
}

func newEndpointGroupVal() *endpointGroupVal {
	n := len(metrics.DurationBucketsMs) + 1
	return &endpointGroupVal{dur: make([]int, n), ttfb: make([]int, n)}
}

func (g *endpointGroupVal) add(r endpointREDRawRow) {
	g.count += float64(r.count)
	for i := range g.dur {
		g.dur[i] += r.dur[i]
	}
	for i := range g.ttfb {
		g.ttfb[i] += r.ttfb[i]
	}
}

func sumBuckets(counts []int) float64 {
	var t float64
	for _, c := range counts {
		t += float64(c)
	}
	return t
}

// normalizeEndpointAction waf_action → 指标 action 标签（小写三态；历史空串与
// 未知脏值按 ALLOW 口径归一，与 accesslogs.NormalizeWAFAction 写入侧归一对应）。
func normalizeEndpointAction(action string) string {
	switch action {
	case "BLOCK":
		return "block"
	case "OBSERVE":
		return "observe"
	default:
		return "allow"
	}
}

// buildEndpointREDRows 纯逻辑：SQL 分组原始行 → 聚合行（状态分类、动作归一、
// 未归类桶、Top-N 护栏与 __OTHER__ 合并）。输出为窗口全量重算结果，不含任何
// 跨窗口状态——同一窗口输入重复计算输出相同（幂等），由调用方整段覆盖落库。
func buildEndpointREDRows(raw []endpointREDRawRow, topN int) []AggRow {
	if topN <= 0 {
		topN = EndpointREDTopN
	}
	groups := map[endpointGroupKey]*endpointGroupVal{}
	endpointTotals := map[string]map[string]float64{} // app -> endpoint -> 请求数
	for _, r := range raw {
		ep := r.endpoint
		switch {
		case ep == "":
			ep = EndpointUnclassified
		case len(ep) > 128: // metrics 标签值上限（allowedLabelKeys 值长 ≤128）
			ep = EndpointOther
		}
		k := endpointGroupKey{r.app, ep, statusClass(r.status), normalizeEndpointAction(r.action)}
		g := groups[k]
		if g == nil {
			g = newEndpointGroupVal()
			groups[k] = g
		}
		g.add(r)
		m := endpointTotals[r.app]
		if m == nil {
			m = map[string]float64{}
			endpointTotals[r.app] = m
		}
		m[ep] += float64(r.count)
	}

	// Top-N 护栏：每应用按请求数排名（同数按端点名升序，结果确定），
	// 保留桶（__UNCLASSIFIED__/__OTHER__）豁免竞争、始终保留。
	keep := map[string]map[string]bool{}
	for app, eps := range endpointTotals {
		type kv struct {
			ep string
			c  float64
		}
		list := make([]kv, 0, len(eps))
		for ep, c := range eps {
			list = append(list, kv{ep, c})
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].c != list[j].c {
				return list[i].c > list[j].c
			}
			return list[i].ep < list[j].ep
		})
		kept := map[string]bool{EndpointUnclassified: true, EndpointOther: true}
		n := 0
		for _, e := range list {
			if e.ep == EndpointUnclassified || e.ep == EndpointOther {
				continue
			}
			if n >= topN {
				break
			}
			kept[e.ep] = true
			n++
		}
		keep[app] = kept
	}

	var out []AggRow
	other := map[endpointGroupKey]*endpointGroupVal{} // 尾端点合并（endpoint=__OTHER__）
	for k, g := range groups {
		if !keep[k.app][k.endpoint] {
			kk := endpointGroupKey{k.app, EndpointOther, k.statusClass, k.action}
			og := other[kk]
			if og == nil {
				og = newEndpointGroupVal()
				other[kk] = og
			}
			og.count += g.count
			for i := range og.dur {
				og.dur[i] += g.dur[i]
				og.ttfb[i] += g.ttfb[i]
			}
			continue
		}
		out = appendEndpointREDRows(out, k, g)
	}
	for k, g := range other {
		out = appendEndpointREDRows(out, k, g)
	}
	return out
}

// appendEndpointREDRows 产出一个维度组合的三指标行（ttfb 无样本时不产出，
// 旧网关数据只有 requests/duration 两行）。
func appendEndpointREDRows(out []AggRow, k endpointGroupKey, g *endpointGroupVal) []AggRow {
	labels := map[string]string{
		"app": k.app, "endpoint": k.endpoint, "status_class": k.statusClass, "action": k.action,
	}
	out = append(out, AggRow{Metric: metrics.HTTPEndpointRequestsTotal, Labels: labels, Value: g.count})
	out = append(out, AggRow{Metric: metrics.HTTPEndpointDurationMs, Labels: labels,
		Value: sumBuckets(g.dur), Extra: map[string]interface{}{"buckets": g.dur}})
	if t := sumBuckets(g.ttfb); t > 0 {
		out = append(out, AggRow{Metric: metrics.HTTPEndpointTTFBMs, Labels: labels,
			Value: t, Extra: map[string]interface{}{"buckets": g.ttfb}})
	}
	return out
}

// RunEndpointRED 端点级 RED 分钟聚合入口（迟到修正口径与 RunMinute 一致：
// 重算当前分钟与上一分钟）。执行记录写 aggregation_jobs（ENDPOINT_RED）。
func (j *Jobs) RunEndpointRED(ctx context.Context, now time.Time) error {
	bucket := now.UTC().Truncate(time.Minute)
	total := 0
	for _, b := range []time.Time{bucket.Add(-time.Minute), bucket} {
		n, err := j.aggregateEndpointREDMinute(ctx, b)
		if err != nil {
			_ = j.store.recordJob(ctx, "ENDPOINT_RED", b, b.Add(time.Minute), "FAILED", n, err.Error())
			return err
		}
		total += n
	}
	return j.store.recordJob(ctx, "ENDPOINT_RED", bucket.Add(-time.Minute), bucket.Add(time.Minute), "SUCCESS", total, "")
}

// aggregateEndpointREDMinute 重算指定分钟桶并覆盖落库：先删本桶三个端点指标
// 旧行再插入重算结果（同事务），崩溃重跑/迟到修正不重复累计。
func (j *Jobs) aggregateEndpointREDMinute(ctx context.Context, bucket time.Time) (int, error) {
	start, end := bucket, bucket.Add(time.Minute)
	rows, err := j.store.db.Query(ctx, endpointREDQuery, start, end)
	if err != nil {
		return 0, fmt.Errorf("endpoint red query: %w", err)
	}
	nb := len(metrics.DurationBucketsMs) + 1
	var raw []endpointREDRawRow
	for rows.Next() {
		var r endpointREDRawRow
		dur := make([]int64, nb)
		ttfb := make([]int64, nb)
		dest := []interface{}{&r.app, &r.endpoint, &r.status, &r.action, &r.count}
		for i := range dur {
			dest = append(dest, &dur[i])
		}
		for i := range ttfb {
			dest = append(dest, &ttfb[i])
		}
		if err := rows.Scan(dest...); err != nil {
			rows.Close()
			return 0, fmt.Errorf("endpoint red scan: %w", err)
		}
		r.dur = make([]int, nb)
		r.ttfb = make([]int, nb)
		for i := range dur {
			r.dur[i] = int(dur[i])
			r.ttfb[i] = int(ttfb[i])
		}
		raw = append(raw, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("endpoint red iterate: %w", err)
	}

	agg := buildEndpointREDRows(raw, EndpointREDTopN)

	tx, err := j.store.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
DELETE FROM metric_minute_aggregates WHERE bucket_start = $1 AND metric = ANY($2)`,
		bucket, endpointREDMetrics); err != nil {
		return 0, fmt.Errorf("endpoint red delete: %w", err)
	}
	n := 0
	for _, r := range agg {
		if _, err := tx.Exec(ctx, `
INSERT INTO metric_minute_aggregates (bucket_start, metric, labels, value, extra, updated_at)
VALUES ($1, $2, $3, $4, $5, now())`,
			bucket, r.Metric, labelsJSON(r.Labels), r.Value, extraJSON(r.Extra)); err != nil {
			return n, fmt.Errorf("endpoint red insert: %w", err)
		}
		n++
	}
	return n, tx.Commit(ctx)
}
