// chstore_metrics_test.go 阶段3 第二批运行时指标单测：查询构造（时间窗恒在、
// service/instance_id 过滤、实例/指标/点上限、桶宽计算）、description 组装、
// DSN 缺失与 CH 各阶段故障降级、三阶段组装（实例→目录→点序列回填与叉积剔除）。
// 不依赖真实 CH——CHQuerier/CHRows fake 复用 chstore_test.go。
package apm

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// ---------- 查询构造 ----------

// TestRuntimeQueryBuilders 三类查询构造：时间窗恒在 WHERE；过滤参数化；
// 实例 +1 探测行；目录上限兜底；点查询桶宽整数插值 + LIMIT BY/全局 LIMIT 兜底。
func TestRuntimeQueryBuilders(t *testing.T) {
	start, end := chTestWindow() // 1h 窗口

	t.Run("instances", func(t *testing.T) {
		sql, args := buildRuntimeInstancesQuery(RuntimeFilter{Start: start, End: end})
		for _, w := range []string{
			"apm.otel_metrics_gauge", "apm.otel_metrics_sum", "apm.otel_metrics_histogram",
			"TimeUnix >= ?", "TimeUnix < ?", "SELECT DISTINCT ServiceName, instance_id",
			"LIMIT 21",
		} {
			if !strings.Contains(sql, w) {
				t.Errorf("instances SQL missing %q:\n%s", w, sql)
			}
		}
		if len(args) != 6 { // 窗口参数三分支各一遍
			t.Errorf("instances args = %d, want 6", len(args))
		}
	})

	t.Run("filters pushed to all branches", func(t *testing.T) {
		f := RuntimeFilter{Start: start, End: end, Service: "order-svc", InstanceID: "host-a-1"}
		sql, args := buildRuntimeCatalogQuery(f)
		// service/instance 过滤必须在全部三个 UNION 分支各出现一次
		if got := strings.Count(sql, "ServiceName = ?"); got != 3 {
			t.Errorf("ServiceName filter count = %d, want 3:\n%s", got, sql)
		}
		if got := strings.Count(sql, "ResourceAttributes['service.instance.id'] = ?"); got != 3 {
			t.Errorf("instance filter count = %d, want 3:\n%s", got, sql)
		}
		if len(args) != 12 { // (start,end,service,instance) × 3 分支
			t.Errorf("catalog args = %d, want 12", len(args))
		}
		if !strings.Contains(sql, "argMax(Value, TimeUnix)") || !strings.Contains(sql, "sum(series_latest)") {
			t.Errorf("catalog must derive latest per series then sum:\n%s", sql)
		}
	})

	t.Run("points", func(t *testing.T) {
		f := RuntimeFilter{Start: start, End: end}
		services := []string{"svc-a"}
		names := []string{"go.goroutine.count"}
		sql, args := buildRuntimePointsQuery(f, services, names, runtimeBucketSeconds(end.Sub(start)))
		for _, w := range []string{
			"toIntervalSecond(18)", // 1h/200 = 18s 桶宽（整数插值，非用户输入）
			"avg(Value)", "sum(v)",
			"ServiceName IN (?)", "MetricName IN (?)",
			"LIMIT 201 BY", "LIMIT 100000",
		} {
			if !strings.Contains(sql, w) {
				t.Errorf("points SQL missing %q:\n%s", w, sql)
			}
		}
		if len(args) != 12 { // (start,end,IN services,IN names) × 3 分支
			t.Errorf("points args = %d, want 12", len(args))
		}
		// 全部过滤走占位符，不把过滤值拼进 SQL
		if strings.Contains(sql, "svc-a") || strings.Contains(sql, "go.goroutine.count'") {
			t.Errorf("filter values must be bound, not interpolated:\n%s", sql)
		}
	})
}

// TestRuntimeBucketSeconds 桶宽：窗口等分 ≤200 桶，最小 1 秒。
func TestRuntimeBucketSeconds(t *testing.T) {
	cases := []struct {
		window time.Duration
		want   int64
	}{
		{time.Hour, 18},                      // 3600/200
		{24 * time.Hour, 432},                // 86400/200
		{time.Minute, 1},                     // 下限 1s
		{59 * time.Second, 1},                // 不足 200s 窗口仍为 1s
		{201 * time.Second, 2},               // 向上取整
		{23*time.Hour + 59*time.Minute, 432}, // 上限窗口内桶数 ≤201
	}
	for _, c := range cases {
		if got := runtimeBucketSeconds(c.window); got != c.want {
			t.Errorf("bucketSeconds(%v) = %d, want %d", c.window, got, c.want)
		}
		// 桶数必须 ≤201（含两端边界桶）
		if n := int64(c.window.Seconds())/runtimeBucketSeconds(c.window) + 1; n > 201 {
			t.Errorf("window %v yields %d buckets > 201", c.window, n)
		}
	}
}

// TestRuntimeDescription description 组装：来源 scope 与直方图折算说明。
func TestRuntimeDescription(t *testing.T) {
	cases := []struct {
		descr, scope, source, want string
	}{
		{"Count of live goroutines.", "go.opentelemetry.io/contrib/instrumentation/runtime", "gauge",
			"Count of live goroutines.（来源 scope: go.opentelemetry.io/contrib/instrumentation/runtime）"},
		{"Scheduler latency.", "runtime", "histogram",
			"Scheduler latency.（来源 scope: runtime；直方图按 Sum/Count 折算均值）"},
		{"plain", "", "sum", "plain"},
		{"", "scope-x", "gauge", "来源 scope: scope-x"},
		{"", "", "gauge", ""},
	}
	for _, c := range cases {
		if got := runtimeDescription(c.descr, c.scope, c.source); got != c.want {
			t.Errorf("runtimeDescription(%q,%q,%q) = %q, want %q", c.descr, c.scope, c.source, got, c.want)
		}
	}
}

// ---------- 降级 ----------

// TestRuntimeNoCH DSN 缺失降级：querier=nil → 空实例 + agentless + note。
func TestRuntimeNoCH(t *testing.T) {
	s := &Store{} // ch 为 nil
	start, end := chTestWindow()
	out, err := s.ListRuntimeMetrics(context.Background(), RuntimeFilter{Start: start, End: end})
	if err != nil {
		t.Fatalf("degraded runtime must not error: %v", err)
	}
	if out.DataSource != dataSourceAgentless || len(out.Instances) != 0 || out.Note == "" {
		t.Errorf("degraded = %+v", out)
	}
	if out.Instances == nil {
		t.Error("instances must be empty array not nil")
	}
}

// TestRuntimeCHErrors CH 各阶段故障均降级为空实例（不 500）。
func TestRuntimeCHErrors(t *testing.T) {
	start, end := chTestWindow()
	f := RuntimeFilter{Start: start, End: end}

	t.Run("instances query error", func(t *testing.T) {
		s := &Store{ch: &fakeCHQuerier{err: errors.New("ch down")}}
		out, err := s.ListRuntimeMetrics(context.Background(), f)
		if err != nil || out.DataSource != dataSourceAgentless || len(out.Instances) != 0 {
			t.Errorf("instances error degrade = %+v, err=%v", out, err)
		}
	})
	t.Run("catalog query error", func(t *testing.T) {
		q := &fakeCHQuerier{results: []*fakeCHRows{
			{scans: [][]any{{"svc-a", "inst-1"}}}, // 实例发现成功
		}}
		q2 := &flakySecondQuery{inner: q}
		s := &Store{ch: q2}
		out, err := s.ListRuntimeMetrics(context.Background(), f)
		if err != nil || out.DataSource != dataSourceAgentless {
			t.Errorf("catalog error degrade = %+v, err=%v", out, err)
		}
	})
	t.Run("points query error", func(t *testing.T) {
		q := &fakeCHQuerier{results: []*fakeCHRows{
			{scans: [][]any{{"svc-a", "inst-1"}}},
			{scans: [][]any{{"svc-a", "inst-1", "go.goroutine.count", "{goroutine}",
				"Count of live goroutines.", "scope-x", "gauge", 42.0}}},
		}}
		q3 := &flakyNthQuery{inner: q, failAt: 3}
		s := &Store{ch: q3}
		out, err := s.ListRuntimeMetrics(context.Background(), f)
		if err != nil || out.DataSource != dataSourceAgentless {
			t.Errorf("points error degrade = %+v, err=%v", out, err)
		}
	})
	t.Run("rows iterate error", func(t *testing.T) {
		q := &fakeCHQuerier{results: []*fakeCHRows{
			{err: errors.New("stream broken")},
		}}
		s := &Store{ch: q}
		out, err := s.ListRuntimeMetrics(context.Background(), f)
		if err != nil || out.DataSource != dataSourceAgentless {
			t.Errorf("iterate error degrade = %+v, err=%v", out, err)
		}
	})
}

// flakyNthQuery 第 failAt 次 Query 失败（点序列阶段故障注入）。
type flakyNthQuery struct {
	inner  *fakeCHQuerier
	failAt int
	n      int
}

func (f *flakyNthQuery) Query(ctx context.Context, query string, args ...any) (CHRows, error) {
	f.n++
	if f.n == f.failAt {
		return nil, errors.New("ch query down")
	}
	return f.inner.Query(ctx, query, args...)
}

// ---------- 组装 ----------

// TestRuntimeAssemble 三阶段组装：实例 → 目录（latest 多序列求和、description 组装、
// 每实例 20 指标上限）→ 点序列回填（仅已选实例对，叉积行剔除）。
func TestRuntimeAssemble(t *testing.T) {
	start, end := chTestWindow()
	ts := time.Date(2026, 8, 30, 11, 30, 0, 0, time.UTC)

	q := &fakeCHQuerier{results: []*fakeCHRows{
		// 实例发现：两实例
		{scans: [][]any{
			{"svc-a", "inst-1"},
			{"svc-a", "inst-2"},
		}},
		// 目录：inst-1 两指标（go.memory.used 两条序列求和 100+56=156），inst-2 一指标
		{scans: [][]any{
			{"svc-a", "inst-1", "go.goroutine.count", "{goroutine}", "Count of live goroutines.", "scope-x", "gauge", 42.123456},
			{"svc-a", "inst-1", "go.memory.used", "By", "Memory used.", "scope-x", "gauge", 156.0},
			{"svc-a", "inst-2", "go.goroutine.count", "{goroutine}", "Count of live goroutines.", "scope-x", "gauge", 7.0},
		}},
		// 点序列：inst-1 goroutine 两点 + memory 一点；一行未选叉积（inst-2 × go.memory.used）必须剔除
		{scans: [][]any{
			{"svc-a", "inst-1", "go.goroutine.count", ts, 40.11111},
			{"svc-a", "inst-1", "go.goroutine.count", ts.Add(18 * time.Second), 44.0},
			{"svc-a", "inst-1", "go.memory.used", ts, 156.0},
			{"svc-a", "inst-2", "go.memory.used", ts, 999.0}, // 目录未选（inst-2 无此指标），剔除
		}},
	}}
	s := &Store{ch: q}
	out, err := s.ListRuntimeMetrics(context.Background(), RuntimeFilter{Start: start, End: end})
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if out.DataSource != dataSourceOTel || len(out.Instances) != 2 {
		t.Fatalf("out = %+v", out)
	}
	if !strings.Contains(out.Note, "降采样") {
		t.Errorf("note = %q", out.Note)
	}

	i1 := out.Instances[0]
	if i1.InstanceID != "inst-1" || i1.ServiceName != "svc-a" || len(i1.Metrics) != 2 {
		t.Fatalf("inst-1 = %+v", i1)
	}
	// 指标按名升序：go.goroutine.count 在前
	g := i1.Metrics[0]
	if g.Name != "go.goroutine.count" || g.Unit != "{goroutine}" || g.LatestValue != 42.123 {
		t.Errorf("goroutine metric = %+v", g)
	}
	if !strings.Contains(g.Description, "来源 scope: scope-x") {
		t.Errorf("description = %q, want scope suffix", g.Description)
	}
	if len(g.Points) != 2 || !g.Points[0].Ts.Equal(ts) || g.Points[0].Value != 40.111 {
		t.Errorf("goroutine points = %+v", g.Points)
	}
	m := i1.Metrics[1]
	if m.Name != "go.memory.used" || m.LatestValue != 156 || len(m.Points) != 1 {
		t.Errorf("memory metric = %+v", m)
	}

	i2 := out.Instances[1]
	if len(i2.Metrics) != 1 || i2.Metrics[0].Name != "go.goroutine.count" || len(i2.Metrics[0].Points) != 0 {
		t.Errorf("inst-2 = %+v（未选叉积点行必须剔除）", i2)
	}
	if len(q.queries) != 3 {
		t.Fatalf("queries = %d, want 3（实例/目录/点序列）", len(q.queries))
	}
}

// TestRuntimeInstanceTruncated 实例截断：返回 21 行时只保留 20 并在 note 标注。
func TestRuntimeInstanceTruncated(t *testing.T) {
	start, end := chTestWindow()
	scans := make([][]any, 0, maxRuntimeInstances+1)
	for i := 0; i < maxRuntimeInstances+1; i++ {
		scans = append(scans, []any{"svc-a", fmt.Sprintf("inst-%02d", i)})
	}
	s := &Store{ch: &fakeCHQuerier{results: []*fakeCHRows{{scans: scans}}}}
	out, err := s.ListRuntimeMetrics(context.Background(), RuntimeFilter{Start: start, End: end})
	if err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if len(out.Instances) != maxRuntimeInstances {
		t.Errorf("instances = %d, want %d", len(out.Instances), maxRuntimeInstances)
	}
	if !strings.Contains(out.Note, "上限") {
		t.Errorf("note = %q, want truncation suffix", out.Note)
	}
	// 截断时目录/点查询不再执行（实例已选满且目录行全弃——但目录查询仍会跑；
	// 此处只断言点查询发生在有指标时：无目录行 → 只有 2 次查询）
	if q, ok := s.ch.(*fakeCHQuerier); ok && len(q.queries) != 2 {
		t.Errorf("queries = %d, want 2（无指标目录行时跳过点序列查询）", len(q.queries))
	}
}

// TestRuntimeEmptyWindow otel 在线但窗口内无数据：空实例 + otel 口径。
func TestRuntimeEmptyWindow(t *testing.T) {
	start, end := chTestWindow()
	s := &Store{ch: &fakeCHQuerier{results: []*fakeCHRows{{}}}} // 实例发现返回空
	out, err := s.ListRuntimeMetrics(context.Background(), RuntimeFilter{Start: start, End: end})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if out.DataSource != dataSourceOTel || len(out.Instances) != 0 || out.Instances == nil {
		t.Errorf("empty window = %+v", out)
	}
}
