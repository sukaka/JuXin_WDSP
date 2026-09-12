// chstore_metrics_integration_test.go 运行时指标真实 ClickHouse 集成测试（阶段3 第二批）。
//
// 运行方式（与 chstore_integration_test.go 同一测试容器约定；25.8-alpine 镜像未设
// CLICKHOUSE_PASSWORD 时 default 用户仅允许 localhost 连接，宿主机访问必须显式设密码）：
//
//	docker run -d --name jiuzhang-ch-test -e CLICKHOUSE_PASSWORD=test -p 18123:9000 clickhouse/clickhouse-server:25.8-alpine
//	docker exec jiuzhang-ch-test clickhouse-client --password test --query "CREATE DATABASE IF NOT EXISTS apm"
//	APM_CH_TEST_DSN="clickhouse://default:test@127.0.0.1:18123/apm" \
//	  go test ./internal/apm -run TestCHStoreRuntime -count=1
//
// APM_CH_TEST_DSN 未设置时 t.Skip（环境不可用如实跳过，不 mock 冒充）。
// 测试自助建 schema：落地 001 + 003_metrics.sql（顺带验证交付 metrics DDL 可干净落地），
// 往 gauge/sum/histogram 三表灌合成指标点后跑真实查询。
package apm

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
)

// setupCHTestMetrics 建连 + 重建 apm 库 + 落地 001/003 schema。
func setupCHTestMetrics(t *testing.T) (context.Context, *Store, func()) {
	t.Helper()
	ctx, store, cancel := setupCHTest(t)
	applyCHSchema(t, ctx, store.ch.(chQuerier).conn, "003_metrics.sql")
	return ctx, store, cancel
}

// chTestMetric 合成指标点（gauge/sum 用 Value；histogram 用 Count/Sum 折算）。
type chTestMetric struct {
	ts       time.Time
	service  string
	instance string
	name     string
	descr    string
	unit     string
	scope    string
	attrs    map[string]string
	value    float64
}

func insertCHGaugePoints(t *testing.T, ctx context.Context, conn driver.Conn, pts []chTestMetric) {
	t.Helper()
	batch, err := conn.PrepareBatch(ctx, `INSERT INTO apm.otel_metrics_gauge
(ResourceAttributes, ScopeName, ServiceName, MetricName, MetricDescription, MetricUnit,
 Attributes, StartTimeUnix, TimeUnix, Value)`)
	if err != nil {
		t.Fatalf("prepare gauge batch: %v", err)
	}
	for _, p := range pts {
		res := map[string]string{}
		if p.instance != "" {
			res["service.instance.id"] = p.instance
		}
		if err := batch.Append(res, p.scope, p.service, p.name, p.descr, p.unit,
			p.attrs, p.ts, p.ts, p.value); err != nil {
			t.Fatalf("append gauge: %v", err)
		}
	}
	if err := batch.Send(); err != nil {
		t.Fatalf("send gauge batch: %v", err)
	}
}

func insertCHSumPoints(t *testing.T, ctx context.Context, conn driver.Conn, pts []chTestMetric) {
	t.Helper()
	batch, err := conn.PrepareBatch(ctx, `INSERT INTO apm.otel_metrics_sum
(ResourceAttributes, ScopeName, ServiceName, MetricName, MetricDescription, MetricUnit,
 Attributes, StartTimeUnix, TimeUnix, Value, AggregationTemporality, IsMonotonic)`)
	if err != nil {
		t.Fatalf("prepare sum batch: %v", err)
	}
	for _, p := range pts {
		res := map[string]string{}
		if p.instance != "" {
			res["service.instance.id"] = p.instance
		}
		if err := batch.Append(res, p.scope, p.service, p.name, p.descr, p.unit,
			p.attrs, p.ts, p.ts, p.value, 2, true); err != nil { // 2 = Cumulative
			t.Fatalf("append sum: %v", err)
		}
	}
	if err := batch.Send(); err != nil {
		t.Fatalf("send sum batch: %v", err)
	}
}

func insertCHHistogramPoints(t *testing.T, ctx context.Context, conn driver.Conn, pts []chTestMetric, count uint64, sum float64) {
	t.Helper()
	batch, err := conn.PrepareBatch(ctx, `INSERT INTO apm.otel_metrics_histogram
(ResourceAttributes, ScopeName, ServiceName, MetricName, MetricDescription, MetricUnit,
 Attributes, StartTimeUnix, TimeUnix, Count, Sum, AggregationTemporality)`)
	if err != nil {
		t.Fatalf("prepare histogram batch: %v", err)
	}
	for _, p := range pts {
		res := map[string]string{}
		if p.instance != "" {
			res["service.instance.id"] = p.instance
		}
		if err := batch.Append(res, p.scope, p.service, p.name, p.descr, p.unit,
			p.attrs, p.ts, p.ts, count, sum, 2); err != nil {
			t.Fatalf("append histogram: %v", err)
		}
	}
	if err := batch.Send(); err != nil {
		t.Fatalf("send histogram batch: %v", err)
	}
}

// findRuntimeMetric 按名取实例指标（不存在返回 nil）。
func findRuntimeMetric(inst RuntimeInstance, name string) *RuntimeMetric {
	for i := range inst.Metrics {
		if inst.Metrics[i].Name == name {
			return &inst.Metrics[i]
		}
	}
	return nil
}

// TestCHStoreRuntimeMetrics 真实 CH（001+003 schema）：合成两类实例的运行时指标
// （gauge 多点降采样、多序列求和 latest、sum 单调计数、histogram 折算），
// 验证实例发现/目录/points 组装与 service/instance_id 过滤。
func TestCHStoreRuntimeMetrics(t *testing.T) {
	ctx, store, cancel := setupCHTestMetrics(t)
	defer cancel()
	conn := store.ch.(chQuerier).conn

	base := time.Now().UTC().Add(-45 * time.Minute).Truncate(time.Second)
	const scope = "go.opentelemetry.io/contrib/instrumentation/runtime"

	// ---- inst-1（jiuzhang-server/test-host-1）----
	// go.goroutine.count：400 点（6s 间隔共 40 分钟，完整落入查询窗口），值单调递增 40→439
	gauges := []chTestMetric{}
	for i := 0; i < 400; i++ {
		gauges = append(gauges, chTestMetric{
			ts: base.Add(time.Duration(i*6) * time.Second), service: "jiuzhang-server", instance: "test-host-1",
			name: "go.goroutine.count", descr: "Count of live goroutines.", unit: "{goroutine}",
			scope: scope, attrs: map[string]string{}, value: float64(40 + i),
		})
	}
	// go.memory.used：两序列（go.memory.type=other/stack），latest 合计 = 100+56=156
	gauges = append(gauges,
		chTestMetric{base, "jiuzhang-server", "test-host-1", "go.memory.used", "Memory used by the Go runtime.",
			"By", scope, map[string]string{"go.memory.type": "other"}, 90},
		chTestMetric{base.Add(time.Minute), "jiuzhang-server", "test-host-1", "go.memory.used", "Memory used by the Go runtime.",
			"By", scope, map[string]string{"go.memory.type": "other"}, 100},
		chTestMetric{base, "jiuzhang-server", "test-host-1", "go.memory.used", "Memory used by the Go runtime.",
			"By", scope, map[string]string{"go.memory.type": "stack"}, 50},
		chTestMetric{base.Add(time.Minute), "jiuzhang-server", "test-host-1", "go.memory.used", "Memory used by the Go runtime.",
			"By", scope, map[string]string{"go.memory.type": "stack"}, 56},
	)
	// inst-2（同服务）单点
	gauges = append(gauges, chTestMetric{base, "jiuzhang-server", "test-host-2", "go.goroutine.count",
		"Count of live goroutines.", "{goroutine}", scope, map[string]string{}, 7})
	// 另一服务（过滤验证）
	gauges = append(gauges, chTestMetric{base, "other-svc", "test-host-9", "go.goroutine.count",
		"Count of live goroutines.", "{goroutine}", scope, map[string]string{}, 3})
	insertCHGaugePoints(t, ctx, conn, gauges)

	// go.memory.allocations：sum 单调累计计数
	insertCHSumPoints(t, ctx, conn, []chTestMetric{
		{base, "jiuzhang-server", "test-host-1", "go.memory.allocations",
			"Count of allocations to the heap by the application.", "{allocation}", scope, map[string]string{}, 1000},
		{base.Add(time.Minute), "jiuzhang-server", "test-host-1", "go.memory.allocations",
			"Count of allocations to the heap by the application.", "{allocation}", scope, map[string]string{}, 2500},
	})

	// go.schedule.duration：histogram（Count=100, Sum=0.5 → 折算均值 0.005）
	insertCHHistogramPoints(t, ctx, conn, []chTestMetric{
		{base, "jiuzhang-server", "test-host-1", "go.schedule.duration",
			"The time goroutines have spent in the scheduler in a runnable state before actually running.",
			"s", scope, map[string]string{}, 0},
	}, 100, 0.5)

	start, end := base.Add(-time.Hour), time.Now().UTC().Add(time.Minute)

	// ---------- 1) 无过滤：三实例（jiuzhang-server ×2 + other-svc ×1），按服务/实例升序 ----------
	out, err := store.ListRuntimeMetrics(ctx, RuntimeFilter{Start: start, End: end})
	if err != nil {
		t.Fatalf("runtime list: %v", err)
	}
	if out.DataSource != dataSourceOTel || len(out.Instances) != 3 {
		t.Fatalf("out = %+v", out)
	}
	if !strings.Contains(out.Note, "降采样") || strings.Contains(out.Note, "上限") {
		t.Errorf("note = %q", out.Note)
	}
	got := []string{}
	for _, in := range out.Instances {
		got = append(got, in.ServiceName+"/"+in.InstanceID)
	}
	want := []string{"jiuzhang-server/test-host-1", "jiuzhang-server/test-host-2", "other-svc/test-host-9"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("instances = %v, want %v", got, want)
		}
	}

	// ---------- 2) inst-1 指标集（按名升序 4 个）与口径 ----------
	inst1 := out.Instances[0]
	if len(inst1.Metrics) != 4 {
		t.Fatalf("inst-1 metrics = %v", inst1.Metrics)
	}
	names := []string{}
	for _, m := range inst1.Metrics {
		names = append(names, m.Name)
	}
	wantNames := []string{"go.goroutine.count", "go.memory.allocations", "go.memory.used", "go.schedule.duration"}
	for i := range wantNames {
		if names[i] != wantNames[i] {
			t.Fatalf("metric order = %v, want %v", names, wantNames)
		}
	}

	// goroutine gauge：latest=最后注入点 439；points 已降采样（≤201 且 >0），首末有序
	g := findRuntimeMetric(inst1, "go.goroutine.count")
	if g == nil || g.LatestValue != 439 || g.Unit != "{goroutine}" {
		t.Errorf("goroutine metric = %+v", g)
	}
	if !strings.Contains(g.Description, "Count of live goroutines.") ||
		!strings.Contains(g.Description, "来源 scope: "+scope) {
		t.Errorf("goroutine description = %q", g.Description)
	}
	if len(g.Points) == 0 || len(g.Points) > 201 {
		t.Errorf("goroutine points = %d, want 1~201（窗口等分降采样）", len(g.Points))
	}
	for i := 1; i < len(g.Points); i++ {
		if !g.Points[i].Ts.After(g.Points[i-1].Ts) {
			t.Errorf("points not strictly ascending at %d: %v", i, g.Points)
			break
		}
	}
	if len(g.Points) > 1 && g.Points[0].Value > g.Points[len(g.Points)-1].Value {
		t.Errorf("points should follow monotonic source: first=%v last=%v",
			g.Points[0].Value, g.Points[len(g.Points)-1].Value)
	}

	// memory.used：两序列 latest 求和 100+56=156
	m := findRuntimeMetric(inst1, "go.memory.used")
	if m == nil || m.LatestValue != 156 {
		t.Errorf("memory metric = %+v, want latest 156（other 100 + stack 56 求和）", m)
	}

	// allocations（sum 单调计数器）：latest=2500
	a := findRuntimeMetric(inst1, "go.memory.allocations")
	if a == nil || a.LatestValue != 2500 {
		t.Errorf("allocations metric = %+v, want latest 2500", a)
	}

	// schedule.duration（histogram 折算 Sum/Count）：latest=0.005，description 附折算说明
	h := findRuntimeMetric(inst1, "go.schedule.duration")
	if h == nil || h.LatestValue != 0.005 {
		t.Errorf("histogram metric = %+v, want latest 0.005", h)
	}
	if !strings.Contains(h.Description, "直方图按 Sum/Count 折算均值") {
		t.Errorf("histogram description = %q, want 折算说明", h.Description)
	}

	// inst-2 单指标单点
	inst2 := out.Instances[1]
	if len(inst2.Metrics) != 1 || inst2.Metrics[0].LatestValue != 7 || len(inst2.Metrics[0].Points) != 1 {
		t.Errorf("inst-2 = %+v", inst2)
	}

	// ---------- 3) service 过滤 ----------
	f := RuntimeFilter{Start: start, End: end, Service: "jiuzhang-server"}
	out, err = store.ListRuntimeMetrics(ctx, f)
	if err != nil || len(out.Instances) != 2 {
		t.Errorf("service filter = %+v, err=%v", out, err)
	}
	for _, in := range out.Instances {
		if in.ServiceName != "jiuzhang-server" {
			t.Errorf("unexpected service %q", in.ServiceName)
		}
	}

	// ---------- 4) instance_id 过滤 ----------
	f = RuntimeFilter{Start: start, End: end, InstanceID: "test-host-9"}
	out, err = store.ListRuntimeMetrics(ctx, f)
	if err != nil || len(out.Instances) != 1 || out.Instances[0].InstanceID != "test-host-9" {
		t.Errorf("instance filter = %+v, err=%v", out, err)
	}

	// ---------- 5) 时间窗外查不到（窗口约束生效） ----------
	out, err = store.ListRuntimeMetrics(ctx, RuntimeFilter{
		Start: base.Add(-2 * time.Hour), End: base.Add(-time.Hour)})
	if err != nil || len(out.Instances) != 0 || out.DataSource != dataSourceOTel {
		t.Errorf("out-of-window = %+v, err=%v", out, err)
	}
}
