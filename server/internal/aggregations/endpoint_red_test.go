// endpoint_red_test.go APM 阶段1 端点级 RED 聚合纯逻辑单测（不依赖数据库，
// 风格同 call_edges_test.go；DB 侧窗口覆盖语义由 aggregateEndpointREDMinute
// delete+insert 同事务保证，集成验证经 tests 包全量迁移 + 真实 PG）。
package aggregations

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/metrics"
)

// bucketsOf 按 DurationBucketsMs 生成桶计数（测试输入便捷构造）。
func bucketsOf(vals ...int) []int {
	b := make([]int, len(metrics.DurationBucketsMs)+1)
	for _, v := range vals {
		b[metrics.BucketIndex(float64(v))]++
	}
	return b
}

func rawEndpointRow(app, ep string, status int, action string, count int64, dur, ttfb []int) endpointREDRawRow {
	if dur == nil {
		dur = make([]int, len(metrics.DurationBucketsMs)+1)
	}
	if ttfb == nil {
		ttfb = make([]int, len(metrics.DurationBucketsMs)+1)
	}
	return endpointREDRawRow{app: app, endpoint: ep, status: status, action: action, count: count, dur: dur, ttfb: ttfb}
}

// findEndpointRow 按指标 + 全标签找聚合行。
func findEndpointRow(t *testing.T, rows []AggRow, metric, app, ep, sc, action string) *AggRow {
	t.Helper()
	for i := range rows {
		r := &rows[i]
		if r.Metric == metric && r.Labels["app"] == app && r.Labels["endpoint"] == ep &&
			r.Labels["status_class"] == sc && r.Labels["action"] == action {
			return r
		}
	}
	t.Fatalf("row %s %s/%s/%s/%s not found in %+v", metric, app, ep, sc, action, rows)
	return nil
}

func endpointRowCount(rows []AggRow, metric string) int {
	n := 0
	for _, r := range rows {
		if r.Metric == metric {
			n++
		}
	}
	return n
}

// canonicalEndpointRows 聚合行 → 确定表示（map key = metric|labels），供重跑对比。
func canonicalEndpointRows(rows []AggRow) map[string]AggRow {
	out := map[string]AggRow{}
	for _, r := range rows {
		k := fmt.Sprintf("%s|%s|%s|%s|%s", r.Metric,
			r.Labels["app"], r.Labels["endpoint"], r.Labels["status_class"], r.Labels["action"])
		out[k] = r
	}
	return out
}

// TestBuildEndpointREDRowsBasic 基本分组：按 (app, endpoint, status_class, action)
// 产 requests/duration/ttfb 三指标；status_class 复用 accesslog.go statusClass 口径；
// 无 ttfb 样本的组不产出 ttfb 行。
func TestBuildEndpointREDRowsBasic(t *testing.T) {
	raw := []endpointREDRawRow{
		rawEndpointRow("shop", "GET /a", 200, "ALLOW", 2, bucketsOf(3, 30), bucketsOf(2, 20)),
		rawEndpointRow("shop", "GET /a", 500, "BLOCK", 1, bucketsOf(900), nil),
	}
	rows := buildEndpointREDRows(raw, EndpointREDTopN)

	req := findEndpointRow(t, rows, metrics.HTTPEndpointRequestsTotal, "shop", "GET /a", "2xx", "allow")
	if req.Value != 2 {
		t.Errorf("2xx allow requests = %v, want 2", req.Value)
	}
	findEndpointRow(t, rows, metrics.HTTPEndpointRequestsTotal, "shop", "GET /a", "5xx", "block")

	dur := findEndpointRow(t, rows, metrics.HTTPEndpointDurationMs, "shop", "GET /a", "2xx", "allow")
	if dur.Value != 2 || !reflect.DeepEqual(dur.Extra["buckets"], []int{1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0}) {
		t.Errorf("duration row wrong: %+v", dur)
	}
	ttfb := findEndpointRow(t, rows, metrics.HTTPEndpointTTFBMs, "shop", "GET /a", "2xx", "allow")
	if ttfb.Value != 2 || !reflect.DeepEqual(ttfb.Extra["buckets"], []int{1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Errorf("ttfb row wrong: %+v", ttfb)
	}
	// 全部 ttfb 为 NULL 的组（旧网关数据）：只有 requests + duration 两行
	if got := endpointRowCount(rows, metrics.HTTPEndpointTTFBMs); got != 1 {
		t.Errorf("ttfb rows = %d, want 1（无样本组不产出）", got)
	}
}

// TestBuildEndpointREDRowsStatusClass 状态分类口径与 accesslog.go statusClass 一致
// （2xx/4xx/5xx，3xx 归 2xx）。
func TestBuildEndpointREDRowsStatusClass(t *testing.T) {
	raw := []endpointREDRawRow{
		rawEndpointRow("shop", "GET /a", 301, "ALLOW", 1, bucketsOf(1), nil),
		rawEndpointRow("shop", "GET /a", 404, "ALLOW", 1, bucketsOf(1), nil),
	}
	rows := buildEndpointREDRows(raw, EndpointREDTopN)
	findEndpointRow(t, rows, metrics.HTTPEndpointRequestsTotal, "shop", "GET /a", "2xx", "allow")
	findEndpointRow(t, rows, metrics.HTTPEndpointRequestsTotal, "shop", "GET /a", "4xx", "allow")
}

// TestBuildEndpointREDRowsUnclassified endpoint_key 缺失（空串）归入 __UNCLASSIFIED__
// 治理桶，不按原始 path 聚合；保留桶豁免 Top-N（topN=1 时仍保留）。
func TestBuildEndpointREDRowsUnclassified(t *testing.T) {
	raw := []endpointREDRawRow{
		rawEndpointRow("shop", "", 200, "", 5, bucketsOf(3), nil),
		rawEndpointRow("shop", "GET /a", 200, "ALLOW", 1, bucketsOf(3), nil),
		rawEndpointRow("shop", "GET /b", 200, "ALLOW", 1, bucketsOf(3), nil),
	}
	rows := buildEndpointREDRows(raw, 1)
	uc := findEndpointRow(t, rows, metrics.HTTPEndpointRequestsTotal, "shop", EndpointUnclassified, "2xx", "allow")
	if uc.Value != 5 {
		t.Errorf("unclassified requests = %v, want 5", uc.Value)
	}
	// 保留桶豁免 Top-N 竞争：topN=1 只保留 GET /a 或 GET /b 之一，另一个进 __OTHER__
	findEndpointRow(t, rows, metrics.HTTPEndpointRequestsTotal, "shop", EndpointOther, "2xx", "allow")
}

// TestBuildEndpointREDRowsTopNGuard Top-N 护栏：每应用按请求数取 Top-N，其余并入
// __OTHER__（按 status_class/action 分组保留维度，直方图桶逐项相加）；同数按端点名
// 升序，结果确定。
func TestBuildEndpointREDRowsTopNGuard(t *testing.T) {
	raw := []endpointREDRawRow{
		rawEndpointRow("shop", "GET /hot", 200, "ALLOW", 100, bucketsOf(3), nil),
		rawEndpointRow("shop", "GET /warm", 200, "ALLOW", 50, bucketsOf(3), nil),
		rawEndpointRow("shop", "GET /tail1", 200, "ALLOW", 4, bucketsOf(3, 30), bucketsOf(2)),
		rawEndpointRow("shop", "GET /tail1", 500, "BLOCK", 1, bucketsOf(900), nil),
		rawEndpointRow("shop", "GET /tail2", 200, "ALLOW", 5, bucketsOf(3), nil),
	}
	rows := buildEndpointREDRows(raw, 2)

	findEndpointRow(t, rows, metrics.HTTPEndpointRequestsTotal, "shop", "GET /hot", "2xx", "allow")
	findEndpointRow(t, rows, metrics.HTTPEndpointRequestsTotal, "shop", "GET /warm", "2xx", "allow")
	// tail1+tail2 并入 __OTHER__：2xx allow 组合并（4+5=9，桶逐项相加），5xx block 组独立保留
	other := findEndpointRow(t, rows, metrics.HTTPEndpointRequestsTotal, "shop", EndpointOther, "2xx", "allow")
	if other.Value != 9 {
		t.Errorf("__OTHER__ 2xx requests = %v, want 9", other.Value)
	}
	otherDur := findEndpointRow(t, rows, metrics.HTTPEndpointDurationMs, "shop", EndpointOther, "2xx", "allow")
	if !reflect.DeepEqual(otherDur.Extra["buckets"], []int{2, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0}) {
		t.Errorf("__OTHER__ duration buckets = %v", otherDur.Extra["buckets"])
	}
	otherTTFB := findEndpointRow(t, rows, metrics.HTTPEndpointTTFBMs, "shop", EndpointOther, "2xx", "allow")
	if otherTTFB.Value != 1 {
		t.Errorf("__OTHER__ ttfb = %v, want 1", otherTTFB.Value)
	}
	ob := findEndpointRow(t, rows, metrics.HTTPEndpointRequestsTotal, "shop", EndpointOther, "5xx", "block")
	if ob.Value != 1 {
		t.Errorf("__OTHER__ 5xx requests = %v, want 1", ob.Value)
	}
	// 尾端点不再单独成行
	for _, r := range rows {
		if strings.HasPrefix(r.Labels["endpoint"], "GET /tail") {
			t.Errorf("tail endpoint must be merged into __OTHER__: %+v", r)
		}
	}

	// 同数决胜：端点名升序，topN=1 时 GET /a 留下、GET /b 进 __OTHER__
	tie := []endpointREDRawRow{
		rawEndpointRow("shop", "GET /b", 200, "ALLOW", 50, bucketsOf(3), nil),
		rawEndpointRow("shop", "GET /a", 200, "ALLOW", 50, bucketsOf(3), nil),
	}
	tieRows := buildEndpointREDRows(tie, 1)
	findEndpointRow(t, tieRows, metrics.HTTPEndpointRequestsTotal, "shop", "GET /a", "2xx", "allow")
	tieOther := findEndpointRow(t, tieRows, metrics.HTTPEndpointRequestsTotal, "shop", EndpointOther, "2xx", "allow")
	if tieOther.Value != 50 {
		t.Errorf("tie-break __OTHER__ = %v, want 50 (GET /b)", tieOther.Value)
	}
}

// TestBuildEndpointREDRowsOverLength endpoint 超 128 字符（metrics 标签值上限）
// 直接并入 __OTHER__，不写超长标签值。
func TestBuildEndpointREDRowsOverLength(t *testing.T) {
	long := "GET /" + strings.Repeat("x", 200)
	raw := []endpointREDRawRow{rawEndpointRow("shop", long, 200, "ALLOW", 3, bucketsOf(3), nil)}
	rows := buildEndpointREDRows(raw, EndpointREDTopN)
	other := findEndpointRow(t, rows, metrics.HTTPEndpointRequestsTotal, "shop", EndpointOther, "2xx", "allow")
	if other.Value != 3 {
		t.Errorf("over-length endpoint must fold into __OTHER__: %+v", other)
	}
	for _, r := range rows {
		if len(r.Labels["endpoint"]) > 128 {
			t.Errorf("label value over 128 chars must not be emitted: %+v", r.Labels)
		}
	}
}

// TestBuildEndpointREDRowsActionNormalization action 标签小写三态；历史空串与
// 未知脏值按 ALLOW 口径归一（与 accesslogs.NormalizeWAFAction 写入侧对应）。
func TestBuildEndpointREDRowsActionNormalization(t *testing.T) {
	raw := []endpointREDRawRow{
		rawEndpointRow("shop", "GET /a", 200, "", 1, bucketsOf(3), nil),      // 历史空串 → allow
		rawEndpointRow("shop", "GET /a", 200, "ALLOW", 1, bucketsOf(3), nil), // 新数据显式 ALLOW
		rawEndpointRow("shop", "GET /a", 200, "OBSERVE", 1, bucketsOf(3), nil),
		rawEndpointRow("shop", "GET /a", 200, "BLOCK", 1, bucketsOf(3), nil),
		rawEndpointRow("shop", "GET /a", 200, "Weird", 1, bucketsOf(3), nil), // 脏值 → allow
	}
	rows := buildEndpointREDRows(raw, EndpointREDTopN)
	allow := findEndpointRow(t, rows, metrics.HTTPEndpointRequestsTotal, "shop", "GET /a", "2xx", "allow")
	if allow.Value != 3 { // 空串 + ALLOW + Weird
		t.Errorf("allow requests = %v, want 3（空串/ALLOW/脏值归一并组）", allow.Value)
	}
	findEndpointRow(t, rows, metrics.HTTPEndpointRequestsTotal, "shop", "GET /a", "2xx", "observe")
	findEndpointRow(t, rows, metrics.HTTPEndpointRequestsTotal, "shop", "GET /a", "2xx", "block")
}

// TestBuildEndpointREDRowsIdempotent 幂等（窗口整段重算口径）：同一窗口输入重复计算
// 输出相同；迟到数据以「完整窗口重算」覆盖而非累加（build(window∪late) 的值 =
// 全量合计，不是 旧值+增量 的重复计数）。
func TestBuildEndpointREDRowsIdempotent(t *testing.T) {
	window := []endpointREDRawRow{
		rawEndpointRow("shop", "GET /a", 200, "ALLOW", 2, bucketsOf(3, 30), bucketsOf(2)),
	}
	first := canonicalEndpointRows(buildEndpointREDRows(window, EndpointREDTopN))
	second := canonicalEndpointRows(buildEndpointREDRows(window, EndpointREDTopN))
	if !reflect.DeepEqual(first, second) {
		t.Fatal("same input must produce identical rows")
	}

	// 迟到修正：窗口重算输入 = 既有 2 条 + 迟到 3 条，输出为全量 5 条（覆盖语义，
	// 由 aggregateEndpointREDMinute delete+insert 落库，重跑不重复）。
	late := append(append([]endpointREDRawRow{}, window...),
		rawEndpointRow("shop", "GET /a", 200, "ALLOW", 3, bucketsOf(3), bucketsOf(4)))
	recomputed := canonicalEndpointRows(buildEndpointREDRows(late, EndpointREDTopN))
	k := fmt.Sprintf("%s|shop|GET /a|2xx|allow", metrics.HTTPEndpointRequestsTotal)
	if recomputed[k].Value != 5 {
		t.Errorf("recomputed window = %v, want 5（整段重算而非累加）", recomputed[k].Value)
	}
	dk := fmt.Sprintf("%s|shop|GET /a|2xx|allow", metrics.HTTPEndpointDurationMs)
	if !reflect.DeepEqual(recomputed[dk].Extra["buckets"], []int{2, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0}) {
		t.Errorf("recomputed duration buckets = %v", recomputed[dk].Extra["buckets"])
	}
}

// TestBuildEndpointREDRowsEmpty 空窗口/空输入安全返回空（不落任何行）。
func TestBuildEndpointREDRowsEmpty(t *testing.T) {
	if got := buildEndpointREDRows(nil, EndpointREDTopN); len(got) != 0 {
		t.Errorf("empty input rows = %v, want empty", got)
	}
}
