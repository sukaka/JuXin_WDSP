// strongflow_test.go 强流程运行指标单测（NG-FLOW-04 §1.9）：聚合正确性
// （五态分桶/积压与比率/滞留时延/冲突率/多应用稳定排序/空应用零值不报错）、
// 渲染段形状（label/空集省略/与 21 项全局指标共存）、采集失败保留上一轮行集。
package metrics

import (
	"strings"
	"testing"
	"time"
)

func TestBuildStrongFlowMetrics(t *testing.T) {
	app1 := "11111111-1111-1111-1111-111111111111"
	app2 := "22222222-2222-2222-2222-222222222222"
	rows := BuildStrongFlowMetrics(
		[]strongFlowInstanceRow{
			{AppID: app2, Status: "ACTIVE", N: 3},
			{AppID: app2, Status: "CONFIRMED", N: 5},
			{AppID: app2, Status: "INDETERMINATE", N: 2},
			{AppID: app1, Status: "CONFIRMED", N: 4},
			{AppID: app2, Status: "UNKNOWN_FUTURE", N: 9}, // 词表外状态不入分桶不报错
		},
		[]strongFlowIndeterminateRow{{AppID: app2, N: 2, AvgSec: 120.5, MaxSec: 300}},
		[]strongFlowReserveRow{{AppID: app2, Total: 20, Conflicts: 3}},
	)
	if len(rows) != 2 {
		t.Fatalf("行数=%d want 2（按应用聚合）: %+v", len(rows), rows)
	}
	// 稳定排序（application_id 升序——同内容恒同序列化）
	if rows[0].ApplicationID != app1 || rows[1].ApplicationID != app2 {
		t.Fatalf("排序: %s, %s", rows[0].ApplicationID, rows[1].ApplicationID)
	}
	m := rows[1]
	// 五态分桶（缺省态补 0；词表外不入）
	if m.InstancesByStatus["ACTIVE"] != 3 || m.InstancesByStatus["CONFIRMED"] != 5 ||
		m.InstancesByStatus["INDETERMINATE"] != 2 || m.InstancesByStatus["CANCELLED"] != 0 ||
		m.InstancesByStatus["FAILED"] != 0 {
		t.Fatalf("分桶: %+v", m.InstancesByStatus)
	}
	// 积压与占实例比（2 / (3+5+2) = 0.2）
	if m.IndeterminateBacklog != 2 || m.IndeterminateRatio != 0.2 {
		t.Fatalf("积压/比率: %d / %v", m.IndeterminateBacklog, m.IndeterminateRatio)
	}
	// 滞留时延透传
	if m.IndeterminateAgeAvgSeconds != 120.5 || m.IndeterminateAgeMaxSeconds != 300 {
		t.Fatalf("时延: %v / %v", m.IndeterminateAgeAvgSeconds, m.IndeterminateAgeMaxSeconds)
	}
	// 冲突率（3/20 = 0.15）
	if m.ReserveTotal24h != 20 || m.ReserveConflict24h != 3 || m.ReserveConflictRatio != 0.15 {
		t.Fatalf("冲突率: %d/%d/%v", m.ReserveTotal24h, m.ReserveConflict24h, m.ReserveConflictRatio)
	}
	// app1：无 INDETERMINATE/无 RESERVE 样本 → 比率与时延 0（真实当前值不外推）
	a := rows[0]
	if a.IndeterminateBacklog != 0 || a.IndeterminateRatio != 0 ||
		a.IndeterminateAgeAvgSeconds != 0 || a.IndeterminateAgeMaxSeconds != 0 ||
		a.ReserveConflictRatio != 0 {
		t.Fatalf("app1 零值口径: %+v", a)
	}
	if a.InstancesByStatus["CONFIRMED"] != 4 || a.InstancesByStatus["ACTIVE"] != 0 {
		t.Fatalf("app1 分桶: %+v", a.InstancesByStatus)
	}
}

func TestBuildStrongFlowMetricsEmpty(t *testing.T) {
	// 空应用/空库零值不报错（无强流程活动 → 空行集 → 渲染整段省略）
	if got := BuildStrongFlowMetrics(nil, nil, nil); len(got) != 0 {
		t.Fatalf("空输入应空行集: %+v", got)
	}
}

func TestRenderStrongFlowSection(t *testing.T) {
	// 空行集 → 整段省略（HELP/TYPE 头同省；无强流程活动即零输出 NG-T-C01）
	if out := RenderStrongFlowSection(nil); out != "" {
		t.Fatalf("空行集应省略整段: %q", out)
	}
	m := StrongFlowAppMetrics{
		ApplicationID:              "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		InstancesByStatus:          map[string]int64{"ACTIVE": 1, "CONFIRMED": 2, "INDETERMINATE": 1, "CANCELLED": 0, "FAILED": 0},
		IndeterminateBacklog:       1,
		IndeterminateRatio:         0.25,
		IndeterminateAgeAvgSeconds: 61.5,
		IndeterminateAgeMaxSeconds: 61.5,
		ReserveTotal24h:            10,
		ReserveConflict24h:         1,
		ReserveConflictRatio:       0.1,
	}
	out := RenderStrongFlowSection([]StrongFlowAppMetrics{m})
	for _, want := range []string{
		"# HELP strong_flow_instances ",
		`strong_flow_instances{application_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",status="ACTIVE"} 1`,
		`strong_flow_instances{application_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",status="FAILED"} 0`,
		`strong_flow_indeterminate_backlog{application_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"} 1`,
		`strong_flow_indeterminate_ratio{application_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"} 0.25`,
		`strong_flow_indeterminate_age_avg_seconds{application_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"} 61.5`,
		`strong_flow_indeterminate_age_max_seconds{application_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"} 61.5`,
		`strong_flow_reserve_conflict_ratio{application_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"} 0.1`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("渲染缺 %q:\n%s", want, out)
		}
	}
	// 五态恒输出（CANCELLED 0 序列出席保持时序连续）
	if !strings.Contains(out, `status="CANCELLED"} 0`) {
		t.Fatalf("缺省态应补 0 序列:\n%s", out)
	}
}

// TestRenderAPISnapshotWithStrongFlow 强流程段与既有 21 项全局指标共存
// （段在自指标之后；空快照仍零强流程输出）。
func TestRenderAPISnapshotWithStrongFlow(t *testing.T) {
	s := APISnapshot{
		CollectedAt: time.Unix(1700000000, 0).UTC(),
		Values:      map[string]int64{APIAssetsTotal: 7},
		Floats:      map[string]float64{},
		StrongFlow: []StrongFlowAppMetrics{{
			ApplicationID:     "app-x",
			InstancesByStatus: map[string]int64{"ACTIVE": 1},
		}},
	}
	out := RenderAPISnapshot(s)
	if !strings.Contains(out, "api_assets_total 7") || !strings.Contains(out, "strong_flow_instances{application_id=\"app-x\",status=\"ACTIVE\"} 1") {
		t.Fatalf("共存渲染:\n%s", out)
	}
	// 自指标仍出席（段插入不破坏尾部）
	if !strings.Contains(out, "api_metrics_last_collect_timestamp_seconds 1700000000") {
		t.Fatalf("自指标: %s", out)
	}
	// 空快照：零强流程输出（NG-T-C01）
	outEmpty := RenderAPISnapshot(APISnapshot{CollectedAt: time.Unix(1700000000, 0).UTC(), Values: map[string]int64{}, Floats: map[string]float64{}})
	if strings.Contains(outEmpty, "strong_flow_") {
		t.Fatalf("空快照不得有强流程输出:\n%s", outEmpty)
	}
}

// TestCollectorStrongFlowSnapshotCopy 快照对 StrongFlow 行集同样做拷贝隔离
// （外部改快照不影响采集器内部状态；采集失败保留上一轮行集的承载字段）。
func TestCollectorStrongFlowSnapshotCopy(t *testing.T) {
	c := NewAPICollector(nil) // 仅快照路径，不触 DB
	c.strongFlow = []StrongFlowAppMetrics{{
		ApplicationID:     "app-keep",
		InstancesByStatus: map[string]int64{"INDETERMINATE": 2},
	}}
	snap := c.Snapshot()
	if len(snap.StrongFlow) != 1 || snap.StrongFlow[0].ApplicationID != "app-keep" {
		t.Fatalf("快照行集: %+v", snap.StrongFlow)
	}
	snap.StrongFlow[0].ApplicationID = "tampered"
	if c.strongFlow[0].ApplicationID != "app-keep" {
		t.Error("Snapshot 未做行集拷贝，内部状态被外部修改")
	}
	// 渲染含保留行集（采集失败轮快照渲染仍输出上一轮值——gauge 缺新值不归零纪律）
	if out := c.Render(); !strings.Contains(out, `strong_flow_indeterminate_backlog{application_id="app-keep"} 0`) {
		t.Errorf("保留行集渲染: %q", out)
	}
}
