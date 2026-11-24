// call_edges_test.go 调用边派生纯逻辑单测（不依赖数据库）。
package aggregations

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// callEdgeTestBase 固定参考时刻（UTC 整点，避免用例受运行时刻影响）。
var callEdgeTestBase = time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

var (
	edgeEP1 = uuid.MustParse("11111111-1111-1111-1111-111111111111")
	edgeEP2 = uuid.MustParse("22222222-2222-2222-2222-222222222222")
	edgeEP3 = uuid.MustParse("33333333-3333-3333-3333-333333333333")
)

func edgeEv(identity string, endpointID uuid.UUID, at time.Time) callEdgeEvent {
	return callEdgeEvent{Identity: identity, EndpointID: endpointID, OccurredAt: at}
}

// findEdge 按 caller+source+target 找边增量。
func findEdge(t *testing.T, deltas []callEdgeDelta, caller string, source, target uuid.UUID) *callEdgeDelta {
	t.Helper()
	for i := range deltas {
		d := &deltas[i]
		if d.Caller == caller && d.SourceID == source && d.TargetID == target {
			return d
		}
	}
	t.Fatalf("edge %s %s->%s not found in %+v", caller, source, target, deltas)
	return nil
}

// TestDeriveCallEdgesSequence 窗口内连续调用序列产边：A→B→C 得 A→B、B→C；
// 同一序列重复观测，count 累计、first/last_seen 取首末次观测时刻。
func TestDeriveCallEdgesSequence(t *testing.T) {
	fp := "fp-a"
	t0 := callEdgeTestBase
	events := []callEdgeEvent{
		// 第一趟：A→B→C（间隔均在窗口内）
		edgeEv(fp, edgeEP1, t0),
		edgeEv(fp, edgeEP2, t0.Add(2*time.Minute)),
		edgeEv(fp, edgeEP3, t0.Add(4*time.Minute)),
		// 第二趟：A→B（重复观测同一条边）
		edgeEv(fp, edgeEP1, t0.Add(6*time.Minute)),
		edgeEv(fp, edgeEP2, t0.Add(8*time.Minute)),
	}
	deltas := deriveCallEdges(events, CallEdgeSessionWindow, nil)
	if len(deltas) != 3 {
		t.Fatalf("deltas = %d, want 3 (A→B/B→C/A→B 合并): %+v", len(deltas), deltas)
	}
	ab := findEdge(t, deltas, fp, edgeEP1, edgeEP2)
	if ab.Count != 2 {
		t.Errorf("A→B count = %d, want 2", ab.Count)
	}
	if !ab.FirstSeen.Equal(t0.Add(2*time.Minute)) || !ab.LastSeen.Equal(t0.Add(8*time.Minute)) {
		t.Errorf("A→B first/last = %v/%v, want %v/%v", ab.FirstSeen, ab.LastSeen,
			t0.Add(2*time.Minute), t0.Add(8*time.Minute))
	}
	bc := findEdge(t, deltas, fp, edgeEP2, edgeEP3)
	if bc.Count != 1 || !bc.FirstSeen.Equal(t0.Add(4*time.Minute)) {
		t.Errorf("B→C = %+v, want count 1 first_seen t0+4m", bc)
	}
	// 序列连续 ≠ 跨跳：不得出现 A→C
	for _, d := range deltas {
		if d.SourceID == edgeEP1 && d.TargetID == edgeEP3 {
			t.Errorf("non-consecutive edge A→C must not exist: %+v", d)
		}
	}
}

// TestDeriveCallEdgesWindowCut 间隔超窗（>10min）序列截断：两侧不成边，
// 超窗后的事件作为新序列起点继续配对。
func TestDeriveCallEdgesWindowCut(t *testing.T) {
	fp := "fp-a"
	t0 := callEdgeTestBase
	events := []callEdgeEvent{
		edgeEv(fp, edgeEP1, t0),
		edgeEv(fp, edgeEP2, t0.Add(11*time.Minute)), // 超窗：A→B 不成边
		edgeEv(fp, edgeEP3, t0.Add(13*time.Minute)), // 窗内：B→C 成边
	}
	deltas := deriveCallEdges(events, CallEdgeSessionWindow, nil)
	if len(deltas) != 1 {
		t.Fatalf("deltas = %d, want 1 (仅 B→C): %+v", len(deltas), deltas)
	}
	findEdge(t, deltas, fp, edgeEP2, edgeEP3)
}

// TestDeriveCallEdgesWatermark 水位过滤：to 时刻 ≤ 水位的边已由上轮计入、不重复；
// 跨水位配对（from 在水位前、to 在水位后，回看上下文）恰好计入一次。
func TestDeriveCallEdgesWatermark(t *testing.T) {
	fp := "fp-a"
	t0 := callEdgeTestBase
	wm := t0.Add(5 * time.Minute)
	events := []callEdgeEvent{
		edgeEv(fp, edgeEP1, t0),                    // 水位前
		edgeEv(fp, edgeEP2, t0.Add(2*time.Minute)), // to=+2m ≤ 水位：A→B 不计
		edgeEv(fp, edgeEP3, t0.Add(6*time.Minute)), // to=+6m > 水位：B→C 计（from 为回看上下文）
		edgeEv(fp, edgeEP1, t0.Add(8*time.Minute)), // C→A 计
	}
	deltas := deriveCallEdges(events, CallEdgeSessionWindow, &wm)
	if len(deltas) != 2 {
		t.Fatalf("deltas = %d, want 2 (B→C/C→A): %+v", len(deltas), deltas)
	}
	findEdge(t, deltas, fp, edgeEP2, edgeEP3)
	findEdge(t, deltas, fp, edgeEP3, edgeEP1)
	for _, d := range deltas {
		if d.SourceID == edgeEP1 && d.TargetID == edgeEP2 {
			t.Errorf("A→B (to ≤ watermark) must not be recounted: %+v", d)
		}
	}
}

// TestDeriveCallEdgesAnonymous 匿名事件（空串身份）不产边、也不打断已识别身份的序列
// （SQL 层已排除匿名，此处验证纯逻辑层防御；docs/API_MICRO_MODELS.md §2.2 边界规则）。
func TestDeriveCallEdgesAnonymous(t *testing.T) {
	fp := "fp-a"
	t0 := callEdgeTestBase
	events := []callEdgeEvent{
		edgeEv(fp, edgeEP1, t0),
		edgeEv("", edgeEP3, t0.Add(1*time.Minute)), // 匿名调用：另一行为主体，不断链
		edgeEv(fp, edgeEP2, t0.Add(2*time.Minute)),
	}
	deltas := deriveCallEdges(events, CallEdgeSessionWindow, nil)
	if len(deltas) != 1 {
		t.Fatalf("deltas = %d, want 1 (A→B): %+v", len(deltas), deltas)
	}
	ab := findEdge(t, deltas, fp, edgeEP1, edgeEP2)
	if ab.Count != 1 {
		t.Errorf("A→B count = %d, want 1", ab.Count)
	}
}

// TestDeriveCallEdgesUnresolvedBreaks 端点未解析（uuid.Nil）的事件是序列截断点：
// A→未知→B 不断言 A→B。
func TestDeriveCallEdgesUnresolvedBreaks(t *testing.T) {
	fp := "fp-a"
	t0 := callEdgeTestBase
	events := []callEdgeEvent{
		edgeEv(fp, edgeEP1, t0),
		edgeEv(fp, uuid.Nil, t0.Add(1*time.Minute)), // 未解析：截断
		edgeEv(fp, edgeEP2, t0.Add(2*time.Minute)),
		edgeEv(fp, edgeEP3, t0.Add(3*time.Minute)), // B→C 正常成边
	}
	deltas := deriveCallEdges(events, CallEdgeSessionWindow, nil)
	if len(deltas) != 1 {
		t.Fatalf("deltas = %d, want 1 (仅 B→C): %+v", len(deltas), deltas)
	}
	findEdge(t, deltas, fp, edgeEP2, edgeEP3)
}

// TestDeriveCallEdgesSelfLoop 自环（连续调用同一端点）不成边。
func TestDeriveCallEdgesSelfLoop(t *testing.T) {
	fp := "fp-a"
	t0 := callEdgeTestBase
	events := []callEdgeEvent{
		edgeEv(fp, edgeEP1, t0),
		edgeEv(fp, edgeEP1, t0.Add(1*time.Minute)), // 自环不成边，但序列延续
		edgeEv(fp, edgeEP2, t0.Add(2*time.Minute)),
	}
	deltas := deriveCallEdges(events, CallEdgeSessionWindow, nil)
	if len(deltas) != 1 {
		t.Fatalf("deltas = %d, want 1 (A→B): %+v", len(deltas), deltas)
	}
	findEdge(t, deltas, fp, edgeEP1, edgeEP2)
}

// TestDeriveCallEdgesIdentityIsolation 多身份序列互相隔离；输出按 caller+source+target
// 排序、与输入顺序无关（结果确定，供测试与重跑对比）。
func TestDeriveCallEdgesIdentityIsolation(t *testing.T) {
	t0 := callEdgeTestBase
	events := []callEdgeEvent{
		edgeEv("fp-b", edgeEP2, t0.Add(1*time.Minute)),
		edgeEv("fp-a", edgeEP1, t0),
		edgeEv("fp-b", edgeEP3, t0.Add(2*time.Minute)),
		edgeEv("fp-a", edgeEP2, t0.Add(3*time.Minute)),
	}
	deltas := deriveCallEdges(events, CallEdgeSessionWindow, nil)
	if len(deltas) != 2 {
		t.Fatalf("deltas = %d, want 2: %+v", len(deltas), deltas)
	}
	// 排序确定：fp-a 的 A→B 在前，fp-b 的 B→C 在后
	if deltas[0].Caller != "fp-a" || deltas[0].SourceID != edgeEP1 || deltas[0].TargetID != edgeEP2 {
		t.Errorf("deltas[0] = %+v, want fp-a A→B", deltas[0])
	}
	if deltas[1].Caller != "fp-b" || deltas[1].SourceID != edgeEP2 || deltas[1].TargetID != edgeEP3 {
		t.Errorf("deltas[1] = %+v, want fp-b B→C", deltas[1])
	}
}

// TestDeriveCallEdgesEmpty 空输入/全匿名输入安全返回空。
func TestDeriveCallEdgesEmpty(t *testing.T) {
	if got := deriveCallEdges(nil, CallEdgeSessionWindow, nil); len(got) != 0 {
		t.Errorf("nil input deltas = %v, want empty", got)
	}
	anon := []callEdgeEvent{edgeEv("", edgeEP1, callEdgeTestBase), edgeEv("", edgeEP2, callEdgeTestBase.Add(time.Minute))}
	if got := deriveCallEdges(anon, CallEdgeSessionWindow, nil); len(got) != 0 {
		t.Errorf("anonymous-only deltas = %v, want empty", got)
	}
}

// TestDeriveCallEdgesSkipsStaticNoiseWithoutBreakingSequence 静态资源/已忽略/非 API 噪声事件
// 不产生边，且不打断同一身份前后真实 API 之间的连续轨迹（例如登录 → favicon.ico → 查订单
// 应直接成边 登录 → 查订单）。
func TestDeriveCallEdgesSkipsStaticNoiseWithoutBreakingSequence(t *testing.T) {
	fp := "fp-browser"
	t0 := callEdgeTestBase
	noiseEP := uuid.MustParse("44444444-4444-4444-4444-444444444444")
	events := []callEdgeEvent{
		edgeEv(fp, edgeEP1, t0),
		{Identity: fp, EndpointID: noiseEP, SkipNoise: true, OccurredAt: t0.Add(2 * time.Second)},
		{Identity: fp, EndpointID: uuid.Nil, SkipNoise: true, OccurredAt: t0.Add(3 * time.Second)},
		edgeEv(fp, edgeEP2, t0.Add(30*time.Second)),
	}
	deltas := deriveCallEdges(events, CallEdgeSessionWindow, nil)
	if len(deltas) != 1 {
		t.Fatalf("deltas = %d, want 1 (EP1→EP2): %+v", len(deltas), deltas)
	}
	findEdge(t, deltas, fp, edgeEP1, edgeEP2)
}

// TestIsCallEdgeNoiseEvent 验证静态资源、已忽略、非 API 与已确认资产的判定边界。
func TestIsCallEdgeNoiseEvent(t *testing.T) {
	cases := []struct {
		name        string
		endpointKey string
		status      string
		isAPI       bool
		matched     bool
		wantNoise   bool
	}{
		{"静态图标_未确认", "GET /favicon_128x128.ico", "DISCOVERED", true, true, true},
		{"静态图片_中文名", "GET /备案图标.png", "DISCOVERED", true, true, true},
		{"静态脚本_未匹配资产", "GET /admin/assets/js/app.js", "", true, false, true},
		{"已确认资产永不跳过", "GET /favicon_128x128.ico", "CONFIRMED", false, true, false},
		{"已忽略端点跳过", "GET /api/v1/legacy", "IGNORED", true, true, true},
		{"非API端点跳过", "GET /customer", "DISCOVERED", false, true, true},
		{"真实API保留", "POST /api/v1/orders", "DISCOVERED", true, true, false},
		{"未知非静态API保留作截断点", "GET /s8ce-unknown/{id}", "", true, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isCallEdgeNoiseEvent(tc.endpointKey, tc.status, tc.isAPI, tc.matched); got != tc.wantNoise {
				t.Errorf("isCallEdgeNoiseEvent(%q,%q,%v,%v) = %v, want %v",
					tc.endpointKey, tc.status, tc.isAPI, tc.matched, got, tc.wantNoise)
			}
		})
	}
}
