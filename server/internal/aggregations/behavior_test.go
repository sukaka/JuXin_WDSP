// behavior_test.go 行为基线画像聚合纯逻辑单测（不依赖数据库）。
package aggregations

import (
	"strconv"
	"testing"
	"time"
)

// behaviorTestBase 固定参考时刻（UTC 整点，避免用例受运行时刻影响）。
var behaviorTestBase = time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)

func behaviorEv(endpointID, identity string, at time.Time, status int) behaviorEvent {
	return behaviorEvent{EndpointID: endpointID, Identity: identity, OccurredAt: at, Status: status}
}

// findProfile 按 endpoint+identity 找画像行。
func findProfile(t *testing.T, profiles []*behaviorProfile, endpointID, identity string) *behaviorProfile {
	t.Helper()
	for _, p := range profiles {
		if p.EndpointID == endpointID && p.Identity == identity {
			return p
		}
	}
	t.Fatalf("profile %s/%s not found in %+v", endpointID, identity, profiles)
	return nil
}

// TestAggregateBehaviorEventsGrouping 身份级行 + 端点级聚合行的分组规则：
// 匿名事件（空串身份）只汇入端点级行，不产身份级行（docs/API_MICRO_MODELS.md §2.2 边界规则）。
func TestAggregateBehaviorEventsGrouping(t *testing.T) {
	windowEnd := behaviorTestBase
	rateStart := windowEnd.Add(-time.Hour)
	events := []behaviorEvent{
		behaviorEv("ep-1", "fp-a", windowEnd.Add(-10*time.Minute), 200),
		behaviorEv("ep-1", "fp-a", windowEnd.Add(-20*time.Minute), 500),
		behaviorEv("ep-1", "", windowEnd.Add(-30*time.Minute), 404), // 匿名
		behaviorEv("ep-2", "fp-a", windowEnd.Add(-5*time.Minute), 200),
	}
	profiles := aggregateBehaviorEvents(events, rateStart, windowEnd, 3600)
	// ep-1: fp-a 身份行 + 端点级行；ep-2: fp-a 身份行 + 端点级行
	if len(profiles) != 4 {
		t.Fatalf("profiles = %d, want 4: %+v", len(profiles), profiles)
	}

	idRow := findProfile(t, profiles, "ep-1", "fp-a")
	if idRow.RequestCount != 2 || idRow.StatusDist["2xx"] != 1 || idRow.StatusDist["5xx"] != 1 {
		t.Errorf("identity row: %+v", idRow)
	}
	epRow := findProfile(t, profiles, "ep-1", "")
	if epRow.RequestCount != 3 || epRow.StatusDist["2xx"] != 1 || epRow.StatusDist["5xx"] != 1 || epRow.StatusDist["4xx"] != 1 {
		t.Errorf("endpoint row: %+v", epRow)
	}
	// 无匿名身份行
	for _, p := range profiles {
		if p.EndpointID == "" {
			t.Errorf("empty endpoint id row should not exist: %+v", p)
		}
	}
	// avg_rate = request_count / window_seconds
	if want := 3.0 / 3600.0; epRow.AvgRate != want {
		t.Errorf("avg_rate = %v, want %v", epRow.AvgRate, want)
	}
}

// TestAggregateBehaviorEventsRateWindow 速率窗口外的事件只计 hour_dist，
// 不进 request_count/status_code_dist（速率基线只看最近窗口）。
func TestAggregateBehaviorEventsRateWindow(t *testing.T) {
	windowEnd := behaviorTestBase
	rateStart := windowEnd.Add(-time.Hour)
	old := windowEnd.Add(-2 * time.Hour) // 速率窗口外、时段回看内
	events := []behaviorEvent{
		behaviorEv("ep-1", "fp-a", windowEnd.Add(-10*time.Minute), 200),
		behaviorEv("ep-1", "fp-a", old, 500),
	}
	p := findProfile(t, aggregateBehaviorEvents(events, rateStart, windowEnd, 3600), "ep-1", "fp-a")
	if p.RequestCount != 1 || p.StatusDist["2xx"] != 1 || len(p.StatusDist) != 1 {
		t.Errorf("rate window should exclude old event: %+v", p)
	}
	// 时段分布覆盖全部传入事件：当前小时桶（11:50→"11"）1 次 + 两小时前小时桶 1 次
	if got := p.HourDist["11"]; got != 1 {
		t.Errorf("hour_dist[11] = %d, want 1 (%+v)", got, p.HourDist)
	}
	oldHour := old.UTC().Hour()
	if got := p.HourDist[timeInt(oldHour)]; got != 1 {
		t.Errorf("hour_dist[%d] = %d, want 1 (%+v)", oldHour, got, p.HourDist)
	}
}

// TestAggregateBehaviorEventsHourBuckets 小时桶按 UTC 归并（跨时区时间戳折算到同一 UTC 桶）。
func TestAggregateBehaviorEventsHourBuckets(t *testing.T) {
	windowEnd := behaviorTestBase // UTC 12:00
	rateStart := windowEnd.Add(-time.Hour)
	plus8 := time.FixedZone("UTC+8", 8*3600)
	events := []behaviorEvent{
		behaviorEv("ep-1", "", windowEnd.Add(-50*time.Minute), 200),             // UTC 11:10
		behaviorEv("ep-1", "", time.Date(2026, 8, 7, 19, 30, 0, 0, plus8), 200), // +08:00 19:30 = UTC 11:30
		behaviorEv("ep-1", "", windowEnd.Add(-10*time.Minute), 200),             // UTC 11:50
		behaviorEv("ep-1", "", windowEnd.Add(-61*time.Minute), 200),             // UTC 10:59，速率窗口外
	}
	p := findProfile(t, aggregateBehaviorEvents(events, rateStart, windowEnd, 3600), "ep-1", "")
	if p.HourDist["11"] != 3 || p.HourDist["10"] != 1 {
		t.Errorf("hour buckets = %+v, want 11:3 10:1", p.HourDist)
	}
	if p.RequestCount != 3 {
		t.Errorf("request_count = %d, want 3（10:59 的事件只计时段）", p.RequestCount)
	}
}

// TestStatusCodeClass 状态码分桶：0/未知归 unknown（不冒充成功类），其余同 statusClass 口径。
func TestStatusCodeClass(t *testing.T) {
	cases := map[int]string{0: "unknown", -1: "unknown", 200: "2xx", 301: "2xx", 404: "4xx", 500: "5xx"}
	for status, want := range cases {
		if got := statusCodeClass(status); got != want {
			t.Errorf("statusCodeClass(%d) = %q, want %q", status, got, want)
		}
	}
}

// TestAggregateBehaviorEventsDeterministic 输出按 endpoint+identity 排序，多次调用结果一致。
func TestAggregateBehaviorEventsDeterministic(t *testing.T) {
	windowEnd := behaviorTestBase
	rateStart := windowEnd.Add(-time.Hour)
	events := []behaviorEvent{
		behaviorEv("ep-2", "fp-b", windowEnd.Add(-time.Minute), 200),
		behaviorEv("ep-1", "fp-a", windowEnd.Add(-time.Minute), 200),
		behaviorEv("ep-1", "", windowEnd.Add(-time.Minute), 200),
		behaviorEv("ep-2", "", windowEnd.Add(-time.Minute), 200),
	}
	first := aggregateBehaviorEvents(events, rateStart, windowEnd, 3600)
	second := aggregateBehaviorEvents(events, rateStart, windowEnd, 3600)
	if len(first) != len(second) {
		t.Fatalf("length mismatch: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].EndpointID != second[i].EndpointID || first[i].Identity != second[i].Identity {
			t.Fatalf("order not deterministic at %d: %+v vs %+v", i, first, second)
		}
	}
	// 排序断言：端点级行（空串身份）排在同端点身份行之前
	if first[0].EndpointID != "ep-1" || first[0].Identity != "" ||
		first[1].EndpointID != "ep-1" || first[1].Identity != "fp-a" {
		t.Errorf("unexpected order: %+v", first)
	}
}

// timeInt 小时数转字符串键（与聚合侧 strconv.Itoa 一致，不补零）。
func timeInt(h int) string {
	return strconv.Itoa(h)
}
