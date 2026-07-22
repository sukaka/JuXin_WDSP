package dashboards

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseTrendRange(t *testing.T) {
	cases := map[string]time.Duration{
		"":    24 * time.Hour,
		"1h":  time.Hour,
		"24h": 24 * time.Hour,
		"7d":  7 * 24 * time.Hour,
		"30d": 30 * 24 * time.Hour,
	}
	for in, want := range cases {
		got, err := ParseTrendRange(in)
		if err != nil || got != want {
			t.Errorf("ParseTrendRange(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := ParseTrendRange("2h"); err == nil {
		t.Error("2h should be rejected")
	}
	if _, err := ParseTrendRange("abc"); err == nil {
		t.Error("abc should be rejected")
	}
}

func TestAggTableForTier(t *testing.T) {
	cases := []struct {
		d    time.Duration
		want string
	}{
		{time.Hour, "metric_minute_aggregates"},
		{24 * time.Hour, "metric_minute_aggregates"}, // 边界：≤24h 分钟表
		{7 * 24 * time.Hour, "metric_hour_aggregates"},
		{30 * 24 * time.Hour, "metric_hour_aggregates"},
	}
	for _, c := range cases {
		if got := AggTableFor(c.d); got != c.want {
			t.Errorf("AggTableFor(%v) = %s want %s", c.d, got, c.want)
		}
	}
}

func TestTrendStepAndTrunc(t *testing.T) {
	cases := []struct {
		d     time.Duration
		step  time.Duration
		trunc string
	}{
		{time.Hour, time.Minute, "minute"},
		{24 * time.Hour, time.Hour, "hour"},
		{7 * 24 * time.Hour, time.Hour, "hour"},
		{30 * 24 * time.Hour, 24 * time.Hour, "day"},
	}
	for _, c := range cases {
		if got := TrendStep(c.d); got != c.step {
			t.Errorf("TrendStep(%v) = %v want %v", c.d, got, c.step)
		}
		if got := StepTrunc(c.step); got != c.trunc {
			t.Errorf("StepTrunc(%v) = %s want %s", c.step, got, c.trunc)
		}
	}
}

func TestTodayWindowUTC(t *testing.T) {
	now := time.Date(2026, 7, 21, 15, 30, 0, 0, time.FixedZone("CST", 8*3600))
	start, end := TodayWindowUTC(now)
	if start.Location() != time.UTC || start.Hour() != 0 || start.Day() != 21 {
		t.Errorf("start: %v", start)
	}
	if !end.Equal(now.UTC()) {
		t.Errorf("end: %v", end)
	}
}

func TestBucketTimes(t *testing.T) {
	start := time.Date(2026, 7, 21, 10, 7, 30, 0, time.UTC)
	end := start.Add(5 * time.Minute)
	buckets := BucketTimes(start, end, time.Minute)
	// 10:07:30 ~ 10:12:30 覆盖 10:07..10:12 共 6 个分钟桶
	if len(buckets) != 6 {
		t.Fatalf("buckets: %v", buckets)
	}
	if buckets[0] != start.Truncate(time.Minute) {
		t.Errorf("first bucket: %v", buckets[0])
	}
	// 空区间
	if got := BucketTimes(end, end, time.Minute); len(got) != 0 {
		t.Errorf("empty range: %v", got)
	}
}

func TestSeriesInto(t *testing.T) {
	base := time.Date(2026, 7, 21, 10, 0, 0, 0, time.UTC)
	buckets := BucketTimes(base, base.Add(3*time.Hour), time.Hour)
	times := []time.Time{
		base.Add(5 * time.Minute),              // → 桶0
		base.Add(50 * time.Minute),             // → 桶0
		base.Add(2*time.Hour + 10*time.Minute), // → 桶2
		base.Add(-time.Minute),                 // 区间外丢弃
	}
	values := []float64{1, 2, 4, 100}
	out := SeriesInto(buckets, times, values, time.Hour)
	if len(out) != 3 || out[0] != 3 || out[1] != 0 || out[2] != 4 {
		t.Errorf("SeriesInto: %v", out)
	}
}

func TestSeriesMapInto(t *testing.T) {
	base := time.Date(2026, 7, 21, 10, 0, 0, 0, time.UTC)
	buckets := BucketTimes(base, base.Add(2*time.Hour), time.Hour)
	series := map[string][]struct {
		T time.Time
		V float64
	}{
		"HIGH": {{base.Add(10 * time.Minute), 2}, {base.Add(time.Hour), 1}},
		"LOW":  {{base.Add(70 * time.Minute), 5}},
	}
	out := SeriesMapInto(buckets, series, time.Hour)
	if out["HIGH"][0] != 2 || out["HIGH"][1] != 1 {
		t.Errorf("HIGH: %v", out["HIGH"])
	}
	if out["LOW"][0] != 0 || out["LOW"][1] != 5 {
		t.Errorf("LOW 缺桶补零: %v", out["LOW"])
	}
}

func TestParseInfoUsedMemory(t *testing.T) {
	info := "# Memory\r\nused_memory:1048576\r\nused_memory_human:1.00M\r\nmem_fragmentation_ratio:1.1\r\n"
	n, ok := ParseInfoUsedMemory(info)
	if !ok || n != 1048576 {
		t.Errorf("got %d, %v", n, ok)
	}
	if _, ok := ParseInfoUsedMemory("# Memory\r\nother:1\r\n"); ok {
		t.Error("missing key should be false")
	}
	if _, ok := ParseInfoUsedMemory("used_memory:abc"); ok {
		t.Error("bad value should be false")
	}
}

func TestSecurityOverviewRejectsBadRange(t *testing.T) {
	h := NewHandler(nil, nil) // 参数校验先于任何 DB 访问
	req := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/security-overview?range=2h", nil)
	rec := httptest.NewRecorder()
	h.SecurityOverview(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: %d, body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "INVALID_ARGUMENT") {
		t.Errorf("body: %s", rec.Body.String())
	}
}
