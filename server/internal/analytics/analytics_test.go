package analytics

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestParseRangeDefault(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	r, err := ParseRange(url.Values{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !r.End.Equal(now) || !r.Start.Equal(now.Add(-24*time.Hour)) {
		t.Errorf("default range: %v ~ %v", r.Start, r.End)
	}
}

func TestParseRangeExplicit(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	q := url.Values{}
	q.Set("start_time", "2026-07-01T00:00:00+08:00")
	q.Set("end_time", "2026-07-02T00:00:00Z")
	r, err := ParseRange(q, now)
	if err != nil {
		t.Fatal(err)
	}
	wantStart := time.Date(2026, 6, 30, 16, 0, 0, 0, time.UTC)
	if !r.Start.Equal(wantStart) || !r.End.Equal(time.Date(2026, 7, 2, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("range: %v ~ %v", r.Start, r.End)
	}
}

func TestParseRangeOnlyEnd(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	q := url.Values{}
	q.Set("end_time", "2026-07-20T00:00:00Z")
	r, err := ParseRange(q, now)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Start.Equal(time.Date(2026, 7, 19, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("start: %v", r.Start)
	}
}

func TestParseRangeInvalid(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	cases := []url.Values{
		{"start_time": {"not-a-time"}},
		{"end_time": {"2026/07/21"}},
		{"start_time": {"2026-07-21T00:00:00Z"}, "end_time": {"2026-07-20T00:00:00Z"}}, // 倒置
		{"start_time": {"2026-07-21T00:00:00Z"}, "end_time": {"2026-07-21T00:00:00Z"}}, // 相等
		{"start_time": {"2025-07-01T00:00:00Z"}, "end_time": {"2026-07-21T00:00:00Z"}}, // >366天
	}
	for i, q := range cases {
		if _, err := ParseRange(q, now); err == nil || !IsInvalidRange(err) {
			t.Errorf("case %d: want invalid range error, got %v", i, err)
		}
	}
}

func TestRangeTableTier(t *testing.T) {
	end := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		d    time.Duration
		want string
	}{
		{time.Hour, "metric_minute_aggregates"},
		{24 * time.Hour, "metric_minute_aggregates"}, // 边界：≤24h 分钟表
		{24*time.Hour + time.Second, "metric_hour_aggregates"},
		{30 * 24 * time.Hour, "metric_hour_aggregates"},
	}
	for _, c := range cases {
		r := Range{Start: end.Add(-c.d), End: end}
		if got := r.Table(); got != c.want {
			t.Errorf("d=%v: got %s want %s", c.d, got, c.want)
		}
	}
}

func TestRangeTrendBucket(t *testing.T) {
	end := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Minute, "minute"},
		{24 * time.Hour, "hour"},
		{7 * 24 * time.Hour, "hour"},
		{30 * 24 * time.Hour, "day"},
	}
	for _, c := range cases {
		r := Range{Start: end.Add(-c.d), End: end}
		if got := r.TrendBucket(); got != c.want {
			t.Errorf("d=%v: got %s want %s", c.d, got, c.want)
		}
	}
}

func TestSortKVsDescTieBreak(t *testing.T) {
	kvs := SortKVsDesc(map[string]float64{"b": 3, "a": 3, "c": 5, "d": 1})
	want := []KV{{"c", 5}, {"a", 3}, {"b", 3}, {"d", 1}}
	if len(kvs) != len(want) {
		t.Fatalf("len %d", len(kvs))
	}
	for i := range want {
		if kvs[i] != want[i] {
			t.Errorf("idx %d: got %+v want %+v", i, kvs[i], want[i])
		}
	}
}

func TestTopN(t *testing.T) {
	kvs := []KV{{"a", 5}, {"b", 4}, {"c", 3}}
	if got := TopN(kvs, 2); len(got) != 2 || got[1].Key != "b" {
		t.Errorf("TopN(2): %+v", got)
	}
	if got := TopN(kvs, 0); len(got) != 3 {
		t.Errorf("TopN(0): %+v", got)
	}
	if got := TopN(kvs, 99); len(got) != 3 {
		t.Errorf("TopN(99): %+v", got)
	}
}

func TestMergeCounts(t *testing.T) {
	dst := MergeCounts([]int{1, 2}, []int{3, 4, 5})
	if len(dst) != 3 || dst[0] != 4 || dst[1] != 6 || dst[2] != 5 {
		t.Errorf("merge: %v", dst)
	}
	dst = MergeCounts(nil, []int{7})
	if len(dst) != 1 || dst[0] != 7 {
		t.Errorf("merge nil: %v", dst)
	}
}

func TestNormalizeCounts(t *testing.T) {
	// 11 桶（含溢出桶）规整为 DurationBucketsMs 长度（10），溢出并入最后一桶
	in := make([]int, 11)
	in[9] = 2
	in[10] = 3
	out := normalizeCounts(in)
	if len(out) != 10 || out[9] != 5 {
		t.Errorf("normalize: %v", out)
	}
	// 短输入补零到 10
	out = normalizeCounts([]int{1})
	if len(out) != 10 || out[0] != 1 || out[9] != 0 {
		t.Errorf("normalize short: %v", out)
	}
}

func TestPivotSeries(t *testing.T) {
	t0 := time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Minute)
	points := []seriesPoint{
		{t: t1, key: "5xx", v: 1},
		{t: t0, key: "2xx", v: 10},
		{t: t1, key: "2xx", v: 20},
		{t: t0, key: "2xx", v: 5}, // 同桶同键累加
	}
	times, keys, series := pivotSeries(points)
	if len(times) != 2 || !times[0].Equal(t0) {
		t.Fatalf("times: %v", times)
	}
	if len(keys) != 2 || keys[0] != "2xx" || keys[1] != "5xx" {
		t.Fatalf("keys: %v", keys)
	}
	if series["2xx"][0] != 15 || series["2xx"][1] != 20 {
		t.Errorf("2xx: %v", series["2xx"])
	}
	if series["5xx"][0] != 0 || series["5xx"][1] != 1 {
		t.Errorf("5xx 缺桶补零: %v", series["5xx"])
	}
}

func TestHandlerRejectsBadRange(t *testing.T) {
	h := NewHandler(nil, nil) // 参数校验先于任何 DB 访问
	req := httptest.NewRequest(http.MethodGet, "/api/v1/analytics/request-trend?start_time=bad", nil)
	rec := httptest.NewRecorder()
	h.RequestTrend(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: %d, body: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "INVALID_ARGUMENT") {
		t.Errorf("body: %s", rec.Body.String())
	}
}

func TestHandlerRejectsBadApplicationID(t *testing.T) {
	h := NewHandler(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/analytics/attack-types?application_id=xyz", nil)
	rec := httptest.NewRecorder()
	h.AttackTypes(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: %d", rec.Code)
	}
}
