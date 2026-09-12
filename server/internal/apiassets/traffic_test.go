// traffic_test.go 接口流量趋势（WDSP 接口访问趋势波形图）：
// 纯逻辑（5 分钟桶 UTC 对齐 / range 解析 / 服务端补零）+ MemStore 累加与窗口过滤
// + traffic-trend 接口（统一信封、补零连续点列、range 缺省与非法回落、404/400）。
package apiassets

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

// 桶对齐：UTC 5 分钟截断；非 UTC 输入先换算再对齐；结果可稳定做 map 键。
func TestTrafficBucketStart(t *testing.T) {
	want := time.Date(2026, 8, 12, 10, 5, 0, 0, time.UTC)
	in := time.Date(2026, 8, 12, 10, 7, 35, 123456789, time.UTC)
	if got := TrafficBucketStart(in); !got.Equal(want) {
		t.Fatalf("TrafficBucketStart(%v) = %v, want %v", in, got, want)
	}
	// +08:00 18:07 → UTC 10:07 → 10:05
	loc := time.FixedZone("CST", 8*3600)
	in2 := time.Date(2026, 8, 12, 18, 7, 0, 0, loc)
	if got := TrafficBucketStart(in2); !got.Equal(want) {
		t.Fatalf("TrafficBucketStart(%v) = %v, want %v", in2, got, want)
	}
	if TrafficBucketStart(in) != TrafficBucketStart(in2) {
		t.Fatal("aligned buckets must be equal as map keys")
	}
	// 恰在桶边界不偏移
	if got := TrafficBucketStart(want); got != want {
		t.Fatalf("boundary bucket = %v, want %v", got, want)
	}
}

// range 解析：1h/24h/7d；缺省与非法值回落 24h；大小写不敏感。
func TestParseTrafficRange(t *testing.T) {
	cases := []struct {
		in   string
		name string
		dur  time.Duration
	}{
		{"1h", "1h", time.Hour},
		{"24h", "24h", 24 * time.Hour},
		{"7d", "7d", 7 * 24 * time.Hour},
		{"", "24h", 24 * time.Hour},
		{"bogus", "24h", 24 * time.Hour},
		{"1H", "1h", time.Hour},
		{" 7d ", "7d", 7 * 24 * time.Hour},
	}
	for _, c := range cases {
		name, dur := ParseTrafficRange(c.in)
		if name != c.name || dur != c.dur {
			t.Errorf("ParseTrafficRange(%q) = (%s, %v), want (%s, %v)", c.in, name, dur, c.name, c.dur)
		}
	}
}

// 补零：from 所属桶到 now 所属桶连续 5 分钟桶，无数据桶 count=0，时间升序；total 为窗口合计。
func TestFillTrafficPoints(t *testing.T) {
	now := time.Date(2026, 8, 12, 10, 7, 35, 0, time.UTC)
	from := now.Add(-time.Hour) // 09:07:35 → 起始桶 09:05，末尾桶 10:05，共 13 桶
	counts := map[time.Time]int64{
		time.Date(2026, 8, 12, 9, 5, 0, 0, time.UTC):  3,
		time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC): 5,
	}
	points, total := FillTrafficPoints(from, now, counts)
	if len(points) != 13 {
		t.Fatalf("points = %d, want 13", len(points))
	}
	if total != 8 {
		t.Fatalf("total = %d, want 8", total)
	}
	for i, p := range points {
		want := time.Date(2026, 8, 12, 9, 5, 0, 0, time.UTC).Add(time.Duration(i) * TrafficBucketSeconds * time.Second)
		if !p.Time.Equal(want) {
			t.Fatalf("points[%d].time = %v, want %v（连续升序）", i, p.Time, want)
		}
	}
	if points[0].Count != 3 || points[11].Count != 5 || points[12].Count != 0 {
		t.Fatalf("counts = %d/%d/%d, want 3/5/0（无数据桶补零）",
			points[0].Count, points[11].Count, points[12].Count)
	}
	// 空窗口数据：全部补零，total=0
	points, total = FillTrafficPoints(from, now, nil)
	if len(points) != 13 || total != 0 {
		t.Fatalf("empty fill = %d points / total %d, want 13/0", len(points), total)
	}
}

// MemStore：同桶累加、未对齐时间按桶对齐、窗口过滤、端点隔离。
func TestMemStoreTrafficBuckets(t *testing.T) {
	ctx := context.Background()
	m := NewMemStore()
	ep, err := m.UpsertDiscovery(ctx, DiscoveryInput{Method: "GET", PathTemplate: "/t/{id}", Confidence: 0.9, IsAPI: true})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 12, 10, 7, 35, 0, time.UTC)
	b0 := TrafficBucketStart(now)
	for i := 0; i < 3; i++ {
		if err := m.RecordTrafficBucket(ctx, ep.ID, now); err != nil {
			t.Fatal(err)
		}
	}
	// 未对齐时间落入上一桶
	if err := m.RecordTrafficBucket(ctx, ep.ID, b0.Add(-TrafficBucketSeconds*time.Second).Add(37*time.Second)); err != nil {
		t.Fatal(err)
	}
	// 窗口外（2 天前）与其他端点不计入
	if err := m.RecordTrafficBucket(ctx, ep.ID, now.Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := m.RecordTrafficBucket(ctx, uuid.New(), now); err != nil {
		t.Fatal(err)
	}
	counts, err := m.TrafficBuckets(ctx, ep.ID, now.Add(-time.Hour), b0.Add(TrafficBucketSeconds*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(counts) != 2 || counts[b0] != 3 || counts[b0.Add(-TrafficBucketSeconds*time.Second)] != 1 {
		t.Fatalf("buckets = %+v, want 当前桶 3 + 上一桶 1", counts)
	}
}

// 接口：统一信封 data 层字段、补零连续点列、range 缺省/非法回落、404/400。
func TestTrafficTrendHTTP(t *testing.T) {
	ctx := context.Background()
	store := NewMemStore()
	h := NewHandler(store, nil)
	mux := newTestMux(h)

	ep, err := store.UpsertDiscovery(ctx, DiscoveryInput{Method: "GET", PathTemplate: "/tt/{id}", Confidence: 0.9, IsAPI: true})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	b0 := TrafficBucketStart(now)
	for i := 0; i < 2; i++ {
		if err := store.RecordTrafficBucket(ctx, ep.ID, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.RecordTrafficBucket(ctx, ep.ID, b0.Add(-TrafficBucketSeconds*time.Second)); err != nil {
		t.Fatal(err)
	}

	// range=1h：13 桶连续升序，total=3
	rr := doJSON(t, mux, http.MethodGet, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/traffic-trend?range=1h", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("traffic-trend status = %d, body=%s", rr.Code, rr.Body.String())
	}
	data := decodeData(t, rr)
	if data["endpoint_id"] != ep.ID.String() || data["range"] != "1h" || data["bucket_seconds"] != float64(300) {
		t.Fatalf("data head = %v/%v/%v", data["endpoint_id"], data["range"], data["bucket_seconds"])
	}
	if data["total"] != float64(3) {
		t.Fatalf("total = %v, want 3", data["total"])
	}
	points, ok := data["points"].([]any)
	if !ok || len(points) != 13 {
		t.Fatalf("points len = %v, want 13", data["points"])
	}
	last := points[12].(map[string]any)
	prev := points[11].(map[string]any)
	if last["count"] != float64(2) || prev["count"] != float64(1) {
		t.Fatalf("last/prev count = %v/%v, want 2/1", last["count"], prev["count"])
	}
	if last["time"] != b0.Format(time.RFC3339) {
		t.Fatalf("last bucket time = %v, want %v", last["time"], b0.Format(time.RFC3339))
	}
	first := points[0].(map[string]any)
	if first["count"] != float64(0) {
		t.Fatalf("first bucket count = %v, want 0（补零）", first["count"])
	}
	// 相邻桶间隔恰为 300s（连续）
	t0, _ := time.Parse(time.RFC3339, first["time"].(string))
	t1, _ := time.Parse(time.RFC3339, points[1].(map[string]any)["time"].(string))
	if t1.Sub(t0) != TrafficBucketSeconds*time.Second {
		t.Fatalf("bucket gap = %v, want 300s", t1.Sub(t0))
	}

	// 缺省 range=24h：289 桶
	data = decodeData(t, doJSON(t, mux, http.MethodGet,
		"/api/v1/api-security/endpoints/"+ep.ID.String()+"/traffic-trend", nil))
	if data["range"] != "24h" {
		t.Fatalf("default range = %v, want 24h", data["range"])
	}
	if got := len(data["points"].([]any)); got != 289 {
		t.Fatalf("24h points = %d, want 289", got)
	}
	// 非法 range 回落 24h
	data = decodeData(t, doJSON(t, mux, http.MethodGet,
		"/api/v1/api-security/endpoints/"+ep.ID.String()+"/traffic-trend?range=bogus", nil))
	if data["range"] != "24h" {
		t.Fatalf("bogus range = %v, want 24h 回落", data["range"])
	}

	// 端点不存在 404；非法 ID 400
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/endpoints/"+uuid.NewString()+"/traffic-trend", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("missing endpoint status = %d, want 404", rr.Code)
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/endpoints/not-a-uuid/traffic-trend", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad id status = %d, want 400", rr.Code)
	}
}
