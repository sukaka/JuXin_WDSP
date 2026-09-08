// stage8_traffic_trend_test.go 接口访问趋势波形图服务端（WDSP，迁移 000034）。
// 覆盖：迁移落位；Store.RecordTrafficBucket 同桶 UPSERT 累加与未对齐时间按桶对齐；
// GET /api/v1/api-security/endpoints/{id}/traffic-trend 统一信封、服务端补零连续点列、
// range 缺省/非法回落 24h、窗口过滤、404/400/401；aggregations.RunTrafficBucketCleanup
// 删除 7 天前桶并记 aggregation_jobs（TRAFFIC_CLEANUP）。
// 真实 PostgreSQL/Valkey，无口令环境 t.Skip（纪律同 stage8_api_security_test.go）。
package tests

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/aggregations"
	"github.com/jiuzhang-waf/server/internal/apiassets"
)

// s8GetTrafficTrend 请求 traffic-trend 并解析统一信封（data 层 + points 点列）。
func s8GetTrafficTrend(t *testing.T, env *testEnv, path string, cookies []*http.Cookie) (apiResp, []map[string]interface{}) {
	t.Helper()
	result := s5OK(t, env.get(t, path, cookies), "traffic-trend "+path)
	raw, ok := result.Data["points"].([]interface{})
	if !ok {
		t.Fatalf("points not array: %v", result.Data["points"])
	}
	points := make([]map[string]interface{}, 0, len(raw))
	for _, p := range raw {
		m, ok := p.(map[string]interface{})
		if !ok {
			t.Fatalf("point not object: %v", p)
		}
		points = append(points, m)
	}
	return result, points
}

// s8AssertPointsChain 断言点列连续（相邻桶间隔恰 300s）、时间升序、数量符合 range 桶数。
func s8AssertPointsChain(t *testing.T, points []map[string]interface{}, wantLen int, what string) {
	t.Helper()
	if len(points) != wantLen {
		t.Fatalf("%s points = %d, want %d", what, len(points), wantLen)
	}
	prev := time.Time{}
	for i, p := range points {
		ts, ok := p["time"].(string)
		if !ok {
			t.Fatalf("%s points[%d].time not string: %v", what, i, p["time"])
		}
		tm, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			t.Fatalf("%s points[%d].time parse: %v", what, i, err)
		}
		if i > 0 {
			if d := tm.Sub(prev); d != time.Duration(apiassets.TrafficBucketSeconds)*time.Second {
				t.Fatalf("%s points[%d] gap = %v, want 300s（连续升序）", what, i, d)
			}
		}
		prev = tm
	}
}

func TestStage8TrafficTrend(t *testing.T) {
	env := setupStage8Env(t)
	cookies, _ := env.s5Login(t, "s8tt", "SECURITY_ADMIN")
	ctx := context.Background()

	// 迁移 000034 落位
	if n := s8Count(t, env,
		`SELECT count(*) FROM information_schema.tables WHERE table_name='api_endpoint_traffic_buckets'`); n != 1 {
		t.Fatalf("migration 000034 table = %d, want 1", n)
	}

	ep := s8SeedEndpoint(t, env, "GET", "/s8tt-"+s5Rand()+"/items/{id}", 0.9)
	store := apiassets.NewStore(env.db)
	now := time.Now().UTC()
	b0 := apiassets.TrafficBucketStart(now)

	// 造数：当前桶 3 次（同桶 UPSERT 累加）；上一桶 1 次（未对齐时间验证服务端对齐）；
	// 2 天前 1 次（range=1h/24h 不计入）；8 天前 1 次（清理对象）。
	for i := 0; i < 3; i++ {
		if err := store.RecordTrafficBucket(ctx, ep.ID, now); err != nil {
			t.Fatalf("RecordTrafficBucket current: %v", err)
		}
	}
	if err := store.RecordTrafficBucket(ctx, ep.ID, b0.Add(-apiassets.TrafficBucketSeconds*time.Second).Add(37*time.Second)); err != nil {
		t.Fatalf("RecordTrafficBucket prev: %v", err)
	}
	if err := store.RecordTrafficBucket(ctx, ep.ID, now.Add(-48*time.Hour)); err != nil {
		t.Fatalf("RecordTrafficBucket -48h: %v", err)
	}
	if err := store.RecordTrafficBucket(ctx, ep.ID, now.Add(-8*24*time.Hour)); err != nil {
		t.Fatalf("RecordTrafficBucket -8d: %v", err)
	}

	// 库内验证：同桶累加 request_count=3；未对齐时间落上一桶
	var cnt int64
	if err := env.db.QueryRow(ctx, `
SELECT request_count FROM api_endpoint_traffic_buckets WHERE endpoint_id=$1 AND bucket_start=$2`,
		ep.ID, b0).Scan(&cnt); err != nil || cnt != 3 {
		t.Fatalf("current bucket count = %d (err=%v), want 3", cnt, err)
	}
	if err := env.db.QueryRow(ctx, `
SELECT request_count FROM api_endpoint_traffic_buckets WHERE endpoint_id=$1 AND bucket_start=$2`,
		ep.ID, b0.Add(-apiassets.TrafficBucketSeconds*time.Second)).Scan(&cnt); err != nil || cnt != 1 {
		t.Fatalf("prev bucket count = %d (err=%v), want 1", cnt, err)
	}

	// range=1h：13 桶连续升序，total=4（-48h/-8d 不计入），当前桶 3、上一桶 1、首桶补零
	result, points := s8GetTrafficTrend(t, env,
		"/api/v1/api-security/endpoints/"+ep.ID.String()+"/traffic-trend?range=1h", cookies)
	if result.Data["endpoint_id"] != ep.ID.String() || result.Data["range"] != "1h" ||
		result.Data["bucket_seconds"] != float64(apiassets.TrafficBucketSeconds) {
		t.Fatalf("data head = %v/%v/%v", result.Data["endpoint_id"], result.Data["range"], result.Data["bucket_seconds"])
	}
	if result.Data["total"] != float64(4) {
		t.Fatalf("1h total = %v, want 4", result.Data["total"])
	}
	s8AssertPointsChain(t, points, 13, "1h")
	if points[12]["count"] != float64(3) || points[11]["count"] != float64(1) || points[0]["count"] != float64(0) {
		t.Fatalf("1h counts last/prev/first = %v/%v/%v, want 3/1/0",
			points[12]["count"], points[11]["count"], points[0]["count"])
	}
	if points[12]["time"] != b0.Format(time.RFC3339) {
		t.Fatalf("1h last bucket = %v, want %v", points[12]["time"], b0.Format(time.RFC3339))
	}

	// 缺省 range=24h：289 桶，total=4
	result, points = s8GetTrafficTrend(t, env,
		"/api/v1/api-security/endpoints/"+ep.ID.String()+"/traffic-trend", cookies)
	if result.Data["range"] != "24h" || result.Data["total"] != float64(4) {
		t.Fatalf("default range/total = %v/%v, want 24h/4", result.Data["range"], result.Data["total"])
	}
	s8AssertPointsChain(t, points, 289, "24h")

	// 非法 range 回落 24h
	result, _ = s8GetTrafficTrend(t, env,
		"/api/v1/api-security/endpoints/"+ep.ID.String()+"/traffic-trend?range=bogus", cookies)
	if result.Data["range"] != "24h" {
		t.Fatalf("bogus range = %v, want 24h 回落", result.Data["range"])
	}

	// range=7d：2017 桶，total=5（含 -48h，不含 -8d）
	result, points = s8GetTrafficTrend(t, env,
		"/api/v1/api-security/endpoints/"+ep.ID.String()+"/traffic-trend?range=7d", cookies)
	if result.Data["range"] != "7d" || result.Data["total"] != float64(5) {
		t.Fatalf("7d range/total = %v/%v, want 7d/5", result.Data["range"], result.Data["total"])
	}
	s8AssertPointsChain(t, points, 2017, "7d")

	// 端点不存在 404；非法 ID 400；未登录 401
	s5Expect(t, env.get(t, "/api/v1/api-security/endpoints/"+uuid.NewString()+"/traffic-trend", cookies),
		http.StatusNotFound, "traffic-trend missing endpoint")
	s5Expect(t, env.get(t, "/api/v1/api-security/endpoints/not-a-uuid/traffic-trend", cookies),
		http.StatusBadRequest, "traffic-trend bad id")
	s5Expect(t, env.do(t, http.MethodGet, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/traffic-trend", "", nil, ""),
		http.StatusUnauthorized, "traffic-trend unauthenticated")

	// 清理任务：8 天前桶删除、近 7 天桶保留；aggregation_jobs 记 TRAFFIC_CLEANUP SUCCESS
	jobs := aggregations.NewJobs(aggregations.NewStore(env.db))
	if err := jobs.RunTrafficBucketCleanup(ctx, now); err != nil {
		t.Fatalf("RunTrafficBucketCleanup: %v", err)
	}
	if n := s8Count(t, env, `
SELECT count(*) FROM api_endpoint_traffic_buckets
WHERE endpoint_id=$1 AND bucket_start < $2`, ep.ID, now.Add(-7*24*time.Hour)); n != 0 {
		t.Fatalf("buckets older than 7d = %d, want 0", n)
	}
	if n := s8Count(t, env,
		`SELECT count(*) FROM api_endpoint_traffic_buckets WHERE endpoint_id=$1`, ep.ID); n != 3 {
		t.Fatalf("remaining buckets = %d, want 3（当前/上一桶/-48h）", n)
	}
	if n := s8Count(t, env, `
SELECT count(*) FROM aggregation_jobs WHERE job_type='TRAFFIC_CLEANUP' AND status='SUCCESS'`); n != 1 {
		t.Fatalf("aggregation_jobs TRAFFIC_CLEANUP SUCCESS = %d, want 1", n)
	}
}
