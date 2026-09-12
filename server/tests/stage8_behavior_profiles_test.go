// stage8_behavior_profiles_test.go 行为基线画像（WDSP 三微模型第二批，访问微模型「访问时间」维度）。
// 覆盖：迁移 000030 两列落位；SavePrimary 持久化 response_status；离线聚合任务
// （aggregations.RunBehaviorProfiles）从 api_runtime_events 产出 endpoint × identity 画像
// （匿名只汇入端点级行；未匹配端点的事件跳过），UPSERT 幂等可重跑；
// GET /api/v1/api-security/behavior-profiles 只读查询（api_runtime.read）与过滤。
// 真实 PostgreSQL/Valkey，无口令环境 t.Skip（纪律同 stage8_api_security_test.go）。
package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/events"
	"github.com/jiuzhang-waf/server/internal/aggregations"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
)

// behaviorProfileRow 从库内读回的一行画像（断言用）。
type behaviorProfileRow struct {
	RequestCount int64
	AvgRate      float64
	StatusDist   map[string]int64
	HourDist     map[string]int64
}

func s8ProfileRow(t *testing.T, env *testEnv, endpointID, identity string) behaviorProfileRow {
	t.Helper()
	var row behaviorProfileRow
	var statusRaw, hourRaw []byte
	if err := env.db.QueryRow(context.Background(), `
SELECT request_count, avg_rate, status_code_dist, hour_dist
FROM api_behavior_profiles WHERE endpoint_id=$1 AND identity_fingerprint=$2`, endpointID, identity).
		Scan(&row.RequestCount, &row.AvgRate, &statusRaw, &hourRaw); err != nil {
		t.Fatalf("read profile %s/%q: %v", endpointID, identity, err)
	}
	if err := json.Unmarshal(statusRaw, &row.StatusDist); err != nil {
		t.Fatalf("status_code_dist unmarshal: %v", err)
	}
	if err := json.Unmarshal(hourRaw, &row.HourDist); err != nil {
		t.Fatalf("hour_dist unmarshal: %v", err)
	}
	return row
}

func hourDistSum(dist map[string]int64) int64 {
	var sum int64
	for _, v := range dist {
		sum += v
	}
	return sum
}

// TestStage8BehaviorProfiles 画像聚合 + 只读接口端到端验证。
func TestStage8BehaviorProfiles(t *testing.T) {
	env := setupStage8Env(t)
	cookies, _ := env.s5Login(t, "s8bp", "SECURITY_ADMIN")
	ctx := context.Background()

	// 迁移 000030 落位：hour_dist / response_status 两列存在
	if n := s8Count(t, env, `
SELECT count(*) FROM information_schema.columns
WHERE (table_name='api_behavior_profiles' AND column_name='hour_dist')
   OR (table_name='api_runtime_events' AND column_name='response_status')`); n != 2 {
		t.Fatalf("migration 000030 columns = %d, want 2", n)
	}

	// 造数：端点 + 5 条运行时事件（4 条归属端点，1 条 endpoint_key 未匹配应跳过）
	ep := s8SeedEndpoint(t, env, "GET", "/s8bp-"+s5Rand()+"/orders/{id}", 0.9)
	fp := "fp-" + s5Rand()
	now := time.Now().UTC()
	rt := apiruntime.NewStore(env.db)
	mk := func(reqID, endpointKey, identity string, at time.Time, status int) *apiruntime.PrimaryEvent {
		return &apiruntime.PrimaryEvent{
			PrimaryEvent: events.PrimaryEvent{
				RequestID: reqID, EndpointKey: endpointKey,
				RiskScore: 10, RiskLevel: "LOW", FinalAction: "LOG",
				OccurredAt: at,
			},
			IdentityFingerprint: identity,
			AuthType:            "api_key",
			ResponseStatus:      status,
		}
	}
	seeded := []struct {
		reqID    string
		identity string
		at       time.Time
		status   int
	}{
		{"bp-1", fp, now.Add(-10 * time.Minute), 200},
		{"bp-2", fp, now.Add(-20 * time.Minute), 500},
		{"bp-3", "", now.Add(-30 * time.Minute), 404}, // 匿名：只汇入端点级行
		{"bp-4", fp, now.Add(-2 * time.Hour), 200},    // 速率窗口外：只计 hour_dist
	}
	for _, s := range seeded {
		if err := rt.SavePrimary(ctx, mk(s.reqID, ep.EndpointKey, s.identity, s.at, s.status)); err != nil {
			t.Fatalf("SavePrimary %s: %v", s.reqID, err)
		}
	}
	// 未匹配端点的事件（endpoint_key 不在 api_endpoints）：聚合应跳过而非报错
	if err := rt.SavePrimary(ctx, mk("bp-5", "GET /s8bp-unknown/{id}", fp, now.Add(-5*time.Minute), 200)); err != nil {
		t.Fatalf("SavePrimary unknown endpoint: %v", err)
	}

	// response_status 持久化（迁移 000030 前 ETL 丢弃该字段）
	var status int
	if err := env.db.QueryRow(ctx,
		`SELECT response_status FROM api_runtime_events WHERE request_id='bp-2'`).Scan(&status); err != nil {
		t.Fatalf("read response_status: %v", err)
	}
	if status != 500 {
		t.Errorf("response_status = %d, want 500", status)
	}

	// 执行离线画像聚合
	jobs := aggregations.NewJobs(aggregations.NewStore(env.db))
	if err := jobs.RunBehaviorProfiles(ctx, now); err != nil {
		t.Fatalf("RunBehaviorProfiles: %v", err)
	}

	// 行数：fp 身份行 + 端点级行 = 2（匿名不产身份行；未匹配端点事件不进画像）
	if n := s8Count(t, env, `SELECT count(*) FROM api_behavior_profiles`); n != 2 {
		t.Fatalf("profile rows = %d, want 2", n)
	}

	// 端点级行：速率窗口内 3 条（bp-1/2/3），bp-4 只进 hour_dist
	epRow := s8ProfileRow(t, env, ep.ID.String(), "")
	if epRow.RequestCount != 3 {
		t.Errorf("endpoint request_count = %d, want 3", epRow.RequestCount)
	}
	if want := 3.0 / 3600.0; epRow.AvgRate < want-1e-9 || epRow.AvgRate > want+1e-9 {
		t.Errorf("endpoint avg_rate = %v, want %v", epRow.AvgRate, want)
	}
	if epRow.StatusDist["2xx"] != 1 || epRow.StatusDist["4xx"] != 1 || epRow.StatusDist["5xx"] != 1 || len(epRow.StatusDist) != 3 {
		t.Errorf("endpoint status_code_dist = %+v, want 2xx/4xx/5xx 各 1", epRow.StatusDist)
	}
	if got := hourDistSum(epRow.HourDist); got != 4 {
		t.Errorf("endpoint hour_dist sum = %d, want 4（含速率窗口外的 bp-4）: %+v", got, epRow.HourDist)
	}
	oldHourKey := strconv.Itoa(seeded[3].at.UTC().Hour())
	if epRow.HourDist[oldHourKey] != 1 {
		t.Errorf("endpoint hour_dist[%s] = %d, want 1: %+v", oldHourKey, epRow.HourDist[oldHourKey], epRow.HourDist)
	}

	// 身份行：bp-1/bp-2 在速率窗口内，bp-4 只计时段；匿名 bp-3 不在身份行
	idRow := s8ProfileRow(t, env, ep.ID.String(), fp)
	if idRow.RequestCount != 2 || idRow.StatusDist["2xx"] != 1 || idRow.StatusDist["5xx"] != 1 || len(idRow.StatusDist) != 2 {
		t.Errorf("identity row = %+v, want count 2 / 2xx,5xx 各 1", idRow)
	}
	if got := hourDistSum(idRow.HourDist); got != 3 {
		t.Errorf("identity hour_dist sum = %d, want 3: %+v", got, idRow.HourDist)
	}

	// 任务执行记录（BEHAVIOR / SUCCESS）
	if n := s8Count(t, env,
		`SELECT count(*) FROM aggregation_jobs WHERE job_type='BEHAVIOR' AND status='SUCCESS'`); n != 1 {
		t.Errorf("aggregation_jobs BEHAVIOR SUCCESS = %d, want 1", n)
	}

	// UPSERT 幂等：同一时刻重跑，行数与计数不变（覆盖式，不累加）
	if err := jobs.RunBehaviorProfiles(ctx, now); err != nil {
		t.Fatalf("RunBehaviorProfiles rerun: %v", err)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_behavior_profiles`); n != 2 {
		t.Errorf("rerun profile rows = %d, want 2 (idempotent)", n)
	}
	if row := s8ProfileRow(t, env, ep.ID.String(), ""); row.RequestCount != 3 {
		t.Errorf("rerun endpoint request_count = %d, want 3 (no double count)", row.RequestCount)
	}

	// 只读接口：按端点过滤（端点级行 + 身份行共 2 条）
	page := s8Page(t, env.get(t,
		"/api/v1/api-security/behavior-profiles?endpoint_id="+ep.ID.String(), cookies), "profiles by endpoint")
	if page.Data.Total != 2 {
		t.Fatalf("profiles by endpoint total = %d, want 2", page.Data.Total)
	}
	// 按身份过滤：仅身份行；响应带出分布字段与 endpoint_key
	page = s8Page(t, env.get(t,
		"/api/v1/api-security/behavior-profiles?identity_fingerprint="+fp, cookies), "profiles by identity")
	if page.Data.Total != 1 {
		t.Fatalf("profiles by identity total = %d, want 1", page.Data.Total)
	}
	item := page.Data.Items[0]
	if item["endpoint_key"] != ep.EndpointKey || item["identity_fingerprint"] != fp {
		t.Errorf("profile item identity = %v/%v, want %s/%s", item["endpoint_key"], item["identity_fingerprint"], ep.EndpointKey, fp)
	}
	if item["window_seconds"] != float64(3600) || item["request_count"] != float64(2) {
		t.Errorf("profile item window/count = %v/%v, want 3600/2", item["window_seconds"], item["request_count"])
	}
	hourDist, ok := item["hour_dist"].(map[string]interface{})
	if !ok || hourDistSum2(hourDist) != 3 {
		t.Errorf("profile item hour_dist = %v, want 3 次调用分布", item["hour_dist"])
	}
	statusDist, ok := item["status_code_dist"].(map[string]interface{})
	if !ok || statusDist["2xx"] != float64(1) || statusDist["5xx"] != float64(1) {
		t.Errorf("profile item status_code_dist = %v, want 2xx/5xx 各 1", item["status_code_dist"])
	}

	// 非法 endpoint_id → 400；未命中指纹 → 空集
	resp := env.get(t, "/api/v1/api-security/behavior-profiles?endpoint_id=not-a-uuid", cookies)
	s5Expect(t, resp, http.StatusBadRequest, "profiles with invalid endpoint_id")
	page = s8Page(t, env.get(t,
		"/api/v1/api-security/behavior-profiles?identity_fingerprint=fp-nonexistent", cookies), "profiles identity miss")
	if page.Data.Total != 0 {
		t.Errorf("identity miss total = %d, want 0", page.Data.Total)
	}

	// 权限底线：未登录访问 401
	resp = env.do(t, http.MethodGet, "/api/v1/api-security/behavior-profiles", "", nil, "")
	s5Expect(t, resp, http.StatusUnauthorized, "unauthenticated profiles query")
}

// hourDistSum2 JSON 响应里的 hour_dist（float64 值）求和。
func hourDistSum2(dist map[string]interface{}) int64 {
	var sum int64
	for _, v := range dist {
		if f, ok := v.(float64); ok {
			sum += int64(f)
		}
	}
	return sum
}
