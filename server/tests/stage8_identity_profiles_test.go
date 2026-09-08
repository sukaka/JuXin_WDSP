// stage8_identity_profiles_test.go 身份画像（WDSP 三微模型增强批）。
// 覆盖：aggregations.RunIdentityProfiles 从 api_runtime_events 聚合写入
// api_identity_profiles；匿名事件不写画像；UPSERT 幂等；GET identity-profiles
// 只读（api_runtime.read）过滤与质量分；非法 endpoint_id → 400；未登录 401。
package tests

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/events"
	"github.com/jiuzhang-waf/server/internal/aggregations"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
)

// TestStage8IdentityProfiles 身份画像聚合 + 只读接口端到端验证。
func TestStage8IdentityProfiles(t *testing.T) {
	env := setupStage8Env(t)
	cookies, _ := env.s5Login(t, "s8id", "SECURITY_ADMIN")
	ctx := context.Background()

	// 表存在（000018 即建表）
	if n := s8Count(t, env, `
SELECT count(*) FROM information_schema.tables
WHERE table_schema='public' AND table_name='api_identity_profiles'`); n != 1 {
		t.Fatalf("api_identity_profiles table missing")
	}

	ep := s8SeedEndpoint(t, env, "GET", "/s8id-"+s5Rand()+"/users/{id}", 0.9)
	fp := "auth:fp-" + s5Rand()
	now := time.Now().UTC()
	rt := apiruntime.NewStore(env.db)
	mk := func(reqID, identity, authType string, at time.Time) *apiruntime.PrimaryEvent {
		return &apiruntime.PrimaryEvent{
			PrimaryEvent: events.PrimaryEvent{
				RequestID: reqID, EndpointKey: ep.EndpointKey,
				RiskScore: 5, RiskLevel: "LOW", FinalAction: "LOG",
				OccurredAt: at,
			},
			IdentityFingerprint: identity,
			AuthType:            authType,
			ResponseStatus:      200,
		}
	}
	// 3 条同身份 + 1 条匿名（匿名不得进身份画像）
	for i, id := range []string{"id-1", "id-2", "id-3"} {
		if err := rt.SavePrimary(ctx, mk(id, fp, "api_key", now.Add(-time.Duration(i+1)*time.Minute))); err != nil {
			t.Fatalf("SavePrimary %s: %v", id, err)
		}
	}
	if err := rt.SavePrimary(ctx, mk("id-anon", "", "", now.Add(-time.Minute))); err != nil {
		t.Fatalf("SavePrimary anon: %v", err)
	}
	// 未匹配端点事件：聚合应跳过
	if err := rt.SavePrimary(ctx, &apiruntime.PrimaryEvent{
		PrimaryEvent: events.PrimaryEvent{
			RequestID: "id-unknown", EndpointKey: "GET /s8id-unknown",
			RiskScore: 1, RiskLevel: "LOW", FinalAction: "LOG", OccurredAt: now,
		},
		IdentityFingerprint: fp, AuthType: "api_key", ResponseStatus: 200,
	}); err != nil {
		t.Fatalf("SavePrimary unknown: %v", err)
	}

	jobs := aggregations.NewJobs(aggregations.NewStore(env.db))
	if err := jobs.RunIdentityProfiles(ctx, now); err != nil {
		t.Fatalf("RunIdentityProfiles: %v", err)
	}

	// 仅 1 行：fp × endpoint（匿名与未匹配端点不进）
	if n := s8Count(t, env, `SELECT count(*) FROM api_identity_profiles`); n != 1 {
		t.Fatalf("identity profile rows = %d, want 1", n)
	}
	var count int64
	var authType string
	if err := env.db.QueryRow(ctx, `
SELECT request_count, auth_type FROM api_identity_profiles
WHERE identity_fingerprint=$1 AND endpoint_id=$2`, fp, ep.ID).Scan(&count, &authType); err != nil {
		t.Fatalf("read profile: %v", err)
	}
	if count != 3 || authType != "api_key" {
		t.Errorf("profile count/auth = %d/%s, want 3/api_key", count, authType)
	}

	// 幂等重跑不翻倍
	if err := jobs.RunIdentityProfiles(ctx, now); err != nil {
		t.Fatalf("rerun: %v", err)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_identity_profiles`); n != 1 {
		t.Fatalf("rerun rows = %d, want 1", n)
	}
	if err := env.db.QueryRow(ctx, `
SELECT request_count FROM api_identity_profiles WHERE identity_fingerprint=$1`, fp).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Errorf("rerun request_count = %d, want 3", count)
	}

	// 任务记录
	if n := s8Count(t, env,
		`SELECT count(*) FROM aggregation_jobs WHERE job_type='IDENTITY' AND status='SUCCESS'`); n < 1 {
		t.Errorf("aggregation_jobs IDENTITY SUCCESS = %d, want >=1", n)
	}

	// 只读 API：按指纹过滤
	page := s8Page(t, env.get(t,
		"/api/v1/api-security/identity-profiles?identity_fingerprint="+fp, cookies), "profiles by fp")
	if page.Data.Total != 1 {
		t.Fatalf("by fingerprint total = %d, want 1", page.Data.Total)
	}
	item := page.Data.Items[0]
	if item["identity_fingerprint"] != fp {
		t.Errorf("fingerprint = %v, want %s", item["identity_fingerprint"], fp)
	}
	if item["endpoint_key"] != ep.EndpointKey {
		t.Errorf("endpoint_key = %v, want %s", item["endpoint_key"], ep.EndpointKey)
	}
	if item["request_count"] != float64(3) {
		t.Errorf("request_count = %v, want 3", item["request_count"])
	}
	// 质量分应为 number 且在 0–100
	qs, ok := item["quality_score"].(float64)
	if !ok || qs < 0 || qs > 100 {
		t.Errorf("quality_score = %v, want 0-100 number", item["quality_score"])
	}

	// 按端点过滤
	page = s8Page(t, env.get(t,
		"/api/v1/api-security/identity-profiles?endpoint_id="+ep.ID.String(), cookies), "profiles by endpoint")
	if page.Data.Total != 1 {
		t.Fatalf("by endpoint total = %d, want 1", page.Data.Total)
	}

	// 非法 endpoint_id → 400
	resp := env.get(t, "/api/v1/api-security/identity-profiles?endpoint_id=not-a-uuid", cookies)
	s5Expect(t, resp, http.StatusBadRequest, "invalid endpoint_id")

	// 未命中指纹 → 空集
	page = s8Page(t, env.get(t,
		"/api/v1/api-security/identity-profiles?identity_fingerprint=fp-none", cookies), "miss")
	if page.Data.Total != 0 {
		t.Errorf("miss total = %d, want 0", page.Data.Total)
	}

	// 未登录 401
	resp = env.do(t, http.MethodGet, "/api/v1/api-security/identity-profiles", "", nil, "")
	s5Expect(t, resp, http.StatusUnauthorized, "unauthenticated")

	// ---------- 详情（画像 + 风险评估 + 近期事件） ----------
	detail := s5OK(t, env.get(t,
		"/api/v1/api-security/identity-profiles/detail?identity_fingerprint="+fp+"&endpoint_id="+ep.ID.String(),
		cookies), "identity detail")
	prof, _ := detail.Data["profile"].(map[string]interface{})
	if prof["identity_fingerprint"] != fp || prof["endpoint_key"] != ep.EndpointKey {
		t.Errorf("detail profile = %+v", prof)
	}
	risk, _ := detail.Data["risk"].(map[string]interface{})
	// 本用例事件全部 LOW/低风险分：可能性1 × 严重程度1 → VERY_LOW
	if risk["level"] != "VERY_LOW" || risk["likelihood"] != float64(1) || risk["severity"] != float64(1) {
		t.Errorf("risk = %+v, want VERY_LOW 1×1", risk)
	}
	ind, _ := risk["indicators"].(map[string]interface{})
	// 3 条匹配端点 + 1 条未匹配端点（威胁主体视角跨端点计数）
	if ind["events_total"] != float64(4) {
		t.Errorf("events_total = %v, want 4", ind["events_total"])
	}
	if ind["risky_events_total"] != float64(0) || ind["blocked_events_total"] != float64(0) {
		t.Errorf("risky/blocked = %v/%v, want 0/0", ind["risky_events_total"], ind["blocked_events_total"])
	}
	if risk["summary"] == "" {
		t.Errorf("risk.summary empty")
	}
	events, _ := detail.Data["recent_events"].([]interface{})
	if len(events) != 4 {
		t.Errorf("recent_events = %d, want 4", len(events))
	}

	// 缺指纹 → 400；非法 endpoint_id → 400；画像不存在 → 404；未登录 → 401
	resp = env.get(t, "/api/v1/api-security/identity-profiles/detail?endpoint_id="+ep.ID.String(), cookies)
	s5Expect(t, resp, http.StatusBadRequest, "missing fingerprint")
	resp = env.get(t, "/api/v1/api-security/identity-profiles/detail?identity_fingerprint="+fp+"&endpoint_id=bad", cookies)
	s5Expect(t, resp, http.StatusBadRequest, "invalid endpoint_id")
	resp = env.get(t, "/api/v1/api-security/identity-profiles/detail?identity_fingerprint=fp-none&endpoint_id="+ep.ID.String(), cookies)
	s5Expect(t, resp, http.StatusNotFound, "profile not found")
	resp = env.do(t, http.MethodGet,
		"/api/v1/api-security/identity-profiles/detail?identity_fingerprint="+fp+"&endpoint_id="+ep.ID.String(), "", nil, "")
	s5Expect(t, resp, http.StatusUnauthorized, "detail unauthenticated")
}
