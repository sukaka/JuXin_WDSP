// stage8_model_maturity_test.go 模型成熟度状态机只读接口集成测试
// （WDSP 三微模型第三批，docs/API_MICRO_MODELS.md §四第 10 项）。
//
// 覆盖：GET /api/v1/api-security/model-maturity（api_runtime.read）响应形状
// （generated_at + 固定顺序四模型 + stage/metrics/summary），以及四个微模型
// stage 随真实表数据的逐级推导：
//   - parameter：LEARNING →（推荐约束）CANDIDATE →（确认约束且随最新 FORMAL 下发）ENFORCING
//     →（v2 取代后旧确认未下发）CONFIRMED →（v2 required 行）ENFORCING；
//   - identity：近 24h 事件身份覆盖率 25% → CANDIDATE，≥50% → CONFIRMED（24h 外事件不计）；
//   - access_env：画像覆盖 1/3 → CANDIDATE，覆盖 2/3（≥45%）且含时段分布 → CONFIRMED；
//   - access_object：api_object_models 为空 → LEARNING（resource.* 命中仅 metrics），
//     有对象模型行但端点覆盖 <45% → CANDIDATE，覆盖 ≥45% → CONFIRMED。
//
// 运行方式（与 make stage8-test-api 一致）：
//
//	POSTGRES_PASSWORD=... VALKEY_PASSWORD=... go test ./tests -run TestStage8ModelMaturity -count=1
//
// 无环境变量时与既有集成测试一致地 t.Skip；数据落真实 PostgreSQL/Valkey。
package tests

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/events"
	"github.com/jiuzhang-waf/server/internal/apimodels"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
)

// s8Maturity 拉取成熟度总览并按 key 索引（断言 200 + 响应基本形状 + 固定模型顺序）。
func s8Maturity(t *testing.T, env *testEnv, cookies []*http.Cookie) map[string]map[string]interface{} {
	t.Helper()
	result := s5OK(t, env.get(t, "/api/v1/api-security/model-maturity", cookies), "model maturity")
	if ga, _ := result.Data["generated_at"].(string); ga == "" {
		t.Fatalf("generated_at missing: %+v", result.Data)
	}
	list, ok := result.Data["models"].([]interface{})
	if !ok || len(list) != 4 {
		t.Fatalf("models = %v, want 4 items: %+v", result.Data["models"], result.Data)
	}
	wantKeys := []string{"parameter", "identity", "access_env", "access_object"}
	out := map[string]map[string]interface{}{}
	for i, item := range list {
		m, ok := item.(map[string]interface{})
		if !ok {
			t.Fatalf("models[%d] not an object: %+v", i, item)
		}
		key, _ := m["key"].(string)
		if key != wantKeys[i] {
			t.Fatalf("models[%d].key = %q, want %q（固定顺序）", i, key, wantKeys[i])
		}
		if m["name"] == "" || m["stage"] == "" || m["summary"] == "" {
			t.Fatalf("models[%d] name/stage/summary missing: %+v", i, m)
		}
		if _, ok := m["metrics"].(map[string]interface{}); !ok {
			t.Fatalf("models[%d] metrics missing or not object: %+v", i, m)
		}
		out[key] = m
	}
	return out
}

// s8MaturityStage 断言指定模型当前 stage。
func s8MaturityStage(t *testing.T, models map[string]map[string]interface{}, key, want string) {
	t.Helper()
	if got := models[key]["stage"]; got != want {
		t.Errorf("%s stage = %v, want %s（summary: %v）", key, got, want, models[key]["summary"])
	}
}

// s8MaturityMetric 取指定模型 metrics 数值字段。
func s8MaturityMetric(t *testing.T, models map[string]map[string]interface{}, key, field string) float64 {
	t.Helper()
	return s5Num(t, models[key]["metrics"].(map[string]interface{}), field)
}

func TestStage8ModelMaturity(t *testing.T) {
	env := setupStage8Env(t)
	cookies, _ := env.s5Login(t, "s8mm", "SECURITY_ADMIN")
	ctx := context.Background()

	// 初始全 LEARNING（空库无产出）
	models := s8Maturity(t, env, cookies)
	for _, key := range []string{"parameter", "identity", "access_env", "access_object"} {
		s8MaturityStage(t, models, key, "LEARNING")
	}
	if got := s8MaturityMetric(t, models, "access_object", "resource_signal_events_24h"); got != 0 {
		t.Errorf("initial resource_signal_events_24h = %v, want 0", got)
	}

	// ---------- parameter：LEARNING → CANDIDATE → ENFORCING → CONFIRMED → ENFORCING ----------
	epP := s8SeedEndpoint(t, env, "POST", "/s8mm-"+s5Rand()+"/orders", 0.8)
	modelsStore := apimodels.NewStore(env.db)
	v1, err := modelsStore.CreateCandidateWithReason(ctx, epP.ID, epP.EndpointKey, "成熟度 v1",
		apimodels.CreatedReasonManual, map[string]string{"amount": "number", "note": "string"}, uuid.Nil)
	if err != nil {
		t.Fatalf("create v1: %v", err)
	}
	if _, err := modelsStore.Confirm(ctx, v1.ID, uuid.Nil); err != nil {
		t.Fatalf("confirm v1: %v", err)
	}
	// FORMAL 参数行已物化但无任何约束产出：仍 LEARNING
	s8MaturityStage(t, s8Maturity(t, env, cookies), "parameter", "LEARNING")
	// 推荐约束（第二批画像聚合产出）→ CANDIDATE
	s8Exec(t, env, `UPDATE api_parameter_models SET recommended_constraints='{"max_length":32}'::jsonb
WHERE model_version_id=$1 AND structured_path='note'`, v1.ID)
	s8MaturityStage(t, s8Maturity(t, env, cookies), "parameter", "CANDIDATE")
	// 人工确认且 v1 为最新 FORMAL（同源口径计入）→ ENFORCING
	s8Exec(t, env, `UPDATE api_parameter_models SET confirmed_constraints='{"max_length":32}'::jsonb
WHERE model_version_id=$1 AND structured_path='note'`, v1.ID)
	s8MaturityStage(t, s8Maturity(t, env, cookies), "parameter", "ENFORCING")
	// v2 确认后 v1 降级 SUPERSEDED：旧确认未随最新 FORMAL 下发 → CONFIRMED
	v2, err := modelsStore.CreateCandidateWithReason(ctx, epP.ID, epP.EndpointKey, "成熟度 v2",
		apimodels.CreatedReasonManual, map[string]string{"amount": "number"}, uuid.Nil)
	if err != nil {
		t.Fatalf("create v2: %v", err)
	}
	if _, err := modelsStore.Confirm(ctx, v2.ID, uuid.Nil); err != nil {
		t.Fatalf("confirm v2: %v", err)
	}
	models = s8Maturity(t, env, cookies)
	s8MaturityStage(t, models, "parameter", "CONFIRMED")
	if got := s8MaturityMetric(t, models, "parameter", "with_confirmed"); got != 1 {
		t.Errorf("with_confirmed = %v, want 1（v1 历史行）", got)
	}
	// v2 参数仅置 required（无确认约束词）也计入下发口径 → ENFORCING
	s8Exec(t, env, `UPDATE api_parameter_models SET required=true
WHERE model_version_id=$1 AND structured_path='amount'`, v2.ID)
	models = s8Maturity(t, env, cookies)
	s8MaturityStage(t, models, "parameter", "ENFORCING")
	if got := s8MaturityMetric(t, models, "parameter", "parameters_total"); got != 3 {
		t.Errorf("parameters_total = %v, want 3（v1 两行 + v2 一行）", got)
	}
	if got := s8MaturityMetric(t, models, "parameter", "enforced_formal_constraints"); got != 1 {
		t.Errorf("enforced_formal_constraints = %v, want 1", got)
	}

	// ---------- identity：CANDIDATE（覆盖率不足）→ CONFIRMED（≥50%） ----------
	rt := apiruntime.NewStore(env.db)
	now := time.Now().UTC()
	mk := func(reqID, identity string, at time.Time) *apiruntime.PrimaryEvent {
		return &apiruntime.PrimaryEvent{
			PrimaryEvent: events.PrimaryEvent{
				RequestID: reqID, EndpointKey: epP.EndpointKey,
				RiskScore: 10, RiskLevel: "LOW", FinalAction: "LOG",
				OccurredAt: at,
			},
			IdentityFingerprint: identity,
			AuthType:            "api_key",
			ResponseStatus:      200,
		}
	}
	// 1 带指纹 + 3 匿名（近 24h）+ 1 带指纹（25h 前，窗口外不计）
	for _, s := range []struct{ reqID, identity string }{
		{"mm-1", "fp-i1"}, {"mm-2", ""}, {"mm-3", ""}, {"mm-4", ""},
	} {
		if err := rt.SavePrimary(ctx, mk(s.reqID, s.identity, now.Add(-10*time.Minute))); err != nil {
			t.Fatalf("SavePrimary %s: %v", s.reqID, err)
		}
	}
	if err := rt.SavePrimary(ctx, mk("mm-old", "fp-old", now.Add(-25*time.Hour))); err != nil {
		t.Fatalf("SavePrimary old: %v", err)
	}
	models = s8Maturity(t, env, cookies)
	s8MaturityStage(t, models, "identity", "CANDIDATE")
	if got := s8MaturityMetric(t, models, "identity", "events_24h"); got != 4 {
		t.Errorf("events_24h = %v, want 4（25h 前事件不计）", got)
	}
	if got := s8MaturityMetric(t, models, "identity", "identity_coverage_24h"); got != 0.25 {
		t.Errorf("identity_coverage_24h = %v, want 0.25", got)
	}
	// 追加 3 个不同身份 → 覆盖率 4/7 ≈ 0.5714 ≥ 50% → CONFIRMED
	for _, s := range []struct{ reqID, identity string }{
		{"mm-5", "fp-i2"}, {"mm-6", "fp-i3"}, {"mm-7", "fp-i4"},
	} {
		if err := rt.SavePrimary(ctx, mk(s.reqID, s.identity, now.Add(-5*time.Minute))); err != nil {
			t.Fatalf("SavePrimary %s: %v", s.reqID, err)
		}
	}
	models = s8Maturity(t, env, cookies)
	s8MaturityStage(t, models, "identity", "CONFIRMED")
	if got := s8MaturityMetric(t, models, "identity", "identity_coverage_24h"); got != 0.5714 {
		t.Errorf("identity_coverage_24h = %v, want 0.5714", got)
	}
	if got := s8MaturityMetric(t, models, "identity", "distinct_identities_24h"); got != 4 {
		t.Errorf("distinct_identities_24h = %v, want 4", got)
	}

	// ---------- access_env：CANDIDATE（覆盖不足）→ CONFIRMED（≥45% 且含时段分布） ----------
	epEnv1 := s8SeedEndpoint(t, env, "GET", "/s8mm-"+s5Rand()+"/env/a", 0.7)
	epEnv2 := s8SeedEndpoint(t, env, "GET", "/s8mm-"+s5Rand()+"/env/b", 0.7)
	// 端点总数 3（epP/epEnv1/epEnv2），画像覆盖 1/3 < 45% → CANDIDATE
	s8Exec(t, env, `INSERT INTO api_behavior_profiles
(endpoint_id, identity_fingerprint, window_seconds, request_count, avg_rate, status_code_dist, hour_dist)
VALUES ($1, '', 3600, 5, 0.001, '{"2xx": 5}', '{}')`, epEnv1.ID)
	models = s8Maturity(t, env, cookies)
	s8MaturityStage(t, models, "access_env", "CANDIDATE")
	if got := s8MaturityMetric(t, models, "access_env", "profiles_with_hour_dist"); got != 0 {
		t.Errorf("profiles_with_hour_dist = %v, want 0", got)
	}
	// 覆盖 2/3 ≥ 45% 且含时段分布 → CONFIRMED
	s8Exec(t, env, `INSERT INTO api_behavior_profiles
(endpoint_id, identity_fingerprint, window_seconds, request_count, avg_rate, status_code_dist, hour_dist)
VALUES ($1, 'fp-i1', 3600, 3, 0.0008, '{"2xx": 3}', '{"9": 3}')`, epEnv2.ID)
	models = s8Maturity(t, env, cookies)
	s8MaturityStage(t, models, "access_env", "CONFIRMED")
	if got := s8MaturityMetric(t, models, "access_env", "endpoint_coverage"); got != 0.6667 {
		t.Errorf("endpoint_coverage = %v, want 0.6667", got)
	}
	if got := s8MaturityMetric(t, models, "access_env", "endpoints_total"); got != 3 {
		t.Errorf("endpoints_total = %v, want 3", got)
	}

	// ---------- access_object：无模型行 → LEARNING（信号仅 metrics）；覆盖 <45% → CANDIDATE；≥45% → CONFIRMED ----------
	resEv := mk("mm-res-1", "fp-i1", now)
	resEv.Details = []dsctx.DetectorMatch{
		{Detector: "auth", RuleID: "resource.unauthenticated_object_access", Severity: "OBSERVE"},
	}
	if err := rt.SavePrimary(ctx, resEv); err != nil {
		t.Fatalf("SavePrimary resource hit: %v", err)
	}
	models = s8Maturity(t, env, cookies)
	s8MaturityStage(t, models, "access_object", "LEARNING")
	if got := s8MaturityMetric(t, models, "access_object", "resource_signal_events_24h"); got != 1 {
		t.Errorf("resource_signal_events_24h = %v, want 1", got)
	}
	if got := s8MaturityMetric(t, models, "access_object", "object_models_total"); got != 0 {
		t.Errorf("object_models_total = %v, want 0", got)
	}
	// 对象模型表出现写入 → 端点覆盖 1/3 ≈ 33% < 45% → CANDIDATE
	s8Exec(t, env, `INSERT INTO api_object_models (endpoint_id, object_segment, identifier_type)
VALUES ($1, '1', 'numeric')`, epP.ID)
	models = s8Maturity(t, env, cookies)
	s8MaturityStage(t, models, "access_object", "CANDIDATE")
	if got := s8MaturityMetric(t, models, "access_object", "endpoints_with_object_models"); got != 1 {
		t.Errorf("endpoints_with_object_models = %v, want 1", got)
	}
	// 覆盖 2/3 ≈ 66.7% ≥ 45% → CONFIRMED
	s8Exec(t, env, `INSERT INTO api_object_models (endpoint_id, object_segment, identifier_type)
VALUES ($1, '1', 'numeric')`, epEnv2.ID)
	models = s8Maturity(t, env, cookies)
	s8MaturityStage(t, models, "access_object", "CONFIRMED")
	if got := s8MaturityMetric(t, models, "access_object", "object_endpoint_coverage"); got != 0.6667 {
		t.Errorf("object_endpoint_coverage = %v, want 0.6667", got)
	}

	// 权限底线：未登录访问 401
	resp := env.do(t, http.MethodGet, "/api/v1/api-security/model-maturity", "", nil, "")
	s5Expect(t, resp, http.StatusUnauthorized, "unauthenticated model-maturity query")
}
