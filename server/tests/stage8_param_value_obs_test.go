// stage8_param_value_obs_test.go 参数值观测通路（三微模型增强批）。
// 覆盖：api_parameter_value_obs 表（000031）；RecordParamObservations 聚合；
// RefreshParameterStatistics 回填 min/max_length 与 distinct_count；semantic_type 推断。
package tests

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apimodels"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
)

// TestStage8ParamValueObservations 值观测 → statistics 回填 → recommended 可产。
func TestStage8ParamValueObservations(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()

	// 迁移 000031 表
	if n := s8Count(t, env, `
SELECT count(*) FROM information_schema.tables
WHERE table_schema='public' AND table_name='api_parameter_value_obs'`); n != 1 {
		t.Skip("migration 000031 not applied; skip value obs integration")
	}

	models := apimodels.NewStore(env.db)
	ep := s8SeedEndpoint(t, env, "POST", "/s8obs-"+s5Rand()+"/pay", 0.8)
	v1, err := models.CreateCandidateWithReason(ctx, ep.ID, ep.EndpointKey, "obs v1",
		apimodels.CreatedReasonManual, map[string]string{"user_id": "string", "amount": "number"}, uuid.Nil)
	if err != nil {
		t.Fatalf("create candidate: %v", err)
	}
	if _, err := models.Confirm(ctx, v1.ID, uuid.Nil); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	s8Exec(t, env, `UPDATE api_endpoints SET learning_status='LEARNED' WHERE id=$1`, ep.ID)
	// 样本：≥100 accepted 才生成 recommended（recommended.go RecommendMinSamples）
	for i := 0; i < 100; i++ {
		s8Exec(t, env, `
INSERT INTO api_learning_samples (api_endpoint_id, request_id, sample_hash, source_fingerprint, response_status, accepted, exclude_reason)
VALUES ($1,$2,$3,'src',200,true,'')`, ep.ID, "r-"+s5Rand(), "h-"+s5Rand())
	}

	// 写入脱敏观测（BODY amount 数值；QUERY user_id 长度）
	obs := apiruntime.NewParamObsStore(env.db)
	amt := 12.5
	if err := obs.RecordParamObservations(ctx, ep.EndpointKey, []apiruntime.ParamObservation{
		{Location: "BODY", Name: "amount", Path: "amount", BaseType: "number", Length: 4, ValueHash: "aaaa1111bbbb2222", NumValue: &amt},
		{Location: "BODY", Name: "user_id", Path: "user_id", BaseType: "string", Length: 8, ValueHash: "cccc3333dddd4444"},
	}); err != nil {
		t.Fatalf("record obs: %v", err)
	}
	// 再记一条不同 hash / 更大长度，验证 min/max 与 distinct
	amt2 := 99.0
	if err := obs.RecordParamObservations(ctx, ep.EndpointKey, []apiruntime.ParamObservation{
		{Location: "BODY", Name: "amount", Path: "amount", BaseType: "number", Length: 5, ValueHash: "eeee5555ffff6666", NumValue: &amt2},
		{Location: "BODY", Name: "user_id", Path: "user_id", BaseType: "string", Length: 16, ValueHash: "gggg7777hhhh8888"},
	}); err != nil {
		t.Fatalf("record obs 2: %v", err)
	}

	n, err := models.RefreshParameterStatistics(ctx)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if n != 2 {
		t.Fatalf("refreshed = %d, want 2", n)
	}

	// amount 行：min/max value 与 length 已回填
	var minLen, maxLen, distinct *int
	var minVal, maxVal *float64
	if err := env.db.QueryRow(ctx, `
SELECT st.min_length, st.max_length, st.min_value, st.max_value, st.distinct_count
FROM api_parameter_statistics st
JOIN api_parameter_models p ON p.id = st.parameter_id
WHERE p.model_version_id=$1 AND p.structured_path='amount'`, v1.ID).
		Scan(&minLen, &maxLen, &minVal, &maxVal, &distinct); err != nil {
		t.Fatalf("read amount stats: %v", err)
	}
	if minLen == nil || maxLen == nil || *minLen != 4 || *maxLen != 5 {
		t.Errorf("amount length = %v/%v, want 4/5", minLen, maxLen)
	}
	if minVal == nil || maxVal == nil || *minVal != 12.5 || *maxVal != 99.0 {
		t.Errorf("amount value = %v/%v, want 12.5/99", minVal, maxVal)
	}
	if distinct == nil || *distinct < 2 {
		t.Errorf("amount distinct = %v, want >=2", distinct)
	}

	// semantic_type 推断：user_id → id
	var sem string
	if err := env.db.QueryRow(ctx, `
SELECT semantic_type FROM api_parameter_models
WHERE model_version_id=$1 AND parameter_name='user_id'`, v1.ID).Scan(&sem); err != nil {
		t.Fatalf("semantic: %v", err)
	}
	if sem != "id" {
		t.Errorf("user_id semantic_type = %q, want id", sem)
	}

	// 样本量 ≥100 且有长度观测 → recommended 含 max_length
	var rec []byte
	if err := env.db.QueryRow(ctx, `
SELECT recommended_constraints FROM api_parameter_models
WHERE model_version_id=$1 AND structured_path='user_id'`, v1.ID).Scan(&rec); err != nil {
		t.Fatalf("recommended: %v", err)
	}
	if string(rec) == "{}" || string(rec) == "null" {
		t.Errorf("recommended_constraints empty for user_id, want length bounds: %s", rec)
	}
}
