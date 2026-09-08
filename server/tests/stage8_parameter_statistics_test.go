// 阶段8（WDSP）参数统计画像集成测试（三微模型框架 §四.5，第二批）。
//
// 覆盖：RefreshParameterStatistics 的范围门控（LEARNED + accepted 样本 + 最新 FORMAL
// 版本的 REQUEST 参数）、UPSERT 幂等（重复执行行数与取值一致）、example_hashes 只留
// accepted 样本哈希、无值观测数据源时可空统计列保持 NULL（不虚构）、observed/
// recommended 不生成空约束、confirmed_constraints 绝不触碰、旧版本参数快照不受影响。
//
// 运行方式（与 make stage8-test-api 一致）：
//
//	POSTGRES_PASSWORD=... VALKEY_PASSWORD=... go test ./tests -run TestStage8ParameterStatistics -count=1
//
// 无环境变量时与既有集成测试一致地 t.Skip；数据落真实 PostgreSQL/Valkey。
package tests

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apimodels"
)

// TestStage8ParameterStatistics 参数统计画像写入方（离线聚合 + UPSERT 幂等 + 三层约束纪律）。
func TestStage8ParameterStatistics(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	models := apimodels.NewStore(env.db)

	// 端点 + FORMAL 版本（Confirm 同事务物化 2 个 BODY 参数行）
	ep := s8SeedEndpoint(t, env, "POST", "/s8"+s5Rand()+"/stats", 0.7)
	v1, err := models.CreateCandidateWithReason(ctx, ep.ID, ep.EndpointKey, "画像测试 v1",
		apimodels.CreatedReasonManual, map[string]string{"amount": "number", "note": "string"}, uuid.Nil)
	if err != nil {
		t.Fatalf("create candidate: %v", err)
	}
	if _, err := models.Confirm(ctx, v1.ID, uuid.Nil); err != nil {
		t.Fatalf("confirm v1: %v", err)
	}
	// 学习完成态（门控条件）+ 样本造数（3 accepted + 1 excluded）
	s8Exec(t, env, `UPDATE api_endpoints SET learning_status='LEARNED' WHERE id=$1`, ep.ID)
	s8Exec(t, env, `
INSERT INTO api_learning_samples (api_endpoint_id, request_id, sample_hash, source_fingerprint, response_status, accepted, exclude_reason)
VALUES ($1,'req-1','hash-1','src-1',200,true,''),
       ($1,'req-2','hash-2','src-2',200,true,''),
       ($1,'req-3','hash-3','src-1',200,true,''),
       ($1,'req-x','hash-x','src-9',500,false,'response_status_500')`, ep.ID)
	// 预置人工确认约束：画像刷新绝不触碰
	s8Exec(t, env, `UPDATE api_parameter_models SET confirmed_constraints='{"max_length":32}'::jsonb
WHERE model_version_id=$1 AND structured_path='note'`, v1.ID)

	// 首轮刷新：2 行统计（每参数 1:1）
	n, err := models.RefreshParameterStatistics(ctx)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if n != 2 {
		t.Fatalf("refreshed rows = %d, want 2", n)
	}
	statsOfVersion := `SELECT count(*) FROM api_parameter_statistics st
JOIN api_parameter_models p ON p.id = st.parameter_id
WHERE p.model_version_id=$1`
	if got := s8Count(t, env, statsOfVersion, v1.ID); got != 2 {
		t.Fatalf("statistics rows = %d, want 2", got)
	}
	// sample_count=3（excluded 不计）、example_hashes 只含 accepted 哈希
	if got := s8Count(t, env, statsOfVersion+`
  AND st.sample_count=3 AND jsonb_array_length(st.example_hashes)=3
  AND st.example_hashes @> '["hash-1","hash-2","hash-3"]'::jsonb
  AND NOT st.example_hashes @> '["hash-x"]'::jsonb`, v1.ID); got != 2 {
		t.Fatalf("sample_count/example_hashes mismatch: %d", got)
	}
	// 无值观测数据源：可空统计列保持 NULL（不虚构）
	if got := s8Count(t, env, statsOfVersion+`
  AND st.min_length IS NULL AND st.max_length IS NULL
  AND st.min_value IS NULL AND st.max_value IS NULL AND st.distinct_count IS NULL`, v1.ID); got != 2 {
		t.Fatalf("value stats should stay NULL without data source: %d", got)
	}
	// 无观测输入：observed/recommended 均不生成（保持空对象）
	if got := s8Count(t, env, `SELECT count(*) FROM api_parameter_models
WHERE model_version_id=$1 AND observed_constraints='{}'::jsonb AND recommended_constraints='{}'::jsonb`, v1.ID); got != 2 {
		t.Fatalf("observed/recommended should stay empty: %d", got)
	}
	// confirmed 未被触碰
	if got := s8Count(t, env, `SELECT count(*) FROM api_parameter_models
WHERE model_version_id=$1 AND confirmed_constraints='{"max_length":32}'::jsonb`, v1.ID); got != 1 {
		t.Fatalf("confirmed_constraints must be untouched: %d", got)
	}

	// 幂等：第二轮行数不增、取值一致（UPSERT 而非重复插入）
	if n, err = models.RefreshParameterStatistics(ctx); err != nil || n != 2 {
		t.Fatalf("second refresh: n=%d err=%v, want 2", n, err)
	}
	if got := s8Count(t, env, statsOfVersion, v1.ID); got != 2 {
		t.Fatalf("statistics rows after rerun = %d, want 2（UPSERT 幂等）", got)
	}
	if got := s8Count(t, env, statsOfVersion+` AND st.sample_count=3`, v1.ID); got != 2 {
		t.Fatalf("sample_count after rerun = %d rows with 3, want 2", got)
	}
	// 重算感知新样本：追加 1 条 accepted 后 sample_count=4
	s8Exec(t, env, `
INSERT INTO api_learning_samples (api_endpoint_id, request_id, sample_hash, source_fingerprint, response_status, accepted)
VALUES ($1,'req-4','hash-4','src-2',200,true)`, ep.ID)
	if n, err = models.RefreshParameterStatistics(ctx); err != nil || n != 2 {
		t.Fatalf("third refresh: n=%d err=%v, want 2", n, err)
	}
	if got := s8Count(t, env, statsOfVersion+` AND st.sample_count=4 AND jsonb_array_length(st.example_hashes)=4`, v1.ID); got != 2 {
		t.Fatalf("recompute should pick up new sample: %d", got)
	}

	// 门控：未 LEARNED 端点（有样本、有 FORMAL 参数行）不产出
	ep2 := s8SeedEndpoint(t, env, "GET", "/s8"+s5Rand()+"/stats/notlearned", 0.7)
	vOther, err := models.CreateCandidateWithReason(ctx, ep2.ID, ep2.EndpointKey, "未学习端点",
		apimodels.CreatedReasonManual, map[string]string{"q": "string"}, uuid.Nil)
	if err != nil {
		t.Fatalf("create candidate ep2: %v", err)
	}
	if _, err := models.Confirm(ctx, vOther.ID, uuid.Nil); err != nil {
		t.Fatalf("confirm ep2: %v", err)
	}
	s8Exec(t, env, `
INSERT INTO api_learning_samples (api_endpoint_id, request_id, sample_hash, accepted)
VALUES ($1,'req-n1','hash-n1',true)`, ep2.ID)
	// 门控：LEARNED + FORMAL 但无 accepted 样本不产出
	ep3 := s8SeedEndpoint(t, env, "GET", "/s8"+s5Rand()+"/stats/nosamples", 0.7)
	vEmpty, err := models.CreateCandidateWithReason(ctx, ep3.ID, ep3.EndpointKey, "无样本端点",
		apimodels.CreatedReasonManual, map[string]string{"q": "string"}, uuid.Nil)
	if err != nil {
		t.Fatalf("create candidate ep3: %v", err)
	}
	if _, err := models.Confirm(ctx, vEmpty.ID, uuid.Nil); err != nil {
		t.Fatalf("confirm ep3: %v", err)
	}
	s8Exec(t, env, `UPDATE api_endpoints SET learning_status='LEARNED' WHERE id=$1`, ep3.ID)
	if _, err := models.RefreshParameterStatistics(ctx); err != nil {
		t.Fatalf("refresh with gated endpoints: %v", err)
	}
	if got := s8Count(t, env, statsOfVersion, vOther.ID); got != 0 {
		t.Fatalf("not-learned endpoint should produce no statistics, got %d", got)
	}
	if got := s8Count(t, env, statsOfVersion, vEmpty.ID); got != 0 {
		t.Fatalf("no-sample endpoint should produce no statistics, got %d", got)
	}

	// 最新 FORMAL 语义：v2 确认后 v1 降级 SUPERSEDED，画像只随 v2 参数重算，
	// v1 统计行作为历史快照保留（版本归档不影响历史参数快照）。
	v2, err := models.CreateCandidateWithReason(ctx, ep.ID, ep.EndpointKey, "画像测试 v2",
		apimodels.CreatedReasonManual, map[string]string{"amount": "number", "extra": "string"}, uuid.Nil)
	if err != nil {
		t.Fatalf("create candidate v2: %v", err)
	}
	if _, err := models.Confirm(ctx, v2.ID, uuid.Nil); err != nil {
		t.Fatalf("confirm v2: %v", err)
	}
	if n, err = models.RefreshParameterStatistics(ctx); err != nil || n != 2 {
		t.Fatalf("refresh after v2: n=%d err=%v, want 2（仅 v2 参数）", n, err)
	}
	if got := s8Count(t, env, statsOfVersion+` AND st.sample_count=4`, v2.ID); got != 2 {
		t.Fatalf("v2 statistics = %d, want 2", got)
	}
	if got := s8Count(t, env, statsOfVersion, v1.ID); got != 2 {
		t.Fatalf("v1 statistics snapshot should be kept, got %d", got)
	}
}
