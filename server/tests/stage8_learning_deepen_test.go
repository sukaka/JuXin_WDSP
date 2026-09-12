// stage8_learning_deepen_test.go 学习闭环加深集成测试（P0-01/02，迁移 000038）。
//
// 覆盖：
//   - 落样维护 unique_ips/unique_identities/first_sample_at（去重口径：accepted 且指纹非空）；
//     (endpoint, request_id) 幂等不重复计数；
//   - ListRunningLearningJobs 进度（成功率原料：带状态码 accepted 数 / 2xx/3xx 数）；
//   - FailLearning（FAILED + last_error）与 AttachLearningCandidate（candidate_version_id 回填）；
//   - CreateLearnedCandidate：有观测 → 非空 schema（类型推断 number/bool/string）+ 自动
//     IN_REVIEW + 参数行 observed/required 物化；无观测 → 回退空 Schema（旧行为）；
//   - Confirm 物化 QUERY/PATH 参数行（孤儿观测断链修复）+ statistics 回填 + enum_suspected 推荐；
//   - learningjobs.SweepOnce 全链路：多条件达标 → COMPLETED + 候选 IN_REVIEW + 版本回填 +
//     端点 LEARNED；未达标且超期 → FAILED + last_error 说明。
//
// 运行方式（与 make stage8-test-api 一致）：
//
//	POSTGRES_PASSWORD=... VALKEY_PASSWORD=... go test ./tests -run 'TestStage8LearningDeepen|TestStage8LearnedCandidate|TestStage8LearningSweepLoop' -count=1
//
// 无环境变量时与既有集成测试一致地 t.Skip；数据落真实 PostgreSQL/Valkey。
package tests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apiassets"
	"github.com/jiuzhang-waf/server/internal/apimodels"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
	"github.com/jiuzhang-waf/server/internal/learningjobs"
)

// s8DeepenGuard 迁移 000038 未应用时跳过（列缺失说明环境未迁移到本批）。
func s8DeepenGuard(t *testing.T, env *testEnv) {
	t.Helper()
	if n := s8Count(t, env, `
SELECT count(*) FROM information_schema.columns
WHERE table_name='api_learning_jobs'
  AND column_name IN ('unique_ips','unique_identities','first_sample_at','candidate_version_id')`); n != 4 {
		t.Skip("migration 000038 not applied; skip learning deepen integration")
	}
}

// s8ValueHash 与网关 observeScalar 同口径的观测哈希（sha256 截断 8 字节 hex）。
func s8ValueHash(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:8])
}

// TestStage8LearningDeepenProgress 落样维护学习质量维度 + 进度查询 + FAILED/候选回填。
func TestStage8LearningDeepenProgress(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	s8DeepenGuard(t, env)

	store := apiassets.NewStore(env.db)
	ep := s8SeedEndpoint(t, env, "POST", "/s8"+s5Rand()+"/deepen", 0.8)
	job, err := store.StartLearning(ctx, ep.ID, 10, nil)
	if err != nil {
		t.Fatalf("start learning: %v", err)
	}

	// 落样：2 来源 × 2 身份；1 条非 2xx/3xx 的 accepted（成功率分母 3，分子 2）；
	// 1 条排除样本（不进 unique 计数）；req-1 重放（幂等不重复计数）。
	samples := []apiassets.LearningSampleInput{
		{EndpointKey: ep.EndpointKey, RequestID: "req-1", SourceFingerprint: "src-a", IdentityFingerprint: "id-1", ResponseStatus: 200, Accepted: true},
		{EndpointKey: ep.EndpointKey, RequestID: "req-2", SourceFingerprint: "src-a", IdentityFingerprint: "id-2", ResponseStatus: 201, Accepted: true},
		{EndpointKey: ep.EndpointKey, RequestID: "req-3", SourceFingerprint: "src-b", IdentityFingerprint: "id-2", ResponseStatus: 500, Accepted: true, ExcludeReason: ""},
		{EndpointKey: ep.EndpointKey, RequestID: "req-4", SourceFingerprint: "src-c", IdentityFingerprint: "", ResponseStatus: 403, Accepted: false, ExcludeReason: "response_status_403"},
		{EndpointKey: ep.EndpointKey, RequestID: "req-1", SourceFingerprint: "src-a", IdentityFingerprint: "id-1", ResponseStatus: 200, Accepted: true},
	}
	for i, in := range samples {
		rec, err := store.RecordLearningSample(ctx, in)
		if err != nil {
			t.Fatalf("record sample %d: %v", i, err)
		}
		if !rec {
			t.Fatalf("sample %d should be recorded (RUNNING job exists)", i)
		}
	}

	progress, err := store.ListRunningLearningJobs(ctx)
	if err != nil {
		t.Fatalf("list running: %v", err)
	}
	if len(progress) != 1 {
		t.Fatalf("running jobs=%d, want 1", len(progress))
	}
	p := progress[0]
	if p.ValidCount != 3 || p.ExcludedCount != 1 || p.CollectedCount != 4 {
		t.Fatalf("counters: collected=%d valid=%d excluded=%d, want 4/3/1（重放幂等）",
			p.CollectedCount, p.ValidCount, p.ExcludedCount)
	}
	if p.UniqueIPs != 2 || p.UniqueIdentities != 2 {
		t.Fatalf("unique: ips=%d identities=%d, want 2/2（accepted 且非空指纹去重）", p.UniqueIPs, p.UniqueIdentities)
	}
	if p.FirstSampleAt == nil {
		t.Fatal("first_sample_at should be set after first sample")
	}
	if p.StatusSampleCount != 3 || p.SuccessCount != 2 {
		t.Fatalf("success material: %d/%d, want 2/3（500 计分母不计分子）", p.SuccessCount, p.StatusSampleCount)
	}

	// AttachLearningCandidate：回填真实候选版本（FK 约束）
	models := apimodels.NewStore(env.db)
	v, err := models.CreateCandidateWithReason(ctx, ep.ID, ep.EndpointKey, "attach 测试",
		apimodels.CreatedReasonManual, map[string]string{"a": "string"}, uuid.Nil)
	if err != nil {
		t.Fatalf("create candidate: %v", err)
	}
	if err := store.AttachLearningCandidate(ctx, job.ID, v.ID); err != nil {
		t.Fatalf("attach candidate: %v", err)
	}
	var attached *uuid.UUID
	if err := env.db.QueryRow(ctx,
		`SELECT candidate_version_id FROM api_learning_jobs WHERE id=$1`, job.ID).Scan(&attached); err != nil {
		t.Fatalf("read candidate_version_id: %v", err)
	}
	if attached == nil || *attached != v.ID {
		t.Fatalf("candidate_version_id=%v, want %v", attached, v.ID)
	}

	// FailLearning：FAILED + last_error；不再出现在 RUNNING 扫描源
	cause := "学习超过最长时限（168h0m0s）仍未达标：有效样本数不足（3/10）"
	if err := store.FailLearning(ctx, job.ID, cause); err != nil {
		t.Fatalf("fail learning: %v", err)
	}
	latest, _, err := store.LearningStatus(ctx, ep.ID)
	if err != nil {
		t.Fatalf("learning status: %v", err)
	}
	if latest == nil || latest.Status != "FAILED" || latest.LastError != cause {
		t.Fatalf("latest job=%+v, want FAILED with cause", latest)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_learning_jobs WHERE id=$1 AND stopped_at IS NOT NULL`, job.ID); n != 1 {
		t.Fatal("FAILED job should have stopped_at")
	}
	progress, err = store.ListRunningLearningJobs(ctx)
	if err != nil {
		t.Fatalf("list running after fail: %v", err)
	}
	if len(progress) != 0 {
		t.Fatalf("FAILED job must leave running scan: %+v", progress)
	}
	// 重复 Fail 返回 ErrLearningNotRunning（并发/重复清扫安全）
	if err := store.FailLearning(ctx, job.ID, "again"); err == nil {
		t.Fatal("re-fail a FAILED job should return ErrLearningNotRunning")
	}
}

// TestStage8LearnedCandidate 自动候选构建：有观测→非空 schema+IN_REVIEW+参数行；
// 无观测→空 Schema 回退；Confirm 物化 QUERY/PATH + statistics 回填 + enum_suspected。
func TestStage8LearnedCandidate(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	s8DeepenGuard(t, env)

	models := apimodels.NewStore(env.db)
	obs := apiruntime.NewParamObsStore(env.db)

	// ---- 有观测：非空候选 + 类型推断 + 自动 IN_REVIEW + 参数行 observed/required ----
	ep := s8SeedEndpoint(t, env, "POST", "/s8"+s5Rand()+"/order", 0.8)
	amt1, amt2 := 12.5, 99.0
	// amount 出现 2 次（数值），flag 2 次（true/false 哈希→布尔），note 1 次（字符串）
	for _, o := range [][]apiruntime.ParamObservation{
		{{Location: "BODY", Name: "amount", Path: "amount", BaseType: "number", Length: 4, ValueHash: s8ValueHash("12.5"), NumValue: &amt1},
			{Location: "BODY", Name: "flag", Path: "flag", BaseType: "bool", Length: 4, ValueHash: s8ValueHash("true")},
			{Location: "BODY", Name: "note", Path: "note", BaseType: "string", Length: 3, ValueHash: s8ValueHash("abc")}},
		{{Location: "BODY", Name: "amount", Path: "amount", BaseType: "number", Length: 2, ValueHash: s8ValueHash("99"), NumValue: &amt2},
			{Location: "BODY", Name: "flag", Path: "flag", BaseType: "bool", Length: 5, ValueHash: s8ValueHash("false")}},
	} {
		if err := obs.RecordParamObservations(ctx, ep.EndpointKey, o); err != nil {
			t.Fatalf("record obs: %v", err)
		}
	}

	v, err := models.CreateLearnedCandidate(ctx, ep.ID, ep.EndpointKey, 2)
	if err != nil {
		t.Fatalf("create learned candidate: %v", err)
	}
	if v.Status != apimodels.StatusInReview {
		t.Fatalf("status=%q, want IN_REVIEW（自动提交评审）", v.Status)
	}
	if v.CreatedReason != apimodels.CreatedReasonLearningThreshold {
		t.Fatalf("created_reason=%q", v.CreatedReason)
	}
	if len(v.Schema) != 3 || v.Schema["amount"] != "number" || v.Schema["flag"] != "bool" || v.Schema["note"] != "string" {
		t.Fatalf("schema=%v, want 3 fields with inferred types number/bool/string", v.Schema)
	}
	if !strings.Contains(v.ChangeSummary, "自动生成") || !strings.Contains(v.ChangeSummary, "观测字段 3 个") {
		t.Fatalf("summary should note auto generation and stats: %q", v.ChangeSummary)
	}
	// 评审轨迹：SUBMIT 记录
	if n := s8Count(t, env, `SELECT count(*) FROM api_model_reviews WHERE model_version_id=$1 AND action='SUBMIT'`, v.ID); n != 1 {
		t.Fatalf("SUBMIT review rows=%d, want 1", n)
	}
	// 参数行：amount 出现率 100% → required=true 且 observed 带数值上下界；note 50% → required=false
	var amountRequired, noteRequired bool
	var amountObserved, noteObserved []byte
	if err := env.db.QueryRow(ctx, `
SELECT required, observed_constraints FROM api_parameter_models
WHERE model_version_id=$1 AND location='BODY' AND structured_path='amount'`, v.ID).
		Scan(&amountRequired, &amountObserved); err != nil {
		t.Fatalf("read amount param: %v", err)
	}
	if err := env.db.QueryRow(ctx, `
SELECT required, observed_constraints FROM api_parameter_models
WHERE model_version_id=$1 AND location='BODY' AND structured_path='note'`, v.ID).
		Scan(&noteRequired, &noteObserved); err != nil {
		t.Fatalf("read note param: %v", err)
	}
	if !amountRequired || noteRequired {
		t.Fatalf("required: amount=%v note=%v, want true/false（presence≥95%% 判定）", amountRequired, noteRequired)
	}
	var amountObs, noteObs map[string]any
	if err := json.Unmarshal(amountObserved, &amountObs); err != nil {
		t.Fatalf("decode amount observed: %v", err)
	}
	if err := json.Unmarshal(noteObserved, &noteObs); err != nil {
		t.Fatalf("decode note observed: %v", err)
	}
	if amountObs["minimum"] != 12.5 || amountObs["maximum"] != 99.0 {
		t.Fatalf("amount observed=%v, want minimum 12.5 / maximum 99", amountObs)
	}
	if noteObs["min_length"] != float64(3) {
		t.Fatalf("note observed=%v, want min_length 3", noteObs)
	}
	// confirmed 约束绝不自动触碰
	if n := s8Count(t, env, `SELECT count(*) FROM api_parameter_models
WHERE model_version_id=$1 AND confirmed_constraints <> '{}'::jsonb`, v.ID); n != 0 {
		t.Fatalf("confirmed_constraints must stay empty, got %d rows touched", n)
	}

	// ---- 无观测：回退空 Schema（旧行为）+ 仍自动 IN_REVIEW ----
	epEmpty := s8SeedEndpoint(t, env, "GET", "/s8"+s5Rand()+"/no-obs", 0.8)
	vEmpty, err := models.CreateLearnedCandidate(ctx, epEmpty.ID, epEmpty.EndpointKey, 10)
	if err != nil {
		t.Fatalf("create fallback candidate: %v", err)
	}
	if vEmpty.Status != apimodels.StatusInReview || len(vEmpty.Schema) != 0 {
		t.Fatalf("fallback: status=%q schema=%v, want IN_REVIEW + empty schema", vEmpty.Status, vEmpty.Schema)
	}
	if !strings.Contains(vEmpty.ChangeSummary, "无参数观测数据") {
		t.Fatalf("fallback summary should note no observations: %q", vEmpty.ChangeSummary)
	}

	// ---- QUERY/PATH 物化（孤儿观测断链修复）+ statistics 回填 + enum_suspected ----
	ep2 := s8SeedEndpoint(t, env, "GET", "/s8"+s5Rand()+"/items/{id}", 0.8)
	// 观测先于 Confirm 产生（真实链路：流量观测与学习/确认无先后依赖）
	for _, o := range [][]apiruntime.ParamObservation{
		{{Location: "QUERY", Name: "page", Path: "", BaseType: "string", Length: 1, ValueHash: s8ValueHash("1")},
			{Location: "PATH", Name: "{id}", Path: "1", BaseType: "string", Length: 36, ValueHash: s8ValueHash("uuid-1")}},
		{{Location: "QUERY", Name: "page", Path: "", BaseType: "string", Length: 2, ValueHash: s8ValueHash("12")}},
	} {
		if err := obs.RecordParamObservations(ctx, ep2.EndpointKey, o); err != nil {
			t.Fatalf("record obs ep2: %v", err)
		}
	}
	v1, err := models.CreateCandidateWithReason(ctx, ep2.ID, ep2.EndpointKey, "qp v1",
		apimodels.CreatedReasonManual, map[string]string{"amount": "number"}, uuid.Nil)
	if err != nil {
		t.Fatalf("create candidate v1: %v", err)
	}
	if _, err := models.Confirm(ctx, v1.ID, uuid.Nil); err != nil {
		t.Fatalf("confirm v1: %v", err)
	}
	// Confirm 物化：BODY amount + QUERY page + PATH {id}
	var qpRows int
	if err := env.db.QueryRow(ctx, `
SELECT count(*) FROM api_parameter_models
WHERE model_version_id=$1 AND direction='REQUEST'
  AND ((location='QUERY' AND parameter_name='page') OR (location='PATH' AND parameter_name='{id}' AND structured_path='1'))`,
		v1.ID).Scan(&qpRows); err != nil {
		t.Fatalf("count qp rows: %v", err)
	}
	if qpRows != 2 {
		t.Fatalf("QUERY/PATH materialized rows=%d, want 2", qpRows)
	}
	// 学习完成态 + 100 accepted 样本（statistics 范围门控 + recommended 样本量阈值）
	s8Exec(t, env, `UPDATE api_endpoints SET learning_status='LEARNED' WHERE id=$1`, ep2.ID)
	for i := 0; i < 100; i++ {
		s8Exec(t, env, `
INSERT INTO api_learning_samples (api_endpoint_id, request_id, sample_hash, source_fingerprint, response_status, accepted, exclude_reason)
VALUES ($1,$2,$3,'src',200,true,'')`, ep2.ID, "r-"+s5Rand(), "h-"+s5Rand())
	}
	n, err := models.RefreshParameterStatistics(ctx)
	if err != nil {
		t.Fatalf("refresh statistics: %v", err)
	}
	if n != 3 {
		t.Fatalf("refreshed=%d, want 3（BODY+QUERY+PATH 全进行画像）", n)
	}
	// QUERY page 观测回填上 statistics（修复前：无参数行 → 孤儿）
	var minLen, maxLen, distinct *int
	if err := env.db.QueryRow(ctx, `
SELECT st.min_length, st.max_length, st.distinct_count
FROM api_parameter_statistics st
JOIN api_parameter_models p ON p.id = st.parameter_id
WHERE p.model_version_id=$1 AND p.location='QUERY' AND p.parameter_name='page'`, v1.ID).
		Scan(&minLen, &maxLen, &distinct); err != nil {
		t.Fatalf("read QUERY page stats: %v", err)
	}
	if minLen == nil || *minLen != 1 || maxLen == nil || *maxLen != 2 || distinct == nil || *distinct != 2 {
		t.Fatalf("QUERY page stats: min=%v max=%v distinct=%v, want 1/2/2", minLen, maxLen, distinct)
	}
	// distinct≤20 且样本量达标 → enum_suspected 推荐（不落明文枚举值）
	var pageRecommended []byte
	if err := env.db.QueryRow(ctx, `
SELECT recommended_constraints FROM api_parameter_models
WHERE model_version_id=$1 AND location='QUERY' AND parameter_name='page'`, v1.ID).Scan(&pageRecommended); err != nil {
		t.Fatalf("read page recommended: %v", err)
	}
	var rec map[string]any
	if err := json.Unmarshal(pageRecommended, &rec); err != nil {
		t.Fatalf("decode recommended: %v", err)
	}
	if rec["enum_suspected"] != true || rec["distinct_count"] != float64(2) {
		t.Fatalf("recommended=%v, want enum_suspected=true + distinct_count=2", rec)
	}
	if _, ok := rec["enum"]; ok {
		t.Fatalf("must not emit plaintext enum values (data minimization): %v", rec)
	}
}

// TestStage8LearningSweepLoop janitor 全链路：多条件达标自动闭环；超期未达标 FAILED。
func TestStage8LearningSweepLoop(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	s8DeepenGuard(t, env)

	store := apiassets.NewStore(env.db)
	worker := learningjobs.NewWorker(store, apimodels.NewStore(env.db), nil, nil)

	// 达标任务：目标 10，10 条 accepted（2 来源 ≥ 默认 min_unique_ips=1，2xx 全部成功）
	ep := s8SeedEndpoint(t, env, "POST", "/s8"+s5Rand()+"/sweep-ok", 0.8)
	job, err := store.StartLearning(ctx, ep.ID, 10, nil)
	if err != nil {
		t.Fatalf("start learning: %v", err)
	}
	for i := 0; i < 10; i++ {
		src := "src-a"
		if i%2 == 1 {
			src = "src-b"
		}
		if _, err := store.RecordLearningSample(ctx, apiassets.LearningSampleInput{
			EndpointKey: ep.EndpointKey, RequestID: uuid.NewString(),
			SourceFingerprint: src, IdentityFingerprint: "id-1",
			ResponseStatus: 200, Accepted: true,
		}); err != nil {
			t.Fatalf("record sample %d: %v", i, err)
		}
	}

	// 超期未达标任务：1 条样本（远低于目标），起点拨回 8 天前（默认上限 7 天）
	epStale := s8SeedEndpoint(t, env, "GET", "/s8"+s5Rand()+"/sweep-stale", 0.8)
	stale, err := store.StartLearning(ctx, epStale.ID, 10, nil)
	if err != nil {
		t.Fatalf("start stale learning: %v", err)
	}
	if _, err := store.RecordLearningSample(ctx, apiassets.LearningSampleInput{
		EndpointKey: epStale.EndpointKey, RequestID: uuid.NewString(),
		SourceFingerprint: "src-x", ResponseStatus: 200, Accepted: true,
	}); err != nil {
		t.Fatalf("record stale sample: %v", err)
	}
	s8Exec(t, env, `UPDATE api_learning_jobs
SET started_at = now() - interval '8 days', first_sample_at = now() - interval '8 days'
WHERE id=$1`, stale.ID)

	stats, err := worker.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if stats.Completed != 1 || stats.Expired != 1 || stats.Failed != 0 {
		t.Fatalf("stats=%+v, want completed=1 expired=1 failed=0", stats)
	}

	// 达标任务：COMPLETED + candidate_version_id 回填 + 版本 IN_REVIEW + 端点 LEARNED
	var status string
	var candidateID *uuid.UUID
	if err := env.db.QueryRow(ctx,
		`SELECT status, candidate_version_id FROM api_learning_jobs WHERE id=$1`, job.ID).
		Scan(&status, &candidateID); err != nil {
		t.Fatalf("read completed job: %v", err)
	}
	if status != "COMPLETED" || candidateID == nil {
		t.Fatalf("job status=%q candidate=%v, want COMPLETED with candidate_version_id", status, candidateID)
	}
	cv, err := apimodels.NewStore(env.db).GetByID(ctx, *candidateID)
	if err != nil {
		t.Fatalf("read candidate version: %v", err)
	}
	if cv.Status != apimodels.StatusInReview || cv.CreatedReason != apimodels.CreatedReasonLearningThreshold {
		t.Fatalf("candidate version=%+v, want IN_REVIEW + learning_threshold", cv)
	}
	if ls, _, err := store.LearningStatus(ctx, ep.ID); err != nil || ls.Status != "COMPLETED" {
		t.Fatalf("learning status=%+v err=%v", ls, err)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_endpoints WHERE id=$1 AND learning_status='LEARNED'`, ep.ID); n != 1 {
		t.Fatal("endpoint should be LEARNED")
	}

	// 超期任务：FAILED + last_error 说明（未达标原因写入）
	var staleStatus, staleErr string
	if err := env.db.QueryRow(ctx,
		`SELECT status, last_error FROM api_learning_jobs WHERE id=$1`, stale.ID).
		Scan(&staleStatus, &staleErr); err != nil {
		t.Fatalf("read stale job: %v", err)
	}
	if staleStatus != "FAILED" {
		t.Fatalf("stale job status=%q, want FAILED", staleStatus)
	}
	if !strings.Contains(staleErr, "超过最长时限") || !strings.Contains(staleErr, "有效样本数不足") {
		t.Fatalf("last_error=%q, want expiry + unmet conditions", staleErr)
	}
}
