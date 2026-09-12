// stage8_model_poisoning_test.go 模型投毒防护集成测试（任务书 §215，W5-C 分片）。
//
// 场景：端点已有 FORMAL（Confirmed）模型且学习任务 RUNNING 时，持续偏离流量
// （新字段 / 类型偏离 / 超长值 / WAF 命中 / 决策阻断 / 5xx）经真实采集链路
// （api-runtime-events JSONL → apiruntime.Collector → PostgreSQL）进入管理面。
//
// 断言（§215「Confirmed 模型不变」的分层防线）：
//  1. FORMAL 版本 schema_json 与人工 confirmed_constraints 逐字节不变，FORMAL 数量恒 1；
//  2. 偏离记录产生：api_runtime_events 主事件 + api_schema_violations 违例行
//     （偏离可见性——投毒不是被静默吞掉，而是被记录）；
//  3. 学习样本按规则排除：waf_hit / schema_deviation / blocked_by_decision /
//     response_status_500 各归其因，仅干净对照样本 accepted；
//  4. 自动候选不含投毒结构：投毒样本不计入有效数 → janitor 清扫不达标 →
//     不创建 learning_threshold 候选（candidate_version_id 恒 NULL，版本表无此行）。
//     覆盖边界（如实声明）：候选构建的数据源是端点级观测表（不按样本过滤），
//     投毒闸口在「样本排除 → 不触发构建」；本测试另断言 BuildLearnedCandidate 的
//     合并纪律作为兜底——既有 FORMAL 已确认字段类型不被投毒观测改写（人工基线优先）。
//
// 运行方式（与 make stage8-test-api 一致）：
//
//	POSTGRES_PASSWORD=... VALKEY_PASSWORD=... go test ./tests -run TestStage8ModelPoisoningResilience -count=1
//
// 无环境变量时与既有集成测试一致地 t.Skip；数据落真实 PostgreSQL/Valkey。
package tests

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/server/internal/apiassets"
	"github.com/jiuzhang-waf/server/internal/apimodels"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
	"github.com/jiuzhang-waf/server/internal/learningjobs"
)

// s8mpRecord 构造一条采集端事件记录（网关 apievents.Record 镜像）。
func s8mpRecord(endpointKey, requestID, finalAction string, status int, details []dsctx.DetectorMatch, obs []apiruntime.ParamObservation) apiruntime.Record {
	return apiruntime.Record{
		RequestID:         requestID,
		OccurredAt:        time.Now().UTC(),
		EndpointKey:       endpointKey,
		Method:            "POST",
		PathTemplate:      strings.SplitN(endpointKey, " ", 2)[1],
		IsAPI:             true,
		APIConfidence:     0.8,
		RiskScore:         10,
		RiskLevel:         "LOW",
		FinalAction:       finalAction,
		Details:           details,
		ResponseStatus:    status,
		SourceFingerprint: "src-poison",
		GatewayNode:       "test-node",
		ParamObservations: obs,
	}
}

func TestStage8ModelPoisoningResilience(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()

	models := apimodels.NewStore(env.db)
	assets := apiassets.NewStore(env.db)
	rt := apiruntime.NewStore(env.db)

	// ---------- 1. 端点 + FORMAL 模型（含人工确认约束基线） ----------
	ep := s8SeedEndpoint(t, env, "POST", "/s8mp-"+s5Rand()+"/orders", 0.8)
	v1, err := models.CreateCandidateWithReason(ctx, ep.ID, ep.EndpointKey, "正式模型 v1",
		apimodels.CreatedReasonManual, map[string]string{"id": "number", "name": "string"}, uuid.Nil)
	if err != nil {
		t.Fatalf("create candidate: %v", err)
	}
	if _, err := models.Confirm(ctx, v1.ID, uuid.Nil); err != nil {
		t.Fatalf("confirm v1: %v", err)
	}
	// 人工 confirmed 约束（绝不被自动流程触碰的基线）
	s8Exec(t, env, `UPDATE api_parameter_models SET confirmed_constraints='{"max_length":32}'::jsonb
WHERE model_version_id=$1 AND structured_path='name'`, v1.ID)

	// FORMAL 状态快照（投毒前）：schema_json / confirmed 约束 / 状态 / FORMAL 数量
	type formalSnap struct {
		schema, confirmed, status string
		formalCount               int
	}
	snap := func() formalSnap {
		var s formalSnap
		if err := env.db.QueryRow(ctx,
			`SELECT schema_json::text, status FROM api_model_versions WHERE id=$1`, v1.ID).
			Scan(&s.schema, &s.status); err != nil {
			t.Fatalf("read formal version: %v", err)
		}
		if err := env.db.QueryRow(ctx, `
SELECT COALESCE(jsonb_agg(confirmed_constraints ORDER BY structured_path)::text,'[]')
FROM api_parameter_models WHERE model_version_id=$1`, v1.ID).Scan(&s.confirmed); err != nil {
			t.Fatalf("read confirmed constraints: %v", err)
		}
		s.formalCount = s8Count(t, env,
			`SELECT count(*) FROM api_model_versions WHERE endpoint_key=$1 AND status='FORMAL'`, ep.EndpointKey)
		return s
	}
	before := snap()
	if before.status != "FORMAL" || before.formalCount != 1 {
		t.Fatalf("precondition: status=%q formalCount=%d", before.status, before.formalCount)
	}

	// ---------- 2. 学习任务 RUNNING（目标 10 有效样本：投毒样本不应计入） ----------
	job, err := assets.StartLearning(ctx, ep.ID, 10, nil)
	if err != nil {
		t.Fatalf("start learning: %v", err)
	}

	// ---------- 3. 投毒流量：真实采集链路（JSONL → Collector → 库） ----------
	schemaDeviation := []dsctx.DetectorMatch{
		{Detector: "api_schema", RuleID: "schema.undefined_field", Category: "OBSERVE", Severity: "MEDIUM",
			Evidence: map[string]string{"field": "evil_field", "type": "string"}},
		{Detector: "api_schema", RuleID: "schema.type_mismatch", Category: "BLOCK", Severity: "HIGH",
			Evidence: map[string]string{"field": "id", "want": "number", "got": "string"}},
	}
	// 投毒观测：新字段 evil_field、超长 name（5000 字符）、类型偏离的 id（string 形态）
	poisonObs := []apiruntime.ParamObservation{
		{Location: "BODY", Name: "evil_field", Path: "evil_field", BaseType: "string", Length: 6, ValueHash: s8ValueHash("inject")},
		{Location: "BODY", Name: "name", Path: "name", BaseType: "string", Length: 5000, ValueHash: s8ValueHash(strings.Repeat("A", 5000))},
		{Location: "BODY", Name: "id", Path: "id", BaseType: "string", Length: 3, ValueHash: s8ValueHash("abc")},
	}
	records := []apiruntime.Record{
		// 偏离事件①（OBSERVE 放行 + 200）：新字段 + 类型偏离 + 投毒观测
		s8mpRecord(ep.EndpointKey, "mp-dev-1", "OBSERVE", 200, schemaDeviation, poisonObs),
		// WAF 命中（detector=waf；OBSERVE 下引擎不阻断的形态）
		s8mpRecord(ep.EndpointKey, "mp-waf-1", "OBSERVE", 200, []dsctx.DetectorMatch{
			{Detector: "waf", RuleID: "942100", Category: "BLOCK", Severity: "HIGH", Evidence: map[string]string{"attribution": "downstream_intercept"}},
		}, nil),
		// 统一决策阻断（BLOCK + 403）
		s8mpRecord(ep.EndpointKey, "mp-block-1", "BLOCK", 403, schemaDeviation[:1], nil),
		// 上游 5xx（带响应侧明细使其 notable 入主事件表；样本排除仍先命中状态码规则）
		s8mpRecord(ep.EndpointKey, "mp-500-1", "ALLOW", 500, []dsctx.DetectorMatch{
			{Detector: "api_response", RuleID: "response.error_signature", Category: "OBSERVE", Severity: "MEDIUM"},
		}, nil),
		// 偏离事件②（枚举/超长值持续偏离，新一轮 request_id）
		s8mpRecord(ep.EndpointKey, "mp-dev-2", "OBSERVE", 200, schemaDeviation, poisonObs),
		// 干净对照样本（accepted；证明采集链路与落样正常）
		s8mpRecord(ep.EndpointKey, "mp-clean-1", "ALLOW", 200, nil, nil),
	}
	logPath := filepath.Join(t.TempDir(), "api-runtime-events.log")
	var lines strings.Builder
	for i := range records {
		raw, err := json.Marshal(records[i])
		if err != nil {
			t.Fatalf("marshal record %d: %v", i, err)
		}
		lines.Write(raw)
		lines.WriteByte('\n')
	}
	if err := os.WriteFile(logPath, []byte(lines.String()), 0o600); err != nil {
		t.Fatalf("write events log: %v", err)
	}
	collector := apiruntime.NewCollector(rt, "test-poison", logPath, "", "test-node")
	collector.SetViolationSaver(rt)
	collector.SetSampleRecorder(assets)
	collector.SetParamObsRecorder(apiruntime.NewParamObsStore(env.db))
	processed, err := collector.CollectOnce(ctx)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if processed != len(records) {
		t.Fatalf("processed = %d, want %d", processed, len(records))
	}

	// ---------- 4. 断言 ----------
	// 4.1 偏离记录产生（可见性，非静默）：
	//     主事件 5 条（对照 ALLOW 无明细不notable，不入主事件表）；schema 违例行按类归集
	if n := s8Count(t, env, `SELECT count(*) FROM api_runtime_events WHERE endpoint_key=$1`, ep.EndpointKey); n != 5 {
		t.Fatalf("api_runtime_events = %d, want 5（干净 ALLOW 无明细不入表）", n)
	}
	if n := s8Count(t, env, `
SELECT count(*) FROM api_schema_violations
WHERE model_version_id=$1 AND violation_type='schema.undefined_field' AND field_path='evil_field'`, v1.ID); n < 1 {
		t.Fatal("schema.undefined_field(evil_field) 偏离记录缺失")
	}
	if n := s8Count(t, env, `
SELECT count(*) FROM api_schema_violations
WHERE model_version_id=$1 AND violation_type='schema.type_mismatch' AND field_path='id'`, v1.ID); n < 1 {
		t.Fatal("schema.type_mismatch(id) 偏离记录缺失")
	}
	// 投毒观测落观测表（观测本身中性；防线在样本排除与确认闸口，见 4.3/4.4）
	if n := s8Count(t, env, `
SELECT count(*) FROM api_parameter_value_obs WHERE endpoint_key=$1 AND structured_path='evil_field'`, ep.EndpointKey); n != 1 {
		t.Fatalf("poison observation evil_field rows = %d, want 1", n)
	}

	// 4.2 学习样本按规则排除：仅干净对照 accepted；排除原因各归其类
	sampleReason := map[string]string{}
	rows, err := env.db.Query(ctx, `
SELECT request_id, accepted, exclude_reason FROM api_learning_samples
WHERE api_endpoint_id=$1 ORDER BY request_id`, ep.ID)
	if err != nil {
		t.Fatalf("list samples: %v", err)
	}
	defer rows.Close()
	acceptedCount := 0
	for rows.Next() {
		var rid, reason string
		var accepted bool
		if err := rows.Scan(&rid, &accepted, &reason); err != nil {
			t.Fatalf("scan sample: %v", err)
		}
		sampleReason[rid] = reason
		if accepted {
			acceptedCount++
			if rid != "mp-clean-1" {
				t.Fatalf("poison sample %s must not be accepted", rid)
			}
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate samples: %v", err)
	}
	if len(sampleReason) != len(records) || acceptedCount != 1 {
		t.Fatalf("samples = %d accepted = %d, want %d/1", len(sampleReason), acceptedCount, len(records))
	}
	wantReason := map[string]string{
		"mp-dev-1":   apiruntime.ExcludeReasonSchemaDeviation,   // schema 偏离
		"mp-waf-1":   apiruntime.ExcludeReasonWAFHit,            // WAF/Coraza 命中
		"mp-block-1": apiruntime.ExcludeReasonBlockedByDecision, // 决策阻断（先于状态码规则）
		"mp-500-1":   "response_status_500",                     // 上游 5xx
		"mp-dev-2":   apiruntime.ExcludeReasonSchemaDeviation,
		"mp-clean-1": "",
	}
	for rid, want := range wantReason {
		if got, ok := sampleReason[rid]; !ok || got != want {
			t.Errorf("sample %s exclude_reason = %q, want %q（存在=%v）", rid, got, want, ok)
		}
	}
	// 任务计数：有效样本仅对照 1 条（投毒 5 条全部排除）
	var validCount, excludedCount int
	if err := env.db.QueryRow(ctx,
		`SELECT valid_count, excluded_count FROM api_learning_jobs WHERE id=$1`, job.ID).
		Scan(&validCount, &excludedCount); err != nil {
		t.Fatalf("read job counters: %v", err)
	}
	if validCount != 1 || excludedCount != 5 {
		t.Fatalf("job valid=%d excluded=%d, want 1/5", validCount, excludedCount)
	}

	// 4.3 自动候选不含投毒结构：投毒不计入有效样本 → 清扫不达标 → 不创建候选
	worker := learningjobs.NewWorker(assets, models, nil, nil)
	stats, err := worker.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if stats.Completed != 0 {
		t.Fatalf("sweep completed = %d, want 0（投毒样本不得推进达标）", stats.Completed)
	}
	var jobStatus string
	var candidateID *uuid.UUID
	if err := env.db.QueryRow(ctx,
		`SELECT status, candidate_version_id FROM api_learning_jobs WHERE id=$1`, job.ID).
		Scan(&jobStatus, &candidateID); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if jobStatus != "RUNNING" || candidateID != nil {
		t.Fatalf("job status=%q candidate=%v, want RUNNING + NULL（无自动候选）", jobStatus, candidateID)
	}
	if n := s8Count(t, env, `
SELECT count(*) FROM api_model_versions
WHERE endpoint_key=$1 AND created_reason='learning_threshold'`, ep.EndpointKey); n != 0 {
		t.Fatalf("learning_threshold candidate versions = %d, want 0（投毒不得触发自动候选）", n)
	}

	// 4.4 FORMAL（Confirmed）模型不变：schema_json/confirmed 约束/状态/数量逐字节同快照
	after := snap()
	if after != before {
		t.Fatalf("FORMAL mutated: before=%+v after=%+v", before, after)
	}

	// 4.5 兜底合并纪律：即使候选构建被触发，既有 FORMAL 已确认字段类型不被投毒观测改写
	//     （候选构建数据源为端点级观测表，不按样本过滤——投毒闸口在 4.3 的不触发；
	//     此处验证「人工基线优先」的第二道防线，不断言新观测字段缺席）
	bp, err := models.BuildLearnedCandidate(ctx, ep.EndpointKey, 1)
	if err != nil {
		t.Fatalf("build learned candidate: %v", err)
	}
	if bp.Schema["id"] != "number" || bp.Schema["name"] != "string" {
		t.Fatalf("formal field types rewritten by poison observations: %v", bp.Schema)
	}
	// 投毒样本不得推进学习：confirmed 约束仍为空（自动流程绝不触碰 confirmed）
	if n := s8Count(t, env, `
SELECT count(*) FROM api_parameter_models p
JOIN api_model_versions v ON v.id = p.model_version_id
WHERE v.endpoint_key=$1 AND v.id<>$2 AND p.confirmed_constraints <> '{}'::jsonb`, ep.EndpointKey, v1.ID); n != 0 {
		t.Fatalf("non-FORMAL version confirmed_constraints touched: %d rows", n)
	}
}
