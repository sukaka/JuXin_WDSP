// stage8_parameter_relations_test.go 参数条件关系闭环（W11-REL / P0-02 残余，任务书 §45）集成测试。
// 覆盖：迁移 000068 列落位与 000147/000154/000159 词表 CHECK 扩展（任务书 §23 值比较六类 + 数组聚合两类）；
// Store 手工新建校验与确认状态机；
// HTTP 路由（create/confirm/reject，权限 api_parameter.edit + 操作审计）；
// 发布通道仅下发 confirmed 关系（候选不下发）、版本戳与 Caddy JSON 联动；
// CO_OCCURS 候选「产生 → 确认 → 下发」全链。
package tests

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/accesscontrolversions"
	"github.com/jiuzhang-waf/server/internal/accessrules"
	"github.com/jiuzhang-waf/server/internal/apimodels"
	"github.com/jiuzhang-waf/server/internal/guardconfig"
	"github.com/jiuzhang-waf/server/internal/protectedaddresses"
	"github.com/jiuzhang-waf/server/internal/ratelimitpolicies"
	"github.com/jiuzhang-waf/server/internal/trustedproxies"
)

// s8RelProvider 按 app.go 同一接线构造发布组装器（WDSP 形态 + 模型仓储注入）。
func s8RelProvider(env *testEnv) *guardconfig.Provider {
	p := guardconfig.NewProvider(
		trustedproxies.NewStore(env.db), protectedaddresses.NewStore(env.db),
		accessrules.NewStore(env.db), ratelimitpolicies.NewStore(env.db),
		accesscontrolversions.NewStore(env.db),
		guardconfig.Config{
			APIDynamicProtection: true, APIProtectionMode: "PROTECT",
			APIEventsLog: "/var/log/caddy/api-runtime-events.log",
			GatewayNode:  "gw-test",
		})
	p.SetAPIModels(apimodels.NewStore(env.db))
	return p
}

// s8RelSeedModel 造数：端点 + FORMAL 模型（schema 两个 BODY 字段）+ 两个 QUERY 参数行，
// 返回版本 ID 与两组参数 ID（body 对 / query 对）。
func s8RelSeedModel(t *testing.T, env *testEnv, method, template string) (versionID uuid.UUID, bodyA, bodyB, queryA, queryB uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	endpointKey := method + " " + template
	var endpointID uuid.UUID
	if err := env.db.QueryRow(ctx, `
INSERT INTO api_endpoints (http_method, normalized_path, endpoint_key)
VALUES ($1, $2, $3)
RETURNING id`, method, template, endpointKey).Scan(&endpointID); err != nil {
		t.Fatalf("insert endpoint: %v", err)
	}
	store := apimodels.NewStore(env.db)
	v, err := store.CreateCandidate(ctx, endpointID, endpointKey, "rel-test",
		map[string]string{"buyer.phone": "string", "buyer.email": "string"}, uuid.Nil)
	if err != nil {
		t.Fatalf("create candidate: %v", err)
	}
	if _, err := store.Confirm(ctx, v.ID, uuid.Nil); err != nil {
		t.Fatalf("confirm model: %v", err)
	}
	versionID = v.ID
	// Confirm 物化的 BODY 参数行（structured_path=schema 字段名）
	rows, err := env.db.Query(ctx, `
SELECT id, structured_path FROM api_parameter_models
WHERE model_version_id=$1 AND direction='REQUEST' AND location='BODY'`, versionID)
	if err != nil {
		t.Fatalf("list body params: %v", err)
	}
	defer rows.Close()
	byPath := map[string]uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		var path string
		if err := rows.Scan(&id, &path); err != nil {
			t.Fatalf("scan param: %v", err)
		}
		byPath[path] = id
	}
	bodyA, bodyB = byPath["buyer.phone"], byPath["buyer.email"]
	if bodyA == uuid.Nil || bodyB == uuid.Nil {
		t.Fatalf("materialized body params missing: %+v", byPath)
	}
	// QUERY 参数行（学习链路等价物，直接 SQL 造数）
	for _, name := range []string{"page", "page_size"} {
		var id uuid.UUID
		if err := env.db.QueryRow(ctx, `
INSERT INTO api_parameter_models (model_version_id, direction, location, structured_path, parameter_name, base_type, confidence)
VALUES ($1,'REQUEST','QUERY',$2,$2,'number',1.0)
RETURNING id`, versionID, name).Scan(&id); err != nil {
			t.Fatalf("insert query param %s: %v", name, err)
		}
		if name == "page" {
			queryA = id
		} else {
			queryB = id
		}
	}
	return versionID, bodyA, bodyB, queryA, queryB
}

// TestStage8ParameterRelationsMigration 迁移 000068/000147/000154/000159 落位：确认列 / 词表 CHECK / 默认值。
func TestStage8ParameterRelationsMigration(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()

	for _, col := range []string{"confirmed", "confirmed_by", "confirmed_at"} {
		if n := s8Count(t, env, `SELECT count(*) FROM information_schema.columns
			WHERE table_name='api_parameter_relations' AND column_name=$1`, col); n != 1 {
			t.Fatalf("api_parameter_relations column %s missing", col)
		}
	}

	// 词表 CHECK：非法 relation_type 拒绝；历史词表 REQUIRES/EXCLUDES/CO_OCCURS、000068 新增 MUTEX、
	// 000147 值比较五类 + 000154 不等值 NOT_EQUALS（任务书 §23）与 000159 数组聚合两类
	// （COUNT_MATCHES 数量一致 / SUM_MATCHES 汇总关系）合法
	versionID, bodyA, bodyB, _, _ := s8RelSeedModel(t, env, "POST", "/v1/rel-migration")
	if _, err := env.db.Exec(ctx, `
INSERT INTO api_parameter_relations (model_version_id, source_parameter_id, target_parameter_id, relation_type)
VALUES ($1,$2,$3,'IMPLIES')`, versionID, bodyA, bodyB); err == nil {
		t.Fatal("bad relation_type IMPLIES must be rejected by CHECK")
	}
	for _, typ := range []string{"REQUIRES", "MUTEX", "CO_OCCURS", "EXCLUDES",
		"EQUALS", "NOT_EQUALS", "GREATER_THAN", "LESS_THAN", "TIME_BEFORE", "TIME_AFTER",
		"COUNT_MATCHES", "SUM_MATCHES"} {
		if _, err := env.db.Exec(ctx, `
INSERT INTO api_parameter_relations (model_version_id, source_parameter_id, target_parameter_id, relation_type)
VALUES ($1,$2,$3,$4)`, versionID, bodyA, bodyB, typ); err != nil {
			t.Fatalf("relation_type %s must be accepted: %v", typ, err)
		}
	}
	// 默认 confirmed=false（候选不生效）
	if n := s8Count(t, env, `SELECT count(*) FROM api_parameter_relations
		WHERE model_version_id=$1 AND confirmed=false AND confirmed_by IS NULL AND confirmed_at IS NULL`,
		versionID); n != 12 {
		t.Fatalf("default confirmed=false rows = %d, want 12", n)
	}
}

// TestStage8ParameterRelationsStore Store 层：手工新建校验与确认状态机。
func TestStage8ParameterRelationsStore(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	store := apimodels.NewStore(env.db)
	versionID, bodyA, bodyB, queryA, queryB := s8RelSeedModel(t, env, "POST", "/v1/rel-store")

	// 非法类型（CO_OCCURS 不开放手工新建；未知词拒绝）
	if _, err := store.CreateParameterRelation(ctx, versionID, queryA, queryB, "CO_OCCURS"); err == nil {
		t.Fatal("manual CO_OCCURS must be rejected")
	}
	if _, err := store.CreateParameterRelation(ctx, versionID, queryA, queryB, "IMPLIES"); err == nil {
		t.Fatal("unknown type must be rejected")
	}
	// 同一参数
	if _, err := store.CreateParameterRelation(ctx, versionID, queryA, queryA, "REQUIRES"); err == nil {
		t.Fatal("same param must be rejected")
	}
	// 参数不属于该版本（跨版本/跨端点）
	_, oBodyA, _, _, _ := s8RelSeedModel(t, env, "GET", "/v1/rel-store-other")
	if _, err := store.CreateParameterRelation(ctx, versionID, queryA, oBodyA, "REQUIRES"); err == nil {
		t.Fatal("param from other version must be rejected")
	}
	// 合法新建：初始候选 confirmed=false
	rel, err := store.CreateParameterRelation(ctx, versionID, queryA, queryB, "REQUIRES")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if rel.Confirmed || rel.ConfirmedBy != nil || rel.ConfirmedAt != nil {
		t.Fatalf("new relation must be unconfirmed candidate: %+v", rel)
	}
	// 重复新建（同版本同参数对同类型）→ 冲突
	if _, err := store.CreateParameterRelation(ctx, versionID, queryA, queryB, "REQUIRES"); err == nil {
		t.Fatal("duplicate must be rejected")
	}
	// 同参数对不同类型（MUTEX）允许
	if _, err := store.CreateParameterRelation(ctx, versionID, queryA, queryB, "MUTEX"); err != nil {
		t.Fatalf("same pair different type must pass: %v", err)
	}
	// 值比较六类 + 数组聚合两类（任务书 §23，000147/000154/000159 词表）开放手工新建：同参数对不同类型允许
	for _, typ := range []string{"EQUALS", "NOT_EQUALS", "GREATER_THAN", "LESS_THAN", "TIME_BEFORE", "TIME_AFTER",
		"COUNT_MATCHES", "SUM_MATCHES"} {
		if _, err := store.CreateParameterRelation(ctx, versionID, queryA, queryB, typ); err != nil {
			t.Fatalf("manual %s must be accepted: %v", typ, err)
		}
	}
	// 值比较类型重复新建（同版本同参数对同类型）→ 冲突
	if _, err := store.CreateParameterRelation(ctx, versionID, queryA, queryB, "EQUALS"); err == nil {
		t.Fatal("duplicate EQUALS must be rejected")
	}

	// 状态机：未确认不可撤回
	if _, err := store.RejectParameterRelation(ctx, rel.ID); err == nil {
		t.Fatal("reject unconfirmed must fail")
	}
	// 确认：confirmed=true + confirmed_by/at 落库
	operator := uuid.New()
	confirmed, err := store.ConfirmParameterRelation(ctx, rel.ID, operator)
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if !confirmed.Confirmed || confirmed.ConfirmedBy == nil || *confirmed.ConfirmedBy != operator || confirmed.ConfirmedAt == nil {
		t.Fatalf("confirmed = %+v", confirmed)
	}
	// 重复确认 → 状态机冲突
	if _, err := store.ConfirmParameterRelation(ctx, rel.ID, operator); err == nil {
		t.Fatal("re-confirm must fail")
	}
	// 撤回：confirmed=false 且 by/at 清空
	rejected, err := store.RejectParameterRelation(ctx, rel.ID)
	if err != nil {
		t.Fatalf("reject: %v", err)
	}
	if rejected.Confirmed || rejected.ConfirmedBy != nil || rejected.ConfirmedAt != nil {
		t.Fatalf("rejected = %+v", rejected)
	}
	// 不存在的关系
	if _, err := store.ConfirmParameterRelation(ctx, uuid.New(), operator); err == nil {
		t.Fatal("confirm missing must fail")
	}
	_ = bodyA
	_ = bodyB
}

// TestStage8ParameterRelationsHTTP HTTP 层：路由接线 / 权限点 / 操作审计 / 确认状态机。
func TestStage8ParameterRelationsHTTP(t *testing.T) {
	env := setupStage8Env(t)
	cookies, csrf := env.s5Login(t, "s8rel", "SECURITY_ADMIN")
	versionID, _, _, queryA, queryB := s8RelSeedModel(t, env, "GET", "/v1/rel-http")

	createURL := fmt.Sprintf("/api/v1/api-security/models/%s/parameter-relations", versionID)
	// 参数校验：非法类型 400；无效 UUID 400
	s5Expect(t, env.post(t, createURL,
		fmt.Sprintf(`{"source_parameter_id":%q,"target_parameter_id":%q,"relation_type":"CO_OCCURS"}`, queryA, queryB),
		cookies, csrf), 400, "create CO_OCCURS manually")
	s5Expect(t, env.post(t, createURL,
		`{"source_parameter_id":"not-a-uuid","target_parameter_id":"`+queryB.String()+`","relation_type":"REQUIRES"}`,
		cookies, csrf), 400, "create with bad uuid")

	// 合法新建：候选（confirmed=false）
	created := s5OK(t, env.post(t, createURL,
		fmt.Sprintf(`{"source_parameter_id":%q,"target_parameter_id":%q,"relation_type":"REQUIRES"}`, queryA, queryB),
		cookies, csrf), "create relation")
	relObj := s5Obj(t, created, "relation")
	relID, _ := relObj["id"].(string)
	if relID == "" {
		t.Fatalf("relation id missing: %+v", relObj)
	}
	if confirmed, _ := relObj["confirmed"].(bool); confirmed {
		t.Fatalf("new relation must be candidate: %+v", relObj)
	}
	// 重复新建 → 409
	s5Expect(t, env.post(t, createURL,
		fmt.Sprintf(`{"source_parameter_id":%q,"target_parameter_id":%q,"relation_type":"REQUIRES"}`, queryA, queryB),
		cookies, csrf), 409, "duplicate create")

	// 权限点：AUDIT_ADMIN 仅 api_parameter.read，confirm 应 403
	auditCookies, auditCSRF := env.s5Login(t, "s8relro", "AUDIT_ADMIN")
	s5Expect(t, env.post(t, "/api/v1/api-security/parameter-relations/"+relID+"/confirm", "", auditCookies, auditCSRF),
		403, "confirm without api_parameter.edit")

	// 未确认先 reject → 409
	s5Expect(t, env.post(t, "/api/v1/api-security/parameter-relations/"+relID+"/reject", "", cookies, csrf),
		409, "reject unconfirmed")
	// 确认 → 200，confirmed=true
	confirmed := s5OK(t, env.post(t, "/api/v1/api-security/parameter-relations/"+relID+"/confirm", "", cookies, csrf), "confirm")
	if c, _ := s5Obj(t, confirmed, "relation")["confirmed"].(bool); !c {
		t.Fatalf("confirmed relation = %+v", confirmed.Data)
	}
	// 重复确认 → 409
	s5Expect(t, env.post(t, "/api/v1/api-security/parameter-relations/"+relID+"/confirm", "", cookies, csrf),
		409, "re-confirm")
	// 撤回 → 200，confirmed=false
	rejected := s5OK(t, env.post(t, "/api/v1/api-security/parameter-relations/"+relID+"/reject", "", cookies, csrf), "reject")
	if c, _ := s5Obj(t, rejected, "relation")["confirmed"].(bool); c {
		t.Fatalf("rejected relation = %+v", rejected.Data)
	}
	// 不存在 ID → 404
	s5Expect(t, env.post(t, "/api/v1/api-security/parameter-relations/"+uuid.NewString()+"/confirm", "", cookies, csrf),
		404, "confirm missing")

	// 列表携带确认状态
	list := s5OK(t, env.get(t, fmt.Sprintf("/api/v1/api-security/models/%s/parameter-relations", versionID), cookies), "list relations")
	items, _ := list.Data["items"].([]interface{})
	if len(items) != 1 {
		t.Fatalf("relations items = %+v, want 1", list.Data)
	}
	item, _ := items[0].(map[string]interface{})
	if _, ok := item["confirmed"]; !ok {
		t.Fatalf("list item missing confirmed field: %+v", item)
	}

	// 操作审计：create/confirm/reject 各落一条（object_type=api_parameter_relation）
	if n := s8Count(t, env, `SELECT count(*) FROM operation_audits
		WHERE module='api_security' AND object_type='api_parameter_relation' AND object_id=$1
		  AND action IN ('create','confirm','reject')`, relID); n != 3 {
		t.Fatalf("audit records = %d, want 3 (create/confirm/reject)", n)
	}
}

// TestStage8ParameterRelationsPublish 发布通道：仅 confirmed 关系下发；版本戳与 Caddy JSON 联动。
func TestStage8ParameterRelationsPublish(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	store := apimodels.NewStore(env.db)
	versionID, bodyA, bodyB, queryA, queryB := s8RelSeedModel(t, env, "POST", "/v1/rel-publish")

	// 基线：无关系 → 无下发
	cfg0, err := s8RelProvider(env).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build baseline: %v", err)
	}
	if len(cfg0.APIParameterRelations) != 0 {
		t.Fatalf("baseline relations = %+v, want empty", cfg0.APIParameterRelations)
	}

	// 候选（未确认）不下发
	cand, err := store.CreateParameterRelation(ctx, versionID, queryA, queryB, "REQUIRES")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	cfg1, err := s8RelProvider(env).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build candidate: %v", err)
	}
	if len(cfg1.APIParameterRelations) != 0 {
		t.Fatalf("candidate must not be distributed: %+v", cfg1.APIParameterRelations)
	}

	// 确认后下发：端点键/类型/两端参数引用齐全；版本戳变化
	if _, err := store.ConfirmParameterRelation(ctx, cand.ID, uuid.Nil); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	mux, err := store.CreateParameterRelation(ctx, versionID, bodyA, bodyB, "MUTEX")
	if err != nil {
		t.Fatalf("create mutex: %v", err)
	}
	if _, err := store.ConfirmParameterRelation(ctx, mux.ID, uuid.Nil); err != nil {
		t.Fatalf("confirm mutex: %v", err)
	}
	cfg2, err := s8RelProvider(env).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build confirmed: %v", err)
	}
	if len(cfg2.APIParameterRelations) != 2 {
		t.Fatalf("relations = %+v, want 2", cfg2.APIParameterRelations)
	}
	byType := map[string]bool{}
	for _, r := range cfg2.APIParameterRelations {
		if r.EndpointKey != "POST /v1/rel-publish" {
			t.Fatalf("endpoint_key = %q", r.EndpointKey)
		}
		byType[r.RelationType] = true
		if r.ParamA.Name == "" || r.ParamB.Name == "" || r.ParamA.Location == "" || r.ParamB.Location == "" {
			t.Fatalf("param refs incomplete: %+v", r)
		}
	}
	if !byType["REQUIRES"] || !byType["MUTEX"] {
		t.Fatalf("relation types = %+v", byType)
	}
	if cfg2.APIPolicyVersion == "" || cfg2.APIPolicyVersion == cfg1.APIPolicyVersion {
		t.Fatal("confirming relations must change api_policy_version")
	}
	// Caddy JSON 含 api_parameter_relations 段
	if j := s8GenerateGuardJSON(t, cfg2); !strings.Contains(j, "api_parameter_relations") {
		t.Fatal("caddy json must contain api_parameter_relations")
	}

	// 全部撤回后：下发清空且版本戳回到基线（同内容恒同版本戳）
	if _, err := store.RejectParameterRelation(ctx, cand.ID); err != nil {
		t.Fatalf("reject requires: %v", err)
	}
	if _, err := store.RejectParameterRelation(ctx, mux.ID); err != nil {
		t.Fatalf("reject mutex: %v", err)
	}
	cfg3, err := s8RelProvider(env).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build rejected: %v", err)
	}
	if len(cfg3.APIParameterRelations) != 0 {
		t.Fatalf("rejected relations must not be distributed: %+v", cfg3.APIParameterRelations)
	}
	if cfg3.APIPolicyVersion != cfg1.APIPolicyVersion {
		t.Fatal("rejecting all relations must restore baseline policy version")
	}
}

// TestStage8ParameterRelationsCoOccursLoop CO_OCCURS 候选「自动产生 → 人工确认 → 下发」全链。
func TestStage8ParameterRelationsCoOccursLoop(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	store := apimodels.NewStore(env.db)
	versionID, _, _, queryA, queryB := s8RelSeedModel(t, env, "GET", "/v1/rel-cooccurs")

	// 两参数均达统计画像阈值（sample_count>=10）→ 候选生成
	for _, id := range []uuid.UUID{queryA, queryB} {
		s8Exec(t, env, `INSERT INTO api_parameter_statistics (parameter_id, sample_count) VALUES ($1, 20)`, id)
	}
	inserted, err := store.RefreshParameterRelationCandidates(ctx)
	if err != nil {
		t.Fatalf("refresh candidates: %v", err)
	}
	if inserted != 1 {
		t.Fatalf("inserted = %d, want 1", inserted)
	}
	rels, err := store.ListParameterRelations(ctx, versionID)
	if err != nil {
		t.Fatalf("list relations: %v", err)
	}
	if len(rels) != 1 || rels[0]["relation_type"] != "CO_OCCURS" || rels[0]["confirmed"] != false {
		t.Fatalf("candidate = %+v", rels)
	}
	// 候选不下发
	cfg0, err := s8RelProvider(env).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build candidate: %v", err)
	}
	if len(cfg0.APIParameterRelations) != 0 {
		t.Fatalf("CO_OCCURS candidate must not be distributed: %+v", cfg0.APIParameterRelations)
	}
	// 确认后下发（relation_type=CO_OCCURS，网关侧仅观察不阻断）
	relID, _ := uuid.Parse(rels[0]["id"].(string))
	if _, err := store.ConfirmParameterRelation(ctx, relID, uuid.Nil); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	cfg1, err := s8RelProvider(env).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build confirmed: %v", err)
	}
	if len(cfg1.APIParameterRelations) != 1 || cfg1.APIParameterRelations[0].RelationType != "CO_OCCURS" {
		t.Fatalf("distributed = %+v", cfg1.APIParameterRelations)
	}
	if cfg1.APIParameterRelations[0].EndpointKey != "GET /v1/rel-cooccurs" {
		t.Fatalf("endpoint_key = %q", cfg1.APIParameterRelations[0].EndpointKey)
	}
}
