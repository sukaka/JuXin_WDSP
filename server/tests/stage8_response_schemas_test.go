// stage8_response_schemas_test.go 响应 Schema 学习通路（P0-06 / W5-A）。
// 覆盖：迁移 000051 列与部分唯一索引；RecordResponseObservations UPSERT 幂等合并
// （并集/类型冲突首胜/sample_count 递增/first_seen 保留）；ListResponseSchemas 按状态码分组；
// 模型确认版本快照物化；只读 GET 接口端到端。
package tests

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/server/internal/apimodels"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
)

// s8RespSchemaRow 直读一行运行时学习结果（schema_json/sample_count/first_seen/last_seen）。
func s8RespSchemaRow(t *testing.T, env *testEnv, endpointKey string, status int) (fields map[string]string, sampleCount int64, firstSeen, lastSeen time.Time, truncated bool) {
	t.Helper()
	var raw []byte
	var fs, ls *time.Time
	if err := env.db.QueryRow(context.Background(), `
SELECT schema_json, sample_count, first_seen, last_seen FROM api_response_schemas
WHERE endpoint_key=$1 AND status_code=$2 AND model_version_id IS NULL`,
		endpointKey, status).Scan(&raw, &sampleCount, &fs, &ls); err != nil {
		t.Fatalf("read runtime schema row: %v", err)
	}
	var doc struct {
		Fields    map[string]string `json:"fields"`
		Truncated bool              `json:"truncated"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("schema_json not a doc: %v raw=%s", err, raw)
	}
	if fs == nil || ls == nil {
		t.Fatal("first_seen/last_seen must be set")
	}
	return doc.Fields, sampleCount, *fs, *ls, doc.Truncated
}

func TestStage8ResponseSchemaLearning(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()

	// 迁移 000051（endpoint_key 列 + 运行时部分唯一索引）
	if n := s8Count(t, env, `
SELECT count(*) FROM information_schema.columns
WHERE table_schema='public' AND table_name='api_response_schemas' AND column_name='endpoint_key'`); n != 1 {
		t.Skip("migration 000051 not applied; skip response schema learning integration")
	}
	if n := s8Count(t, env, `
SELECT count(*) FROM pg_indexes
WHERE schemaname='public' AND indexname='ux_api_response_schemas_runtime'`); n != 1 {
		t.Fatal("runtime unique index missing")
	}

	ep := s8SeedEndpoint(t, env, "GET", "/s8resp-"+s5Rand()+"/users/{id}", 0.8)
	rec := apiruntime.NewRespSchemaStore(env.db)

	obs1 := []dsctx.ResponseObservation{{
		StatusCode: 200, ContentType: "application/json", BodySize: 64,
		Fields: map[string]string{"id": "number", "name": "string"}, FieldCount: 2,
	}}
	if err := rec.RecordResponseObservations(ctx, ep.EndpointKey, obs1); err != nil {
		t.Fatalf("record obs1: %v", err)
	}
	fields, n, firstSeen, _, truncated := s8RespSchemaRow(t, env, ep.EndpointKey, 200)
	if n != 1 || len(fields) != 2 || fields["id"] != "number" || truncated {
		t.Fatalf("after obs1: fields=%v n=%d truncated=%v", fields, n, truncated)
	}

	// 第二次观测：同字段幂等 + 新字段并集 + 类型冲突首胜（name 保持 string）+ truncated 粘住
	obs2 := []dsctx.ResponseObservation{{
		StatusCode: 200, ContentType: "application/json", BodySize: 80, Truncated: true,
		Fields: map[string]string{"name": "number", "extra": "bool"}, FieldCount: 3,
	}}
	if err := rec.RecordResponseObservations(ctx, ep.EndpointKey, obs2); err != nil {
		t.Fatalf("record obs2: %v", err)
	}
	// 第三次重复 obs2：字段集合收敛不变，sample_count 继续递增
	if err := rec.RecordResponseObservations(ctx, ep.EndpointKey, obs2); err != nil {
		t.Fatalf("record obs2 again: %v", err)
	}
	fields, n, firstSeen2, lastSeen, truncated := s8RespSchemaRow(t, env, ep.EndpointKey, 200)
	if n != 3 {
		t.Fatalf("sample_count = %d, want 3", n)
	}
	if len(fields) != 3 || fields["name"] != "string" || fields["extra"] != "bool" {
		t.Fatalf("merged fields = %v (union + first-wins type)", fields)
	}
	if !truncated {
		t.Fatal("truncated must stick after merge")
	}
	if !firstSeen2.Equal(firstSeen) {
		t.Fatalf("first_seen must be preserved: %v -> %v", firstSeen, firstSeen2)
	}
	if lastSeen.Before(firstSeen) {
		t.Fatalf("last_seen %v before first_seen %v", lastSeen, firstSeen)
	}

	// 另一状态码独立成行；空字段/零状态码观测跳过不产出
	if err := rec.RecordResponseObservations(ctx, ep.EndpointKey, []dsctx.ResponseObservation{
		{StatusCode: 404, ContentType: "application/problem+json", Fields: map[string]string{"error": "string"}, FieldCount: 1},
		{StatusCode: 0, Fields: map[string]string{"x": "string"}},
		{StatusCode: 500},
	}); err != nil {
		t.Fatalf("record 404: %v", err)
	}
	if got := s8Count(t, env, `
SELECT count(*) FROM api_response_schemas WHERE endpoint_key=$1 AND model_version_id IS NULL`, ep.EndpointKey); got != 2 {
		t.Fatalf("runtime rows = %d, want 2 (200/404)", got)
	}

	// ListResponseSchemas：按状态码升序两行，字段解析正确
	models := apimodels.NewStore(env.db)
	list, err := models.ListResponseSchemas(ctx, ep.EndpointKey)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 2 || list[0].StatusCode != 200 || list[1].StatusCode != 404 {
		t.Fatalf("list = %+v", list)
	}
	if list[0].Fields["extra"] != "bool" || list[0].SampleCount != 3 || !list[0].Truncated ||
		list[1].Fields["error"] != "string" || list[1].ContentType != "application/problem+json" {
		t.Fatalf("list rows = %+v", list)
	}

	// 模型确认：运行时学习行按版本物化快照（model_version_id 关联），学习行不动
	v1, err := models.CreateCandidateWithReason(ctx, ep.ID, ep.EndpointKey, "resp v1",
		apimodels.CreatedReasonManual, map[string]string{"id": "number"}, uuid.Nil)
	if err != nil {
		t.Fatalf("create candidate: %v", err)
	}
	if _, err := models.Confirm(ctx, v1.ID, uuid.Nil); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if got := s8Count(t, env, `
SELECT count(*) FROM api_response_schemas WHERE model_version_id=$1`, v1.ID); got != 2 {
		t.Fatalf("snapshot rows = %d, want 2", got)
	}
	// 快照后运行时行不变（仍 2 行），读接口仍只见运行时行
	if got := s8Count(t, env, `
SELECT count(*) FROM api_response_schemas WHERE endpoint_key=$1 AND model_version_id IS NULL`, ep.EndpointKey); got != 2 {
		t.Fatalf("runtime rows after snapshot = %d, want 2", got)
	}
	list, err = models.ListResponseSchemas(ctx, ep.EndpointKey)
	if err != nil || len(list) != 2 {
		t.Fatalf("list after snapshot = %+v, err=%v", list, err)
	}

	// 只读 GET 接口端到端（按状态码分组返回 items）
	cookies, _ := env.s5Login(t, "s8rs", "SECURITY_ADMIN")
	result := s5OK(t, env.get(t, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/response-schemas", cookies), "response-schemas")
	items, ok := result.Data["items"].([]interface{})
	if !ok || len(items) != 2 {
		t.Fatalf("api items = %v", result.Data)
	}
	first := items[0].(map[string]interface{})
	if first["status_code"].(float64) != 200 || first["sample_count"].(float64) != 3 {
		t.Fatalf("api first item = %v", first)
	}
	if first["fields"].(map[string]interface{})["name"] != "string" {
		t.Fatalf("api fields = %v", first["fields"])
	}
	// 未归属端点（不存在 ID）→ 404
	s5Expect(t, env.get(t, "/api/v1/api-security/endpoints/"+uuid.NewString()+"/response-schemas", cookies), 404, "unknown endpoint")
}
