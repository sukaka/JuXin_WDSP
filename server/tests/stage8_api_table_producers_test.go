// stage8_api_table_producers_test.go W16-TABLES 残余空表生产方集成测试。
// 覆盖：迁移 000073 落位（api_object_models 观测列 / api_classifications 16 项内置种子 /
// api_request_schemas 保留注释）与 up 文件整体重放幂等（含存量端点段形回填口径）；
// apiassets 发现链路段形生产（首插派生、命中重放不改写、拆分派生、合并级联清理）；
// apiauthz 对象模型清扫（路径占位段 + Query 对象参数形态、形态合并、样本计数、水位幂等）；
// 三张原 TABLE_ONLY 表均有真实数据。
package tests

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/server/internal/apiassets"
	"github.com/jiuzhang-waf/server/internal/apiauthz"
)

// w16Classifications 任务书 §34.1 内置业务领域词表（16 项；企业自定义走 api_custom_taxonomies）。
var w16Classifications = [][2]string{
	{"IDENTITY_AUTH", "身份认证"},
	{"USER_ACCOUNT", "用户账户"},
	{"ORG_PERMISSION", "组织权限"},
	{"DATA_RESOURCE", "数据资源"},
	{"PROCESS_APPROVAL", "流程审批"},
	{"TRANSACTION_FUND", "交易资金"},
	{"FILE_CONTENT", "文件内容"},
	{"QUERY_ANALYTICS", "查询分析"},
	{"IMPORT_EXPORT", "导入导出"},
	{"MESSAGE_NOTIFICATION", "消息通知"},
	{"EXTERNAL_INTEGRATION", "外部集成"},
	{"SYSTEM_CONFIG", "系统配置"},
	{"SYSTEM_OPS", "系统运维"},
	{"DEVICE_IOT", "设备物联网"},
	{"AI_INTELLIGENCE", "人工智能"},
	{"PRIVACY_COMPLIANCE", "隐私合规"},
}

// TestStage8TableProducersMigration 迁移 000073 落位：观测列 / 种子词表完整 /
// 保留注释；up 文件整体重放幂等（含存量端点段形回填）。
func TestStage8TableProducersMigration(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	rid := s5Rand()

	// api_object_models 观测列
	for _, col := range []string{"first_seen", "last_seen", "sample_count"} {
		if n := s8Count(t, env, `SELECT count(*) FROM information_schema.columns
			WHERE table_name='api_object_models' AND column_name=$1`, col); n != 1 {
			t.Fatalf("api_object_models column %s missing", col)
		}
	}

	// api_request_schemas 保留注释（标注 schema_json 内联为权威来源）
	var comment *string
	if err := env.db.QueryRow(ctx,
		`SELECT obj_description('api_request_schemas'::regclass, 'pg_class')`).Scan(&comment); err != nil {
		t.Fatalf("read table comment: %v", err)
	}
	if comment == nil || !strings.Contains(*comment, "api_model_versions.schema_json") ||
		!strings.Contains(*comment, "不再使用") {
		t.Fatalf("api_request_schemas comment=%v", comment)
	}

	// api_classifications 内置种子：16（000073）+8（000087 扩展）+10（000096 启发式值回填）= 34 项词表完整
	if n := s8Count(t, env, `SELECT count(*) FROM api_classifications WHERE is_builtin`); n != 34 {
		t.Fatalf("builtin classifications=%d want 34", n)
	}
	for _, want := range w16Classifications {
		if n := s8Count(t, env, `SELECT count(*) FROM api_classifications
			WHERE code=$1 AND name=$2 AND is_builtin`, want[0], want[1]); n != 1 {
			t.Fatalf("seed classification %v missing", want)
		}
	}

	// 存量端点（绕过生产方直插，无段形行）→ up 文件重放后回填段形，且整体幂等
	legacyKey := "GET /w16b-" + rid + "/legacy/{id}"
	s8Exec(t, env, `INSERT INTO api_endpoints (http_method, normalized_path, endpoint_key)
		VALUES ('GET', $1, $2)`, "/w16b-"+rid+"/legacy/{id}", legacyKey)
	raw, err := os.ReadFile("../migrations/000073_api_classifications_seed.up.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	if _, err := env.db.Exec(ctx, string(raw)); err != nil {
		t.Fatalf("replay migration 000073: %v", err)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_classifications WHERE is_builtin`); n != 34 {
		t.Fatalf("classifications after replay=%d want 34（重放幂等）", n)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_endpoint_path_segments s
		JOIN api_endpoints e ON e.id=s.endpoint_id WHERE e.endpoint_key=$1`, legacyKey); n != 3 {
		t.Fatalf("backfilled segments=%d want 3", n)
	}
	// 回填口径：位置 0 起、{id} 为变量段
	if n := s8Count(t, env, `SELECT count(*) FROM api_endpoint_path_segments s
		JOIN api_endpoints e ON e.id=s.endpoint_id
		WHERE e.endpoint_key=$1 AND s.position=2 AND s.is_variable AND s.variable_name='id' AND s.literal_value=''`,
		legacyKey); n != 1 {
		t.Fatalf("backfilled variable segment wrong")
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_endpoint_path_segments s
		JOIN api_endpoints e ON e.id=s.endpoint_id
		WHERE e.endpoint_key=$1 AND s.position=1 AND NOT s.is_variable AND s.literal_value='legacy'`,
		legacyKey); n != 1 {
		t.Fatalf("backfilled static segment wrong")
	}
}

// TestStage8PathSegmentsProducer 发现链路段形生产方（真实 SQL）：
// 首插派生、命中重放不改写、拆分派生、合并级联清理。
func TestStage8PathSegmentsProducer(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	rid := s5Rand()
	assets := apiassets.NewStore(env.db)

	template := "/w16s-" + rid + "/users/{id}/orders/{uuid}"
	ep, err := assets.UpsertDiscovery(ctx, apiassets.DiscoveryInput{
		Method: "GET", PathTemplate: template, Confidence: 0.8, IsAPI: true})
	if err != nil {
		t.Fatalf("UpsertDiscovery: %v", err)
	}
	type segWant struct {
		pos      int
		literal  string
		variable bool
		varName  string
	}
	want := []segWant{
		{0, "w16s-" + rid, false, ""},
		{1, "users", false, ""},
		{2, "", true, "id"},
		{3, "orders", false, ""},
		{4, "", true, "uuid"},
	}
	assertSegments := func(who string) {
		t.Helper()
		segs, err := assets.ListPathSegments(ctx, ep.ID)
		if err != nil {
			t.Fatalf("%s ListPathSegments: %v", who, err)
		}
		if len(segs) != len(want) {
			t.Fatalf("%s segs=%+v", who, segs)
		}
		for i, w := range want {
			s := segs[i]
			if s.EndpointID != ep.ID || s.Position != w.pos || s.LiteralValue != w.literal ||
				s.IsVariable != w.variable || s.VariableName != w.varName {
				t.Fatalf("%s seg[%d]=%+v want %+v", who, i, s, w)
			}
		}
	}
	assertSegments("首插")
	// 表内确实落库 5 行且 sample_hashes 保持默认
	if n := s8Count(t, env, `SELECT count(*) FROM api_endpoint_path_segments
		WHERE endpoint_id=$1 AND sample_hashes='[]'::jsonb`, ep.ID); n != 5 {
		t.Fatalf("segments rows=%d want 5", n)
	}

	// 命中重放：hit_count 累加，段形不重写（幂等）
	ep2, err := assets.UpsertDiscovery(ctx, apiassets.DiscoveryInput{
		Method: "get", PathTemplate: template, Confidence: 0.9, IsAPI: true})
	if err != nil {
		t.Fatalf("UpsertDiscovery replay: %v", err)
	}
	if ep2.ID != ep.ID || ep2.HitCount != 2 {
		t.Fatalf("replay ep=%+v", ep2)
	}
	assertSegments("重放")

	// 拆分：新端点派生段形
	created, err := assets.Split(ctx, ep.ID, []string{"/w16s-" + rid + "/users/{id}/detail"}, "tester")
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if len(created) != 1 {
		t.Fatalf("split=%+v", created)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_endpoint_path_segments
		WHERE endpoint_id=$1`, created[0].ID); n != 4 {
		t.Fatalf("split segments=%d want 4", n)
	}

	// 合并：对方端点段形随 ON DELETE CASCADE 清理，主端点不受影响
	if _, err := assets.Merge(ctx, ep.ID, created[0].ID, "tester"); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_endpoint_path_segments
		WHERE endpoint_id=$1`, created[0].ID); n != 0 {
		t.Fatalf("merged-away segments not cascaded")
	}
	assertSegments("合并后主端点")
}

// TestStage8ObjectModelsProducer 对象模型清扫（真实 SQL）：路径占位段 + Query 对象参数
// 形态、匿名事件计入、形态合并 mixed、样本计数、first/last_seen、示例哈希、水位幂等；
// 三张原 TABLE_ONLY 表均有真实数据。
func TestStage8ObjectModelsProducer(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	rid := s5Rand()

	// 发现链路建端点（同时生产段形行）
	template := "/w16o-" + rid + "/users/{id}"
	assets := apiassets.NewStore(env.db)
	ep, err := assets.UpsertDiscovery(ctx, apiassets.DiscoveryInput{
		Method: "GET", PathTemplate: template, Confidence: 0.8, IsAPI: true})
	if err != nil {
		t.Fatalf("UpsertDiscovery: %v", err)
	}
	epKey := ep.EndpointKey

	base := time.Now().UTC().Add(-time.Hour)
	uuidVal := "9f0a1b2c-3d4e-5f60-7a8b-9c0d1e2f3041"
	uuidVal2 := "11111111-2222-4333-8444-555555555555"
	// 实名数字对象 / 匿名数字对象（对象模型不限身份）/ 同段 uuid（→ mixed）/ 带 Query 对象参数
	apiauthzSaveEvent(t, env, epKey, "w16-req-"+rid+"-1", "fp-a-"+rid, "/w16o-"+rid+"/users/1001", base)
	apiauthzSaveEvent(t, env, epKey, "w16-req-"+rid+"-2", "", "/w16o-"+rid+"/users/1002", base.Add(time.Minute))
	apiauthzSaveEvent(t, env, epKey, "w16-req-"+rid+"-3", "fp-b-"+rid, "/w16o-"+rid+"/users/"+uuidVal, base.Add(2*time.Minute))
	apiauthzSaveEvent(t, env, epKey, "w16-req-"+rid+"-4", "fp-a-"+rid,
		"/w16o-"+rid+"/users/1003?account_id="+uuidVal2+"&verbose=true", base.Add(3*time.Minute))

	store := apiauthz.NewStore(env.db)
	res, err := store.SweepObjectModelsOnce(ctx)
	if err != nil {
		t.Fatalf("SweepObjectModelsOnce: %v", err)
	}
	if res.EventsScanned != 4 || res.SegmentsExtracted != 5 || res.ModelsUpserted != 5 ||
		res.SkippedNoEndpoint != 0 || res.SkippedNoMatch != 0 {
		t.Fatalf("sweep result=%+v", res)
	}

	// path:2 行：4 样本、numeric+uuid → mixed、首末次不回头、示例哈希留首个
	var idType, exampleHash string
	var sampleCount int64
	var firstSeen, lastSeen time.Time
	if err := env.db.QueryRow(ctx, `SELECT identifier_type, sample_count, example_hash, first_seen, last_seen
		FROM api_object_models WHERE endpoint_id=$1 AND object_segment='path:2'`, ep.ID).
		Scan(&idType, &sampleCount, &exampleHash, &firstSeen, &lastSeen); err != nil {
		t.Fatalf("query path model: %v", err)
	}
	if idType != "mixed" || sampleCount != 4 {
		t.Fatalf("path model type=%s count=%d", idType, sampleCount)
	}
	if !firstSeen.Equal(base) || !lastSeen.Equal(base.Add(3*time.Minute)) {
		t.Fatalf("path model first=%v last=%v", firstSeen, lastSeen)
	}
	wantHash := sha256.Sum256([]byte("1001"))
	if exampleHash != hex.EncodeToString(wantHash[:]) {
		t.Fatalf("example_hash=%s want sha256(1001)", exampleHash)
	}
	// query:account_id 行：uuid 形态、1 样本（verbose=true 非标识形态不产出）
	if err := env.db.QueryRow(ctx, `SELECT identifier_type, sample_count
		FROM api_object_models WHERE endpoint_id=$1 AND object_segment='query:account_id'`, ep.ID).
		Scan(&idType, &sampleCount); err != nil {
		t.Fatalf("query model: %v", err)
	}
	if idType != "uuid" || sampleCount != 1 {
		t.Fatalf("query model type=%s count=%d", idType, sampleCount)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_object_models WHERE endpoint_id=$1`, ep.ID); n != 2 {
		t.Fatalf("object models rows=%d want 2", n)
	}

	// 水位幂等：立即重扫零命中、计数/形态不变
	res2, err := store.SweepObjectModelsOnce(ctx)
	if err != nil || res2.EventsScanned != 0 || res2.ModelsUpserted != 0 {
		t.Fatalf("second sweep=%+v err=%v", res2, err)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_object_models
		WHERE endpoint_id=$1 AND object_segment='path:2' AND sample_count=4 AND identifier_type='mixed'`,
		ep.ID); n != 1 {
		t.Fatalf("row changed after idle sweep")
	}

	// 新事件（更晚时间）→ sample_count 累加、last_seen 前移
	apiauthzSaveEvent(t, env, epKey, "w16-req-"+rid+"-5", "fp-a-"+rid, "/w16o-"+rid+"/users/1004", base.Add(4*time.Minute))
	res3, err := store.SweepObjectModelsOnce(ctx)
	if err != nil || res3.ModelsUpserted != 1 {
		t.Fatalf("third sweep=%+v err=%v", res3, err)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_object_models
		WHERE endpoint_id=$1 AND object_segment='path:2' AND sample_count=5 AND last_seen=$2`,
		ep.ID, base.Add(4*time.Minute)); n != 1 {
		t.Fatalf("sample_count/last_seen not advanced")
	}

	// 三张原 TABLE_ONLY 表均有真实数据
	if n := s8Count(t, env, `SELECT count(*) FROM api_object_models`); n == 0 {
		t.Fatalf("api_object_models empty")
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_endpoint_path_segments WHERE endpoint_id=$1`, ep.ID); n != 3 {
		t.Fatalf("segments for endpoint=%d want 3", n)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_classifications WHERE is_builtin`); n != 34 {
		t.Fatalf("classifications=%d want 34", n)
	}
}
