// stage8_api_sensitive_data_test.go 敏感数据管理面（WDSP P0-19 补全，S5 分片）集成测试。
// 覆盖：迁移 000040 两张表 / api_sensitive_fields 新列 / 内置种子 / CHECK 约束落位；
// SQL Store 类型与规则 CRUD、导入 upsert；SweepOnce 对真实 api_runtime_events 的
// upsert 与水位幂等；SensitiveOverview 聚合；HTTP 路由接线（权限点 api_data.*）。
package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/google/uuid"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/events"
	"github.com/jiuzhang-waf/server/internal/apiassets"
	"github.com/jiuzhang-waf/server/internal/apidata"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
	"github.com/jiuzhang-waf/server/internal/apisecurity"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// apidataInjectPrincipal 模拟认证链：注入持有 api_data 权限点的主体（权限种子由集成方登记，
// 测试环境直接注入，绕开登录链路）。
func apidataInjectPrincipal(next http.Handler) http.Handler {
	perms := map[string]bool{apidata.PermDataRead: true, apidata.PermDataManage: true}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &authz.Principal{UserID: uuid.New(), Username: "s5-tester", PermsSet: perms}
		ctx := authz.WithPrincipal(r.Context(), p)
		ctx = context.WithValue(ctx, response.RequestIDKey, "s5-rid")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// apidataMux 装配敏感数据管理面路由（真实 SQL Store；审计服务由集成方装配，此处 nil 跳过）。
func apidataMux(env *testEnv) *http.ServeMux {
	mux := http.NewServeMux()
	apidata.RegisterRoutes(mux, apidataInjectPrincipal, apidata.NewHandler(apidata.NewStore(env.db), nil))
	return mux
}

func apidataDo(t *testing.T, mux http.Handler, method, url string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body == nil {
		reader = bytes.NewReader(nil)
	} else {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, url, reader)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// apidataSaveEvent 落一条含敏感明细的运行时事件（经真实 SavePrimary 序列化 details_json）。
func apidataSaveEvent(t *testing.T, env *testEnv, endpointKey, requestID string, at time.Time, details []dsctx.DetectorMatch) {
	t.Helper()
	rt := apiruntime.NewStore(env.db)
	err := rt.SavePrimary(context.Background(), &apiruntime.PrimaryEvent{
		PrimaryEvent: events.PrimaryEvent{
			RequestID: requestID, EndpointKey: endpointKey, OccurredAt: at,
			RiskScore: 40, RiskLevel: "MEDIUM", FinalAction: "OBSERVE", Details: details,
		},
	})
	if err != nil {
		t.Fatalf("SavePrimary: %v", err)
	}
}

func apidataQueryHit(field, dataType string) dsctx.DetectorMatch {
	return dsctx.DetectorMatch{
		Detector: "sensitive_data", RuleID: "sensitive.in_query", Category: "BLOCK", Severity: "HIGH",
		Evidence: map[string]string{"field": field, "data_type": dataType, "location": "query"},
	}
}

// TestStage8SensitiveDataMigration 迁移 000040 落位：表结构 / 新列 / 内置种子 / CHECK 约束。
func TestStage8SensitiveDataMigration(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()

	// 两张新表存在
	for _, table := range []string{"api_sensitive_data_types", "api_masking_rules"} {
		if n := s8Count(t, env, `SELECT count(*) FROM information_schema.tables WHERE table_name=$1`, table); n != 1 {
			t.Fatalf("table %s missing", table)
		}
	}
	// 契约列（发布分片按列名读取，不得改动）
	for _, col := range []string{"id", "name", "enabled", "scope", "application_id", "endpoint_key",
		"field_path", "data_type", "algorithm", "params_json", "exclusions_json", "created_by", "created_at", "updated_at"} {
		if n := s8Count(t, env, `SELECT count(*) FROM information_schema.columns
			WHERE table_name='api_masking_rules' AND column_name=$1`, col); n != 1 {
			t.Fatalf("api_masking_rules column %s missing", col)
		}
	}
	// api_sensitive_fields 新列（含 000224 masked_sample）
	if n := s8Count(t, env, `SELECT count(*) FROM information_schema.columns
		WHERE table_name='api_sensitive_fields'
		AND column_name IN ('first_seen','last_seen','occurrence_count','source_detail','masked_sample')`); n != 5 {
		t.Fatalf("api_sensitive_fields new columns = %d, want 5", n)
	}
	// 内置值级类型（regex 非空）均默认包含 response_body 检测位置（000224）
	if n := s8Count(t, env, `SELECT count(*) FROM api_sensitive_data_types
		WHERE is_builtin AND regex <> '' AND locations @> '["response_body"]'::jsonb`); n != 5 {
		t.Fatalf("builtin value types with response_body = %d, want 5", n)
	}

	// 内置种子：7 个内置类型且值级 regex 可编译（验证 SQL 转义正确）
	if n := s8Count(t, env, `SELECT count(*) FROM api_sensitive_data_types WHERE is_builtin`); n != 7 {
		t.Fatalf("builtin seeds = %d, want 7", n)
	}
	rows, err := env.db.Query(ctx, `SELECT name, regex FROM api_sensitive_data_types WHERE is_builtin`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	seeded := map[string]string{}
	for rows.Next() {
		var name, re string
		if err := rows.Scan(&name, &re); err != nil {
			t.Fatal(err)
		}
		seeded[name] = re
		if re != "" {
			if _, err := regexp.Compile(re); err != nil {
				t.Fatalf("seed %s regex not compilable: %v", name, err)
			}
		}
	}
	for _, want := range []string{"手机号码", "身份证号", "银行卡号", "电子邮箱", "密码口令", "访问令牌", "JWT 令牌"} {
		if _, ok := seeded[want]; !ok {
			t.Fatalf("builtin seed %s missing", want)
		}
	}

	// CHECK 约束：非法 level / status / scope / algorithm / 作用域不一致均拒绝
	badInserts := []string{
		`INSERT INTO api_sensitive_data_types (name, data_type, level) VALUES ('bad-level', 'x', 'TOP_SECRET')`,
		`INSERT INTO api_sensitive_data_types (name, data_type, status) VALUES ('bad-status', 'x', 'ON')`,
		`INSERT INTO api_masking_rules (name, scope) VALUES ('bad-scope', 'TENANT')`,
		`INSERT INTO api_masking_rules (name, field_path, algorithm) VALUES ('bad-algo', 'json.a', 'ENCRYPT')`,
		`INSERT INTO api_masking_rules (name, scope, endpoint_key) VALUES ('bad-coherence', 'GLOBAL', 'GET /a')`,
		`INSERT INTO api_masking_rules (name, scope) VALUES ('bad-app', 'APPLICATION')`,
	}
	for i, sql := range badInserts {
		if _, err := env.db.Exec(ctx, sql); err == nil {
			t.Fatalf("bad insert %d unexpectedly succeeded", i)
		}
	}
}

// TestStage8SensitiveDataStoreCRUD SQL Store：类型 CRUD/重名冲突/导入 upsert；规则 CRUD。
func TestStage8SensitiveDataStoreCRUD(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	store := apidata.NewStore(env.db)
	rid := s5Rand()

	// 类型：创建 → 读取 → 编辑 version 自增 → 重名冲突 → 删除
	ty := &apidata.SensitiveDataType{
		Name: "集成类型-" + rid, DataType: "it_" + rid, Level: "SENSITIVE", Status: "ENABLED",
		Keywords: []string{"k1"}, Locations: []string{"json"}, Regex: "^\\d{6}$",
	}
	if err := store.CreateType(ctx, ty); err != nil {
		t.Fatalf("CreateType: %v", err)
	}
	if ty.ID == uuid.Nil || ty.Version != 1 || ty.IsBuiltin {
		t.Fatalf("created=%+v", ty)
	}
	got, err := store.GetType(ctx, ty.ID)
	if err != nil || got.Regex != "^\\d{6}$" || len(got.Keywords) != 1 || got.Locations[0] != "json" {
		t.Fatalf("GetType=%+v err=%v", got, err)
	}
	got.Description = "更新"
	if err := store.UpdateType(ctx, got); err != nil || got.Version != 2 {
		t.Fatalf("UpdateType version=%d err=%v", got.Version, err)
	}
	dup := &apidata.SensitiveDataType{Name: ty.Name, DataType: "x", Level: "GENERAL", Status: "ENABLED"}
	if err := store.CreateType(ctx, dup); err == nil {
		t.Fatalf("duplicate name should fail")
	}
	// 导入：同名更新（version+1）+ 新建
	created, updated, err := store.ImportTypes(ctx, []apidata.SensitiveDataType{
		{Name: ty.Name, DataType: "it_" + rid, Level: "IMPORTANT", Status: "ENABLED", Description: "导入更新"},
		{Name: "导入新建-" + rid, DataType: "imp_" + rid, Level: "GENERAL", Status: "ENABLED"},
	})
	if err != nil || created != 1 || updated != 1 {
		t.Fatalf("ImportTypes created=%d updated=%d err=%v", created, updated, err)
	}
	got2, err := store.GetType(ctx, ty.ID)
	if err != nil || got2.Version != 3 || got2.Level != "IMPORTANT" || got2.Description != "导入更新" {
		t.Fatalf("after import=%+v err=%v", got2, err)
	}
	if err := store.DeleteType(ctx, ty.ID); err != nil {
		t.Fatalf("DeleteType: %v", err)
	}
	if _, err := store.GetType(ctx, ty.ID); err == nil {
		t.Fatalf("deleted type still readable")
	}

	// 规则：GLOBAL + ENDPOINT 各一；列表过滤；启用集合
	epKey := "GET /s5sens-" + rid + "/orders/{id}"
	global := &apidata.MaskingRule{
		Name: "全局手机号掩码-" + rid, Enabled: true, Scope: "GLOBAL", FieldPath: "json.phone",
		Algorithm: "MASK", Params: json.RawMessage(`{"keep_prefix":3}`), Exclusions: json.RawMessage(`{}`),
	}
	if err := store.CreateMaskingRule(ctx, global); err != nil {
		t.Fatalf("CreateMaskingRule global: %v", err)
	}
	endpoint := &apidata.MaskingRule{
		Name: "端点手机号移除-" + rid, Enabled: true, Scope: "ENDPOINT", EndpointKey: &epKey,
		FieldPath: "json.phone", Algorithm: "REMOVE",
		Params: json.RawMessage(`{}`), Exclusions: json.RawMessage(`{"role":["AUDIT_ADMIN"]}`),
	}
	if err := store.CreateMaskingRule(ctx, endpoint); err != nil {
		t.Fatalf("CreateMaskingRule endpoint: %v", err)
	}
	enabled, err := store.ListEnabledMaskingRules(ctx)
	if err != nil {
		t.Fatalf("ListEnabledMaskingRules: %v", err)
	}
	// MaskPlan 求值（发布分片同路径）：ENDPOINT 覆盖 GLOBAL
	plan := apidata.MaskPlanForEndpoint(epKey, nil, enabled, nil)
	if len(plan) != 1 || plan[0].Algorithm != "REMOVE" || plan[0].Scope != "ENDPOINT" {
		t.Fatalf("plan=%+v", plan)
	}
	// 排除生效：审计管理员角色命中排除 → 回退 GLOBAL
	plan = apidata.MaskPlanForEndpoint(epKey, nil, enabled, &apidata.MaskRequest{Role: "AUDIT_ADMIN"})
	if len(plan) != 1 || plan[0].Algorithm != "MASK" {
		t.Fatalf("excluded plan=%+v", plan)
	}
	if err := store.DeleteMaskingRule(ctx, global.ID); err != nil {
		t.Fatalf("DeleteMaskingRule: %v", err)
	}
}

// TestStage8SensitiveSweep SweepOnce：真实事件 upsert、水位幂等、新事件累加、overview 聚合。
func TestStage8SensitiveSweep(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	rid := s5Rand()

	// 端点资产 + 两条含敏感明细事件（同字段两次命中）
	assets := apiassets.NewStore(env.db)
	ep, err := assets.UpsertDiscovery(ctx, apiassets.DiscoveryInput{
		Method: "GET", PathTemplate: "/s5sens-" + rid + "/orders/{id}", Confidence: 1, IsAPI: true,
	})
	if err != nil {
		t.Fatalf("UpsertDiscovery: %v", err)
	}
	base := time.Now().UTC().Add(-time.Hour)
	apidataSaveEvent(t, env, ep.EndpointKey, "s5-req-"+rid+"-1", base,
		[]dsctx.DetectorMatch{apidataQueryHit("phone", "phone")})
	apidataSaveEvent(t, env, ep.EndpointKey, "s5-req-"+rid+"-2", base.Add(time.Minute),
		[]dsctx.DetectorMatch{apidataQueryHit("phone", "phone")})

	store := apidata.NewStore(env.db)
	res, err := store.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if res.EventsScanned != 2 || res.Hits != 2 || res.FieldsUpserted != 2 || res.SkippedNoEndpoint != 0 {
		t.Fatalf("sweep result=%+v", res)
	}
	var occ int
	var source, path string
	if err := env.db.QueryRow(ctx, `
SELECT structured_path, detection_source, occurrence_count FROM api_sensitive_fields
WHERE endpoint_id=$1`, ep.ID).Scan(&path, &source, &occ); err != nil {
		t.Fatalf("query sensitive field: %v", err)
	}
	if path != "query.phone" || source != "RUNTIME" || occ != 2 {
		t.Fatalf("field row path=%s source=%s occ=%d", path, source, occ)
	}
	// 新列非空
	if n := s8Count(t, env, `SELECT count(*) FROM api_sensitive_fields
		WHERE endpoint_id=$1 AND first_seen IS NOT NULL AND last_seen IS NOT NULL AND source_detail IS NOT NULL`, ep.ID); n != 1 {
		t.Fatalf("enrichment columns n=%d", n)
	}

	// 水位幂等：立即重扫零命中、计数不变
	res2, err := store.SweepOnce(ctx)
	if err != nil || res2.EventsScanned != 0 || res2.Hits != 0 {
		t.Fatalf("second sweep=%+v err=%v", res2, err)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_sensitive_fields WHERE endpoint_id=$1 AND occurrence_count=2`, ep.ID); n != 1 {
		t.Fatalf("occurrence changed after idle sweep")
	}

	// 新事件累加
	apidataSaveEvent(t, env, ep.EndpointKey, "s5-req-"+rid+"-3", base.Add(2*time.Minute),
		[]dsctx.DetectorMatch{apidataQueryHit("phone", "phone")})
	res3, err := store.SweepOnce(ctx)
	if err != nil || res3.Hits != 1 {
		t.Fatalf("third sweep=%+v err=%v", res3, err)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_sensitive_fields WHERE endpoint_id=$1 AND occurrence_count=3`, ep.ID); n != 1 {
		t.Fatalf("occurrence not incremented")
	}

	// overview：涉敏 API 数/类型分布/趋势（今天 3 事件 3 命中——base 为一小时前，仍属今天窗口内）
	overview, err := store.SensitiveOverview(ctx, 7)
	if err != nil {
		t.Fatalf("SensitiveOverview: %v", err)
	}
	if overview.SensitiveEndpointCount != 1 || overview.SensitiveFieldCount != 1 {
		t.Fatalf("overview summary=%+v", overview)
	}
	if len(overview.TypeDistribution) != 1 || overview.TypeDistribution[0].DataType != "phone" ||
		overview.TypeDistribution[0].OccurrenceCount != 3 {
		t.Fatalf("overview dist=%+v", overview.TypeDistribution)
	}
	if len(overview.Trend) != 7 {
		t.Fatalf("overview trend=%d", len(overview.Trend))
	}
	var totalEvents, totalHits int64
	for _, p := range overview.Trend {
		totalEvents += p.EventCount
		totalHits += p.HitCount
	}
	if totalEvents != 3 || totalHits != 3 {
		t.Fatalf("trend totals events=%d hits=%d", totalEvents, totalHits)
	}
}

// TestStage8SensitiveDataHTTP HTTP 接线：类型创建/重名 409/内置禁删；规则校验 400。
func TestStage8SensitiveDataHTTP(t *testing.T) {
	env := setupStage8Env(t)
	mux := apidataMux(env)
	rid := s5Rand()

	// 创建 + 重名 409
	req := map[string]any{"name": "HTTP类型-" + rid, "data_type": "http_" + rid, "level": "GENERAL"}
	rr := apidataDo(t, mux, http.MethodPost, "/api/v1/api-security/sensitive-types", req)
	if rr.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = apidataDo(t, mux, http.MethodPost, "/api/v1/api-security/sensitive-types", req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("conflict status=%d", rr.Code)
	}
	// 内置类型禁删（迁移种子里取一个）
	var builtinID string
	if err := env.db.QueryRow(context.Background(),
		`SELECT id FROM api_sensitive_data_types WHERE name='手机号码'`).Scan(&builtinID); err != nil {
		t.Fatalf("query builtin: %v", err)
	}
	rr = apidataDo(t, mux, http.MethodDelete, "/api/v1/api-security/sensitive-types/"+builtinID, nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("builtin delete status=%d", rr.Code)
	}
	// 规则校验：GLOBAL 带 endpoint_key → 400
	rr = apidataDo(t, mux, http.MethodPost, "/api/v1/api-security/masking-rules",
		map[string]any{"name": "x", "scope": "GLOBAL", "endpoint_key": "GET /a", "field_path": "json.a"})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("coherence status=%d", rr.Code)
	}
	// overview 接口
	rr = apidataDo(t, mux, http.MethodGet, "/api/v1/api-security/sensitive/overview", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("overview status=%d", rr.Code)
	}
}

// TestStage8SensitiveFieldsConfidenceAndBatchDelete 置信度透传落库（值级 1.0 / 字段名默认 0.8 /
// GREATEST 不降级）、列表扩展字段（endpoint_key/首末次/命中次数）与批量删除接口（403/200/条数）。
func TestStage8SensitiveFieldsConfidenceAndBatchDelete(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	rid := s5Rand()

	assets := apiassets.NewStore(env.db)
	ep, err := assets.UpsertDiscovery(ctx, apiassets.DiscoveryInput{
		Method: "POST", PathTemplate: "/s5sens-" + rid + "/conf", Confidence: 1, IsAPI: true,
	})
	if err != nil {
		t.Fatalf("UpsertDiscovery: %v", err)
	}
	base := time.Now().UTC().Add(-time.Hour)
	// 值级命中（显式 confidence=1.0，与网关 addValueMatch 一致，带 masked_sample）+ 字段名命中（零值 → 回落 0.8）
	valueHit := dsctx.DetectorMatch{
		Detector: "sensitive_data", RuleID: "sensitive.value", Category: "OBSERVE", Severity: "MEDIUM",
		Confidence: 1.0,
		Evidence:   map[string]string{"field": "contact", "data_type": "phone", "location": "json", "masked_sample": "138****8000"},
	}
	apidataSaveEvent(t, env, ep.EndpointKey, "s5-req-"+rid+"-c1", base,
		[]dsctx.DetectorMatch{valueHit, apidataQueryHit("phone", "phone")})

	store := apidata.NewStore(env.db)
	if _, err := store.SweepOnce(ctx); err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	confByPath := map[string]float64{}
	sampleByPath := map[string]string{}
	rows, err := env.db.Query(ctx, `SELECT structured_path, confidence, masked_sample FROM api_sensitive_fields WHERE endpoint_id=$1`, ep.ID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var p, ms string
		var c float64
		if err := rows.Scan(&p, &c, &ms); err != nil {
			t.Fatal(err)
		}
		confByPath[p] = c
		sampleByPath[p] = ms
	}
	rows.Close()
	if confByPath["json.contact"] != 1.0 || confByPath["query.phone"] != 0.8 {
		t.Fatalf("confidence by path=%v", confByPath)
	}
	if sampleByPath["json.contact"] != "138****8000" || sampleByPath["query.phone"] != "" {
		t.Fatalf("masked_sample by path=%v", sampleByPath)
	}

	// 低置信度（字段名 0.8，无 masked_sample）再次命中已是 1.0 的字段 → 置信度不降级且不清空已有脱敏样本
	apidataSaveEvent(t, env, ep.EndpointKey, "s5-req-"+rid+"-c2", base.Add(time.Minute),
		[]dsctx.DetectorMatch{{
			Detector: "sensitive_data", RuleID: "sensitive.field", Category: "OBSERVE", Severity: "MEDIUM",
			Evidence: map[string]string{"field": "contact", "data_type": "phone", "location": "json"},
		}})
	if _, err := store.SweepOnce(ctx); err != nil {
		t.Fatalf("SweepOnce2: %v", err)
	}
	var conf float64
	var ms string
	if err := env.db.QueryRow(ctx,
		`SELECT confidence, masked_sample FROM api_sensitive_fields WHERE endpoint_id=$1 AND structured_path='json.contact'`, ep.ID).Scan(&conf, &ms); err != nil {
		t.Fatal(err)
	}
	if conf != 1.0 || ms != "138****8000" {
		t.Fatalf("confidence/sample downgraded: conf=%v sample=%q", conf, ms)
	}

	// 新的值级命中 → 覆盖为最新 1 条脱敏样本
	apidataSaveEvent(t, env, ep.EndpointKey, "s5-req-"+rid+"-c3", base.Add(2*time.Minute),
		[]dsctx.DetectorMatch{{
			Detector: "sensitive_data", RuleID: "sensitive.value", Category: "OBSERVE", Severity: "MEDIUM",
			Confidence: 1.0,
			Evidence:   map[string]string{"field": "contact", "data_type": "phone", "location": "json", "masked_sample": "139****5678"},
		}})
	if _, err := store.SweepOnce(ctx); err != nil {
		t.Fatalf("SweepOnce3: %v", err)
	}

	// 列表扩展字段（apisecurity.Store：endpoint_key/首末次/命中次数/来源明细/最新脱敏样本）
	secStore := apisecurity.NewStore(env.db)
	fields, total, err := secStore.ListSensitiveFields(ctx, ep.ID.String(), "", "", 1, 20)
	if err != nil || total != 2 || len(fields) != 2 {
		t.Fatalf("list total=%d len=%d err=%v", total, len(fields), err)
	}
	for _, f := range fields {
		if f.EndpointKey != ep.EndpointKey {
			t.Fatalf("endpoint_key=%q want %q", f.EndpointKey, ep.EndpointKey)
		}
		if f.FirstSeen == nil || f.LastSeen == nil || f.OccurrenceCount < 1 || len(f.SourceDetail) == 0 {
			t.Fatalf("enrichment fields missing: %+v", f)
		}
		if f.StructuredPath == "json.contact" && f.MaskedSample != "139****5678" {
			t.Fatalf("list masked_sample=%q want 139****5678", f.MaskedSample)
		}
	}

	// 批量删除 HTTP：无权限 403 → 持 api_data.manage 200 删除 2 条 → 列表清空
	muxNoPerm := http.NewServeMux()
	apisecurity.RegisterRoutes(muxNoPerm, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "nobody", PermsSet: map[string]bool{}}
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
		})
	}, apisecurity.NewHandler(secStore, nil))
	rr := apidataDo(t, muxNoPerm, http.MethodPost, "/api/v1/api-security/sensitive-fields/batch-delete",
		map[string]any{"ids": []string{fields[0].ID.String()}})
	if rr.Code != http.StatusForbidden {
		t.Fatalf("no-perm batch-delete status=%d", rr.Code)
	}

	mux := http.NewServeMux()
	apisecurity.RegisterRoutes(mux, apidataInjectPrincipal, apisecurity.NewHandler(secStore, nil))
	ids := []string{fields[0].ID.String(), fields[1].ID.String(), uuid.NewString()} // 含不存在 ID：不影响删除
	rr = apidataDo(t, mux, http.MethodPost, "/api/v1/api-security/sensitive-fields/batch-delete",
		map[string]any{"ids": ids})
	if rr.Code != http.StatusOK {
		t.Fatalf("batch-delete status=%d body=%s", rr.Code, rr.Body.String())
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_sensitive_fields WHERE endpoint_id=$1`, ep.ID); n != 0 {
		t.Fatalf("after batch-delete rows=%d", n)
	}
}
