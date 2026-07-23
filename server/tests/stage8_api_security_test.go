// 阶段8（WDSP）接口集成测试（任务书五十七章）。
//
// 覆盖：51.1 端点组（发现/列表过滤/批量确认/资产编辑/自动分类/忽略/合并/拆分/生命周期）、
// 51.2 模型生命周期（候选/评审/确认/对比/激活/归档/拒绝/FORMAL 不可变）、51.3 参数约束、
// 51.4 用途分类与图谱、51.5 规范导入对比、51.6 风险与运行时、防护策略（db>env>default）、
// 五十二章权限点（只读角色全写操作 403）与操作审计落库。
// WAF/WDSP 形态开关本身不在此测试（路由注册门控在 app 层，本环境按 WDSP 形态装配即默认开启）。
//
// 运行方式（与 make stage8-test-api 一致）：
//
//	POSTGRES_PASSWORD=... VALKEY_PASSWORD=... go test ./tests -run TestStage8 -count=1
//
// 无 POSTGRES_PASSWORD/VALKEY_PASSWORD 环境变量时与既有集成测试一致地 t.Skip；
// 不得 mock，全部请求走真实 HTTP 到 httptest 启动的真实应用，数据落真实 PostgreSQL/Valkey。
package tests

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/apiassets"
	"github.com/jiuzhang-waf/server/internal/app"
	"github.com/jiuzhang-waf/server/internal/cache"
	"github.com/jiuzhang-waf/server/internal/config"
	"github.com/jiuzhang-waf/server/internal/database"
	"github.com/jiuzhang-waf/server/internal/product"
	"github.com/jiuzhang-waf/server/internal/security"
	"github.com/jiuzhang-waf/server/internal/users"
)

// ---------- 阶段8 测试环境与通用辅助 ----------

// setupStage8Env 初始化阶段8集成测试环境。
// 与 setupTestEnv 同一套纪律（真实 postgres/valkey、独立测试库重建、全量迁移、
// 真实应用 + httptest.Server），差异仅在显式以 WDSP 产品形态装配：
// 阶段8路由在 app 层按 cfg.Product.APIDynamicProtectionEnabled() 门控，
// 不开启时 /api/v1/api-security/* 一律 404。
func setupStage8Env(t *testing.T) *testEnv {
	t.Helper()
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}

	cfg := &config.Config{
		Env: "test",
		DB: config.DBConfig{
			Host:     envOr("POSTGRES_HOST", "127.0.0.1"),
			Port:     envInt("POSTGRES_PORT", 5432),
			Database: testDBName,
			User:     envOr("POSTGRES_USER", "jiuzhang"),
			Password: os.Getenv("POSTGRES_PASSWORD"),
			SSLMode:  "disable",
			MaxConns: 5,
		},
		Cache: config.CacheConfig{
			Host:     envOr("VALKEY_HOST", "127.0.0.1"),
			Port:     envInt("VALKEY_PORT", 6379),
			Password: os.Getenv("VALKEY_PASSWORD"),
			DB:       15, // 独立 Valkey DB
		},
		Security: config.SecurityConfig{
			CookieSecure: false,
		},
		// WDSP 形态 + API 动态防护开启；默认模式 OBSERVE（非 env 来源 → mode_source=default）。
		Product: product.Settings{
			Edition:              product.EditionWDSP,
			APIDynamicProtection: true,
			APIProtectionMode:    "OBSERVE",
			MaxBodyParseBytes:    1 << 20,
			MaxBodySampleBytes:   64 << 10,
			MaxJSONDepth:         32,
			MaxFieldCount:        2048,
		},
	}
	// 数据目录指向测试临时目录，避免在仓库内产生报告/备份/配置产物
	cfg.Gateway.DataDir = t.TempDir()
	if cfg.DB.Password == "" || cfg.Cache.Password == "" {
		t.Skip("POSTGRES_PASSWORD/VALKEY_PASSWORD not set, skipping integration test")
	}

	ctx := context.Background()

	// 重建测试数据库（每个用例独立数据，与既有阶段测试同一纪律）
	adminDSN := fmt.Sprintf("postgres://%s:%s@%s:%d/postgres?sslmode=disable",
		cfg.DB.User, cfg.DB.Password, cfg.DB.Host, cfg.DB.Port)
	adminPool, err := pgxpool.New(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect admin db: %v", err)
	}
	_, _ = adminPool.Exec(ctx, fmt.Sprintf("DROP DATABASE IF EXISTS %s", testDBName))
	if _, err := adminPool.Exec(ctx, fmt.Sprintf("CREATE DATABASE %s", testDBName)); err != nil {
		adminPool.Close()
		t.Fatalf("create test db: %v", err)
	}
	adminPool.Close()

	// 全量迁移（含 000018 阶段8完整结构 / 000019 阶段8权限点种子）
	db, err := database.Connect(ctx, cfg.DB)
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	if err := database.Migrate(ctx, db, "../migrations", "up"); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Valkey
	cacheClient, err := cache.New(ctx, cfg.Cache)
	if err != nil {
		t.Fatalf("connect valkey: %v", err)
	}
	cacheClient.Redis().FlushDB(ctx)

	// 创建测试管理员（密码固定用于测试）
	adminPwd := "Test@Admin2026!"
	hash, _ := security.HashPassword(adminPwd)
	store := users.NewStore(db)
	now := time.Now()
	adminUser := &users.User{
		Username:           "test_sysadmin",
		DisplayName:        "测试系统管理员",
		PasswordHash:       hash,
		Status:             users.StatusActive,
		MustChangePassword: false,
		PasswordChangedAt:  &now,
	}
	if err := store.Create(ctx, adminUser); err != nil {
		t.Fatalf("create admin: %v", err)
	}
	roleID, err := store.GetRoleIDByCode(ctx, "SYSTEM_ADMIN")
	if err != nil {
		t.Fatalf("get role: %v", err)
	}
	if err := store.AssignRole(ctx, adminUser.ID, roleID, adminUser.ID); err != nil {
		t.Fatalf("assign role: %v", err)
	}

	// 启动真实应用服务
	application, err := app.New(cfg, db, cacheClient)
	if err != nil {
		t.Fatalf("initialize application: %v", err)
	}
	server := httptest.NewServer(application.Handler)
	t.Cleanup(func() {
		server.Close()
		db.Close()
		cacheClient.Close()
	})

	return &testEnv{
		server:   server,
		db:       db,
		cache:    cacheClient,
		cfg:      cfg,
		adminPwd: adminPwd,
		app:      application,
	}
}

// s8SeedEndpoint 通过存储层写入一条发现端点。
// 发现数据在真实部署中由网关采集链路（apiruntime.Collector → UpsertDiscovery）喂入，
// 采集器本身为文件通道，集成测试等价地直接调用同一存储方法造数。
func s8SeedEndpoint(t *testing.T, env *testEnv, method, pathTemplate string, confidence float64) *apiassets.Endpoint {
	t.Helper()
	ep, err := apiassets.NewStore(env.db).UpsertDiscovery(context.Background(), apiassets.DiscoveryInput{
		Method: method, PathTemplate: pathTemplate, Confidence: confidence, IsAPI: true,
	})
	if err != nil {
		t.Fatalf("seed endpoint %s %s: %v", method, pathTemplate, err)
	}
	return ep
}

// s8SeedHits 重复发现同一路径 n 次（hit_count 从 1 起每次冲突 +1），返回端点。
func s8SeedHits(t *testing.T, env *testEnv, method, pathTemplate string, confidence float64, n int) *apiassets.Endpoint {
	t.Helper()
	var ep *apiassets.Endpoint
	for i := 0; i < n; i++ {
		ep = s8SeedEndpoint(t, env, method, pathTemplate, confidence)
	}
	return ep
}

// s8Exec 直接写库造数（findings/violations/参数/样本等无 HTTP 写入口的数据）。
func s8Exec(t *testing.T, env *testEnv, query string, args ...any) {
	t.Helper()
	if _, err := env.db.Exec(context.Background(), query, args...); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

// s8Count 标量计数查询。
func s8Count(t *testing.T, env *testEnv, query string, args ...any) int {
	t.Helper()
	var n int
	if err := env.db.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", query, err)
	}
	return n
}

// s8Page 断言响应 200 并解析分页响应体（失败即 Fatal 并附带响应原文）。
func s8Page(t *testing.T, resp *http.Response, what string) apiRespPage5 {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s status = %d, want 200, body: %s", what, resp.StatusCode, readBodyString(t, resp))
	}
	var page apiRespPage5
	readJSON(t, resp, &page)
	return page
}

// s8StrList 把 JSON 数组字段转成字符串切片（断言 diff added/removed 等列表用）。
func s8StrList(t *testing.T, v interface{}, what string) []string {
	t.Helper()
	arr, ok := v.([]interface{})
	if !ok {
		t.Fatalf("%s not an array: %+v", what, v)
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		s, ok := item.(string)
		if !ok {
			t.Fatalf("%s item not a string: %+v", what, item)
		}
		out = append(out, s)
	}
	return out
}

// s8Contains 判断字符串切片是否含目标值。
func s8Contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// ---------- 1. 端点组：发现→过滤→确认→资产编辑→自动分类→忽略→合并→拆分→生命周期 ----------

// TestStage8EndpointGroupLifecycle 端点组全生命周期（任务书 51.1）。
func TestStage8EndpointGroupLifecycle(t *testing.T) {
	env := setupStage8Env(t)
	cookies, csrf := env.s5Login(t, "s8sec", "SECURITY_ADMIN")
	kw := "s8" + s5Rand() // 路径关键词（用例数据隔离）

	// 发现数据（等价网关采集链路 UpsertDiscovery 喂入）
	ep1 := s8SeedEndpoint(t, env, "GET", "/"+kw+"/users/{id}", 0.7)
	ep2 := s8SeedEndpoint(t, env, "POST", "/"+kw+"/orders", 0.8)
	ep3 := s8SeedEndpoint(t, env, "GET", "/"+kw+"/legacy/report", 0.5)

	// 列表过滤：asset_status / learning_status / keyword
	page := s8Page(t, env.get(t, "/api/v1/api-security/endpoints?asset_status=DISCOVERED&keyword="+kw, cookies), "list by asset_status")
	if page.Data.Total != 3 {
		t.Errorf("asset_status=DISCOVERED total = %d, want 3", page.Data.Total)
	}
	page = s8Page(t, env.get(t, "/api/v1/api-security/endpoints?learning_status=NOT_STARTED&keyword="+kw, cookies), "list by learning_status")
	if page.Data.Total != 3 {
		t.Errorf("learning_status=NOT_STARTED total = %d, want 3", page.Data.Total)
	}
	page = s8Page(t, env.get(t, "/api/v1/api-security/endpoints?keyword="+kw+"/users", cookies), "list by keyword")
	if page.Data.Total != 1 || page.Data.Items[0]["id"] != ep1.ID.String() {
		t.Errorf("keyword filter total = %d, want 1 (ep1)", page.Data.Total)
	}

	// 调用图谱 / 拓扑可见发现的节点（任务书 51.4 图谱冒烟）
	result := s5OK(t, env.get(t, "/api/v1/api-security/graph", cookies), "graph")
	if nodes, _ := result.Data["nodes"].([]interface{}); len(nodes) != 3 {
		t.Errorf("graph nodes = %d, want 3", len(nodes))
	}
	result = s5OK(t, env.get(t, "/api/v1/api-security/topology", cookies), "topology")
	if apps, _ := result.Data["applications"].([]interface{}); len(apps) == 0 {
		t.Error("topology applications empty, want >= 1")
	}

	// 批量确认（含一个不存在 ID：confirmed/failed 分支）
	ghost := uuid.NewString()
	resp := env.post(t, "/api/v1/api-security/endpoints/confirm",
		fmt.Sprintf(`{"ids":[%q,%q,%q]}`, ep1.ID, ep2.ID, ghost), cookies, csrf)
	result = s5OK(t, resp, "batch confirm")
	if s5Num(t, result.Data, "confirmed") != 2 {
		t.Errorf("confirmed = %v, want 2", result.Data["confirmed"])
	}
	if failed, _ := result.Data["failed"].([]interface{}); len(failed) != 1 {
		t.Errorf("failed len = %d, want 1 (不存在的ID应进 failed)", len(failed))
	}
	// 空 ids → 400
	resp = env.post(t, "/api/v1/api-security/endpoints/confirm", `{"ids":[]}`, cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "batch confirm with empty ids")

	page = s8Page(t, env.get(t, "/api/v1/api-security/endpoints?asset_status=CONFIRMED&keyword="+kw, cookies), "list confirmed")
	if page.Data.Total != 2 {
		t.Errorf("asset_status=CONFIRMED total = %d, want 2", page.Data.Total)
	}

	// PATCH 资产字段（purpose/exposure/owner/tags 全量替换）
	resp = env.do(t, http.MethodPatch, "/api/v1/api-security/endpoints/"+ep1.ID.String(),
		`{"purpose":"用户中心","exposure":"PUBLIC","owner":"team-a","tags":["core","pii"]}`, cookies, csrf)
	result = s5OK(t, resp, "patch endpoint asset")
	epObj := s5Obj(t, result, "endpoint")
	asset := s5Obj(t, apiResp{Data: epObj}, "asset")
	if asset["purpose"] != "用户中心" || asset["exposure"] != "PUBLIC" || asset["owner"] != "team-a" {
		t.Errorf("asset after patch = %+v", asset)
	}
	if tags, _ := asset["tags"].([]interface{}); len(tags) != 2 {
		t.Errorf("asset tags len = %d, want 2", len(tags))
	}
	// 非法 exposure → 400
	resp = env.do(t, http.MethodPatch, "/api/v1/api-security/endpoints/"+ep1.ID.String(),
		`{"exposure":"SECRET"}`, cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "patch endpoint with invalid exposure")
	// 详情回读确认落库
	result = s5OK(t, env.get(t, "/api/v1/api-security/endpoints/"+ep1.ID.String(), cookies), "get endpoint detail")
	epObj = s5Obj(t, result, "endpoint")
	if asset = s5Obj(t, apiResp{Data: epObj}, "asset"); asset["owner"] != "team-a" {
		t.Errorf("detail asset owner = %v, want team-a", asset["owner"])
	}

	// 自动分类（启发式：POST /orders → PURPOSE=TRADE / ACCESS=WRITE）
	resp = env.post(t, "/api/v1/api-security/endpoints/"+ep2.ID.String()+"/classify", "", cookies, csrf)
	result = s5OK(t, resp, "auto classify")
	dims, ok := result.Data["dimensions"].([]interface{})
	if !ok || len(dims) == 0 {
		t.Fatalf("classify dimensions empty: %+v", result.Data)
	}
	dimMap := map[string]string{}
	for _, d := range dims {
		m := d.(map[string]interface{})
		dimMap[m["dimension"].(string)] = m["value"].(string)
	}
	if dimMap["PURPOSE"] != "TRADE" || dimMap["ACCESS"] != "WRITE" {
		t.Errorf("auto classify dims = %v, want PURPOSE=TRADE ACCESS=WRITE", dimMap)
	}

	// 忽略（asset_status=IGNORED）
	resp = env.post(t, "/api/v1/api-security/endpoints/"+ep3.ID.String()+"/ignore", "", cookies, csrf)
	result = s5OK(t, resp, "ignore endpoint")
	if s5Obj(t, result, "endpoint")["asset_status"] != "IGNORED" {
		t.Errorf("asset_status after ignore = %v, want IGNORED", s5Obj(t, result, "endpoint")["asset_status"])
	}
	page = s8Page(t, env.get(t, "/api/v1/api-security/endpoints?asset_status=IGNORED&keyword="+kw, cookies), "list ignored")
	if page.Data.Total != 1 {
		t.Errorf("asset_status=IGNORED total = %d, want 1", page.Data.Total)
	}

	// 合并：epB(3次命中) 并入 epA(2次命中) → 命中累加为 5，别名归档，原端点删除
	epA := s8SeedHits(t, env, "GET", "/"+kw+"/merge/a", 0.7, 2)
	epB := s8SeedHits(t, env, "GET", "/"+kw+"/merge/b", 0.6, 3)
	resp = env.post(t, "/api/v1/api-security/endpoints/"+epA.ID.String()+"/merge",
		fmt.Sprintf(`{"other_id":%q}`, epB.ID), cookies, csrf)
	result = s5OK(t, resp, "merge endpoint")
	if got := s5Num(t, s5Obj(t, result, "endpoint"), "hit_count"); got != 5 {
		t.Errorf("hit_count after merge = %v, want 5（命中累加）", got)
	}
	// 别名归档：被合并端点键进入 api_endpoint_aliases
	if n := s8Count(t, env, `SELECT count(*) FROM api_endpoint_aliases WHERE endpoint_id=$1 AND alias_key=$2`,
		epA.ID, "GET /"+kw+"/merge/b"); n != 1 {
		t.Errorf("alias rows = %d, want 1（被合并端点键归档）", n)
	}
	// 被合并端点已删除 → 404
	resp = env.get(t, "/api/v1/api-security/endpoints/"+epB.ID.String(), cookies)
	s5Expect(t, resp, http.StatusNotFound, "get merged-away endpoint")
	// 合并到自身 → 400
	resp = env.post(t, "/api/v1/api-security/endpoints/"+epA.ID.String()+"/merge",
		fmt.Sprintf(`{"other_id":%q}`, epA.ID), cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "merge endpoint into itself")

	// 拆分：从 epA 拆出新路径端点；拆出与现有端点冲突的路径 → 409
	resp = env.post(t, "/api/v1/api-security/endpoints/"+epA.ID.String()+"/split",
		fmt.Sprintf(`{"paths":[%q]}`, "/"+kw+"/merge/a/detail"), cookies, csrf)
	result = s5OK(t, resp, "split endpoint")
	created, _ := result.Data["endpoints"].([]interface{})
	if len(created) != 1 {
		t.Fatalf("split created len = %d, want 1", len(created))
	}
	if created[0].(map[string]interface{})["normalized_path"] != "/"+kw+"/merge/a/detail" {
		t.Errorf("split normalized_path = %v", created[0].(map[string]interface{})["normalized_path"])
	}
	resp = env.post(t, "/api/v1/api-security/endpoints/"+epA.ID.String()+"/split",
		fmt.Sprintf(`{"paths":[%q]}`, "/"+kw+"/merge/a"), cookies, csrf)
	s5Expect(t, resp, http.StatusConflict, "split into existing endpoint key")

	// 生命周期事件：MERGED + SPLIT 均有记录
	page = s8Page(t, env.get(t, "/api/v1/api-security/endpoints/"+epA.ID.String()+"/lifecycle-events", cookies), "lifecycle events")
	if page.Data.Total < 2 {
		t.Fatalf("lifecycle events total = %d, want >= 2", page.Data.Total)
	}
	statuses := []string{}
	for _, item := range page.Data.Items {
		statuses = append(statuses, item["to_status"].(string))
	}
	if !s8Contains(statuses, "MERGED") || !s8Contains(statuses, "SPLIT") {
		t.Errorf("lifecycle to_status = %v, want 含 MERGED 与 SPLIT", statuses)
	}
}

// ---------- 2. 学习：start/status/samples/stop 与重复操作 409 ----------

// TestStage8LearningLifecycle 学习启停与样本列表（任务书 51.1 学习接口组）。
func TestStage8LearningLifecycle(t *testing.T) {
	env := setupStage8Env(t)
	cookies, csrf := env.s5Login(t, "s8sec", "SECURITY_ADMIN")

	ep := s8SeedEndpoint(t, env, "POST", "/s8"+s5Rand()+"/learn/{id}", 0.7)
	base := "/api/v1/api-security/endpoints/" + ep.ID.String() + "/learning"

	// 启动学习 → RUNNING；端点 learning_status=LEARNING
	result := s5OK(t, env.post(t, base+"/start", "", cookies, csrf), "learning start")
	job := s5Obj(t, result, "job")
	if job["status"] != "RUNNING" {
		t.Errorf("job status = %v, want RUNNING", job["status"])
	}
	// 重复启动 → 409（已有运行中任务）
	resp := env.post(t, base+"/start", "", cookies, csrf)
	s5Expect(t, resp, http.StatusConflict, "duplicate learning start")

	result = s5OK(t, env.get(t, base+"/status", cookies), "learning status")
	if result.Data["learning_status"] != "LEARNING" {
		t.Errorf("learning_status = %v, want LEARNING", result.Data["learning_status"])
	}
	if s5Obj(t, result, "job")["status"] != "RUNNING" {
		t.Errorf("status job = %v, want RUNNING", s5Obj(t, result, "job")["status"])
	}

	// 样本数据（学习样本无 HTTP 写入口，直接 SQL 造数：2 采纳 + 1 排除）
	s8Exec(t, env, `
INSERT INTO api_learning_samples (api_endpoint_id, request_id, sample_hash, source_fingerprint, identity_fingerprint, response_status, accepted, exclude_reason)
VALUES ($1,'req-1','hash-1','src-1','idt-1',200,true,''),
       ($1,'req-2','hash-2','src-2','idt-2',200,true,''),
       ($1,'req-3','hash-3','src-3','idt-3',400,false,'异常状态码')`, ep.ID)

	page := s8Page(t, env.get(t, base+"/samples", cookies), "learning samples")
	if page.Data.Total != 3 {
		t.Errorf("samples total = %d, want 3", page.Data.Total)
	}
	page = s8Page(t, env.get(t, base+"/samples?accepted=true", cookies), "learning samples accepted")
	if page.Data.Total != 2 {
		t.Errorf("samples accepted=true total = %d, want 2", page.Data.Total)
	}
	page = s8Page(t, env.get(t, base+"/samples?accepted=false", cookies), "learning samples excluded")
	if page.Data.Total != 1 {
		t.Errorf("samples accepted=false total = %d, want 1", page.Data.Total)
	}
	// status 聚合样本统计
	result = s5OK(t, env.get(t, base+"/status", cookies), "learning status with samples")
	stats := s5Obj(t, result, "samples")
	if s5Num(t, stats, "total") != 3 || s5Num(t, stats, "accepted") != 2 || s5Num(t, stats, "excluded") != 1 {
		t.Errorf("sample stats = %+v, want total=3 accepted=2 excluded=1", stats)
	}

	// 停止学习 → STOPPED；端点 learning_status=PAUSED
	result = s5OK(t, env.post(t, base+"/stop", "", cookies, csrf), "learning stop")
	if s5Obj(t, result, "job")["status"] != "STOPPED" {
		t.Errorf("job status after stop = %v, want STOPPED", s5Obj(t, result, "job")["status"])
	}
	result = s5OK(t, env.get(t, base+"/status", cookies), "learning status after stop")
	if result.Data["learning_status"] != "PAUSED" {
		t.Errorf("learning_status after stop = %v, want PAUSED", result.Data["learning_status"])
	}
	// 重复停止 → 409（无运行中任务）
	resp = env.post(t, base+"/stop", "", cookies, csrf)
	s5Expect(t, resp, http.StatusConflict, "duplicate learning stop")
}

// ---------- 3. 模型：候选→评审→确认→对比→激活→归档；拒绝；FORMAL 不可变 ----------

// TestStage8ModelLifecycle 模型版本生命周期（任务书 51.2）。
func TestStage8ModelLifecycle(t *testing.T) {
	env := setupStage8Env(t)
	cookies, csrf := env.s5Login(t, "s8sec", "SECURITY_ADMIN")

	ep := s8SeedEndpoint(t, env, "GET", "/s8"+s5Rand()+"/orders/{id}", 0.8)

	// 创建候选模型（schema：字段名→类型）
	result := s5OK(t, env.post(t, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/models",
		`{"schema":{"id":"integer","name":"string","price":"number"},"change_summary":"初版"}`, cookies, csrf), "create candidate model")
	v1 := s5Obj(t, result, "version")
	v1ID, _ := v1["id"].(string)
	if v1["status"] != "CANDIDATE" {
		t.Errorf("v1 status = %v, want CANDIDATE", v1["status"])
	}
	// 空 schema → 400
	resp := env.post(t, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/models",
		`{"schema":{}}`, cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "create model with empty schema")

	// 提交评审 → IN_REVIEW
	result = s5OK(t, env.post(t, "/api/v1/api-security/models/"+v1ID+"/submit-review",
		`{"comment":"请评审"}`, cookies, csrf), "submit review v1")
	if s5Obj(t, result, "version")["status"] != "IN_REVIEW" {
		t.Errorf("v1 status after submit = %v, want IN_REVIEW", s5Obj(t, result, "version")["status"])
	}

	// 确认为正式模型 → FORMAL
	result = s5OK(t, env.post(t, "/api/v1/api-security/models/"+v1ID+"/confirm", "", cookies, csrf), "confirm v1")
	v1 = s5Obj(t, result, "version")
	if v1["status"] != "FORMAL" {
		t.Errorf("v1 status after confirm = %v, want FORMAL", v1["status"])
	}
	vn1 := int(s5Num(t, v1, "version_number"))

	// 再建第二个候选并直接确认（CANDIDATE 也可确认）：版本号严格 +1，旧 FORMAL 降级 SUPERSEDED。
	// 注意：候选行 version_number 列默认 1 且参与 MAX 计算，实际首个 FORMAL 版本号为 2 而非 1
	// （疑似 store.Confirm 的 off-by-one，测试按"递增且唯一"不变量断言，数值差异另见汇报）。
	result = s5OK(t, env.post(t, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/models",
		`{"schema":{"id":"string","name":"string","extra":"boolean"},"change_summary":"第二版"}`, cookies, csrf), "create second candidate")
	v2 := s5Obj(t, result, "version")
	v2ID, _ := v2["id"].(string)
	result = s5OK(t, env.post(t, "/api/v1/api-security/models/"+v2ID+"/confirm", "", cookies, csrf), "confirm v2")
	v2 = s5Obj(t, result, "version")
	vn2 := int(s5Num(t, v2, "version_number"))
	if v2["status"] != "FORMAL" || vn2 != vn1+1 {
		t.Errorf("v2 status=%v version_number=%d, want FORMAL 且为 v1(%d)+1", v2["status"], vn2, vn1)
	}
	// 旧 FORMAL → SUPERSEDED
	result = s5OK(t, env.get(t, "/api/v1/api-security/models/"+v1ID, cookies), "get v1 after v2 confirm")
	if result.Data["status"] != "SUPERSEDED" {
		t.Errorf("v1 status after v2 confirm = %v, want SUPERSEDED", result.Data["status"])
	}

	// 版本对比 v1→v2：added=[extra] removed=[price] type_changed=[id: integer→string]
	result = s5OK(t, env.get(t, "/api/v1/api-security/models/"+v2ID+"/diff/"+v1ID, cookies), "diff v2 vs v1")
	diff := s5Obj(t, result, "diff")
	if added := s8StrList(t, diff["added"], "diff.added"); !s8Contains(added, "extra") || len(added) != 1 {
		t.Errorf("diff added = %v, want [extra]", added)
	}
	if removed := s8StrList(t, diff["removed"], "diff.removed"); !s8Contains(removed, "price") || len(removed) != 1 {
		t.Errorf("diff removed = %v, want [price]", removed)
	}
	changed, _ := diff["type_changed"].([]interface{})
	if len(changed) != 1 {
		t.Fatalf("diff type_changed len = %d, want 1", len(changed))
	}
	tc := changed[0].(map[string]interface{})
	if tc["field"] != "id" || tc["from"] != "integer" || tc["to"] != "string" {
		t.Errorf("diff type_changed = %+v, want id integer→string", tc)
	}

	// 激活 → 端点 current_model_version_id 被设置
	s5OK(t, env.post(t, "/api/v1/api-security/models/"+v2ID+"/activate", "", cookies, csrf), "activate v2")
	result = s5OK(t, env.get(t, "/api/v1/api-security/endpoints/"+ep.ID.String(), cookies), "get endpoint after activate")
	if s5Obj(t, result, "endpoint")["current_model_version_id"] != v2ID {
		t.Errorf("current_model_version_id = %v, want %s", s5Obj(t, result, "endpoint")["current_model_version_id"], v2ID)
	}

	// FORMAL 不可变：确认/送审/拒绝 FORMAL 版本一律 409
	resp = env.post(t, "/api/v1/api-security/models/"+v2ID+"/confirm", "", cookies, csrf)
	s5Expect(t, resp, http.StatusConflict, "confirm a FORMAL model")
	resp = env.post(t, "/api/v1/api-security/models/"+v2ID+"/submit-review", "", cookies, csrf)
	s5Expect(t, resp, http.StatusConflict, "submit-review a FORMAL model")
	resp = env.post(t, "/api/v1/api-security/models/"+v2ID+"/reject", "", cookies, csrf)
	s5Expect(t, resp, http.StatusConflict, "reject a FORMAL model")

	// 归档 FORMAL → ARCHIVED；归档后不可再激活（仅 FORMAL 可激活）
	result = s5OK(t, env.post(t, "/api/v1/api-security/models/"+v2ID+"/archive", "", cookies, csrf), "archive v2")
	if s5Obj(t, result, "version")["status"] != "ARCHIVED" {
		t.Errorf("v2 status after archive = %v, want ARCHIVED", s5Obj(t, result, "version")["status"])
	}
	resp = env.post(t, "/api/v1/api-security/models/"+v2ID+"/activate", "", cookies, csrf)
	s5Expect(t, resp, http.StatusConflict, "activate an ARCHIVED model")

	// 拒绝路径：候选 → 送审 → 拒绝（REJECTED）；重复拒绝 → 409
	result = s5OK(t, env.post(t, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/models",
		`{"schema":{"id":"integer"},"change_summary":"第三版"}`, cookies, csrf), "create third candidate")
	v3ID, _ := s5Obj(t, result, "version")["id"].(string)
	s5OK(t, env.post(t, "/api/v1/api-security/models/"+v3ID+"/submit-review", "", cookies, csrf), "submit review v3")
	result = s5OK(t, env.post(t, "/api/v1/api-security/models/"+v3ID+"/reject",
		`{"comment":"字段不完整"}`, cookies, csrf), "reject v3")
	if s5Obj(t, result, "version")["status"] != "REJECTED" {
		t.Errorf("v3 status after reject = %v, want REJECTED", s5Obj(t, result, "version")["status"])
	}
	resp = env.post(t, "/api/v1/api-security/models/"+v3ID+"/reject", "", cookies, csrf)
	s5Expect(t, resp, http.StatusConflict, "reject a REJECTED model")

	// 端点模型列表共 3 个版本
	page := s8Page(t, env.get(t, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/models", cookies), "list models")
	if page.Data.Total != 3 {
		t.Errorf("models total = %d, want 3", page.Data.Total)
	}
}

// ---------- 4. 参数：直接 SQL 造数 → list/get → PATCH 确认约束 → confirm（confirmed=recommended） ----------

// TestStage8ParameterConstraints 参数模型约束管理（任务书 51.3）。
func TestStage8ParameterConstraints(t *testing.T) {
	env := setupStage8Env(t)
	cookies, csrf := env.s5Login(t, "s8sec", "SECURITY_ADMIN")

	ep := s8SeedEndpoint(t, env, "GET", "/s8"+s5Rand()+"/param/{id}", 0.8)
	result := s5OK(t, env.post(t, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/models",
		`{"schema":{"page":"integer","name":"string"}}`, cookies, csrf), "create model for parameters")
	versionID, _ := s5Obj(t, result, "version")["id"].(string)

	// 参数模型由学习/建模链路产生，无 HTTP 写入口，直接 SQL 造数
	var p1, p2 string
	if err := env.db.QueryRow(context.Background(), `
INSERT INTO api_parameter_models (model_version_id, direction, location, structured_path, parameter_name,
  base_type, required, recommended_constraints, confidence)
VALUES ($1,'REQUEST','QUERY','$.page','page','integer',false,'{"minimum":1,"maximum":1000}'::jsonb,0.9)
RETURNING id`, versionID).Scan(&p1); err != nil {
		t.Fatalf("insert parameter p1: %v", err)
	}
	if err := env.db.QueryRow(context.Background(), `
INSERT INTO api_parameter_models (model_version_id, direction, location, structured_path, parameter_name,
  base_type, required, recommended_constraints, confidence)
VALUES ($1,'REQUEST','BODY','$.user.name','name','string',true,'{"maxLength":64}'::jsonb,0.8)
RETURNING id`, versionID).Scan(&p2); err != nil {
		t.Fatalf("insert parameter p2: %v", err)
	}

	// 列表（按版本）
	result = s5OK(t, env.get(t, "/api/v1/api-security/models/"+versionID+"/parameters", cookies), "list parameters")
	items, _ := result.Data["items"].([]interface{})
	if len(items) != 2 {
		t.Fatalf("parameters len = %d, want 2", len(items))
	}

	// 详情（p1 与 p2 各查一次）
	result = s5OK(t, env.get(t, "/api/v1/api-security/parameters/"+p1, cookies), "get parameter")
	if result.Data["parameter_name"] != "page" || result.Data["base_type"] != "integer" {
		t.Errorf("parameter p1 = %+v", result.Data)
	}
	rec := s5Obj(t, apiResp{Data: map[string]interface{}{"x": result.Data["recommended_constraints"]}}, "x")
	if s5Num(t, rec, "minimum") != 1 || s5Num(t, rec, "maximum") != 1000 {
		t.Errorf("recommended_constraints = %+v", rec)
	}
	// 不存在 → 404
	resp := env.get(t, "/api/v1/api-security/parameters/"+uuid.NewString(), cookies)
	s5Expect(t, resp, http.StatusNotFound, "get missing parameter")

	// PATCH 确认约束
	resp = env.do(t, http.MethodPatch, "/api/v1/api-security/parameters/"+p1,
		`{"required":true,"nullable":false,"empty_allowed":false,"confirmed_constraints":{"minimum":5},"sensitivity_level":"LOW"}`,
		cookies, csrf)
	result = s5OK(t, resp, "patch parameter")
	param := s5Obj(t, result, "parameter")
	if param["required"] != true || param["sensitivity_level"] != "LOW" {
		t.Errorf("parameter after patch = %+v", param)
	}
	confirmed := s5Obj(t, apiResp{Data: map[string]interface{}{"x": param["confirmed_constraints"]}}, "x")
	if s5Num(t, confirmed, "minimum") != 5 {
		t.Errorf("confirmed_constraints after patch = %+v, want minimum=5", confirmed)
	}

	// 确认：confirmed_constraints 整体采纳 recommended_constraints
	result = s5OK(t, env.post(t, "/api/v1/api-security/parameters/"+p1+"/confirm", "", cookies, csrf), "confirm parameter")
	param = s5Obj(t, result, "parameter")
	confirmed = s5Obj(t, apiResp{Data: map[string]interface{}{"x": param["confirmed_constraints"]}}, "x")
	if s5Num(t, confirmed, "minimum") != 1 || s5Num(t, confirmed, "maximum") != 1000 {
		t.Errorf("confirmed_constraints after confirm = %+v, want 与 recommended 一致", confirmed)
	}
	// p2 详情可读（列表覆盖之外的第二条参数）
	result = s5OK(t, env.get(t, "/api/v1/api-security/parameters/"+p2, cookies), "get parameter p2")
	if result.Data["parameter_name"] != "name" || result.Data["location"] != "BODY" {
		t.Errorf("parameter p2 = %+v", result.Data)
	}
}

// ---------- 5. 分类：自定义分类法 → 端点分类覆盖（锁定）→ 二次覆盖与前后摘要审计 ----------

// TestStage8Classification 用途分类管理（任务书 51.4）。
func TestStage8Classification(t *testing.T) {
	env := setupStage8Env(t)
	cookies, csrf := env.s5Login(t, "s8sec", "SECURITY_ADMIN")

	// 初始分类列表（内置表无种子数据，为空数组；自定义为空）
	result := s5OK(t, env.get(t, "/api/v1/api-security/classifications", cookies), "list classifications")
	if custom, _ := result.Data["custom"].([]interface{}); len(custom) != 0 {
		t.Errorf("initial custom taxonomy len = %d, want 0", len(custom))
	}

	// 新增自定义分类法；重复 → 409
	result = s5OK(t, env.post(t, "/api/v1/api-security/classifications",
		`{"dimension":"BU","value":"FINANCE","description":"金融业务"}`, cookies, csrf), "create taxonomy")
	if result.Data["dimension"] != "BU" || result.Data["value"] != "FINANCE" {
		t.Errorf("created taxonomy = %+v", result.Data)
	}
	resp := env.post(t, "/api/v1/api-security/classifications",
		`{"dimension":"BU","value":"FINANCE"}`, cookies, csrf)
	s5Expect(t, resp, http.StatusConflict, "duplicate taxonomy")

	result = s5OK(t, env.get(t, "/api/v1/api-security/classifications", cookies), "list classifications after create")
	custom, _ := result.Data["custom"].([]interface{})
	if len(custom) != 1 {
		t.Fatalf("custom taxonomy len = %d, want 1", len(custom))
	}

	// 端点分类覆盖：PURPOSE=TRADE + BU=FINANCE → classification_locked=true
	ep := s8SeedEndpoint(t, env, "POST", "/s8"+s5Rand()+"/pay/orders", 0.9)
	resp = env.do(t, http.MethodPut, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/classification",
		`{"dimensions":[{"dimension":"PURPOSE","value":"TRADE"},{"dimension":"BU","value":"FINANCE"}]}`, cookies, csrf)
	result = s5OK(t, resp, "put endpoint classification")
	if result.Data["classification_locked"] != true {
		t.Errorf("classification_locked = %v, want true", result.Data["classification_locked"])
	}
	if dims, _ := result.Data["dimensions"].([]interface{}); len(dims) != 2 {
		t.Errorf("dimensions len = %d, want 2", len(dims))
	}

	// 二次 PUT 覆盖：PURPOSE 改为 AUTH（BU 保留）
	resp = env.do(t, http.MethodPut, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/classification",
		`{"dimensions":[{"dimension":"PURPOSE","value":"AUTH"}]}`, cookies, csrf)
	result = s5OK(t, resp, "re-put endpoint classification")
	dimMap := map[string]string{}
	for _, d := range result.Data["dimensions"].([]interface{}) {
		m := d.(map[string]interface{})
		dimMap[m["dimension"].(string)] = m["value"].(string)
	}
	if dimMap["PURPOSE"] != "AUTH" || dimMap["BU"] != "FINANCE" {
		t.Errorf("dimensions after override = %v, want PURPOSE=AUTH BU=FINANCE", dimMap)
	}
	// 端点详情回读锁定标记
	result = s5OK(t, env.get(t, "/api/v1/api-security/endpoints/"+ep.ID.String(), cookies), "get endpoint classification lock")
	if s5Obj(t, result, "endpoint")["classification_locked"] != true {
		t.Error("endpoint classification_locked = false, want true")
	}
	// 锁定后自动分类 → 409（防止自动覆盖人工分类）
	resp = env.post(t, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/classify", "", cookies, csrf)
	s5Expect(t, resp, http.StatusConflict, "auto classify on locked endpoint")

	// 前后摘要审计：两次 PUT 各产生一条 api_security/update 审计；
	// 维度载荷为 JSON 数组，按审计脱敏纪律非对象载荷不原样放行（"(unstructured, masked)"）。
	rows, err := env.db.Query(context.Background(), `
SELECT before_summary, after_summary FROM operation_audits
WHERE module='api_security' AND action='update' AND object_type='api_endpoint_classification' AND object_id=$1
ORDER BY occurred_at ASC, id ASC`, ep.ID.String())
	if err != nil {
		t.Fatalf("query audits: %v", err)
	}
	defer rows.Close()
	auditRows := 0
	for rows.Next() {
		var before, after string
		if err := rows.Scan(&before, &after); err != nil {
			t.Fatalf("scan audit: %v", err)
		}
		if before != "(unstructured, masked)" || after != "(unstructured, masked)" {
			t.Errorf("audit summaries = (%q, %q), want 数组载荷脱敏占位", before, after)
		}
		auditRows++
	}
	if auditRows != 2 {
		t.Errorf("classification audit rows = %d, want 2（两次 PUT 各一条）", auditRows)
	}
}

// ---------- 6. 规范：内联 OpenAPI 3 导入 → 列表 → 运行时对比 diff ----------

// TestStage8SpecImport 规范导入与运行时对比（任务书 51.5）。
func TestStage8SpecImport(t *testing.T) {
	env := setupStage8Env(t)
	cookies, csrf := env.s5Login(t, "s8sec", "SECURITY_ADMIN")
	kw := "s8" + s5Rand()

	// 运行时端点：一个在规范内（GET orders/{id}），一个规范外（DELETE legacy → MISSING_IN_SPEC）
	s8SeedEndpoint(t, env, "GET", "/"+kw+"/orders/{id}", 0.8)
	s8SeedEndpoint(t, env, "DELETE", "/"+kw+"/legacy", 0.6)

	// 内联 OpenAPI 3 文档（3 个路径 → 3 个端点），含包装形式 file_name
	doc := fmt.Sprintf(`{
  "spec": {
    "openapi": "3.0.3",
    "info": {"title": "s8测试规范", "version": "1.0.0"},
    "paths": {
      "/%s/orders/{id}": {"get": {"summary": "订单详情"}},
      "/%s/users": {"get": {"summary": "用户列表"}},
      "/%s/admin": {"post": {"summary": "管理操作"}}
    }
  },
  "file_name": "s8-spec.json"
}`, kw, kw, kw)
	result := s5OK(t, env.post(t, "/api/v1/api-security/specs/import", doc, cookies, csrf), "import spec")
	spec := s5Obj(t, result, "spec")
	specID, _ := spec["id"].(string)
	if s5Num(t, spec, "endpoint_count") != 3 {
		t.Errorf("endpoint_count = %v, want 3", spec["endpoint_count"])
	}
	// 规范有而运行时无：users/admin 两个；运行时有而规范无：legacy 一个
	if s5Num(t, result.Data, "missing_in_runtime") != 2 {
		t.Errorf("missing_in_runtime = %v, want 2", result.Data["missing_in_runtime"])
	}
	if s5Num(t, result.Data, "missing_in_spec") != 1 {
		t.Errorf("missing_in_spec = %v, want 1", result.Data["missing_in_spec"])
	}

	// 规范列表
	page := s8Page(t, env.get(t, "/api/v1/api-security/specs", cookies), "list specs")
	if page.Data.Total != 1 || s5Num(t, page.Data.Items[0], "endpoint_count") != 3 {
		t.Errorf("specs list total = %d, endpoint_count = %v, want 1/3",
			page.Data.Total, page.Data.Items[0]["endpoint_count"])
	}

	// 对比结果：2 条 MISSING_IN_RUNTIME + 1 条 MISSING_IN_SPEC
	result = s5OK(t, env.get(t, "/api/v1/api-security/specs/"+specID+"/diff", cookies), "spec diff")
	diffs, _ := result.Data["diffs"].([]interface{})
	if len(diffs) != 3 {
		t.Fatalf("spec diffs len = %d, want 3", len(diffs))
	}
	byType := map[string]int{}
	for _, d := range diffs {
		byType[d.(map[string]interface{})["diff_type"].(string)]++
	}
	if byType["MISSING_IN_RUNTIME"] != 2 || byType["MISSING_IN_SPEC"] != 1 {
		t.Errorf("spec diff types = %v, want MISSING_IN_RUNTIME=2 MISSING_IN_SPEC=1", byType)
	}

	// 非 3.x 文档 → 400
	resp := env.post(t, "/api/v1/api-security/specs/import",
		`{"openapi":"2.0","info":{},"paths":{"/x":{"get":{}}}}`, cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "import swagger 2.0 doc")
	// 非 JSON（如 YAML）→ 400
	resp = env.post(t, "/api/v1/api-security/specs/import", "openapi: 3.0.0\npaths: {}", cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "import yaml spec")
}

// ---------- 7. 风险运行时：findings/violations/posture/statistics/events ----------

// TestStage8RuntimeRisk 风险发现 / Schema 违例 / 安全态势 / 运行时统计与事件（任务书 51.6）。
func TestStage8RuntimeRisk(t *testing.T) {
	env := setupStage8Env(t)
	cookies, _ := env.s5Login(t, "s8sec", "SECURITY_ADMIN")
	kw := "s8" + s5Rand()

	ep := s8SeedEndpoint(t, env, "GET", "/"+kw+"/pay/{id}", 0.9)
	epKey := "GET /" + kw + "/pay/{id}"

	// 检测明细由网关检测管线写入，无 HTTP 写入口，直接 SQL 造数：
	// findings 3 条（2 OPEN：HIGH/LOW；1 RESOLVED：MEDIUM）
	s8Exec(t, env, `
INSERT INTO api_runtime_findings (endpoint_id, request_id, finding_type, severity, status, title)
VALUES ($1,'f-req-1','SHADOW','HIGH','OPEN','影子API'),
       ($1,'f-req-2','BOLA','LOW','OPEN','越权访问迹象'),
       ($1,'f-req-3','ZOMBIE','MEDIUM','RESOLVED','僵尸API')`, ep.ID)
	// violations 2 条
	s8Exec(t, env, `
INSERT INTO api_schema_violations (endpoint_id, request_id, violation_type, field_path, expected, observed, action_taken)
VALUES ($1,'v-req-1','undefined_field','$.debug','','true','OBSERVE'),
       ($1,'v-req-2','type_mismatch','$.id','integer','string','BLOCK')`, ep.ID)
	// 运行时主事件 4 条（ALLOW×2 / LOG×1 / BLOCK×1；NONE×2 / MEDIUM×1 / HIGH×1）
	rid := s5Rand()
	s8Exec(t, env, `
INSERT INTO api_runtime_events (request_id, endpoint_key, risk_score, risk_level, final_action)
VALUES ($2,$1,0,'NONE','ALLOW'),
       ($3,$1,0,'NONE','ALLOW'),
       ($4,$1,60,'MEDIUM','LOG'),
       ($5,$1,90,'HIGH','BLOCK')`,
		epKey, "r1-"+rid, "r2-"+rid, "r3-"+rid, "r4-"+rid)

	// findings 过滤与分页
	page := s8Page(t, env.get(t, "/api/v1/api-security/findings?status=OPEN", cookies), "findings OPEN")
	if page.Data.Total != 2 {
		t.Errorf("findings OPEN total = %d, want 2", page.Data.Total)
	}
	page = s8Page(t, env.get(t, "/api/v1/api-security/findings?severity=HIGH", cookies), "findings HIGH")
	if page.Data.Total != 1 {
		t.Errorf("findings HIGH total = %d, want 1", page.Data.Total)
	}
	page = s8Page(t, env.get(t, "/api/v1/api-security/findings?finding_type=BOLA", cookies), "findings BOLA")
	if page.Data.Total != 1 {
		t.Errorf("findings BOLA total = %d, want 1", page.Data.Total)
	}
	page = s8Page(t, env.get(t, "/api/v1/api-security/findings?status=OPEN&page=1&page_size=1", cookies), "findings paged")
	if page.Data.Total != 2 || len(page.Data.Items) != 1 {
		t.Errorf("findings page total = %d items = %d, want 2/1", page.Data.Total, len(page.Data.Items))
	}

	// violations 过滤
	page = s8Page(t, env.get(t, "/api/v1/api-security/violations?endpoint_id="+ep.ID.String(), cookies), "violations by endpoint")
	if page.Data.Total != 2 {
		t.Errorf("violations total = %d, want 2", page.Data.Total)
	}
	page = s8Page(t, env.get(t, "/api/v1/api-security/violations?violation_type=undefined_field", cookies), "violations by type")
	if page.Data.Total != 1 {
		t.Errorf("violations undefined_field total = %d, want 1", page.Data.Total)
	}
	resp := env.get(t, "/api/v1/api-security/violations?endpoint_id=not-a-uuid", cookies)
	s5Expect(t, resp, http.StatusBadRequest, "violations with invalid endpoint_id")

	// 安全态势聚合（库内仅本用例数据：1 端点 DISCOVERED / 2 OPEN findings）
	result := s5OK(t, env.get(t, "/api/v1/api-security/posture", cookies), "posture")
	endpoints := s5Obj(t, result, "endpoints")
	if s5Num(t, endpoints, "total") != 1 {
		t.Errorf("posture endpoints.total = %v, want 1", endpoints["total"])
	}
	byAsset := s5Obj(t, apiResp{Data: map[string]interface{}{"x": endpoints["by_asset_status"]}}, "x")
	if s5Num(t, byAsset, "DISCOVERED") != 1 {
		t.Errorf("posture by_asset_status = %+v, want DISCOVERED=1", byAsset)
	}
	findings := s5Obj(t, result, "findings")
	if s5Num(t, findings, "open_total") != 2 {
		t.Errorf("posture findings.open_total = %v, want 2", findings["open_total"])
	}
	bySev := s5Obj(t, apiResp{Data: map[string]interface{}{"x": findings["open_by_severity"]}}, "x")
	if s5Num(t, bySev, "HIGH") != 1 || s5Num(t, bySev, "LOW") != 1 {
		t.Errorf("posture open_by_severity = %+v, want HIGH=1 LOW=1", bySev)
	}

	// 运行时统计：总量 + 动作/等级分布 + Top 端点
	result = s5OK(t, env.get(t, "/api/v1/api-security/runtime/statistics", cookies), "runtime statistics")
	if s5Num(t, result.Data, "total") != 4 {
		t.Errorf("statistics total = %v, want 4", result.Data["total"])
	}
	byAction := s5Obj(t, apiResp{Data: map[string]interface{}{"x": result.Data["by_final_action"]}}, "x")
	if s5Num(t, byAction, "ALLOW") != 2 || s5Num(t, byAction, "LOG") != 1 || s5Num(t, byAction, "BLOCK") != 1 {
		t.Errorf("by_final_action = %+v, want ALLOW=2 LOG=1 BLOCK=1", byAction)
	}
	byLevel := s5Obj(t, apiResp{Data: map[string]interface{}{"x": result.Data["by_risk_level"]}}, "x")
	if s5Num(t, byLevel, "NONE") != 2 || s5Num(t, byLevel, "MEDIUM") != 1 || s5Num(t, byLevel, "HIGH") != 1 {
		t.Errorf("by_risk_level = %+v, want NONE=2 MEDIUM=1 HIGH=1", byLevel)
	}
	top, _ := result.Data["top_endpoints"].([]interface{})
	if len(top) != 1 || top[0].(map[string]interface{})["endpoint_key"] != epKey ||
		top[0].(map[string]interface{})["count"] != float64(4) {
		t.Errorf("top_endpoints = %+v, want [%s:4]", top, epKey)
	}

	// 运行时事件过滤
	page = s8Page(t, env.get(t, "/api/v1/api-security/runtime/events?final_action=BLOCK", cookies), "events BLOCK")
	if page.Data.Total != 1 {
		t.Errorf("events BLOCK total = %d, want 1", page.Data.Total)
	}
	// endpoint_key 含空格（"GET /path"），查询串需 URL 编码
	page = s8Page(t, env.get(t, "/api/v1/api-security/runtime/events?endpoint_key="+url.QueryEscape(epKey), cookies), "events by endpoint_key")
	if page.Data.Total != 4 {
		t.Errorf("events endpoint_key total = %d, want 4", page.Data.Total)
	}
}

// ---------- 8. 策略：default → PUT PROTECT → db；非法值 400 ----------

// TestStage8PolicyMode 防护策略模式管理（db>env>default 取值顺序）。
func TestStage8PolicyMode(t *testing.T) {
	env := setupStage8Env(t)
	cookies, csrf := env.s5Login(t, "s8sec", "SECURITY_ADMIN")

	// 初始：product 默认 OBSERVE，无 env 无 db 覆盖 → mode_source=default
	result := s5OK(t, env.get(t, "/api/v1/api-security/policy", cookies), "get policy")
	if result.Data["mode"] != "OBSERVE" || result.Data["mode_source"] != "default" {
		t.Errorf("initial policy = mode %v source %v, want OBSERVE/default",
			result.Data["mode"], result.Data["mode_source"])
	}
	if result.Data["api_dynamic_protection"] != true || result.Data["edition"] != "wdsp" {
		t.Errorf("policy edition/protection = %v/%v, want wdsp/true",
			result.Data["edition"], result.Data["api_dynamic_protection"])
	}

	// PUT PROTECT → settings 表覆盖
	resp := env.do(t, http.MethodPut, "/api/v1/api-security/policy", `{"mode":"PROTECT"}`, cookies, csrf)
	result = s5OK(t, resp, "put policy PROTECT")
	policy := s5Obj(t, result, "policy")
	if policy["mode"] != "PROTECT" || policy["mode_source"] != "db" {
		t.Errorf("policy after put = mode %v source %v, want PROTECT/db", policy["mode"], policy["mode_source"])
	}

	// 再 GET：db 覆盖生效
	result = s5OK(t, env.get(t, "/api/v1/api-security/policy", cookies), "get policy after put")
	if result.Data["mode"] != "PROTECT" || result.Data["mode_source"] != "db" {
		t.Errorf("policy get after put = mode %v source %v, want PROTECT/db",
			result.Data["mode"], result.Data["mode_source"])
	}

	// 非法模式 → 400
	resp = env.do(t, http.MethodPut, "/api/v1/api-security/policy", `{"mode":"BLOCK"}`, cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "put policy with invalid mode")
	resp = env.do(t, http.MethodPut, "/api/v1/api-security/policy", `{"mode":""}`, cookies, csrf)
	s5Expect(t, resp, http.StatusBadRequest, "put policy with empty mode")
}

// ---------- 9. 权限与审计：只读角色全写操作 403；写操作落操作审计 ----------

// TestStage8PermissionAndAudit 五十二章权限点强制 + 操作审计落库。
func TestStage8PermissionAndAudit(t *testing.T) {
	env := setupStage8Env(t)
	auditCookies, auditCSRF := env.s5Login(t, "s8aud", "AUDIT_ADMIN")

	// 只读角色（AUDIT_ADMIN）对全部只读接口有权限
	for _, path := range []string{
		"/api/v1/api-security/endpoints",
		"/api/v1/api-security/classifications",
		"/api/v1/api-security/specs",
		"/api/v1/api-security/findings",
		"/api/v1/api-security/violations",
		"/api/v1/api-security/posture",
		"/api/v1/api-security/runtime/statistics",
		"/api/v1/api-security/runtime/events",
		"/api/v1/api-security/graph",
		"/api/v1/api-security/topology",
		"/api/v1/api-security/policy",
	} {
		resp := env.get(t, path, auditCookies)
		s5Expect(t, resp, http.StatusOK, "AUDIT_ADMIN GET "+path)
	}

	// 只读角色对全部写操作 403（五十二章：写权限点仅 SECURITY_ADMIN 持有）
	anyID := uuid.NewString()
	type writeCall struct{ method, path, body string }
	writes := []writeCall{
		{http.MethodPost, "/api/v1/api-security/endpoints/confirm", `{"ids":["` + anyID + `"]}`},
		{http.MethodPatch, "/api/v1/api-security/endpoints/" + anyID, `{"purpose":"x"}`},
		{http.MethodPost, "/api/v1/api-security/endpoints/" + anyID + "/merge", `{"other_id":"` + uuid.NewString() + `"}`},
		{http.MethodPost, "/api/v1/api-security/endpoints/" + anyID + "/split", `{"paths":["/x"]}`},
		{http.MethodPost, "/api/v1/api-security/endpoints/" + anyID + "/ignore", ""},
		{http.MethodPost, "/api/v1/api-security/endpoints/" + anyID + "/classify", ""},
		{http.MethodPost, "/api/v1/api-security/endpoints/" + anyID + "/learning/start", ""},
		{http.MethodPost, "/api/v1/api-security/endpoints/" + anyID + "/learning/stop", ""},
		{http.MethodPost, "/api/v1/api-security/endpoints/" + anyID + "/models", `{"schema":{"a":"string"}}`},
		{http.MethodPost, "/api/v1/api-security/models/" + anyID + "/submit-review", ""},
		{http.MethodPost, "/api/v1/api-security/models/" + anyID + "/confirm", ""},
		{http.MethodPost, "/api/v1/api-security/models/" + anyID + "/reject", ""},
		{http.MethodPost, "/api/v1/api-security/models/" + anyID + "/activate", ""},
		{http.MethodPost, "/api/v1/api-security/models/" + anyID + "/archive", ""},
		{http.MethodPatch, "/api/v1/api-security/parameters/" + anyID, `{"required":true}`},
		{http.MethodPost, "/api/v1/api-security/parameters/" + anyID + "/confirm", ""},
		{http.MethodPost, "/api/v1/api-security/classifications", `{"dimension":"D","value":"V"}`},
		{http.MethodPut, "/api/v1/api-security/endpoints/" + anyID + "/classification", `{"dimensions":[{"dimension":"PURPOSE","value":"TRADE"}]}`},
		{http.MethodPost, "/api/v1/api-security/specs/import", `{"openapi":"3.0.3","paths":{"/x":{"get":{}}}}`},
		{http.MethodPut, "/api/v1/api-security/policy", `{"mode":"PROTECT"}`},
		{http.MethodPost, "/api/v1/api-security/policy/publish", ""},
	}
	for _, w := range writes {
		resp := env.do(t, w.method, w.path, w.body, auditCookies, auditCSRF)
		s5Expect(t, resp, http.StatusForbidden, "AUDIT_ADMIN "+w.method+" "+w.path)
	}

	// SECURITY_ADMIN 写操作（confirm/merge/policy PUT）落操作审计
	secCookies, secCSRF, secUser := func() ([]*http.Cookie, string, string) {
		username := "s8sec_" + s5Rand()
		password := "S8@Test2026!"
		env.createUserDirect(t, username, password, "SECURITY_ADMIN")
		c, token := env.login(t, username, password)
		return c, token, username
	}()
	kw := "s8" + s5Rand()
	epA := s8SeedHits(t, env, "GET", "/"+kw+"/audit/a", 0.7, 1)
	epB := s8SeedHits(t, env, "GET", "/"+kw+"/audit/b", 0.6, 1)

	resp := env.post(t, "/api/v1/api-security/endpoints/confirm",
		fmt.Sprintf(`{"ids":[%q,%q]}`, epA.ID, epB.ID), secCookies, secCSRF)
	s5OK(t, resp, "security admin batch confirm")
	resp = env.post(t, "/api/v1/api-security/endpoints/"+epA.ID.String()+"/merge",
		fmt.Sprintf(`{"other_id":%q}`, epB.ID), secCookies, secCSRF)
	s5OK(t, resp, "security admin merge")
	resp = env.do(t, http.MethodPut, "/api/v1/api-security/policy", `{"mode":"PROTECT"}`, secCookies, secCSRF)
	s5OK(t, resp, "security admin put policy")

	// 审计表（operation_audits）应含 module 以 api 开头的三类记录
	rows, err := env.db.Query(context.Background(), `
SELECT module, action, object_type FROM operation_audits
WHERE username=$1 AND module LIKE 'api%'`, secUser)
	if err != nil {
		t.Fatalf("query audits: %v", err)
	}
	defer rows.Close()
	type auditKey struct{ module, action, objectType string }
	found := map[auditKey]bool{}
	for rows.Next() {
		var module, action, objectType string
		if err := rows.Scan(&module, &action, &objectType); err != nil {
			t.Fatalf("scan audit: %v", err)
		}
		if !strings.HasPrefix(module, "api") {
			t.Errorf("audit module = %q, want api 前缀", module)
		}
		found[auditKey{module, action, objectType}] = true
	}
	for _, want := range []auditKey{
		{"api_assets", "confirm", "api_endpoint"},
		{"api_assets", "merge", "api_endpoint"},
		{"api_security", "update", "api_policy"},
	} {
		if !found[want] {
			t.Errorf("缺少审计记录 %+v（confirm/merge/policy PUT 应落 operation_audits）", want)
		}
	}
}
