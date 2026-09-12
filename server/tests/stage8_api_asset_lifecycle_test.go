// stage8_api_asset_lifecycle_test.go 资产生命周期增强集成测试（WDSP P0-10/P0-11，迁移 000045）。
// 覆盖：迁移落位（asset_value/asset_value_explain/zombie_since 三列 + 注释词表含 ZOMBIE）；
// deprecate/restore HTTP 状态机（200/409）与生命周期事件；SweepOnce 僵尸判定
// （近 7 天窗口内仍有流量的 DEPRECATED → ZOMBIE + zombie_since + 事件；幂等）；
// 资产价值评分 SQL 装配与回填（分类维度/敏感字段/身份形态/流量桶）；
// 服务资产聚合 GET /api/v1/api-security/service-assets。
// 真实 PostgreSQL/Valkey，无口令环境 t.Skip（纪律同 stage8_api_security_test.go）。
package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apiassets"
)

// s8SeedUpstream 造应用 + 源站（服务资产聚合原料），返回应用 id。
func s8SeedUpstream(t *testing.T, env *testEnv, tag, host string, port int) uuid.UUID {
	t.Helper()
	var appID uuid.UUID
	if err := env.db.QueryRow(context.Background(),
		`INSERT INTO applications (code, name) VALUES ($1, $2) RETURNING id`,
		"s8la-"+tag, "资产生命周期测试-"+tag).Scan(&appID); err != nil {
		t.Fatalf("seed application: %v", err)
	}
	if _, err := env.db.Exec(context.Background(),
		`INSERT INTO upstreams (application_id, name, scheme, host, normalized_host, port)
		 VALUES ($1, $2, 'http', $3, $3, $4)`,
		appID, "up-"+tag, host, port); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	return appID
}

func TestStage8APIAssetLifecycle(t *testing.T) {
	env := setupStage8Env(t)
	cookies, csrf := env.s5Login(t, "s8lc", "SECURITY_ADMIN")
	ctx := context.Background()
	store := apiassets.NewStore(env.db)

	// ---------- 迁移 000045 落位 ----------
	if n := s8Count(t, env, `
SELECT count(*) FROM information_schema.columns
WHERE table_name='api_endpoints'
  AND column_name IN ('asset_value','asset_value_explain','zombie_since')`); n != 3 {
		t.Fatalf("migration 000045 columns = %d, want 3", n)
	}

	// ---------- deprecate / restore 状态机 ----------
	ep := s8SeedEndpoint(t, env, "GET", "/s8lc-"+s5Rand()+"/legacy/{id}", 0.9)
	result := s5OK(t, env.post(t, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/deprecate", "", cookies, csrf), "deprecate")
	if got := s5Obj(t, result, "endpoint")["asset_status"]; got != "DEPRECATED" {
		t.Fatalf("asset_status after deprecate = %v, want DEPRECATED", got)
	}
	// 重复下线 409（DEPRECATED 不在合法起点）
	s5Expect(t, env.post(t, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/deprecate", "", cookies, csrf),
		http.StatusConflict, "re-deprecate")
	// 恢复 → CONFIRMED + confirmed_at 落时
	result = s5OK(t, env.post(t, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/restore", "", cookies, csrf), "restore")
	obj := s5Obj(t, result, "endpoint")
	if obj["asset_status"] != "CONFIRMED" || obj["confirmed_at"] == nil {
		t.Fatalf("endpoint after restore = %v", obj)
	}
	// 再恢复 409（仅 DEPRECATED/ZOMBIE 可恢复）
	s5Expect(t, env.post(t, "/api/v1/api-security/endpoints/"+ep.ID.String()+"/restore", "", cookies, csrf),
		http.StatusConflict, "re-restore")
	// 生命周期事件两条（DISCOVERED→DEPRECATED / DEPRECATED→CONFIRMED）
	if n := s8Count(t, env, `
SELECT count(*) FROM api_lifecycle_events
WHERE endpoint_id=$1 AND to_status IN ('DEPRECATED','CONFIRMED')`, ep.ID); n != 2 {
		t.Fatalf("lifecycle events = %d, want 2", n)
	}

	// ---------- SweepOnce 僵尸判定 ----------
	zom := s8SeedEndpoint(t, env, "GET", "/s8lc-"+s5Rand()+"/zombie/{id}", 0.8)
	stale := s8SeedEndpoint(t, env, "GET", "/s8lc-"+s5Rand()+"/stale/{id}", 0.8)
	for _, id := range []uuid.UUID{zom.ID, stale.ID} {
		if _, err := store.Deprecate(ctx, id, "tester"); err != nil {
			t.Fatalf("deprecate: %v", err)
		}
	}
	now := time.Now().UTC()
	// zom 近窗口有流量；stale 仅 8 天前流量（出窗口）
	if err := store.RecordTrafficBucket(ctx, zom.ID, now.Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordTrafficBucket(ctx, stale.ID, now.Add(-8*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	res, err := apiassets.NewSweeper(store, apiassets.SweepOptions{}).SweepOnce(ctx)
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if res.Zombied != 1 {
		t.Fatalf("zombied = %d, want 1（result=%+v）", res.Zombied, res)
	}
	zomAfter, err := store.GetByID(ctx, zom.ID)
	if err != nil {
		t.Fatal(err)
	}
	if zomAfter.AssetStatus != "ZOMBIE" || zomAfter.ZombieSince == nil {
		t.Fatalf("zom status=%s zombie_since=%v, want ZOMBIE + zombie_since",
			zomAfter.AssetStatus, zomAfter.ZombieSince)
	}
	staleAfter, err := store.GetByID(ctx, stale.ID)
	if err != nil {
		t.Fatal(err)
	}
	if staleAfter.AssetStatus != "DEPRECATED" {
		t.Fatalf("stale status=%s, want DEPRECATED（窗口外流量不判僵尸）", staleAfter.AssetStatus)
	}
	if n := s8Count(t, env, `
SELECT count(*) FROM api_lifecycle_events
WHERE endpoint_id=$1 AND from_status='DEPRECATED' AND to_status='ZOMBIE' AND actor='system'`, zom.ID); n != 1 {
		t.Fatalf("zombie lifecycle event = %d, want 1", n)
	}
	// 幂等：二轮无新迁移
	res2, err := apiassets.NewSweeper(store, apiassets.SweepOptions{}).SweepOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Zombied != 0 {
		t.Fatalf("second sweep zombied = %d, want 0", res2.Zombied)
	}
	// ZOMBIE 人工恢复：zombie_since 清空
	if _, err := store.Restore(ctx, zom.ID, "tester"); err != nil {
		t.Fatal(err)
	}
	if n := s8Count(t, env, `
SELECT count(*) FROM api_endpoints WHERE id=$1 AND asset_status='CONFIRMED' AND zombie_since IS NULL`, zom.ID); n != 1 {
		t.Fatal("restore zombie: zombie_since 未清空或状态非 CONFIRMED")
	}

	// ---------- 资产价值评分（SQL 装配 + 回填 + 列表/详情带出） ----------
	val := s8SeedEndpoint(t, env, "POST", "/s8lc-"+s5Rand()+"/pay/{id}", 0.9)
	if _, err := store.AutoClassify(ctx, val.ID); err != nil { // 路径含 /pay → PURPOSE=TRADE / EXPOSURE=INTERNAL
		t.Fatal(err)
	}
	for i, p := range []string{"$.card_no", "$.cvv"} {
		s8Exec(t, env, `
INSERT INTO api_sensitive_fields (endpoint_id, direction, structured_path, data_type)
VALUES ($1, 'REQUEST', $2, 'bank_card')`, val.ID, fmt.Sprintf("f%d-%s", i, p))
	}
	s8Exec(t, env, `
INSERT INTO api_identity_profiles (identity_fingerprint, endpoint_id, auth_type)
VALUES ('fp-`+s5Rand()+`', $1, 'cookie_session')`, val.ID)
	for i := 0; i < 7; i++ { // 近 7 天每天 1 请求 → 日均 1
		if err := store.RecordTrafficBucket(ctx, val.ID, now.Add(-time.Duration(i)*24*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.RefreshAssetValues(ctx, 100); err != nil {
		t.Fatalf("RefreshAssetValues: %v", err)
	}
	valAfter, err := store.GetByID(ctx, val.ID)
	if err != nil {
		t.Fatal(err)
	}
	// TRADE(3)+敏感2(1)+INTERNAL(0)+cookie_session(3)+POST(2)+trans(3)+流量日均1(1)=13 → MEDIUM
	if valAfter.AssetValue != "MEDIUM" {
		t.Fatalf("asset_value = %s, want MEDIUM（explain=%s）", valAfter.AssetValue, valAfter.AssetValueExplain)
	}
	var score apiassets.AssetValueScore
	if err := json.Unmarshal(valAfter.AssetValueExplain, &score); err != nil {
		t.Fatalf("asset_value_explain not json: %v", err)
	}
	if score.Total != 13 || len(score.Dimensions) != 9 || score.ComputedAt == nil {
		t.Fatalf("score total=%d dims=%d computed=%v, want 13/9/非空", score.Total, len(score.Dimensions), score.ComputedAt)
	}
	// 详情接口带出两字段
	result = s5OK(t, env.get(t, "/api/v1/api-security/endpoints/"+val.ID.String(), cookies), "get endpoint")
	obj = s5Obj(t, result, "endpoint")
	if obj["asset_value"] != "MEDIUM" || obj["asset_value_explain"] == nil {
		t.Fatalf("detail asset_value fields = %v / %v", obj["asset_value"], obj["asset_value_explain"])
	}
	// 列表接口带出 asset_value（keyword 用站点唯一随机段）
	page := s8Page(t, env.get(t, "/api/v1/api-security/endpoints?keyword="+val.NormalizedPath[1:14], cookies), "list with asset_value")
	found := false
	for _, item := range page.Data.Items {
		if item["id"] == val.ID.String() {
			found = true
			if item["asset_value"] != "MEDIUM" {
				t.Fatalf("list asset_value = %v, want MEDIUM", item["asset_value"])
			}
		}
	}
	if !found {
		t.Fatal("list 未找到评分端点")
	}

	// ---------- 服务资产聚合 ----------
	appA := s8SeedUpstream(t, env, s5Rand(), "10.9.9.1", 8080)
	appB := s8SeedUpstream(t, env, s5Rand(), "10.9.9.1", 8080)
	// appB 另有一个独立服务（host:port 不同）
	if _, err := env.db.Exec(ctx, `
INSERT INTO upstreams (application_id, name, scheme, host, normalized_host, port)
VALUES ($1, 'up-extra', 'http', '10.9.9.2', '10.9.9.2', 9090)`, appB); err != nil {
		t.Fatal(err)
	}
	seed := func(method, path string, app uuid.UUID) *apiassets.Endpoint {
		ep, err := store.UpsertDiscovery(ctx, apiassets.DiscoveryInput{
			Method: method, PathTemplate: path, Confidence: 0.8, IsAPI: true, ApplicationID: &app,
		})
		if err != nil {
			t.Fatalf("seed endpoint: %v", err)
		}
		return ep
	}
	e1 := seed("GET", "/s8lc-"+s5Rand()+"/a1", appA)
	e2 := seed("POST", "/s8lc-"+s5Rand()+"/a2", appA)
	e3 := seed("GET", "/s8lc-"+s5Rand()+"/b1", appB)
	for i := 0; i < 5; i++ {
		if err := store.RecordTrafficBucket(ctx, e1.ID, now); err != nil {
			t.Fatal(err)
		}
	}
	s8Exec(t, env, `
INSERT INTO api_sensitive_fields (endpoint_id, direction, structured_path, data_type)
VALUES ($1, 'RESPONSE', '$.id_card', 'id_card')`, e1.ID)
	s8Exec(t, env, `
INSERT INTO api_runtime_findings (endpoint_id, finding_type, severity, status, title)
VALUES ($1, 'BOLA', 'HIGH', 'NEW', '越权风险')`, e2.ID)
	s8Exec(t, env, `
INSERT INTO api_runtime_findings (endpoint_id, finding_type, severity, status, title)
VALUES ($1, 'SHADOW', 'LOW', 'RESOLVED', '已闭环风险')`, e3.ID)

	page = s8Page(t, env.get(t, "/api/v1/api-security/service-assets", cookies), "service-assets")
	if page.Data.Total != 2 {
		t.Fatalf("service-assets total = %d, want 2", page.Data.Total)
	}
	byAddr := map[string]map[string]interface{}{}
	for _, item := range page.Data.Items {
		byAddr[fmt.Sprintf("%v:%v", item["server_ip"], item["port"])] = item
	}
	svc1, ok := byAddr["10.9.9.1:8080"]
	if !ok {
		t.Fatalf("缺少服务 10.9.9.1:8080: %v", byAddr)
	}
	// 承载 appA/appB 两应用；3 端点；流量 5；敏感端点 1；未闭环风险 1
	if svc1["application_count"] != float64(2) || svc1["api_count"] != float64(3) ||
		svc1["traffic_7d"] != float64(5) || svc1["sensitive_api_count"] != float64(1) ||
		svc1["risk_count"] != float64(1) {
		t.Fatalf("svc 10.9.9.1:8080 = %v", svc1)
	}
	svc2, ok := byAddr["10.9.9.2:9090"]
	if !ok {
		t.Fatalf("缺少服务 10.9.9.2:9090: %v", byAddr)
	}
	if svc2["application_count"] != float64(1) || svc2["api_count"] != float64(1) ||
		svc2["traffic_7d"] != float64(0) || svc2["sensitive_api_count"] != float64(0) ||
		svc2["risk_count"] != float64(0) {
		t.Fatalf("svc 10.9.9.2:9090 = %v（RESOLVED 风险不计入）", svc2)
	}

	// 未登录 401（POST 路由的 401/403 已由包内单测覆盖）
	s5Expect(t, env.do(t, http.MethodGet, "/api/v1/api-security/service-assets", "", nil, ""),
		http.StatusUnauthorized, "service-assets unauthenticated")
}
