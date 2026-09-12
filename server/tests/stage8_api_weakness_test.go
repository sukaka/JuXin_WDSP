// 阶段8（WDSP）API 弱点中心集成测试（P0-13 Risk/Weakness 分离，迁移 000039）。
//
// 覆盖：SweepOnce 派生四条 v1 规则（真实 PG：api_runtime_events details_json JSONB 查询、
// api_runtime_findings 跨天持续判定）、派生 upsert（trigger_count++/FIXED 再触发 REPRODUCED）、
// 空表安全、证据脱敏（不落原始字段值）、生命周期 HTTP 流转与操作审计落库。
//
// 运行方式（与 make stage8-test-api 同一纪律）：
//
//	POSTGRES_PASSWORD=... go test ./tests -run TestStage8APIWeakness -count=1
//
// 无 POSTGRES_PASSWORD 时与既有集成测试一致地 t.Skip；不 mock，全部走真实 PostgreSQL。
// 注意：弱点中心路由尚未装配进 app（由集成方统一接线），本测试用本地 mux +
// 真实 apiweakness.Store / audits.Service 驱动，等价验证 SQL 与流转语义。
package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/apiweakness"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/config"
	"github.com/jiuzhang-waf/server/internal/database"
	"github.com/jiuzhang-waf/server/internal/response"
)

// setupWeaknessDB 重建测试库并执行全量迁移（只需 PostgreSQL；不依赖 Valkey/完整应用）。
func setupWeaknessDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	if testing.Short() {
		t.Skip("integration test skipped in short mode")
	}
	password := os.Getenv("POSTGRES_PASSWORD")
	if password == "" {
		t.Skip("POSTGRES_PASSWORD not set, skipping integration test")
	}
	cfg := config.DBConfig{
		Host:     envOr("POSTGRES_HOST", "127.0.0.1"),
		Port:     envInt("POSTGRES_PORT", 5432),
		Database: testDBName,
		User:     envOr("POSTGRES_USER", "jiuzhang"),
		Password: password,
		SSLMode:  "disable",
		MaxConns: 5,
	}
	ctx := context.Background()
	adminDSN := fmt.Sprintf("postgres://%s:%s@%s:%d/postgres?sslmode=disable",
		cfg.User, cfg.Password, cfg.Host, cfg.Port)
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

	db, err := database.Connect(ctx, cfg)
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	if err := database.Migrate(ctx, db, "../migrations", "up"); err != nil {
		db.Close()
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

// weaknessTestMux 本地路由装配：注入持有弱点权限点的主体（权限种子迁移由集成方统一登记）。
func weaknessTestMux(h *apiweakness.Handler) *http.ServeMux {
	authzInject := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "sec-admin",
				PermsSet: map[string]bool{apiweakness.PermRead: true, apiweakness.PermHandle: true}}
			ctx := authz.WithPrincipal(r.Context(), p)
			ctx = context.WithValue(ctx, response.RequestIDKey, "weak-it-rid")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	mux := http.NewServeMux()
	apiweakness.RegisterRoutes(mux, authzInject, h)
	return mux
}

// seedEndpoint 写入端点并返回 ID。
func seedEndpoint(t *testing.T, db *pgxpool.Pool, key string) uuid.UUID {
	t.Helper()
	parts := strings.SplitN(key, " ", 2)
	var id uuid.UUID
	err := db.QueryRow(context.Background(), `
INSERT INTO api_endpoints (http_method, normalized_path, endpoint_key)
VALUES ($1, $2, $3) RETURNING id`, parts[0], parts[1], key).Scan(&id)
	if err != nil {
		t.Fatalf("seed endpoint %s: %v", key, err)
	}
	return id
}

// seedEvent 写入一条运行时事件。
func seedEvent(t *testing.T, db *pgxpool.Pool, endpointKey, authType, details string, occurredAt time.Time) {
	t.Helper()
	_, err := db.Exec(context.Background(), `
INSERT INTO api_runtime_events (request_id, endpoint_key, risk_level, final_action, details_json, occurred_at, auth_type)
VALUES ($1, $2, 'NONE', 'ALLOW', $3::jsonb, $4, $5)`,
		uuid.NewString()[:32], endpointKey, details, occurredAt, authType)
	if err != nil {
		t.Fatalf("seed event %s: %v", endpointKey, err)
	}
}

// doWeakReq 发送 JSON 请求。
func doWeakReq(t *testing.T, mux http.Handler, method, url string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body == nil {
		reader = strings.NewReader("")
	} else {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = strings.NewReader(string(raw))
	}
	req := httptest.NewRequest(method, url, reader)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// TestStage8APIWeakness 弱点中心全链路：空表安全 → 四规则派生 → upsert 计数 →
// FIXED 再触发 REPRODUCED → 复测关闭 → 历史与审计落库。
func TestStage8APIWeakness(t *testing.T) {
	db := setupWeaknessDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// 1) 空表安全：无任何运行时数据时派生零产出、无错误
	sweeper := apiweakness.NewSweeper(db)
	res, err := sweeper.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("empty sweep: %v", err)
	}
	if res.Inserted != 0 || res.Updated != 0 || res.Reproduced != 0 {
		t.Fatalf("empty sweep result: %+v", res)
	}

	// 2) 造数：四个命中端点 + 两个负面对照
	epSensitive := seedEndpoint(t, db, "GET /api/users/{id}")
	epDeprecated := seedEndpoint(t, db, "GET /api/old/orders")
	epInQuery := seedEndpoint(t, db, "POST /api/login")
	epDrift := seedEndpoint(t, db, "GET /api/items")
	epAuthed := seedEndpoint(t, db, "GET /api/internal/stats") // 对照：已认证

	// UNAUTHENTICATED_SENSITIVE_API：匿名 + sensitive 命中 ×3（达样本量）；另有 1 条已认证命中不应计入
	sensitiveHit := `[{"detector":"sensitive","rule_id":"sensitive.field","evidence":{"field":"id_card"}}]`
	for i := 0; i < 3; i++ {
		seedEvent(t, db, "GET /api/users/{id}", "", sensitiveHit, now.Add(-time.Duration(i)*time.Hour))
	}
	seedEvent(t, db, "GET /api/internal/stats", "api_key", sensitiveHit, now.Add(-time.Hour))
	// DEPRECATED_STILL_CALLED：近 24h 一条命中（24h 前的旧命中不应计入）
	seedEvent(t, db, "GET /api/old/orders", "bearer_or_basic", `[{"detector":"lifecycle","rule_id":"lifecycle.deprecated_api_call"}]`, now.Add(-2*time.Hour))
	seedEvent(t, db, "GET /api/old/orders", "bearer_or_basic", `[{"detector":"lifecycle","rule_id":"lifecycle.deprecated_api_call"}]`, now.Add(-48*time.Hour))
	// SENSITIVE_IN_QUERY
	seedEvent(t, db, "POST /api/login", "", `[{"detector":"sensitive","rule_id":"sensitive.in_query","evidence":{"param":"password"}}]`, now.Add(-time.Hour))
	// SCHEMA_DRIFT_PERSISTENT：首现 4 天前 + 近 24h 仍出现；对照：已 RESOLVED 的漂移不计入
	seedFinding := func(endpointID uuid.UUID, status string, firstSeen, lastSeen time.Time) {
		t.Helper()
		_, err := db.Exec(ctx, `
INSERT INTO api_runtime_findings (endpoint_id, finding_type, severity, status, title, first_seen_at, last_seen_at)
VALUES ($1, 'SCHEMA_DEVIATION', 'LOW', $2, 'schema 漂移', $3, $4)`, endpointID, status, firstSeen, lastSeen)
		if err != nil {
			t.Fatalf("seed finding: %v", err)
		}
	}
	seedFinding(epDrift, "NEW", now.Add(-96*time.Hour), now.Add(-time.Hour))
	seedFinding(epSensitive, "RESOLVED", now.Add(-96*time.Hour), now.Add(-time.Hour)) // 对照：已闭环

	// 3) 第一轮派生：4 条 NEW 弱点（对照端点不得产出）
	res, err = sweeper.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("first sweep: %v", err)
	}
	if res.Inserted != 4 || res.Updated != 0 || res.Reproduced != 0 {
		t.Fatalf("first sweep result: %+v", res)
	}
	var count int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM api_weaknesses WHERE endpoint_id = $1`, epAuthed).Scan(&count); err != nil || count != 0 {
		t.Fatalf("authenticated endpoint must not yield weakness: count=%d err=%v", count, err)
	}
	// 已下线仍被调用端点产出 DEPRECATED_STILL_CALLED（48h 前的旧命中不影响判定）
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM api_weaknesses WHERE endpoint_id = $1 AND weakness_code = $2`,
		epDeprecated, apiweakness.CodeDeprecatedStillCalled).Scan(&count); err != nil || count != 1 {
		t.Fatalf("deprecated weakness count=%d, want 1 (err=%v)", count, err)
	}
	// 证据脱敏：不得包含原始字段值 id_card / password
	var evidence string
	if err := db.QueryRow(ctx,
		`SELECT evidence_json::text FROM api_weaknesses WHERE endpoint_id = $1 AND weakness_code = $2`,
		epSensitive, apiweakness.CodeUnauthenticatedSensitiveAPI).Scan(&evidence); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(evidence, "id_card") || !strings.Contains(evidence, "sample_count") {
		t.Fatalf("evidence not sanitized: %s", evidence)
	}

	// 4) 第二轮派生：同端点同码计数 +1，不重复插入
	res, err = sweeper.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	if res.Inserted != 0 || res.Updated != 4 {
		t.Fatalf("second sweep result: %+v", res)
	}
	if err := db.QueryRow(ctx,
		`SELECT trigger_count FROM api_weaknesses WHERE endpoint_id = $1 AND weakness_code = $2`,
		epInQuery, apiweakness.CodeSensitiveInQuery).Scan(&count); err != nil || count != 2 {
		t.Fatalf("trigger_count=%d, want 2 (err=%v)", count, err)
	}

	// 5) HTTP 生命周期：SENSITIVE_IN_QUERY 弱点 confirm → assign → fixed → 再扫中 REPRODUCED → retest 关闭
	store := apiweakness.NewStore(db)
	h := apiweakness.NewHandler(store, audits.NewService(db))
	mux := weaknessTestMux(h)

	var weakID string
	if err := db.QueryRow(ctx,
		`SELECT id FROM api_weaknesses WHERE endpoint_id = $1 AND weakness_code = $2`,
		epInQuery, apiweakness.CodeSensitiveInQuery).Scan(&weakID); err != nil {
		t.Fatal(err)
	}
	base := "/api/v1/api-security/weaknesses/" + weakID

	// 列表过滤（severity=HIGH 命中 2 条：未认证敏感 + 查询串敏感）
	rr := doWeakReq(t, mux, http.MethodGet, "/api/v1/api-security/weaknesses?severity=HIGH", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", rr.Code, rr.Body.String())
	}
	var listEnv struct {
		Data struct {
			Total int64 `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &listEnv); err != nil || listEnv.Data.Total != 2 {
		t.Fatalf("list HIGH total=%d err=%v", listEnv.Data.Total, err)
	}
	// 非法过滤值 → 400
	if rr := doWeakReq(t, mux, http.MethodGet, "/api/v1/api-security/weaknesses?status=OPEN", nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad status filter status=%d", rr.Code)
	}

	// 非法迁移（NEW 直接 fixed）→ 400
	if rr := doWeakReq(t, mux, http.MethodPost, base+"/fixed", nil); rr.Code != http.StatusBadRequest {
		t.Fatalf("fixed from NEW status=%d, want 400", rr.Code)
	}
	// confirm → assign → fixed
	if rr := doWeakReq(t, mux, http.MethodPost, base+"/confirm", nil); rr.Code != http.StatusOK {
		t.Fatalf("confirm status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = doWeakReq(t, mux, http.MethodPost, base+"/assign", map[string]any{"owner": "zhangsan", "note": "整改查询串"})
	if rr.Code != http.StatusOK {
		t.Fatalf("assign status=%d body=%s", rr.Code, rr.Body.String())
	}
	if rr := doWeakReq(t, mux, http.MethodPost, base+"/fixed", nil); rr.Code != http.StatusOK {
		t.Fatalf("fixed status=%d body=%s", rr.Code, rr.Body.String())
	}
	// 再扫中 → REPRODUCED
	res, err = sweeper.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("third sweep: %v", err)
	}
	if res.Reproduced != 1 {
		t.Fatalf("third sweep reproduced=%d, want 1（%+v）", res.Reproduced, res)
	}
	var status string
	if err := db.QueryRow(ctx, `SELECT status FROM api_weaknesses WHERE id = $1`, weakID).Scan(&status); err != nil ||
		status != apiweakness.StatusReproduced {
		t.Fatalf("status=%s, want REPRODUCED (err=%v)", status, err)
	}
	// 重新指派 → 整改 → 复测通过关闭
	if rr := doWeakReq(t, mux, http.MethodPost, base+"/assign", map[string]any{"owner": "lisi"}); rr.Code != http.StatusOK {
		t.Fatalf("re-assign status=%d", rr.Code)
	}
	if rr := doWeakReq(t, mux, http.MethodPost, base+"/fixed", nil); rr.Code != http.StatusOK {
		t.Fatalf("re-fixed status=%d", rr.Code)
	}
	if rr := doWeakReq(t, mux, http.MethodPost, base+"/retest", map[string]any{"result": "PASS"}); rr.Code != http.StatusOK {
		t.Fatalf("retest status=%d body=%s", rr.Code, rr.Body.String())
	}

	// 详情：历史轨迹完整（DERIVED + CONFIRM/ASSIGN/MARK_FIXED + REPRODUCED + ASSIGN/MARK_FIXED/RETEST_PASS）
	rr = doWeakReq(t, mux, http.MethodGet, base, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("detail status=%d", rr.Code)
	}
	var detailEnv struct {
		Data struct {
			Weakness struct {
				Status       string `json:"status"`
				TriggerCount int    `json:"trigger_count"`
			} `json:"weakness"`
			Actions []struct {
				Action string `json:"action"`
				Actor  string `json:"actor"`
			} `json:"actions"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &detailEnv); err != nil {
		t.Fatal(err)
	}
	if detailEnv.Data.Weakness.Status != apiweakness.StatusArchived || detailEnv.Data.Weakness.TriggerCount != 3 {
		t.Fatalf("weakness detail: %+v", detailEnv.Data.Weakness)
	}
	if len(detailEnv.Data.Actions) != 8 {
		t.Fatalf("actions=%d, want 8（%+v）", len(detailEnv.Data.Actions), detailEnv.Data.Actions)
	}

	// 操作审计落库（confirm/assign/fixed/assign/fixed/retest 共 6 条；派生与 REPRODUCED 走 actions 表不走审计）
	if err := db.QueryRow(ctx,
		`SELECT count(*) FROM operation_audits WHERE module = 'api_security' AND object_type = 'api_weakness' AND object_id = $1`,
		weakID).Scan(&count); err != nil || count != 6 {
		t.Fatalf("audit entries=%d, want 6 (err=%v)", count, err)
	}
}
