// wizard_integration_test.go 向导 PG 契约测试（NG-AZ-04 D9 server 组）：
// 迁移 000175 up/up/down 幂等与表结构；影响评估聚合（计数/分桶/主体/样本裁剪/
// token 仅 manage 签发）；确认单生命周期（签发/签署/消费/过期/复用/绑定不符/
// 未签署各拒）；conflicts 独立查询；readiness 装配（节点事实空表 NEVER_ACKED 路径）。
// Opt-in（AUTHZ_TEST_PG_DSN）——单元运行不需要活动数据库。
package apiauthzwizard

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
	"github.com/jiuzhang-waf/server/internal/apiauthz"
	"github.com/jiuzhang-waf/server/internal/database"
)

func openWizardPG(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	dsn := os.Getenv("AUTHZ_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("AUTHZ_TEST_PG_DSN not set, skipping wizard PG test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("create pg pool: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping pg: %v", err)
	}
	return pool, ctx
}

// wizardFixture 测试夹具（应用/端点/对象模型/关系/决策行）。
type wizardFixture struct {
	appID, endpointID, modelID uuid.UUID
	endpointKey                string
}

func seedWizardFixture(t *testing.T, pool *pgxpool.Pool, ctx context.Context) wizardFixture {
	t.Helper()
	code := fmt.Sprintf("wz175-%d", time.Now().UnixNano())
	var f wizardFixture
	f.endpointKey = "GET /v1/wz/orders/{id}"
	if err := pool.QueryRow(ctx, `INSERT INTO applications(code,name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&f.appID); err != nil {
		t.Fatalf("insert application: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO api_endpoints(application_id,http_method,normalized_path,endpoint_key,asset_status)
		VALUES ($1,'GET','/v1/wz/orders/{id}',$2,'CONFIRMED') RETURNING id`, f.appID, f.endpointKey).Scan(&f.endpointID); err != nil {
		t.Fatalf("insert endpoint: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO api_object_models(endpoint_id,object_segment,publishable,required_relation,owner_exclusive)
		VALUES ($1,'path:3',true,'OWNER',true) RETURNING id`, f.endpointID).Scan(&f.modelID); err != nil {
		t.Fatalf("insert object model: %v", err)
	}
	objref := "objref:" + strings.Repeat("ab", 32)
	if _, err := pool.Exec(ctx, `INSERT INTO api_object_relations(application_id,principal_id,object_type,object_ref,relation,source,reason,confirmed_by)
		VALUES ($1,'principal-wz','orders',$2,'OWNER','MANUAL','wz 契约夹具','wz-tester')`, f.appID, objref); err != nil {
		t.Fatalf("insert relation: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM api_authorization_decisions WHERE application_id=$1`, f.appID)
		_, _ = pool.Exec(bg, `DELETE FROM api_runtime_events WHERE endpoint_key=$1`, f.endpointKey)
		_, _ = pool.Exec(bg, `DELETE FROM api_object_relations WHERE application_id=$1`, f.appID)
		_, _ = pool.Exec(bg, `DELETE FROM api_authority_conflicts WHERE application_id=$1`, f.appID)
		_, _ = pool.Exec(bg, `DELETE FROM api_authz_enforcement_confirmations WHERE application_id=$1`, f.appID)
		_, _ = pool.Exec(bg, `DELETE FROM api_object_models WHERE endpoint_id=$1`, f.endpointID)
		_, _ = pool.Exec(bg, `DELETE FROM api_endpoints WHERE id=$1`, f.endpointID)
		_, _ = pool.Exec(bg, `DELETE FROM applications WHERE id=$1`, f.appID)
	})
	return f
}

func seedDecisions(t *testing.T, pool *pgxpool.Pool, ctx context.Context, f wizardFixture) {
	t.Helper()
	mk := func(decision, reason string, n int) {
		t.Helper()
		checks := "[]"
		if reason != "" {
			checks = fmt.Sprintf(`[{"type":"BOLA","decision":"%s","reason_code":"%s"}]`, decision, reason)
		}
		for i := 0; i < n; i++ {
			// 键族口径锚定：决策落库键为请求路径归一化键——不可归一对象值（t00N）
			// 保留字面（每值一键），与模板键同族聚合（联调修正前按模板精确键漏计）
			key := f.endpointKey
			if i > 0 {
				key = strings.Replace(f.endpointKey, "{id}", fmt.Sprintf("t%03d", i), 1)
			}
			if _, err := pool.Exec(ctx, `INSERT INTO api_authorization_decisions(decision_id,application_id,endpoint_key,decision,checks)
				VALUES (gen_random_uuid(),$1,$2,$3,$4::jsonb)`, f.appID, key, decision, checks); err != nil {
				t.Fatalf("insert decision %s: %v", decision, err)
			}
		}
	}
	mk("OBSERVE_VIOLATION", "AUTHZ-BOLA-001", 3)
	mk("UNKNOWN", "AUTHZ-IDENTITY-001", 2)
	mk("UNKNOWN", "AUTHZ-LEASE-001", 1)
	mk("VERIFIED_VIOLATION", "AUTHZ-BOLA-001", 1)
	mk("ALLOW", "", 4)
	if _, err := pool.Exec(ctx, `INSERT INTO api_runtime_events(id,request_id,endpoint_key,jwt_verification,occurred_at)
		VALUES (gen_random_uuid(),$1,$2,$3::jsonb,now()),(gen_random_uuid(),$4,$2,$5::jsonb,now())`,
		"req-wz-1", f.endpointKey, `{"status":"VERIFIED","verified_principal_id":"p-1"}`,
		"req-wz-2", `{"status":"VERIFIED","verified_principal_id":"p-2"}`); err != nil {
		t.Fatalf("insert runtime events: %v", err)
	}
}

func okCapability(_ context.Context, _ int) (bool, string) { return true, "" }

// TestWizardMigration175PostgresContract 迁移 000175：up/up 幂等、表结构与约束、
// down 一步回滚、再 up 恢复。
func TestWizardMigration175PostgresContract(t *testing.T) {
	pool, ctx := openWizardPG(t)
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("rerun migrations: %v", err)
	}
	var applied int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version=175`).Scan(&applied); err != nil {
		t.Fatalf("check migration record: %v", err)
	}
	if applied != 1 {
		t.Fatalf("migration 175 records=%d, want 1", applied)
	}
	for _, col := range []string{"confirm_token", "application_id", "endpoint_id", "object_segment",
		"window_days", "impact_snapshot", "confirm_text", "enforcement_owner", "evidence_source",
		"on_unknown", "token_expires_at", "signed_at", "consumed_at", "consumed_audit_id"} {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_schema=current_schema() AND table_name='api_authz_enforcement_confirmations' AND column_name=$1
		)`, col).Scan(&exists); err != nil {
			t.Fatalf("check column %s: %v", col, err)
		}
		if !exists {
			t.Fatalf("column api_authz_enforcement_confirmations.%s missing", col)
		}
	}
	// down 十一步（185..175：先回滚 000185（升级任务 executor_deadline 列，
	// NG-REL-02 F7），再回滚其上的 NG-ID/NG-MCP/NG-GRPC/NG-FLOW 各迁移）+ 再 up
	for _, v := range []int{185, 184, 183, 182, 181, 180, 179, 178, 177, 176, 175} {
		if err := database.Migrate(ctx, pool, "../../migrations", "down"); err != nil {
			t.Fatalf("migrate down %d: %v", v, err)
		}
	}
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('api_authz_enforcement_confirmations') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatalf("check table after down: %v", err)
	}
	if exists {
		t.Fatal("table must be dropped after down")
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("migrate up again: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT to_regclass('api_authz_enforcement_confirmations') IS NOT NULL`).Scan(&exists); err != nil || !exists {
		t.Fatalf("table must exist after re-up: %v", err)
	}
}

// TestWizardImpactPostgresContract 影响评估：窗口词表、计数/分桶/主体、样本权限
// 裁剪、token 仅 manage 签发、多行须指定 object_segment。
func TestWizardImpactPostgresContract(t *testing.T) {
	pool, ctx := openWizardPG(t)
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	f := seedWizardFixture(t, pool, ctx)
	seedDecisions(t, pool, ctx, f)
	store := NewStore(pool)

	call := func(t *testing.T, perms []string, body map[string]any) (int, ImpactResult) {
		t.Helper()
		h := NewHandler(store, nil, nil, okCapability)
		mux := http.NewServeMux()
		RegisterRoutes(mux, injectPerms(perms...), h)
		rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/enforcement-impact", body)
		var env struct {
			Code string          `json:"code"`
			Data json.RawMessage `json:"data"`
		}
		_ = json.Unmarshal(rr.Body.Bytes(), &env)
		var out ImpactResult
		if env.Data != nil {
			_ = json.Unmarshal(env.Data, &out)
		}
		return rr.Code, out
	}

	// 窗口词表外 400
	for _, days := range []int{0, 31, -1} {
		if code, _ := call(t, []string{apiauthz.PermAuthzRead}, map[string]any{"endpoint_id": f.endpointID.String(), "window_days": days}); code != http.StatusBadRequest {
			t.Fatalf("window_days=%d 应 400, got %d", days, code)
		}
	}

	// read 评估：无 token 无样本
	code, res := call(t, []string{apiauthz.PermAuthzRead}, map[string]any{"endpoint_id": f.endpointID.String(), "window_days": 7})
	if code != http.StatusOK {
		t.Fatalf("read 评估 status=%d", code)
	}
	if res.ObserveViolationCount != 3 || res.UnknownTotal != 3 || res.VerifiedViolationCount != 1 {
		t.Fatalf("计数不符: %+v", res)
	}
	if res.DistinctPrincipalCount != 2 {
		t.Fatalf("主体计数=%d want 2", res.DistinctPrincipalCount)
	}
	bucket := map[string]int64{}
	for _, b := range res.UnknownByReason {
		bucket[b.ReasonCode] = b.Count
	}
	if bucket["AUTHZ-IDENTITY-001"] != 2 || bucket["AUTHZ-LEASE-001"] != 1 {
		t.Fatalf("分桶不符: %+v", res.UnknownByReason)
	}
	if res.ConfirmToken != uuid.Nil || res.ConfirmTokenExpiresAt != nil {
		t.Fatalf("read 主体不得签发 token: %+v", res)
	}
	if len(res.RecentSamples) != 0 {
		t.Fatalf("无 evidence_read 不得返回样本: %+v", res.RecentSamples)
	}
	if res.EndpointKey != f.endpointKey || res.ObjectSegment != "path:3" {
		t.Fatalf("粒度不符: %+v", res)
	}

	// manage+evidence_read 评估：签发 token + 样本带出（≤5，ALLOW 不计入）
	code, res = call(t, []string{apiauthz.PermAuthzRead, apiauthz.PermAuthzManage, apiauthz.PermEvidenceRead},
		map[string]any{"endpoint_id": f.endpointID.String(), "window_days": 7})
	if code != http.StatusOK || res.ConfirmToken == uuid.Nil || res.ConfirmTokenExpiresAt == nil {
		t.Fatalf("manage 评估应签发 token: %d %+v", code, res)
	}
	if len(res.RecentSamples) != 5 {
		t.Fatalf("样本数=%d want 5（非 ALLOW 决策上限 5）", len(res.RecentSamples))
	}
	for _, s := range res.RecentSamples {
		if s.Decision == "ALLOW" {
			t.Fatalf("样本不得含 ALLOW: %+v", s)
		}
	}
	// 影响评估结果不入库（确认单才算）——token 行恰一条且未签署未消费
	var n, unsigned, unconsumed int
	if err := pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE signed_at IS NULL), count(*) FILTER (WHERE consumed_at IS NULL)
		FROM api_authz_enforcement_confirmations WHERE endpoint_id=$1`, f.endpointID).Scan(&n, &unsigned, &unconsumed); err != nil {
		t.Fatalf("count confirmations: %v", err)
	}
	if n != 1 || unsigned != 1 || unconsumed != 1 {
		t.Fatalf("确认单状态 n=%d unsigned=%d unconsumed=%d, want 1/1/1", n, unsigned, unconsumed)
	}
}

// TestWizardConfirmationLifecyclePostgresContract 确认单生命周期：
// 签发→签署→（消费在 PATCH 侧集成测试覆盖）；过期/重复签署/词表外各拒。
func TestWizardConfirmationLifecyclePostgresContract(t *testing.T) {
	pool, ctx := openWizardPG(t)
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	f := seedWizardFixture(t, pool, ctx)
	store := NewStore(pool)
	now := time.Now().UTC()

	// 签发
	token, expires, err := store.IssueConfirmation(ctx, f.appID, f.endpointID, "path:3", 7, []byte(`{"window_days":7,"observe_violation_count":3,"distinct_principal_count":2}`), now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if !expires.Equal(now.Add(15 * time.Minute)) {
		t.Fatalf("TTL=%v want 15m", expires.Sub(now))
	}
	var id uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM api_authz_enforcement_confirmations WHERE confirm_token=$1`, token).Scan(&id); err != nil {
		t.Fatalf("read confirmation id: %v", err)
	}

	// 签署词表外各拒（handler 层）
	h := NewHandler(store, nil, nil, okCapability)
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPerms(apiauthz.PermAuthzManage), h)
	sign := func(body map[string]any) *httptest.ResponseRecorder {
		return doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/enforcement-confirmations/"+token.String()+"/sign", body)
	}
	if rr := sign(map[string]any{"enforcement_owner": "", "evidence_source": "MANUAL_CONFIRMED", "on_unknown": "ALLOW_UNKNOWN"}); rr.Code != http.StatusBadRequest {
		t.Fatalf("owner 空应 400, got %d", rr.Code)
	}
	if rr := sign(map[string]any{"enforcement_owner": "a@b.c", "evidence_source": "GUESSED", "on_unknown": "ALLOW_UNKNOWN"}); rr.Code != http.StatusBadRequest {
		t.Fatalf("evidence_source 词表外应 400, got %d", rr.Code)
	}
	if rr := sign(map[string]any{"enforcement_owner": "a@b.c", "evidence_source": "MANUAL_CONFIRMED", "on_unknown": "DENY_UNKNOWN"}); rr.Code != http.StatusBadRequest {
		t.Fatalf("on_unknown 词表外应 400, got %d", rr.Code)
	}

	// 正常签署：signed_at+四要素+冻结文案落库（按 confirm_token 路径——§1.3 响应无行 id，
	// 向导只持有令牌；签署 URL 路径参数即 confirm_token 语义）
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/enforcement-confirmations/"+uuid.NewString()+"/sign",
		map[string]any{"enforcement_owner": "a@b.c", "evidence_source": "MANUAL_CONFIRMED", "on_unknown": "ALLOW_UNKNOWN"})
	if rr.Code != http.StatusNotFound {
		t.Fatalf("不存在的 confirm_token 签署应 404, got %d", rr.Code)
	}
	rr = sign(map[string]any{"enforcement_owner": "zhang.lei@example.com", "evidence_source": "manual_confirmed", "on_unknown": "allow_unknown"})
	if rr.Code != http.StatusOK {
		t.Fatalf("签署 status=%d body=%s", rr.Code, rr.Body.String())
	}
	var signedAt *time.Time
	var owner, text string
	if err := pool.QueryRow(ctx, `SELECT signed_at, enforcement_owner, confirm_text FROM api_authz_enforcement_confirmations WHERE id=$1`, id).
		Scan(&signedAt, &owner, &text); err != nil {
		t.Fatalf("read signed row: %v", err)
	}
	if signedAt == nil || owner != "zhang.lei@example.com" {
		t.Fatalf("签署落库不符: signed_at=%v owner=%q", signedAt, owner)
	}
	for _, want := range []string{"UNKNOWN 永不阻断", "近 7 天", "3 次", "2 个", "确认文案 v1"} {
		if !strings.Contains(text, want) {
			t.Fatalf("确认文案缺 %q: %s", want, text)
		}
	}

	// 重复签署 400（已签署）
	if rr := sign(map[string]any{"enforcement_owner": "x@y.z", "evidence_source": "MANUAL_CONFIRMED", "on_unknown": "ALLOW_UNKNOWN"}); rr.Code != http.StatusBadRequest {
		t.Fatalf("重复签署应 400, got %d", rr.Code)
	}

	// 过期：新签发后回拨 token_expires_at → 签署 400
	token2, _, err := store.IssueConfirmation(ctx, f.appID, f.endpointID, "path:3", 7, []byte(`{}`), now)
	if err != nil {
		t.Fatalf("issue#2: %v", err)
	}
	var id2 uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM api_authz_enforcement_confirmations WHERE confirm_token=$1`, token2).Scan(&id2); err != nil {
		t.Fatalf("read id2: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE api_authz_enforcement_confirmations SET token_expires_at=now()-interval '1 minute' WHERE id=$1`, id2); err != nil {
		t.Fatalf("backdate expires: %v", err)
	}
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/enforcement-confirmations/"+token2.String()+"/sign",
		map[string]any{"enforcement_owner": "a@b.c", "evidence_source": "MANUAL_CONFIRMED", "on_unknown": "ALLOW_UNKNOWN"})
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "过期") {
		t.Fatalf("过期签署应 400 含过期: %d %s", rr.Code, rr.Body.String())
	}

	// 查询端点（read）
	readMux := http.NewServeMux()
	RegisterRoutes(readMux, injectPerms(apiauthz.PermAuthzRead), NewHandler(store, nil, nil, okCapability))
	rr = doJSON(t, readMux, http.MethodGet, "/api/v1/api-security/authz/enforcement-confirmations?application_id="+f.appID.String(), nil)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"total":2`) {
		t.Fatalf("确认单查询: %d %s", rr.Code, rr.Body.String())
	}
}

// TestWizardConsumeConfirmTokenContract ConsumeConfirmToken 五类校验（供 PATCH 事务调用）：
// 不存在/未签署/绑定不符/已过期/已消费各拒；成功后置 consumed_at+consumed_audit_id。
func TestWizardConsumeConfirmTokenContract(t *testing.T) {
	pool, ctx := openWizardPG(t)
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	f := seedWizardFixture(t, pool, ctx)
	store := NewStore(pool)
	now := time.Now().UTC()

	consume := func(token, endpointID uuid.UUID, segment string) error {
		return ConsumeConfirmToken(ctx, pool, token, endpointID, segment, "req-consume-1", now)
	}

	// 不存在
	if err := consume(uuid.New(), f.endpointID, "path:3"); err != ErrInvalidTokenID {
		t.Fatalf("不存在应 ErrInvalidTokenID: %v", err)
	}
	// 未签署
	token, _, _ := store.IssueConfirmation(ctx, f.appID, f.endpointID, "path:3", 7, []byte(`{}`), now)
	if err := consume(token, f.endpointID, "path:3"); err != ErrNotSigned {
		t.Fatalf("未签署应 ErrNotSigned: %v", err)
	}
	// 签署后：绑定不符（端点）
	if _, err := store.SignConfirmation(ctx, token, "o@b.c", "MANUAL_CONFIRMED", "ALLOW_UNKNOWN", "text", uuid.New(), "tester", now); err != nil {
		t.Fatalf("sign（按 confirm_token）: %v", err)
	}
	if err := consume(token, uuid.New(), "path:3"); err != ErrTokenMismatch {
		t.Fatalf("端点绑定不符应 ErrTokenMismatch: %v", err)
	}
	if err := consume(token, f.endpointID, "path:9"); err != ErrTokenMismatch {
		t.Fatalf("对象段绑定不符应 ErrTokenMismatch: %v", err)
	}
	// 过期
	_, _ = pool.Exec(ctx, `UPDATE api_authz_enforcement_confirmations SET token_expires_at=$1 WHERE confirm_token=$2`, now.Add(-time.Minute), token)
	if err := consume(token, f.endpointID, "path:3"); err != ErrExpired {
		t.Fatalf("过期应 ErrExpired: %v", err)
	}
	_, _ = pool.Exec(ctx, `UPDATE api_authz_enforcement_confirmations SET token_expires_at=$1 WHERE confirm_token=$2`, now.Add(time.Hour), token)
	// 成功消费
	if err := consume(token, f.endpointID, "path:3"); err != nil {
		t.Fatalf("消费应成功: %v", err)
	}
	var auditID string
	if err := pool.QueryRow(ctx, `SELECT consumed_audit_id FROM api_authz_enforcement_confirmations WHERE confirm_token=$1`, token).Scan(&auditID); err != nil {
		t.Fatalf("read consumed: %v", err)
	}
	if auditID != "req-consume-1" {
		t.Fatalf("consumed_audit_id=%q want req-consume-1", auditID)
	}
	// 复用拒
	if err := consume(token, f.endpointID, "path:3"); err != ErrConsumed {
		t.Fatalf("复用应 ErrConsumed: %v", err)
	}
}

// TestWizardConflictsAndReadinessContract conflicts 独立查询与 readiness 装配
// （ACK 空表 NEVER_ACKED 保守路径 → BLOCKED_BY_NODE）。
func TestWizardConflictsAndReadinessContract(t *testing.T) {
	pool, ctx := openWizardPG(t)
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	f := seedWizardFixture(t, pool, ctx)
	store := NewStore(pool)

	// OPEN 冲突行（orders 对象类型——与夹具模型 object_type 一致）
	if _, err := pool.Exec(ctx, `INSERT INTO api_authority_conflicts(application_id,object_type,object_ref,principals,status)
		VALUES ($1,'orders','objref:cc','["a","b"]'::jsonb,'OPEN')`, f.appID); err != nil {
		t.Fatalf("insert conflict: %v", err)
	}
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPerms(apiauthz.PermAuthzRead), NewHandler(store, nil, nil, okCapability))

	// conflicts 查询（默认 OPEN）
	rr := doJSON(t, mux, http.MethodGet, "/api/v1/api-security/authz/conflicts?application_id="+f.appID.String(), nil)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"object_type":"orders"`) {
		t.Fatalf("conflicts 查询: %d %s", rr.Code, rr.Body.String())
	}
	// status 词表外 400
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/authz/conflicts?status=PENDING", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status 词表外应 400, got %d", rr.Code)
	}

	// readiness：ACK 空表（acks=nil）→ BLOCKED_BY_NODE；且 OPEN 冲突因子入 reasons
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/authz/enforcement-readiness?application_id="+f.appID.String(), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("readiness status=%d", rr.Code)
	}
	var env struct {
		Data struct {
			Items []ReadinessItem `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode readiness: %v body=%s", err, rr.Body.String())
	}
	if len(env.Data.Items) != 1 {
		t.Fatalf("readiness 行数=%d want 1", len(env.Data.Items))
	}
	item := env.Data.Items[0]
	if item.Readiness != ReadinessBlockedByConflict {
		t.Fatalf("冲突优先级高于节点应 BLOCKED_BY_CONFLICT: %+v", item)
	}
	joined := strings.Join(item.Reasons, " ")
	if !strings.Contains(joined, "OPEN 冲突") || !strings.Contains(joined, "ACK") {
		t.Fatalf("reasons 应含冲突与节点因子: %v", item.Reasons)
	}

	// readiness：application_id 缺省 400
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/authz/enforcement-readiness", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("缺 application_id 应 400, got %d", rr.Code)
	}
}
