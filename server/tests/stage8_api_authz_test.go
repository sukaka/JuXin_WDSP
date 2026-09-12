// stage8_api_authz_test.go API 授权实体层（WDSP P0-15/16/17 补全，W3-A 分片）集成测试。
// 覆盖：迁移 000043/000044 三张表与约束落位；SQL Store 角色基线/字段权限 CRUD 与冲突映射；
// SweepOnce 对真实 api_runtime_events 的权属提取与水位幂等；EvaluateBOLA 五档；
// HTTP 路由接线（权限点 api_authorization.*）。
package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/gateway/dynamic_security/events"
	"github.com/jiuzhang-waf/server/internal/apiauthz"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// apiauthzInjectPrincipal 模拟认证链：注入持有 api_authorization 权限点的主体
// （权限种子由集成方登记，测试环境直接注入，绕开登录链路）。
func apiauthzInjectPrincipal(next http.Handler) http.Handler {
	perms := map[string]bool{apiauthz.PermAuthzRead: true, apiauthz.PermAuthzManage: true}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &authz.Principal{UserID: uuid.New(), Username: "w3a-tester", PermsSet: perms}
		ctx := authz.WithPrincipal(r.Context(), p)
		ctx = context.WithValue(ctx, response.RequestIDKey, "w3a-rid")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// apiauthzMux 装配授权实体层路由（真实 SQL Store；审计服务由集成方装配，此处 nil 跳过）。
func apiauthzMux(env *testEnv) *http.ServeMux {
	mux := http.NewServeMux()
	apiauthz.RegisterRoutes(mux, apiauthzInjectPrincipal, apiauthz.NewHandler(apiauthz.NewStore(env.db), nil))
	return mux
}

func apiauthzDo(t *testing.T, mux http.Handler, method, url string, body any) *httptest.ResponseRecorder {
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

// apiauthzSaveEvent 落一条带身份与原始路径的运行时事件（经真实 SavePrimary 序列化）。
func apiauthzSaveEvent(t *testing.T, env *testEnv, endpointKey, requestID, identity, rawPath string, at time.Time) {
	t.Helper()
	rt := apiruntime.NewStore(env.db)
	err := rt.SavePrimary(context.Background(), &apiruntime.PrimaryEvent{
		PrimaryEvent: events.PrimaryEvent{
			RequestID: requestID, EndpointKey: endpointKey, OccurredAt: at,
			RiskScore: 10, RiskLevel: "LOW", FinalAction: "ALLOW",
		},
		IdentityFingerprint: identity,
		Method:              "GET",
		RawPath:             rawPath,
	})
	if err != nil {
		t.Fatalf("SavePrimary: %v", err)
	}
}

// TestStage8AuthzMigration 迁移 000043/000044 落位：表结构 / CHECK 约束 / 唯一约束。
func TestStage8AuthzMigration(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()

	for _, table := range []string{"api_role_baselines", "api_object_ownership", "api_field_permissions"} {
		if n := s8Count(t, env, `SELECT count(*) FROM information_schema.tables WHERE table_name=$1`, table); n != 1 {
			t.Fatalf("table %s missing", table)
		}
	}
	// 契约列
	for _, col := range []string{"id", "endpoint_id", "role", "method", "action", "allowed",
		"source", "confidence", "confirmed", "created_by", "created_at", "updated_at"} {
		if n := s8Count(t, env, `SELECT count(*) FROM information_schema.columns
			WHERE table_name='api_role_baselines' AND column_name=$1`, col); n != 1 {
			t.Fatalf("api_role_baselines column %s missing", col)
		}
	}
	for _, col := range []string{"id", "endpoint_id", "identity_fingerprint", "object_type",
		"object_id", "first_seen", "last_seen", "access_count"} {
		if n := s8Count(t, env, `SELECT count(*) FROM information_schema.columns
			WHERE table_name='api_object_ownership' AND column_name=$1`, col); n != 1 {
			t.Fatalf("api_object_ownership column %s missing", col)
		}
	}
	for _, col := range []string{"id", "endpoint_id", "field_path", "direction", "attribute",
		"role", "tenant", "created_by", "created_at", "updated_at"} {
		if n := s8Count(t, env, `SELECT count(*) FROM information_schema.columns
			WHERE table_name='api_field_permissions' AND column_name=$1`, col); n != 1 {
			t.Fatalf("api_field_permissions column %s missing", col)
		}
	}

	// CHECK 约束：非法 source / direction / attribute / confidence 越界均拒绝
	epID := uuid.New()
	badInserts := []string{
		`INSERT INTO api_role_baselines (endpoint_id, role, method, action, source)
		 VALUES ('` + epID.String() + `', 'R', 'GET', 'READ', 'GUESSED')`,
		`INSERT INTO api_role_baselines (endpoint_id, role, method, action, confidence)
		 VALUES ('` + epID.String() + `', 'R', 'GET', 'READ', 1.5)`,
		`INSERT INTO api_field_permissions (endpoint_id, field_path, direction, attribute)
		 VALUES ('` + epID.String() + `', 'json.a', 'UPLOAD', 'READABLE')`,
		`INSERT INTO api_field_permissions (endpoint_id, field_path, direction, attribute)
		 VALUES ('` + epID.String() + `', 'json.a', 'REQUEST', 'HIDDEN')`,
	}
	for i, sql := range badInserts {
		if _, err := env.db.Exec(ctx, sql); err == nil {
			t.Fatalf("bad insert %d unexpectedly succeeded", i)
		}
	}
}

// apiauthzSeedEndpoint 登记端点资产（直接 SQL 插入最小行）。
// 说明：既有用例惯用的 apiassets.UpsertDiscovery 在本工作树被其他分片的在途改动
// 暂时破坏（endpointColumns 扫描 NULL 报错，既有 TestStage8SensitiveSweep 同样失败），
// 故本分片测试绕开该路径，只依赖稳定的表结构（http_method/normalized_path/endpoint_key
// 为仅有的无默认值非空列，已用真实 PG 验证）。
func apiauthzSeedEndpoint(t *testing.T, env *testEnv, method, template string) (uuid.UUID, string) {
	t.Helper()
	endpointKey := method + " " + template
	var endpointID uuid.UUID
	if err := env.db.QueryRow(context.Background(), `
INSERT INTO api_endpoints (http_method, normalized_path, endpoint_key)
VALUES ($1, $2, $3)
RETURNING id`, method, template, endpointKey).Scan(&endpointID); err != nil {
		t.Fatalf("insert endpoint: %v", err)
	}
	return endpointID, endpointKey
}

// TestStage8AuthzStoreCRUD SQL Store：角色基线 CRUD/冲突/确认；字段权限默认行/覆盖行/冲突。
func TestStage8AuthzStoreCRUD(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	store := apiauthz.NewStore(env.db)
	rid := s5Rand()
	epID, _ := apiauthzSeedEndpoint(t, env, "GET", "/w3a-"+rid+"/users/{id}")

	// 角色基线：创建（候选）→ 重键冲突 → 确认 → 编辑 → 删除
	b := &apiauthz.RoleBaseline{
		EndpointID: epID, Role: "OPS_ADMIN", Method: "GET", Action: "READ",
		Allowed: true, Source: "MANUAL", Confidence: 0.9,
	}
	if err := store.CreateRoleBaseline(ctx, b); err != nil {
		t.Fatalf("CreateRoleBaseline: %v", err)
	}
	if b.ID == uuid.Nil || b.Confirmed {
		t.Fatalf("created=%+v", b)
	}
	dup := &apiauthz.RoleBaseline{EndpointID: epID, Role: "OPS_ADMIN", Method: "GET", Action: "READ", Source: "SPEC"}
	if err := store.CreateRoleBaseline(ctx, dup); err == nil {
		t.Fatalf("duplicate baseline should fail")
	}
	badEP := &apiauthz.RoleBaseline{EndpointID: uuid.New(), Role: "R", Method: "GET", Action: "READ", Source: "MANUAL"}
	if err := store.CreateRoleBaseline(ctx, badEP); err == nil {
		t.Fatalf("unknown endpoint should fail (FK)")
	}
	confirmed, err := store.ConfirmRoleBaseline(ctx, b.ID, true)
	if err != nil || !confirmed.Confirmed {
		t.Fatalf("Confirm=%+v err=%v", confirmed, err)
	}
	b.Action = "EXPORT"
	if err := store.UpdateRoleBaseline(ctx, b); err != nil {
		t.Fatalf("UpdateRoleBaseline: %v", err)
	}
	got, err := store.GetRoleBaseline(ctx, b.ID)
	if err != nil || got.Action != "EXPORT" || !got.Confirmed {
		t.Fatalf("Get=%+v err=%v", got, err)
	}
	list, total, err := store.ListRoleBaselines(ctx, apiauthz.RoleBaselineFilter{EndpointID: &epID})
	if err != nil || total != 1 || len(list) != 1 {
		t.Fatalf("List total=%d err=%v", total, err)
	}
	if err := store.DeleteRoleBaseline(ctx, b.ID); err != nil {
		t.Fatalf("DeleteRoleBaseline: %v", err)
	}

	// 字段权限：默认行 + 角色覆盖行共存；同键（含 NULL 归一）冲突
	fp := &apiauthz.FieldPermission{
		EndpointID: epID, FieldPath: "json.role", Direction: "REQUEST", Attribute: "ADMIN_WRITABLE",
	}
	if err := store.CreateFieldPermission(ctx, fp); err != nil {
		t.Fatalf("CreateFieldPermission: %v", err)
	}
	role := "SUPER_ADMIN"
	ov := &apiauthz.FieldPermission{
		EndpointID: epID, FieldPath: "json.role", Direction: "REQUEST", Attribute: "WRITABLE", Role: &role,
	}
	if err := store.CreateFieldPermission(ctx, ov); err != nil {
		t.Fatalf("CreateFieldPermission override: %v", err)
	}
	dupFP := &apiauthz.FieldPermission{EndpointID: epID, FieldPath: "json.role", Direction: "REQUEST", Attribute: "READABLE"}
	if err := store.CreateFieldPermission(ctx, dupFP); err == nil {
		t.Fatalf("duplicate default row should fail (NULL 归一唯一)")
	}
	_, total, err = store.ListFieldPermissions(ctx, apiauthz.FieldPermFilter{EndpointID: &epID})
	if err != nil || total != 2 {
		t.Fatalf("field perms total=%d err=%v", total, err)
	}
	_, total, err = store.ListFieldPermissions(ctx, apiauthz.FieldPermFilter{EndpointID: &epID, DefaultsOnly: true})
	if err != nil || total != 1 {
		t.Fatalf("defaults only total=%d err=%v", total, err)
	}
	if err := store.DeleteFieldPermission(ctx, fp.ID); err != nil {
		t.Fatalf("DeleteFieldPermission: %v", err)
	}
}

// TestStage8AuthzSweep SweepOnce：真实事件权属提取、水位幂等、新事件累加。
func TestStage8AuthzSweep(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	rid := s5Rand()
	epID, epKey := apiauthzSeedEndpoint(t, env, "GET", "/w3a-"+rid+"/orders/{id}")

	base := time.Now().UTC().Add(-time.Hour)
	// fp-a 两次访问对象 1001；fp-b 一次访问同对象；匿名事件不产权属
	apiauthzSaveEvent(t, env, epKey, "w3a-req-"+rid+"-1", "fp-a-"+rid, "/w3a-"+rid+"/orders/1001", base)
	apiauthzSaveEvent(t, env, epKey, "w3a-req-"+rid+"-2", "fp-a-"+rid, "/w3a-"+rid+"/orders/1001", base.Add(time.Minute))
	apiauthzSaveEvent(t, env, epKey, "w3a-req-"+rid+"-3", "fp-b-"+rid, "/w3a-"+rid+"/orders/1001", base.Add(2*time.Minute))
	apiauthzSaveEvent(t, env, epKey, "w3a-req-"+rid+"-4", "", "/w3a-"+rid+"/orders/1002", base.Add(3*time.Minute))

	store := apiauthz.NewStore(env.db)
	res, err := store.SweepOnce(ctx)
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if res.EventsScanned != 3 || res.ObjectsExtracted != 3 || res.OwnershipUpserted != 3 || res.SkippedNoEndpoint != 0 {
		t.Fatalf("sweep result=%+v", res)
	}
	var cnt int
	if err := env.db.QueryRow(ctx, `SELECT count(*) FROM api_object_ownership WHERE endpoint_id=$1`, epID).Scan(&cnt); err != nil {
		t.Fatalf("count ownership: %v", err)
	}
	if cnt != 2 {
		t.Fatalf("ownership rows=%d want 2", cnt)
	}
	var accessCount int
	var objectType string
	if err := env.db.QueryRow(ctx, `SELECT object_type, access_count FROM api_object_ownership
		WHERE endpoint_id=$1 AND identity_fingerprint=$2`, epID, "fp-a-"+rid).Scan(&objectType, &accessCount); err != nil {
		t.Fatalf("query ownership: %v", err)
	}
	if objectType != "orders" || accessCount != 2 {
		t.Fatalf("fp-a ownership type=%s count=%d", objectType, accessCount)
	}

	// 水位幂等：立即重扫零命中、计数不变
	res2, err := store.SweepOnce(ctx)
	if err != nil || res2.EventsScanned != 0 || res2.OwnershipUpserted != 0 {
		t.Fatalf("second sweep=%+v err=%v", res2, err)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_object_ownership
		WHERE endpoint_id=$1 AND identity_fingerprint=$2 AND access_count=2`, epID, "fp-a-"+rid); n != 1 {
		t.Fatalf("access_count changed after idle sweep")
	}

	// 新事件累加
	apiauthzSaveEvent(t, env, epKey, "w3a-req-"+rid+"-5", "fp-a-"+rid, "/w3a-"+rid+"/orders/1001", base.Add(4*time.Minute))
	res3, err := store.SweepOnce(ctx)
	if err != nil || res3.OwnershipUpserted != 1 {
		t.Fatalf("third sweep=%+v err=%v", res3, err)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_object_ownership
		WHERE endpoint_id=$1 AND identity_fingerprint=$2 AND access_count=3`, epID, "fp-a-"+rid); n != 1 {
		t.Fatalf("access_count not incremented")
	}
}

// TestStage8AuthzEvaluate EvaluateBOLA 五档（真实库；权属由 SweepOnce 生产）。
func TestStage8AuthzEvaluate(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	rid := s5Rand()
	epID, epKey := apiauthzSeedEndpoint(t, env, "GET", "/w3aev-"+rid+"/users/{id}")
	store := apiauthz.NewStore(env.db)

	base := time.Now().UTC().Add(-time.Hour)
	apiauthzSaveEvent(t, env, epKey, "w3aev-req-"+rid+"-1", "fp-a-"+rid, "/w3aev-"+rid+"/users/1001", base)
	apiauthzSaveEvent(t, env, epKey, "w3aev-req-"+rid+"-2", "fp-b-"+rid, "/w3aev-"+rid+"/users/2002", base.Add(time.Minute))
	if _, err := store.SweepOnce(ctx); err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}

	evaluate := func(identity, objectID string) *apiauthz.EvaluateResult {
		t.Helper()
		res, err := store.EvaluateBOLA(ctx, apiauthz.EvaluateInput{
			EndpointID: epID, Identity: identity, ObjectID: objectID,
		})
		if err != nil {
			t.Fatalf("EvaluateBOLA(%s,%s): %v", identity, objectID, err)
		}
		return res
	}

	// 1. 权属匹配 → POLICY_CONFIRMED（允许）
	if r := evaluate("fp-a-"+rid, "1001"); r.Verdict != apiauthz.VerdictPolicyConfirmed || r.Allowed == nil || !*r.Allowed {
		t.Fatalf("POLICY_CONFIRMED res=%+v", r)
	}
	// 2. 对象有属主、访问者不是属主 → HIGH_CONFIDENCE（越权）
	if r := evaluate("fp-b-"+rid, "1001"); r.Verdict != apiauthz.VerdictHighConfidence || r.Allowed == nil || *r.Allowed {
		t.Fatalf("HIGH_CONFIDENCE res=%+v", r)
	}
	// 3. 对象无记录、身份有权属基线 → LIKELY（倾向允许）
	if r := evaluate("fp-a-"+rid, "9999"); r.Verdict != apiauthz.VerdictLikely || r.Allowed == nil || !*r.Allowed {
		t.Fatalf("LIKELY res=%+v", r)
	}
	// 4. 端点有权属画像但双方均无记录 → POSSIBLE（倾向可疑）
	if r := evaluate("fp-new-"+rid, "8888"); r.Verdict != apiauthz.VerdictPossible || r.Allowed == nil || *r.Allowed {
		t.Fatalf("POSSIBLE res=%+v", r)
	}
	// 5. 无权属的干净端点 → INSUFFICIENT_EVIDENCE（无法判定）
	ep2ID, _ := apiauthzSeedEndpoint(t, env, "GET", "/w3aev-"+rid+"/fresh/{id}")
	res, err := store.EvaluateBOLA(ctx, apiauthz.EvaluateInput{EndpointID: ep2ID, Identity: "fp-a-" + rid, ObjectID: "1"})
	if err != nil || res.Verdict != apiauthz.VerdictInsufficientEvidence || res.Allowed != nil {
		t.Fatalf("INSUFFICIENT res=%+v err=%v", res, err)
	}
	// 端点不存在 → ErrNotFound
	if _, err := store.EvaluateBOLA(ctx, apiauthz.EvaluateInput{EndpointID: uuid.New(), ObjectID: "1"}); err == nil {
		t.Fatalf("unknown endpoint should fail")
	}
}

// TestStage8AuthzHTTP HTTP 接线：基线创建/冲突 409/确认；字段权限校验 400；评估接口。
func TestStage8AuthzHTTP(t *testing.T) {
	env := setupStage8Env(t)
	mux := apiauthzMux(env)
	rid := s5Rand()
	epID, _ := apiauthzSeedEndpoint(t, env, "GET", "/w3ahttp-"+rid+"/items/{id}")

	// 基线创建 + 重键 409 + 确认
	req := map[string]any{
		"endpoint_id": epID.String(), "role": "OPS_ADMIN", "method": "GET",
		"action": "READ", "allowed": true, "confidence": 0.8,
	}
	rr := apiauthzDo(t, mux, http.MethodPost, "/api/v1/api-security/authz/role-baselines", req)
	if rr.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", rr.Code, rr.Body.String())
	}
	var created apiauthz.RoleBaseline
	authzDecodeData(t, rr, &created)
	rr = apiauthzDo(t, mux, http.MethodPost, "/api/v1/api-security/authz/role-baselines", req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("conflict status=%d", rr.Code)
	}
	rr = apiauthzDo(t, mux, http.MethodPost,
		"/api/v1/api-security/authz/role-baselines/"+created.ID.String()+"/confirm", map[string]any{"confirmed": true})
	if rr.Code != http.StatusOK {
		t.Fatalf("confirm status=%d body=%s", rr.Code, rr.Body.String())
	}

	// 字段权限校验：非法 attribute → 400
	rr = apiauthzDo(t, mux, http.MethodPost, "/api/v1/api-security/authz/field-permissions",
		map[string]any{"endpoint_id": epID.String(), "field_path": "json.a", "direction": "REQUEST", "attribute": "HIDDEN"})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad attribute status=%d", rr.Code)
	}

	// 评估接口：无数据 → INSUFFICIENT_EVIDENCE；参数缺失 → 400
	rr = apiauthzDo(t, mux, http.MethodGet,
		"/api/v1/api-security/authz/evaluate?endpoint_id="+epID.String()+"&identity=fp-x&object_id=1", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("evaluate status=%d body=%s", rr.Code, rr.Body.String())
	}
	var result apiauthz.EvaluateResult
	authzDecodeData(t, rr, &result)
	if result.Verdict != apiauthz.VerdictInsufficientEvidence {
		t.Fatalf("verdict=%s", result.Verdict)
	}
	rr = apiauthzDo(t, mux, http.MethodGet, "/api/v1/api-security/authz/evaluate?endpoint_id="+epID.String(), nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("missing object_id status=%d", rr.Code)
	}
	// 权属只读接口接线
	rr = apiauthzDo(t, mux, http.MethodGet, "/api/v1/api-security/authz/ownership?endpoint_id="+epID.String(), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("ownership status=%d", rr.Code)
	}
}

// authzDecodeData 解码统一响应的 data 字段（本分片测试本地辅助）。
func authzDecodeData(t *testing.T, rr *httptest.ResponseRecorder, dst any) {
	t.Helper()
	var env struct {
		Code string          `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v body=%s", err, rr.Body.String())
	}
	if env.Code != "SUCCESS" {
		t.Fatalf("code=%s body=%s", env.Code, rr.Body.String())
	}
	if err := json.Unmarshal(env.Data, dst); err != nil {
		t.Fatalf("decode data: %v body=%s", err, rr.Body.String())
	}
}
