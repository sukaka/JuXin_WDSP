// handler_test.go 授权实体层接口测试：权限、角色基线 CRUD/确认、对象权属只读查询、
// 字段权限 CRUD（默认行/覆盖行语义）、BOLA 评估接口。
package apiauthz

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// testPerms 本端点组全部权限点。
var testPerms = []string{PermAuthzRead, PermAuthzManage}

// injectPrincipal 模拟认证链：注入持有全部权限点的主体与 Request ID。
func injectPrincipal(next http.Handler) http.Handler {
	perms := map[string]bool{}
	for _, p := range testPerms {
		perms[p] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &authz.Principal{UserID: uuid.New(), Username: "tester", PermsSet: perms}
		ctx := authz.WithPrincipal(r.Context(), p)
		ctx = context.WithValue(ctx, response.RequestIDKey, "test-rid")
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// noPerms 模拟无权限主体（权限点检查 403）。
func noPerms(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := &authz.Principal{UserID: uuid.New(), Username: "outsider", PermsSet: map[string]bool{}}
		next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
	})
}

func newTestMux(h *Handler) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPrincipal, h)
	return mux
}

func doJSON(t *testing.T, mux http.Handler, method, url string, body any) *httptest.ResponseRecorder {
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

// decodeData 解码统一响应的 data 字段。
func decodeData(t *testing.T, rr *httptest.ResponseRecorder, dst any) {
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

// seedEndpoint 登记端点并返回 ID（角色基线/字段权限引用必须有端点资产）。
func seedEndpoint(t *testing.T, store *MemStore, key, template string) uuid.UUID {
	t.Helper()
	return store.addEndpoint(key, template)
}

// TestPermissionGuard 无权限点主体一律 403。
func TestPermissionGuard(t *testing.T) {
	store := NewMemStore()
	mux := http.NewServeMux()
	RegisterRoutes(mux, noPerms, NewHandler(store, nil))
	for _, tc := range []struct{ method, url string }{
		{http.MethodGet, "/api/v1/api-security/authz/role-baselines"},
		{http.MethodPost, "/api/v1/api-security/authz/role-baselines"},
		{http.MethodGet, "/api/v1/api-security/authz/ownership"},
		{http.MethodGet, "/api/v1/api-security/authz/field-permissions"},
		{http.MethodPost, "/api/v1/api-security/authz/field-permissions"},
		{http.MethodGet, "/api/v1/api-security/authz/evaluate?endpoint_id=" + uuid.NewString() + "&object_id=1"},
	} {
		rr := doJSON(t, mux, tc.method, tc.url, map[string]any{})
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s %s status=%d want 403", tc.method, tc.url, rr.Code)
		}
	}
}

// TestBaselineCRUD 创建（候选）→ 读取 → 列表过滤 → 编辑 → 确认 → 删除；冲突与校验。
func TestBaselineCRUD(t *testing.T) {
	store := NewMemStore()
	endpointID := seedEndpoint(t, store, "GET /v1/users/{id}", "/v1/users/{id}")
	mux := newTestMux(NewHandler(store, nil))

	create := map[string]any{
		"endpoint_id": endpointID.String(),
		"role":        "OPS_ADMIN", "method": "get", "action": "read",
		"allowed": true, "confidence": 0.9,
	}
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/role-baselines", create)
	if rr.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", rr.Code, rr.Body.String())
	}
	var created RoleBaseline
	decodeData(t, rr, &created)
	if created.ID == uuid.Nil || created.Method != "GET" || created.Action != "READ" ||
		created.Source != SourceManual || created.Confirmed || created.Confidence != 0.9 {
		t.Fatalf("created=%+v", created)
	}
	if created.CreatedBy == nil || *created.CreatedBy != "tester" {
		t.Fatalf("created_by=%v", created.CreatedBy)
	}

	// 重复创建 → 409
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/role-baselines", create)
	if rr.Code != http.StatusConflict {
		t.Fatalf("duplicate status=%d want 409", rr.Code)
	}

	// 校验失败矩阵 → 400
	for name, bad := range map[string]map[string]any{
		"缺 endpoint_id": {"role": "R", "method": "GET", "action": "READ"},
		"非法 method":     {"endpoint_id": endpointID.String(), "role": "R", "method": "FETCH", "action": "READ"},
		"非法 source":     {"endpoint_id": endpointID.String(), "role": "R", "method": "GET", "action": "READ", "source": "GUESSED"},
		"confidence 越界": {"endpoint_id": endpointID.String(), "role": "R", "method": "GET", "action": "READ", "confidence": 1.5},
		"role 非法字符":     {"endpoint_id": endpointID.String(), "role": "a b", "method": "GET", "action": "READ"},
		"不存在端点":         {"endpoint_id": uuid.NewString(), "role": "R", "method": "GET", "action": "READ"},
	} {
		rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/role-baselines", bad)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d want 400 body=%s", name, rr.Code, rr.Body.String())
		}
	}

	// 读取
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/authz/role-baselines/"+created.ID.String(), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("get status=%d", rr.Code)
	}

	// 列表过滤：confirmed=false 命中、source=OBSERVED 不命中
	var page struct {
		Items []RoleBaseline `json:"items"`
		Total int64          `json:"total"`
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/authz/role-baselines?confirmed=false&method=GET", nil)
	decodeData(t, rr, &page)
	if page.Total != 1 {
		t.Fatalf("list total=%d want 1", page.Total)
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/authz/role-baselines?source=OBSERVED", nil)
	decodeData(t, rr, &page)
	if page.Total != 0 {
		t.Fatalf("source filter total=%d want 0", page.Total)
	}

	// 编辑（改 allowed + action；confirmed 不随编辑变更）
	rr = doJSON(t, mux, http.MethodPatch, "/api/v1/api-security/authz/role-baselines/"+created.ID.String(),
		map[string]any{"allowed": false, "action": "export"})
	if rr.Code != http.StatusOK {
		t.Fatalf("patch status=%d body=%s", rr.Code, rr.Body.String())
	}
	var updated RoleBaseline
	decodeData(t, rr, &updated)
	if updated.Allowed || updated.Action != "EXPORT" || updated.Confirmed {
		t.Fatalf("updated=%+v", updated)
	}

	// 确认（候选 → 正式基线），再撤回
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/role-baselines/"+created.ID.String()+"/confirm",
		map[string]any{"confirmed": true})
	if rr.Code != http.StatusOK {
		t.Fatalf("confirm status=%d body=%s", rr.Code, rr.Body.String())
	}
	var confirmed RoleBaseline
	decodeData(t, rr, &confirmed)
	if !confirmed.Confirmed {
		t.Fatalf("confirmed=%+v", confirmed)
	}
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/role-baselines/"+created.ID.String()+"/confirm",
		map[string]any{"confirmed": false})
	decodeData(t, rr, &confirmed)
	if confirmed.Confirmed {
		t.Fatalf("unconfirm=%+v", confirmed)
	}
	// confirm 缺 confirmed 字段 → 400
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/role-baselines/"+created.ID.String()+"/confirm",
		map[string]any{})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("confirm empty status=%d want 400", rr.Code)
	}

	// 删除 → 再读 404
	rr = doJSON(t, mux, http.MethodDelete, "/api/v1/api-security/authz/role-baselines/"+created.ID.String(), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("delete status=%d", rr.Code)
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/authz/role-baselines/"+created.ID.String(), nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("get after delete status=%d want 404", rr.Code)
	}
}

// TestOwnershipQuery 权属只读查询（数据由 SweepOnce 生产；无写接口）。
func TestOwnershipQuery(t *testing.T) {
	store := NewMemStore()
	epKey := "GET /v1/users/{id}"
	endpointID := store.addEndpoint(epKey, "/v1/users/{id}")
	base := time.Now().UTC().Add(-time.Hour)
	store.addRuntimeEvent(epKey, "fp-a", "/v1/users/1001", base)
	store.addRuntimeEvent(epKey, "fp-a", "/v1/users/1002", base.Add(time.Minute))
	store.addRuntimeEvent(epKey, "fp-b", "/v1/users/1001", base.Add(2*time.Minute))
	if _, err := store.SweepOnce(context.Background()); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	mux := newTestMux(NewHandler(store, nil))

	var page struct {
		Items []ObjectOwnership `json:"items"`
		Total int64             `json:"total"`
	}
	// 全量（按端点）
	rr := doJSON(t, mux, http.MethodGet, "/api/v1/api-security/authz/ownership?endpoint_id="+endpointID.String(), nil)
	decodeData(t, rr, &page)
	if page.Total != 3 {
		t.Fatalf("total=%d want 3 body", page.Total)
	}
	// 按身份过滤
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/authz/ownership?identity=fp-a", nil)
	decodeData(t, rr, &page)
	if page.Total != 2 {
		t.Fatalf("identity filter total=%d want 2", page.Total)
	}
	// 按对象过滤（查属主）
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/authz/ownership?object_id=1001", nil)
	decodeData(t, rr, &page)
	if page.Total != 2 {
		t.Fatalf("object filter total=%d want 2", page.Total)
	}
	owners := map[string]bool{}
	for _, o := range page.Items {
		owners[o.IdentityFingerprint] = true
		if o.ObjectType != "users" || o.ObjectID != "1001" || o.AccessCount != 1 {
			t.Fatalf("row=%+v", o)
		}
	}
	if !owners["fp-a"] || !owners["fp-b"] {
		t.Fatalf("owners=%v", owners)
	}
	// 非法 endpoint_id → 400
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/authz/ownership?endpoint_id=bad", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad endpoint_id status=%d want 400", rr.Code)
	}
}

// TestFieldPermissionCRUD 创建（默认行/覆盖行）→ 列表过滤 → 编辑（清除覆盖回默认行）→
// 冲突 → 删除；校验矩阵。
func TestFieldPermissionCRUD(t *testing.T) {
	store := NewMemStore()
	endpointID := seedEndpoint(t, store, "POST /v1/users", "/v1/users")
	mux := newTestMux(NewHandler(store, nil))

	// 默认行（role/tenant 缺省 = NULL）
	create := map[string]any{
		"endpoint_id": endpointID.String(), "field_path": "json.role",
		"direction": "request", "attribute": "admin_writable",
	}
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/field-permissions", create)
	if rr.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", rr.Code, rr.Body.String())
	}
	var created FieldPermission
	decodeData(t, rr, &created)
	if created.ID == uuid.Nil || created.Direction != DirectionRequest || created.Attribute != AttrAdminWritable ||
		created.Role != nil || created.Tenant != nil {
		t.Fatalf("created=%+v", created)
	}

	// 角色覆盖行（同字段同方向，role 非空 → 不冲突）
	override := map[string]any{
		"endpoint_id": endpointID.String(), "field_path": "json.role",
		"direction": "REQUEST", "attribute": "WRITABLE", "role": "SUPER_ADMIN",
	}
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/field-permissions", override)
	if rr.Code != http.StatusOK {
		t.Fatalf("override status=%d body=%s", rr.Code, rr.Body.String())
	}
	// 重复默认行 → 409（NULL 归一口径）
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/field-permissions", create)
	if rr.Code != http.StatusConflict {
		t.Fatalf("duplicate default status=%d want 409", rr.Code)
	}
	// 重复覆盖行 → 409
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/field-permissions", override)
	if rr.Code != http.StatusConflict {
		t.Fatalf("duplicate override status=%d want 409", rr.Code)
	}

	// 列表：defaults_only=true 只出默认行；role 过滤只出覆盖行
	var page struct {
		Items []FieldPermission `json:"items"`
		Total int64             `json:"total"`
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/authz/field-permissions?defaults_only=true", nil)
	decodeData(t, rr, &page)
	if page.Total != 1 || page.Items[0].Role != nil {
		t.Fatalf("defaults_only=%+v", page)
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/authz/field-permissions?role=SUPER_ADMIN", nil)
	decodeData(t, rr, &page)
	if page.Total != 1 || page.Items[0].Role == nil || *page.Items[0].Role != "SUPER_ADMIN" {
		t.Fatalf("role filter=%+v", page)
	}

	// 校验失败矩阵 → 400
	for name, bad := range map[string]map[string]any{
		"非法 direction": {"endpoint_id": endpointID.String(), "field_path": "json.a", "direction": "UPLOAD", "attribute": "READABLE"},
		"非法 attribute": {"endpoint_id": endpointID.String(), "field_path": "json.a", "direction": "REQUEST", "attribute": "HIDDEN"},
		"缺 field_path": {"endpoint_id": endpointID.String(), "direction": "REQUEST", "attribute": "READABLE"},
		"不存在端点":        {"endpoint_id": uuid.NewString(), "field_path": "json.a", "direction": "REQUEST", "attribute": "READABLE"},
	} {
		rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/authz/field-permissions", bad)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d want 400 body=%s", name, rr.Code, rr.Body.String())
		}
	}

	// 编辑覆盖行：role 显式空串清除 → 与既有默认行撞键 → 409
	var overrideRow FieldPermission
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/authz/field-permissions?role=SUPER_ADMIN", nil)
	decodeData(t, rr, &page)
	overrideRow = page.Items[0]
	rr = doJSON(t, mux, http.MethodPatch, "/api/v1/api-security/authz/field-permissions/"+overrideRow.ID.String(),
		map[string]any{"role": "", "attribute": "ADMIN_WRITABLE"})
	if rr.Code != http.StatusConflict {
		t.Fatalf("clear role status=%d want 409 body=%s", rr.Code, rr.Body.String())
	}
	// 正常编辑（改 attribute，role 保持）
	rr = doJSON(t, mux, http.MethodPatch, "/api/v1/api-security/authz/field-permissions/"+overrideRow.ID.String(),
		map[string]any{"attribute": "READABLE"})
	if rr.Code != http.StatusOK {
		t.Fatalf("patch status=%d body=%s", rr.Code, rr.Body.String())
	}
	var updated FieldPermission
	decodeData(t, rr, &updated)
	if updated.Attribute != AttrReadable || updated.Role == nil || *updated.Role != "SUPER_ADMIN" {
		t.Fatalf("updated=%+v", updated)
	}

	// 删除
	rr = doJSON(t, mux, http.MethodDelete, "/api/v1/api-security/authz/field-permissions/"+created.ID.String(), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("delete status=%d", rr.Code)
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/authz/field-permissions/"+created.ID.String(), nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("get after delete status=%d want 404", rr.Code)
	}
}

// TestEvaluateEndpoint 评估接口：参数校验 + 五档结论经 HTTP 输出。
func TestEvaluateEndpoint(t *testing.T) {
	store := NewMemStore()
	epKey := "GET /v1/users/{id}"
	endpointID := store.addEndpoint(epKey, "/v1/users/{id}")
	store.addRuntimeEvent(epKey, "fp-a", "/v1/users/1001", time.Now().UTC())
	if _, err := store.SweepOnce(context.Background()); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	mux := newTestMux(NewHandler(store, nil))

	// 参数校验
	for name, url := range map[string]string{
		"缺 endpoint_id": "/api/v1/api-security/authz/evaluate?object_id=1",
		"缺 object_id":   "/api/v1/api-security/authz/evaluate?endpoint_id=" + endpointID.String(),
		"非法 endpoint":   "/api/v1/api-security/authz/evaluate?endpoint_id=bad&object_id=1",
	} {
		rr := doJSON(t, mux, http.MethodGet, url, nil)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d want 400", name, rr.Code)
		}
	}
	// 端点不存在 → 404
	rr := doJSON(t, mux, http.MethodGet,
		"/api/v1/api-security/authz/evaluate?endpoint_id="+uuid.NewString()+"&object_id=1", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown endpoint status=%d want 404", rr.Code)
	}
	// 权属匹配 → POLICY_CONFIRMED
	rr = doJSON(t, mux, http.MethodGet,
		"/api/v1/api-security/authz/evaluate?endpoint_id="+endpointID.String()+"&identity=fp-a&object_id=1001", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("evaluate status=%d body=%s", rr.Code, rr.Body.String())
	}
	var result EvaluateResult
	decodeData(t, rr, &result)
	if result.Verdict != VerdictPolicyConfirmed || result.Allowed == nil || !*result.Allowed ||
		result.Evidence == nil || !result.Evidence.OwnMatch {
		t.Fatalf("result=%+v", result)
	}
	// 他人对象 → HIGH_CONFIDENCE
	rr = doJSON(t, mux, http.MethodGet,
		"/api/v1/api-security/authz/evaluate?endpoint_id="+endpointID.String()+"&identity=fp-x&object_id=1001", nil)
	decodeData(t, rr, &result)
	if result.Verdict != VerdictHighConfidence || result.Allowed == nil || *result.Allowed {
		t.Fatalf("high confidence result=%+v", result)
	}
}
