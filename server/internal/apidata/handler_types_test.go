// handler_types_test.go 敏感数据类型接口测试：权限、CRUD、内置保护、导入导出、校验。
package apidata

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// testPerms 本端点组全部权限点。
var testPerms = []string{PermDataRead, PermDataManage}

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

// validTypeReq 合法创建请求（测试按需改字段）。
func validTypeReq() map[string]any {
	return map[string]any{
		"name":      "测试类型-" + uuid.NewString()[:8],
		"data_type": "test_dt",
		"category":  "测试",
		"level":     "SENSITIVE",
		"keywords":  []string{"foo", "bar"},
		"locations": []string{"json", "query"},
		"regex":     "^\\d+$",
	}
}

// createType 创建类型并解码响应。
func createType(t *testing.T, mux http.Handler, req map[string]any) SensitiveDataType {
	t.Helper()
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/sensitive-types", req)
	if rr.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", rr.Code, rr.Body.String())
	}
	var created SensitiveDataType
	decodeData(t, rr, &created)
	return created
}

// TestRoutesPermission 未登录 401、无权限 403。
func TestRoutesPermission(t *testing.T) {
	h := NewHandler(NewMemStore(), nil)

	// 无主体：RequirePermission 返回 401
	muxNoAuth := http.NewServeMux()
	RegisterRoutes(muxNoAuth, func(next http.Handler) http.Handler { return next }, h)
	rr := doJSON(t, muxNoAuth, http.MethodGet, "/api/v1/api-security/sensitive-types", nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no-auth status=%d", rr.Code)
	}

	// 有主体无权限：403
	muxNoPerm := http.NewServeMux()
	RegisterRoutes(muxNoPerm, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "noperm", PermsSet: map[string]bool{}}
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
		})
	}, h)
	rr = doJSON(t, muxNoPerm, http.MethodGet, "/api/v1/api-security/sensitive-types", nil)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("no-perm status=%d", rr.Code)
	}
	rr = doJSON(t, muxNoPerm, http.MethodPost, "/api/v1/api-security/sensitive-types", validTypeReq())
	if rr.Code != http.StatusForbidden {
		t.Fatalf("no-perm create status=%d", rr.Code)
	}
}

// TestTypeCRUD 创建 → 读取 → 列表 → 编辑（version 自增）→ 删除。
func TestTypeCRUD(t *testing.T) {
	mux := newTestMux(NewHandler(NewMemStore(), nil))

	created := createType(t, mux, validTypeReq())
	if created.ID == uuid.Nil || created.Version != 1 || created.IsBuiltin {
		t.Fatalf("created=%+v", created)
	}
	if created.Level != "SENSITIVE" || created.Status != "ENABLED" {
		t.Fatalf("defaults level/status=%s/%s", created.Level, created.Status)
	}

	// 读取
	rr := doJSON(t, mux, http.MethodGet, "/api/v1/api-security/sensitive-types/"+created.ID.String(), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("get status=%d", rr.Code)
	}

	// 列表（含 keyword 过滤）
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/sensitive-types?keyword="+url.QueryEscape(created.Name), nil)
	var page struct {
		Items []SensitiveDataType `json:"items"`
		Total int64               `json:"total"`
	}
	decodeData(t, rr, &page)
	if page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("list total=%d items=%d", page.Total, len(page.Items))
	}

	// 编辑（PATCH 部分更新 + version 自增）
	patch := map[string]any{"description": "更新描述", "level": "important"}
	rr = doJSON(t, mux, http.MethodPatch, "/api/v1/api-security/sensitive-types/"+created.ID.String(), patch)
	if rr.Code != http.StatusOK {
		t.Fatalf("patch status=%d body=%s", rr.Code, rr.Body.String())
	}
	var updated SensitiveDataType
	decodeData(t, rr, &updated)
	if updated.Version != 2 || updated.Description != "更新描述" || updated.Level != "IMPORTANT" {
		t.Fatalf("updated=%+v", updated)
	}
	if updated.Name != created.Name || updated.DataType != created.DataType {
		t.Fatalf("partial update should keep name/data_type, got %+v", updated)
	}

	// 启用/禁用（PATCH status）
	rr = doJSON(t, mux, http.MethodPatch, "/api/v1/api-security/sensitive-types/"+created.ID.String(),
		map[string]any{"status": "disabled"})
	var disabled SensitiveDataType
	decodeData(t, rr, &disabled)
	if disabled.Status != "DISABLED" || disabled.Version != 3 {
		t.Fatalf("disabled=%+v", disabled)
	}
	// status 过滤
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/sensitive-types?status=DISABLED", nil)
	decodeData(t, rr, &page)
	if page.Total != 1 {
		t.Fatalf("status filter total=%d", page.Total)
	}

	// 删除
	rr = doJSON(t, mux, http.MethodDelete, "/api/v1/api-security/sensitive-types/"+created.ID.String(), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("delete status=%d", rr.Code)
	}
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/sensitive-types/"+created.ID.String(), nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("get after delete status=%d", rr.Code)
	}
}

// TestTypeValidation 参数校验。
func TestTypeValidation(t *testing.T) {
	mux := newTestMux(NewHandler(NewMemStore(), nil))

	cases := []struct {
		name   string
		mutate func(req map[string]any)
	}{
		{"空名称", func(req map[string]any) { req["name"] = " " }},
		{"非法level", func(req map[string]any) { req["level"] = "TOP_SECRET" }},
		{"非法status", func(req map[string]any) { req["status"] = "ON" }},
		{"空data_type", func(req map[string]any) { req["data_type"] = "" }},
		{"regex不可编译", func(req map[string]any) { req["regex"] = "([a-z" }},
		{"非法validator", func(req map[string]any) { req["validator"] = "md5" }},
		{"非法location", func(req map[string]any) { req["locations"] = []string{"body"} }},
		{"超长keyword", func(req map[string]any) { req["keywords"] = []string{strings.Repeat("a", 129)} }},
	}
	for _, tc := range cases {
		req := validTypeReq()
		tc.mutate(req)
		rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/sensitive-types", req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: status=%d body=%s", tc.name, rr.Code, rr.Body.String())
		}
	}

	// 名称冲突 409
	req := validTypeReq()
	createType(t, mux, req)
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/sensitive-types", req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("conflict status=%d", rr.Code)
	}

	// 列表过滤参数非法 400
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/sensitive-types?level=BAD", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad level filter status=%d", rr.Code)
	}
	// 非法 ID 400
	rr = doJSON(t, mux, http.MethodGet, "/api/v1/api-security/sensitive-types/not-a-uuid", nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad id status=%d", rr.Code)
	}
}

// TestBuiltinProtection 内置类型：禁删、名称不可改，其余字段可编辑。
func TestBuiltinProtection(t *testing.T) {
	store := NewMemStore()
	mux := newTestMux(NewHandler(store, nil))

	created := createType(t, mux, validTypeReq())
	// 模拟迁移种子：标记内置（单测同包直接改内存行）
	store.mu.Lock()
	store.types[created.ID].IsBuiltin = true
	store.mu.Unlock()

	// 禁删
	rr := doJSON(t, mux, http.MethodDelete, "/api/v1/api-security/sensitive-types/"+created.ID.String(), nil)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("builtin delete status=%d", rr.Code)
	}
	// 名称不可改
	rr = doJSON(t, mux, http.MethodPatch, "/api/v1/api-security/sensitive-types/"+created.ID.String(),
		map[string]any{"name": "新名称"})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("builtin rename status=%d", rr.Code)
	}
	// 其余字段可改（version 自增）
	rr = doJSON(t, mux, http.MethodPatch, "/api/v1/api-security/sensitive-types/"+created.ID.String(),
		map[string]any{"description": "内置类型描述更新", "status": "DISABLED"})
	if rr.Code != http.StatusOK {
		t.Fatalf("builtin patch status=%d body=%s", rr.Code, rr.Body.String())
	}
	var updated SensitiveDataType
	decodeData(t, rr, &updated)
	if updated.Version != 2 || updated.Description != "内置类型描述更新" || !updated.IsBuiltin {
		t.Fatalf("builtin updated=%+v", updated)
	}
}

// TestTypesImportExport 导出 → 导入回灌（新建+更新）；非法条目整体 400。
func TestTypesImportExport(t *testing.T) {
	store := NewMemStore()
	mux := newTestMux(NewHandler(store, nil))

	a := createType(t, mux, validTypeReq())
	b := createType(t, mux, validTypeReq())

	// 导出
	rr := doJSON(t, mux, http.MethodGet, "/api/v1/api-security/sensitive-types/export", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("export status=%d", rr.Code)
	}
	var exported struct {
		Format string              `json:"format"`
		Types  []SensitiveDataType `json:"types"`
	}
	decodeData(t, rr, &exported)
	if exported.Format != "jiuzhang-api-sensitive-data-types" || len(exported.Types) != 2 {
		t.Fatalf("exported=%+v", exported)
	}

	// 导入：先在新库建同名类型，再导入同名称（更新）+ 新类型（创建）
	fresh := NewMemStore()
	freshMux := newTestMux(NewHandler(fresh, nil))
	createType(t, freshMux, map[string]any{"name": a.Name, "data_type": a.DataType})
	payload := map[string]any{"types": []map[string]any{
		{"name": a.Name, "data_type": a.DataType, "description": "导入更新"},
		{"name": "导入新增", "data_type": "imp_dt", "level": "CORE", "keywords": []string{"imp"}},
	}}
	rr = doJSON(t, freshMux, http.MethodPost, "/api/v1/api-security/sensitive-types/import", payload)
	if rr.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", rr.Code, rr.Body.String())
	}
	var result struct {
		Created int `json:"created"`
		Updated int `json:"updated"`
	}
	decodeData(t, rr, &result)
	if result.Created != 1 || result.Updated != 1 {
		t.Fatalf("import result=%+v", result)
	}
	// 导入更新 version 自增
	list, _, err := fresh.ListTypes(context.Background(), TypeFilter{Keyword: a.Name})
	if err != nil || len(list) != 1 {
		t.Fatalf("list after import: %v %d", err, len(list))
	}
	if list[0].Version != 2 || list[0].Description != "导入更新" {
		t.Fatalf("imported update=%+v", list[0])
	}
	// store 层：导入不授予/不改变 is_builtin（内置身份仅由迁移种子授予）
	if _, _, err := fresh.ImportTypes(context.Background(), []SensitiveDataType{
		{Name: "伪装内置", DataType: "fake", IsBuiltin: true, Version: 99},
	}); err != nil {
		t.Fatalf("store import: %v", err)
	}
	fake, _, _ := fresh.ListTypes(context.Background(), TypeFilter{Keyword: "伪装内置"})
	if len(fake) != 1 || fake[0].IsBuiltin || fake[0].Version != 1 {
		t.Fatalf("fake builtin=%+v", fake)
	}

	// 非法条目整体 400 且不落库
	bad := map[string]any{"types": []map[string]any{
		{"name": "ok-1", "data_type": "d1"},
		{"name": "bad-1", "data_type": ""},
	}}
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/sensitive-types/import", bad)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("bad import status=%d", rr.Code)
	}
	// 负载内名称重复 400
	dup := map[string]any{"types": []map[string]any{
		{"name": "dup", "data_type": "d1"},
		{"name": "dup", "data_type": "d2"},
	}}
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/sensitive-types/import", dup)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("dup import status=%d", rr.Code)
	}
	// 空负载 400
	rr = doJSON(t, mux, http.MethodPost, "/api/v1/api-security/sensitive-types/import",
		map[string]any{"types": []any{}})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty import status=%d", rr.Code)
	}
	_ = b
}
