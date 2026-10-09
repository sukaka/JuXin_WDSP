// bindings_test.go gRPC 描述符 per-app 绑定单测（NG-GRPC G1 批次 B1）：
// ValidateBindingInput 词表矩阵、CRUD HTTP 映射（201/200/400/404/409×2）、
// 权限（api_spec.read/manage 零新增；jiuzhang_admin 越权全 403）、写操作 HIGH 审计。
// fake 仓储承载 HTTP 映射；事务/唯一键/FK 语义由 PG 契约测试覆盖。
package apigrpcdesc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
)

// ---------- ValidateBindingInput 词表矩阵 ----------

func TestValidateBindingInput(t *testing.T) {
	okApp := uuid.NewString()
	cases := []struct {
		name string
		in   BindingInput
		want string
	}{
		{"合法全字段", BindingInput{ApplicationID: okApp, Service: "pkg.orders.payment", DescriptorName: "set-a", Mode: "PROTECT"}, ""},
		{"大写驼峰服务名（词表裁决：protobuf 实际规则）", BindingInput{ApplicationID: okApp, Service: "echo.EchoService", DescriptorName: "set-a", Mode: "PROTECT"}, ""},
		{"包段小写+服务段大写混合", BindingInput{ApplicationID: okApp, Service: "pkg.orders.PaymentService", DescriptorName: "set-a", Mode: ""}, ""},
		{"裸服务名合法", BindingInput{ApplicationID: okApp, Service: "echo", DescriptorName: "set-a", Mode: ""}, ""},
		{"mode 缺省合法", BindingInput{ApplicationID: okApp, Service: "pkg.svc", DescriptorName: "set-a", Mode: ""}, ""},
		{"mode 小写归一", BindingInput{ApplicationID: okApp, Service: "pkg.svc", DescriptorName: "set-a", Mode: "observe"}, ""},
		{"application_id 非法", BindingInput{ApplicationID: "xx", Service: "pkg.svc", DescriptorName: "set-a"}, "application_id"},
		{"service 空", BindingInput{ApplicationID: okApp, Service: " ", DescriptorName: "set-a"}, "service"},
		{"service 大写开头拒收", BindingInput{ApplicationID: okApp, Service: "Pkg.Svc", DescriptorName: "set-a"}, "service"},
		{"service 连字符拒收", BindingInput{ApplicationID: okApp, Service: "pkg-orders.Svc", DescriptorName: "set-a"}, "service"},
		{"service 空段拒收", BindingInput{ApplicationID: okApp, Service: "pkg..Svc", DescriptorName: "set-a"}, "service"},
		{"service 多层合法", BindingInput{ApplicationID: okApp, Service: "a.b.c.d.e", DescriptorName: "set-a"}, ""},
		{"descriptor_name 空", BindingInput{ApplicationID: okApp, Service: "pkg.svc", DescriptorName: " "}, "descriptor_name"},
		{"mode 词表外", BindingInput{ApplicationID: okApp, Service: "pkg.svc", DescriptorName: "set-a", Mode: "BLOCK"}, "mode"},
	}
	for _, c := range cases {
		got := ValidateBindingInput(c.in)
		if c.want == "" && got != "" {
			t.Fatalf("%s 应合法: %s", c.name, got)
		}
		if c.want != "" && !strings.Contains(got, c.want) {
			t.Fatalf("%s 应含 %q: %s", c.name, c.want, got)
		}
	}
}

// ---------- fake 绑定仓储 ----------

type fakeBindingRepo struct {
	rows             map[uuid.UUID]*Binding
	descriptorExists bool
	appExists        bool
}

func newFakeBindingRepo() *fakeBindingRepo {
	return &fakeBindingRepo{rows: map[uuid.UUID]*Binding{}, descriptorExists: true, appExists: true}
}

func (f *fakeBindingRepo) CreateBinding(_ context.Context, in BindingInput, by string) (*Binding, error) {
	if !f.appExists {
		return nil, ErrApplicationNotFound
	}
	if !f.descriptorExists {
		return nil, ErrDescriptorNotFound
	}
	appID, _ := uuid.Parse(in.ApplicationID)
	for _, b := range f.rows {
		if b.ApplicationID == appID && b.Service == strings.TrimSpace(in.Service) {
			return nil, ErrBindingDuplicate
		}
	}
	mode := strings.ToUpper(strings.TrimSpace(in.Mode))
	if mode == "" {
		mode = ModeObserve
	}
	b := &Binding{ID: uuid.New(), ApplicationID: appID, Service: strings.TrimSpace(in.Service),
		DescriptorName: strings.TrimSpace(in.DescriptorName), Mode: mode, Version: 1,
		CreatedBy: by, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	f.rows[b.ID] = b
	return b, nil
}

func (f *fakeBindingRepo) ListBindings(_ context.Context, applicationID uuid.UUID) ([]Binding, error) {
	out := []Binding{}
	for _, b := range f.rows {
		if applicationID == uuid.Nil || b.ApplicationID == applicationID {
			out = append(out, *b)
		}
	}
	return out, nil
}

func (f *fakeBindingRepo) UpdateBinding(_ context.Context, id uuid.UUID, in BindingInput) (*Binding, error) {
	b, ok := f.rows[id]
	if !ok {
		return nil, ErrBindingNotFound
	}
	if b.Version != in.Version {
		return nil, ErrBindingVersionConflict
	}
	if !f.descriptorExists {
		return nil, ErrDescriptorNotFound
	}
	b.DescriptorName = strings.TrimSpace(in.DescriptorName)
	if m := strings.ToUpper(strings.TrimSpace(in.Mode)); m != "" {
		b.Mode = m
	}
	b.Version++
	return b, nil
}

func (f *fakeBindingRepo) DeleteBinding(_ context.Context, id uuid.UUID) error {
	if _, ok := f.rows[id]; !ok {
		return ErrBindingNotFound
	}
	delete(f.rows, id)
	return nil
}

func (f *fakeBindingRepo) ListUndocumentedServices(_ context.Context) ([]UndocumentedService, error) {
	return []UndocumentedService{}, nil
}

// dualRepo 组合 fake（Handler 需要 Repository（描述符集）+ BindingRepository（绑定）双接口——
// NewHandler 类型断言注入 bindRepo）。
type dualRepo struct {
	*fakeRepo
	*fakeBindingRepo
}

// ---------- HTTP 映射 ----------

func injectPerms(perms ...string) func(http.Handler) http.Handler {
	set := map[string]bool{}
	for _, p := range perms {
		set[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "tester", PermsSet: set}
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
		})
	}
}

func doReq(t *testing.T, mux *http.ServeMux, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func validBindingBody(appID string) string {
	return `{"application_id":"` + appID + `","service":"pkg.orders.payment","descriptor_name":"set-a","mode":"OBSERVE"}`
}

// CRUD 全链：create 200 → 同（应用,服务）409 → list 过滤 → update 乐观锁两态 → delete 200/404。
func TestBindingCRUDHTTP(t *testing.T) {
	repo := &dualRepo{fakeRepo: newFakeRepo(), fakeBindingRepo: newFakeBindingRepo()}
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPerms("api_spec.read", "api_spec.manage"), NewHandler(repo, nil))
	appID := uuid.NewString()

	// create 200（mode 缺省归一 OBSERVE）
	rr := doReq(t, mux, http.MethodPost, "/api/v1/api-security/grpc-bindings", validBindingBody(appID))
	if rr.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	// 解析信封
	var env map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	var b Binding
	if err := json.Unmarshal(env["data"], &b); err != nil {
		t.Fatal(err)
	}
	if b.Mode != ModeObserve || b.Version != 1 {
		t.Fatalf("mode/version 归一: %+v", b)
	}
	// 同（应用,服务）→ 409
	if rr := doReq(t, mux, http.MethodPost, "/api/v1/api-security/grpc-bindings", validBindingBody(appID)); rr.Code != http.StatusConflict {
		t.Fatalf("重复绑定应 409: %d %s", rr.Code, rr.Body.String())
	}
	// service 形态 400
	bad := strings.Replace(validBindingBody(appID), "pkg.orders.payment", "Pkg.Orders", 1)
	if rr := doReq(t, mux, http.MethodPost, "/api/v1/api-security/grpc-bindings", bad); rr.Code != http.StatusBadRequest {
		t.Fatalf("service 形态应 400: %d", rr.Code)
	}
	// 描述符不存在 → 400
	repo.descriptorExists = false
	if rr := doReq(t, mux, http.MethodPost, "/api/v1/api-security/grpc-bindings",
		`{"application_id":"`+uuid.NewString()+`","service":"pkg.x.Y","descriptor_name":"ghost","mode":"OBSERVE"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("描述符缺失应 400: %d", rr.Code)
	}
	repo.descriptorExists = true
	// list（application_id 过滤）
	rr = doReq(t, mux, http.MethodGet, "/api/v1/api-security/grpc-bindings?application_id="+appID, "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "pkg.orders.payment") {
		t.Fatalf("list: %d %s", rr.Code, rr.Body.String())
	}
	// update：version 缺失 400 / 冲突 409 / 合法 200
	if rr := doReq(t, mux, http.MethodPut, "/api/v1/api-security/grpc-bindings/"+b.ID.String(),
		`{"descriptor_name":"set-b","mode":"PROTECT","version":0}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("version 缺失应 400: %d", rr.Code)
	}
	if rr := doReq(t, mux, http.MethodPut, "/api/v1/api-security/grpc-bindings/"+b.ID.String(),
		`{"descriptor_name":"set-b","mode":"PROTECT","version":9}`); rr.Code != http.StatusConflict {
		t.Fatalf("乐观锁冲突应 409: %d", rr.Code)
	}
	rr = doReq(t, mux, http.MethodPut, "/api/v1/api-security/grpc-bindings/"+b.ID.String(),
		`{"descriptor_name":"set-b","mode":"PROTECT","version":1}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rr.Code, rr.Body.String())
	}
	// delete 200；重复 delete 404
	if rr := doReq(t, mux, http.MethodDelete, "/api/v1/api-security/grpc-bindings/"+b.ID.String(), ""); rr.Code != http.StatusOK {
		t.Fatalf("delete: %d", rr.Code)
	}
	if rr := doReq(t, mux, http.MethodDelete, "/api/v1/api-security/grpc-bindings/"+b.ID.String(), ""); rr.Code != http.StatusNotFound {
		t.Fatalf("重复 delete 应 404: %d", rr.Code)
	}
	// 未登记服务清单（read 权限路径）
	if rr := doReq(t, mux, http.MethodGet, "/api/v1/api-security/grpc-bindings/undocumented-services", ""); rr.Code != http.StatusOK {
		t.Fatalf("undocumented-services: %d %s", rr.Code, rr.Body.String())
	}
}

// 越权对照（jiuzhang_admin 形态全 403；read/manage 权限点零新增实证）。
func TestBindingEndpointsForbiddenForSysAdmin(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPerms("system.read", "applications.edit"), NewHandler(&dualRepo{fakeRepo: newFakeRepo(), fakeBindingRepo: newFakeBindingRepo()}, nil))
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/v1/api-security/grpc-bindings", ""},
		{http.MethodPost, "/api/v1/api-security/grpc-bindings", validBindingBody(uuid.NewString())},
		{http.MethodPut, "/api/v1/api-security/grpc-bindings/" + uuid.NewString(), `{"descriptor_name":"s","mode":"OBSERVE","version":1}`},
		{http.MethodDelete, "/api/v1/api-security/grpc-bindings/" + uuid.NewString(), ""},
		{http.MethodGet, "/api/v1/api-security/grpc-bindings/undocumented-services", ""},
	} {
		rr := doReq(t, mux, tc.method, tc.path, tc.body)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s %s: 应 403, got %d", tc.method, tc.path, rr.Code)
		}
	}
}

// 写操作 HIGH 审计（object_type/api_grpc_binding + after 摘要 JSON 全值）。
func TestBindingAuditHigh(t *testing.T) {
	repo := &dualRepo{fakeRepo: newFakeRepo(), fakeBindingRepo: newFakeBindingRepo()}
	spy := &spyAudits{}
	h := NewHandler(repo, nil)
	h.audits = spy
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPerms("api_spec.manage"), h)
	appID := uuid.NewString()
	rr := doReq(t, mux, http.MethodPost, "/api/v1/api-security/grpc-bindings", validBindingBody(appID))
	if rr.Code != http.StatusOK {
		t.Fatalf("create: %d", rr.Code)
	}
	if len(spy.entries) != 1 {
		t.Fatalf("create 审计条数: %d", len(spy.entries))
	}
	e := spy.entries[0]
	if e.ObjectType != "api_grpc_binding" || e.RiskLevel != "HIGH" || e.Action != "create" ||
		!strings.Contains(e.AfterSummary, "pkg.orders.payment") || !strings.Contains(e.AfterSummary, `"mode":"OBSERVE"`) {
		t.Fatalf("create 审计内容: %+v", e)
	}
}
