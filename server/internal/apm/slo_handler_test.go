// slo_handler_test.go SLO 管理接口单测（httptest + fake SLORepository，不依赖数据库；
// 权限在路由层由 middleware.RequirePermission 强制，经注入主体验证）。
package apm

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
)

// fakeSLORepo 内存版 SLORepository（记录调用，可注入错误）。
type fakeSLORepo struct {
	items      []SLOListItem
	defs       map[uuid.UUID]*SLO
	trend      []SLOTrendPoint
	err        error // 统一错误注入（优先级最高）
	conflict   bool  // Create/Update 返回 ErrSLOConflict
	notFound   bool  // Get/Update/Delete 返回 ErrSLONotFound
	evalCalls  int   // EvaluateSLO 调用次数（验证"创建/更新即评估"）
	evalAllCnt int
}

func newFakeSLORepo() *fakeSLORepo {
	return &fakeSLORepo{defs: map[uuid.UUID]*SLO{}, trend: []SLOTrendPoint{}}
}

func (f *fakeSLORepo) CreateSLO(_ context.Context, slo *SLO) error {
	if f.err != nil {
		return f.err
	}
	if f.conflict {
		return ErrSLOConflict
	}
	slo.ID = uuid.New()
	slo.CreatedAt = time.Now().UTC()
	slo.UpdatedAt = slo.CreatedAt
	f.defs[slo.ID] = slo
	return nil
}

func (f *fakeSLORepo) GetSLO(_ context.Context, id uuid.UUID) (*SLO, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.notFound {
		return nil, ErrSLONotFound
	}
	if d, ok := f.defs[id]; ok {
		return d, nil
	}
	return nil, ErrSLONotFound
}

func (f *fakeSLORepo) UpdateSLO(_ context.Context, slo *SLO) error {
	if f.err != nil {
		return f.err
	}
	if f.notFound {
		return ErrSLONotFound
	}
	if _, ok := f.defs[slo.ID]; !ok {
		return ErrSLONotFound
	}
	if f.conflict {
		return ErrSLOConflict
	}
	slo.UpdatedAt = time.Now().UTC()
	f.defs[slo.ID] = slo
	return nil
}

func (f *fakeSLORepo) DeleteSLO(_ context.Context, id uuid.UUID) error {
	if f.err != nil {
		return f.err
	}
	if f.notFound {
		return ErrSLONotFound
	}
	if _, ok := f.defs[id]; !ok {
		return ErrSLONotFound
	}
	delete(f.defs, id)
	return nil
}

func (f *fakeSLORepo) EvaluateSLO(_ context.Context, def *SLO, _ time.Time) (*SLOListItem, error) {
	f.evalCalls++
	if f.err != nil {
		return nil, f.err
	}
	v := 0.999
	return &SLOListItem{ID: def.ID, Name: def.Name, Service: def.Service,
		MetricType: def.MetricType, Target: def.Target, Window: def.Window,
		CurrentValue: &v, ComplianceRatio: 0.999, ErrorBudgetRemaining: 0.9,
		Status: SLOStatusOK, UpdatedAt: def.UpdatedAt}, nil
}

func (f *fakeSLORepo) EvaluateAllSLOs(_ context.Context, _ time.Time) ([]SLOListItem, error) {
	f.evalAllCnt++
	if f.err != nil {
		return nil, f.err
	}
	return f.items, nil
}

func (f *fakeSLORepo) SLOTrend(_ context.Context, _ *SLO, _ time.Time) ([]SLOTrendPoint, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.trend, nil
}

// fakeAuditSpy 审计记录 spy。
type fakeAuditSpy struct{ inputs []audits.RecordInput }

func (f *fakeAuditSpy) Record(_ context.Context, in audits.RecordInput) error {
	f.inputs = append(f.inputs, in)
	return nil
}

func newSLOTestMux(h *SLOHandler, perms ...string) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterSLORoutes(mux, injectPrincipal(perms...), h)
	return mux
}

func doSLOReq(t *testing.T, mux *http.ServeMux, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// TestSLOPermissions 权限注册：读 apm.overview.read、写 apm.settings.manage；
// 无权限 403、未注入主体 401（authz 中间件未挂，handler 单测直接走 RegisterSLORoutes 包装链）。
func TestSLOPermissions(t *testing.T) {
	h := NewSLOHandler(newFakeSLORepo())

	// 读接口：apm.overview.read 放行；仅写权限不足
	if rr := doSLOReq(t, newSLOTestMux(h, "apm.overview.read"), "GET", "/api/v1/apm/slos", ""); rr.Code != 200 {
		t.Errorf("list with read perm = %d, want 200", rr.Code)
	}
	if rr := doSLOReq(t, newSLOTestMux(h, PermSettingsManage), "GET", "/api/v1/apm/slos", ""); rr.Code != 403 {
		t.Errorf("list with write-only perm = %d, want 403", rr.Code)
	}
	// 写接口：apm.settings.manage 放行；仅读权限 403
	body := `{"name":"n","service":"shop","metric_type":"availability","target":0.99,"window":"7d"}`
	if rr := doSLOReq(t, newSLOTestMux(h, PermSettingsManage), "POST", "/api/v1/apm/slos", body); rr.Code != 200 {
		t.Errorf("create with manage perm = %d, want 200, body %s", rr.Code, rr.Body.String())
	}
	if rr := doSLOReq(t, newSLOTestMux(h, "apm.overview.read"), "POST", "/api/v1/apm/slos", body); rr.Code != 403 {
		t.Errorf("create with read-only perm = %d, want 403", rr.Code)
	}
	// 无任何权限：403；未注入主体：401（injectPrincipal 无权限参数时仍注入空主体——
	// 401 分支由路由链外层的真实认证保证，这里验证权限不足路径）
	if rr := doSLOReq(t, newSLOTestMux(h), "GET", "/api/v1/apm/slos", ""); rr.Code != 403 {
		t.Errorf("list without perm = %d, want 403", rr.Code)
	}
	if rr := doSLOReq(t, newSLOTestMux(h), "DELETE", "/api/v1/apm/slos/"+uuid.NewString(), ""); rr.Code != 403 {
		t.Errorf("delete without perm = %d, want 403", rr.Code)
	}
}

// TestSLOCreateValidation 创建校验：非法入参 400；合法创建 200 且创建即评估一次 + 审计。
func TestSLOCreateValidation(t *testing.T) {
	repo := newFakeSLORepo()
	spy := &fakeAuditSpy{}
	h := NewSLOHandler(repo).SetAudits(spy)
	mux := newSLOTestMux(h, PermSettingsManage)

	bad := []string{
		`{"name":"","service":"shop","metric_type":"availability","target":0.99,"window":"7d"}`,
		`{"name":"n","service":"","metric_type":"availability","target":0.99,"window":"7d"}`,
		`{"name":"n","service":"shop","metric_type":"availability","target":1,"window":"7d"}`,
		`{"name":"n","service":"shop","metric_type":"availability","target":0,"window":"7d"}`,
		`{"name":"n","service":"shop","metric_type":"latency_p95","target":0,"window":"7d"}`,
		`{"name":"n","service":"shop","metric_type":"latency_p95","target":600001,"window":"7d"}`,
		`{"name":"n","service":"shop","metric_type":"latency_p95","target":500,"window":"1d"}`,
		`{"name":"n","service":"shop","metric_type":"qps","target":1,"window":"7d"}`,
		`not-json`,
	}
	for _, b := range bad {
		if rr := doSLOReq(t, mux, "POST", "/api/v1/apm/slos", b); rr.Code != 400 {
			t.Errorf("create %s = %d, want 400", b, rr.Code)
		}
	}

	rr := doSLOReq(t, mux, "POST", "/api/v1/apm/slos",
		`{"name":"可用性","service":"shop","metric_type":"availability","target":0.99,"window":"7d"}`)
	if rr.Code != 200 {
		t.Fatalf("create = %d, body %s", rr.Code, rr.Body.String())
	}
	if repo.evalCalls != 1 {
		t.Errorf("eval calls after create = %d, want 1（创建即评估一次）", repo.evalCalls)
	}
	if len(spy.inputs) != 1 {
		t.Fatalf("audit records = %d, want 1", len(spy.inputs))
	}
	a := spy.inputs[0]
	if a.Module != "apm" || a.Action != "create" || a.ObjectType != "apm_slo" ||
		a.RiskLevel != audits.RiskMedium || a.Result != audits.ResultSuccess {
		t.Errorf("audit = %+v", a)
	}
	if a.AfterSummary == "" || a.BeforeSummary != "" {
		t.Errorf("audit summaries: before=%q after=%q", a.BeforeSummary, a.AfterSummary)
	}
}

// TestSLOConflict 唯一约束冲突 409（创建与更新）。
func TestSLOConflict(t *testing.T) {
	repo := newFakeSLORepo()
	repo.conflict = true
	h := NewSLOHandler(repo)
	mux := newSLOTestMux(h, PermSettingsManage)

	body := `{"name":"n","service":"shop","metric_type":"availability","target":0.99,"window":"7d"}`
	if rr := doSLOReq(t, mux, "POST", "/api/v1/apm/slos", body); rr.Code != 409 {
		t.Errorf("create conflict = %d, want 409", rr.Code)
	}
	if rr := doSLOReq(t, mux, "PUT", "/api/v1/apm/slos/"+uuid.NewString(), body); rr.Code != 404 {
		// conflict 先于 notFound？本 fake 在 notFound=false 时 Update 走到 conflict 分支需先存在——
		// 此处 id 不存在返回 404，验证 404 优先语义
		t.Errorf("update missing = %d, want 404", rr.Code)
	}
}

// TestSLOUpdateDeleteNotFound 更新/删除/详情对不存在 SLO 返回 404；非法 id 400。
func TestSLOUpdateDeleteNotFound(t *testing.T) {
	repo := newFakeSLORepo()
	spy := &fakeAuditSpy{}
	h := NewSLOHandler(repo).SetAudits(spy)
	mux := newSLOTestMux(h, PermSettingsManage, "apm.overview.read")

	body := `{"name":"n","service":"shop","metric_type":"availability","target":0.99,"window":"7d"}`
	missing := uuid.NewString()
	if rr := doSLOReq(t, mux, "GET", "/api/v1/apm/slos/"+missing, ""); rr.Code != 404 {
		t.Errorf("get missing = %d, want 404", rr.Code)
	}
	if rr := doSLOReq(t, mux, "PUT", "/api/v1/apm/slos/"+missing, body); rr.Code != 404 {
		t.Errorf("update missing = %d, want 404", rr.Code)
	}
	if rr := doSLOReq(t, mux, "DELETE", "/api/v1/apm/slos/"+missing, ""); rr.Code != 404 {
		t.Errorf("delete missing = %d, want 404", rr.Code)
	}
	if rr := doSLOReq(t, mux, "GET", "/api/v1/apm/slos/bad-id", ""); rr.Code != 400 {
		t.Errorf("get bad id = %d, want 400", rr.Code)
	}

	// 完整生命周期：创建 → 更新（评估 + 审计 before/after）→ 详情（含 trend）→ 删除（审计）
	rr := doSLOReq(t, mux, "POST", "/api/v1/apm/slos", body)
	if rr.Code != 200 {
		t.Fatalf("create = %d", rr.Code)
	}
	var id string
	for k := range repo.defs {
		id = k.String()
	}
	rr = doSLOReq(t, mux, "PUT", "/api/v1/apm/slos/"+id,
		`{"name":"n2","service":"shop","metric_type":"latency_p95","target":500,"window":"30d"}`)
	if rr.Code != 200 {
		t.Fatalf("update = %d, body %s", rr.Code, rr.Body.String())
	}
	if repo.defs[uuid.MustParse(id)].Name != "n2" {
		t.Error("update did not apply")
	}
	rr = doSLOReq(t, mux, "GET", "/api/v1/apm/slos/"+id, "")
	if rr.Code != 200 {
		t.Fatalf("get = %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"trend"`) {
		t.Error("detail must contain trend field")
	}
	rr = doSLOReq(t, mux, "DELETE", "/api/v1/apm/slos/"+id, "")
	if rr.Code != 200 {
		t.Fatalf("delete = %d", rr.Code)
	}
	if rr := doSLOReq(t, mux, "GET", "/api/v1/apm/slos/"+id, ""); rr.Code != 404 {
		t.Errorf("get after delete = %d, want 404", rr.Code)
	}
	// 审计：create + update + delete 共 3 条，delete 的 after 为 deleted=true
	if len(spy.inputs) != 3 {
		t.Fatalf("audit records = %d, want 3", len(spy.inputs))
	}
	if spy.inputs[2].Action != "delete" || spy.inputs[2].AfterSummary != "deleted=true" ||
		spy.inputs[2].BeforeSummary == "" {
		t.Errorf("delete audit = %+v", spy.inputs[2])
	}
	// 纯 GET 不审计：全部 GET 未产生额外审计记录（3 条均为写操作）
	for _, in := range spy.inputs {
		if in.Action != "create" && in.Action != "update" && in.Action != "delete" {
			t.Errorf("unexpected audit action %q", in.Action)
		}
	}
}

// TestSLOListShape 列表响应形状 {list,total} 与评估错误传播。
func TestSLOListShape(t *testing.T) {
	repo := newFakeSLORepo()
	v := 0.9995
	repo.items = []SLOListItem{
		{ID: uuid.New(), Name: "a", Service: "shop", MetricType: SLOMetricAvailability,
			Target: 0.99, Window: SLOWindow7d, CurrentValue: &v, ComplianceRatio: 0.9995,
			ErrorBudgetRemaining: 0.5, Status: SLOStatusOK, UpdatedAt: time.Now().UTC()},
	}
	h := NewSLOHandler(repo)
	mux := newSLOTestMux(h, "apm.overview.read")

	rr := doSLOReq(t, mux, "GET", "/api/v1/apm/slos", "")
	if rr.Code != 200 {
		t.Fatalf("list = %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"total":1`) || !strings.Contains(body, `"list"`) {
		t.Errorf("list body missing list/total: %s", body)
	}
	if repo.evalAllCnt != 1 {
		t.Errorf("EvaluateAllSLOs calls = %d", repo.evalAllCnt)
	}

	repo.err = errors.New("db down")
	if rr := doSLOReq(t, mux, "GET", "/api/v1/apm/slos", ""); rr.Code != 500 {
		t.Errorf("list with store error = %d, want 500", rr.Code)
	}
}
