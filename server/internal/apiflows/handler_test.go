// handler_test.go 流程基线 CRUD 单测（fake 仓储 + spy 审计，不依赖数据库）：
// 载荷校验（validateFlow 与网关 ValidateFlowBaselines 同口径）、创建/查询/整体替换
// （乐观锁 409）/删除（404）、写操作审计。pgx 路径由集成测试覆盖。
package apiflows

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
)

// fakeRepo 内存仓储（镜像 Store 语义：validateFlow 入库校验 + version 乐观锁）。
type fakeRepo struct {
	flows map[uuid.UUID]*Flow
}

func newFakeRepo() *fakeRepo { return &fakeRepo{flows: map[uuid.UUID]*Flow{}} }

func toSteps(in []StepInput) []Step {
	out := []Step{}
	for _, s := range in {
		epID, _ := uuid.Parse(strings.TrimSpace(s.EndpointID))
		preds := s.Predecessors
		if preds == nil {
			preds = []string{}
		}
		out = append(out, Step{ID: uuid.New(), StepID: s.StepID, EndpointID: epID,
			Sequence: s.Sequence, Predecessors: preds, Terminal: s.Terminal,
			StateFrom: s.StateFrom, StateTo: s.StateTo,
			MaxPerWindow: s.MaxPerWindow, RateWindowSeconds: s.RateWindowSeconds,
			CancelsFlow: s.CancelsFlow})
	}
	return out
}

func (f *fakeRepo) Create(_ context.Context, in FlowInput, createdBy string) (*Flow, error) {
	if err := validateFlow(&in); err != nil {
		return nil, err
	}
	for _, fl := range f.flows {
		if fl.FlowID == in.FlowID {
			return nil, ErrDuplicateFlowID
		}
	}
	fl := &Flow{ID: uuid.New(), FlowID: in.FlowID, Name: in.Name, Description: in.Description,
		Enabled: in.Enabled, Version: 1, MaxPerWindow: in.MaxPerWindow,
		RateWindowSeconds: in.RateWindowSeconds, Steps: toSteps(in.Steps), CreatedBy: createdBy}
	f.flows[fl.ID] = fl
	return fl, nil
}

func (f *fakeRepo) List(_ context.Context, enabled *bool) ([]Summary, error) {
	out := []Summary{}
	for _, fl := range f.flows {
		if enabled != nil && fl.Enabled != *enabled {
			continue
		}
		out = append(out, Summary{ID: fl.ID, FlowID: fl.FlowID, Enabled: fl.Enabled,
			Version: fl.Version, StepCount: len(fl.Steps)})
	}
	return out, nil
}

func (f *fakeRepo) Get(_ context.Context, id uuid.UUID) (*Flow, error) {
	fl, ok := f.flows[id]
	if !ok {
		return nil, ErrNotFound
	}
	return fl, nil
}

func (f *fakeRepo) Update(_ context.Context, id uuid.UUID, in FlowInput, expectedVersion int) (*Flow, error) {
	fl, ok := f.flows[id]
	if !ok {
		return nil, ErrNotFound
	}
	if fl.Version != expectedVersion {
		return nil, ErrVersionConflict
	}
	if err := validateFlow(&in); err != nil {
		return nil, err
	}
	for id2, other := range f.flows {
		if id2 != id && other.FlowID == in.FlowID {
			return nil, ErrDuplicateFlowID
		}
	}
	fl.FlowID, fl.Name, fl.Description, fl.Enabled = in.FlowID, in.Name, in.Description, in.Enabled
	fl.MaxPerWindow, fl.RateWindowSeconds = in.MaxPerWindow, in.RateWindowSeconds
	fl.Steps = toSteps(in.Steps)
	fl.Version++
	return fl, nil
}

func (f *fakeRepo) Delete(_ context.Context, id uuid.UUID) error {
	if _, ok := f.flows[id]; !ok {
		return ErrNotFound
	}
	delete(f.flows, id)
	return nil
}

type spyAudits struct{ entries []audits.RecordInput }

func (s *spyAudits) Record(_ context.Context, in audits.RecordInput) error {
	s.entries = append(s.entries, in)
	return nil
}

func withTester(r *http.Request) *http.Request {
	p := &authz.Principal{UserID: uuid.New(), Username: "tester"}
	return r.WithContext(authz.WithPrincipal(r.Context(), p))
}

func newJSONRequest(t *testing.T, method, target, body string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return withTester(req)
}

func decodeData[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var env struct {
		Data T `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode response: %v (body %s)", err, w.Body.String())
	}
	return env.Data
}

var testEndpointID = uuid.New().String()

func validCreateBody() string {
	return `{"flow_id":"checkout","name":"下单流程","steps":[
		{"step_id":"browse","endpoint_id":"` + testEndpointID + `","sequence":1},
		{"step_id":"pay","endpoint_id":"` + testEndpointID + `","sequence":2,
		 "predecessors":["browse"],"terminal":true,"state_from":"CREATED","state_to":"PAID"}]}`
}

func TestValidateFlow(t *testing.T) {
	valid := FlowInput{FlowID: "checkout", Steps: []StepInput{
		{StepID: "a", EndpointID: testEndpointID, Sequence: 1},
		{StepID: "b", EndpointID: testEndpointID, Sequence: 2, Predecessors: []string{"a"}},
	}}
	if err := validateFlow(&valid); err != nil {
		t.Fatalf("valid flow rejected: %v", err)
	}
	cases := []struct {
		name string
		in   FlowInput
	}{
		{"空 flow_id", FlowInput{Steps: []StepInput{{StepID: "a", EndpointID: testEndpointID}}}},
		{"无步骤", FlowInput{FlowID: "f"}},
		{"空 step_id", FlowInput{FlowID: "f", Steps: []StepInput{{EndpointID: testEndpointID}}}},
		{"缺 endpoint_id", FlowInput{FlowID: "f", Steps: []StepInput{{StepID: "a"}}}},
		{"step_id 重复", FlowInput{FlowID: "f", Steps: []StepInput{
			{StepID: "a", EndpointID: testEndpointID}, {StepID: "a", EndpointID: testEndpointID}}}},
		{"前置自引用", FlowInput{FlowID: "f", Steps: []StepInput{
			{StepID: "a", EndpointID: testEndpointID, Predecessors: []string{"a"}}}}},
		{"前置未声明", FlowInput{FlowID: "f", Steps: []StepInput{
			{StepID: "a", EndpointID: testEndpointID, Predecessors: []string{"ghost"}}}}},
		{"流程级 max_per_window 为负", FlowInput{FlowID: "f", MaxPerWindow: -1, Steps: []StepInput{
			{StepID: "a", EndpointID: testEndpointID}}}},
		{"流程级 rate_window_seconds 为负", FlowInput{FlowID: "f", RateWindowSeconds: -1, Steps: []StepInput{
			{StepID: "a", EndpointID: testEndpointID}}}},
		{"流程级窗口超会话 TTL", FlowInput{FlowID: "f", MaxPerWindow: 10, RateWindowSeconds: 601, Steps: []StepInput{
			{StepID: "a", EndpointID: testEndpointID}}}},
		{"步骤级 max_per_window 为负", FlowInput{FlowID: "f", Steps: []StepInput{
			{StepID: "a", EndpointID: testEndpointID, MaxPerWindow: -1}}}},
		{"步骤级 rate_window_seconds 为负", FlowInput{FlowID: "f", Steps: []StepInput{
			{StepID: "a", EndpointID: testEndpointID, RateWindowSeconds: -1}}}},
		{"步骤级窗口超会话 TTL", FlowInput{FlowID: "f", Steps: []StepInput{
			{StepID: "a", EndpointID: testEndpointID, MaxPerWindow: 3, RateWindowSeconds: 1200}}}},
	}
	for _, tc := range cases {
		if err := validateFlow(&tc.in); err == nil {
			t.Errorf("%s: 应拒绝", tc.name)
		} else {
			var verr *ValidationError
			if !errors.As(err, &verr) {
				t.Errorf("%s: 校验错误应为 ValidationError，实得 %T", tc.name, err)
			}
		}
	}
	// 批量执行/取消语义字段合法值（步骤级 + 流程级，含窗口上限边界 600s）
	rich := FlowInput{FlowID: "checkout", MaxPerWindow: 100, RateWindowSeconds: 600, Steps: []StepInput{
		{StepID: "a", EndpointID: testEndpointID, Sequence: 1},
		{StepID: "b", EndpointID: testEndpointID, Sequence: 2, Predecessors: []string{"a"},
			MaxPerWindow: 3, RateWindowSeconds: 10, CancelsFlow: true},
	}}
	if err := validateFlow(&rich); err != nil {
		t.Fatalf("valid rate/cancel fields rejected: %v", err)
	}
}

// TestFlowRateCancelFieldsCRUD 批量执行/取消语义字段经 handler 全量往返
// （创建 201 回读、整体替换覆盖——未携带字段回落 0/false）。
func TestFlowRateCancelFieldsCRUD(t *testing.T) {
	repo := newFakeRepo()
	h := &Handler{repo: repo}

	w := httptest.NewRecorder()
	h.Create(w, newJSONRequest(t, http.MethodPost, "/api/v1/api-security/flow-baselines",
		`{"flow_id":"cancel-flow","max_per_window":50,"rate_window_seconds":120,"steps":[
			{"step_id":"a","endpoint_id":"`+testEndpointID+`","sequence":1},
			{"step_id":"cancel","endpoint_id":"`+testEndpointID+`","sequence":2,
			 "predecessors":["a"],"max_per_window":2,"rate_window_seconds":10,"cancels_flow":true}]}`))
	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body %s", w.Code, w.Body.String())
	}
	created := decodeData[Flow](t, w)
	if created.MaxPerWindow != 50 || created.RateWindowSeconds != 120 {
		t.Fatalf("flow-level fields = %+v", created)
	}
	if created.Steps[1].MaxPerWindow != 2 || created.Steps[1].RateWindowSeconds != 10 ||
		!created.Steps[1].CancelsFlow || created.Steps[0].CancelsFlow {
		t.Fatalf("step fields = %+v", created.Steps)
	}

	// 校验失败：负上限 / 超窗 → 400（文案含字段名）
	for _, bad := range []string{
		`{"flow_id":"f1","max_per_window":-1,"steps":[{"step_id":"a","endpoint_id":"` + testEndpointID + `","sequence":1}]}`,
		`{"flow_id":"f2","steps":[{"step_id":"a","endpoint_id":"` + testEndpointID + `","sequence":1,"rate_window_seconds":601}]}`,
	} {
		w = httptest.NewRecorder()
		h.Create(w, newJSONRequest(t, http.MethodPost, "/api/v1/api-security/flow-baselines", bad))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("invalid rate payload status = %d, want 400 (body %s)", w.Code, w.Body.String())
		}
	}

	// 整体替换未携带批量字段 → 回落 0/false（0 = 不判定，向后兼容）
	target := "/api/v1/api-security/flow-baselines/" + created.ID.String()
	w = httptest.NewRecorder()
	put := newJSONRequest(t, http.MethodPut, target, `{"flow_id":"cancel-flow","expected_version":1,"steps":[
		{"step_id":"a","endpoint_id":"`+testEndpointID+`","sequence":1}]}`)
	put.SetPathValue("id", created.ID.String())
	h.Update(w, put)
	if w.Code != http.StatusOK {
		t.Fatalf("update status = %d, body %s", w.Code, w.Body.String())
	}
	updated := decodeData[Flow](t, w)
	if updated.MaxPerWindow != 0 || updated.RateWindowSeconds != 0 || updated.Steps[0].CancelsFlow {
		t.Fatalf("omitted rate/cancel fields must reset to zero: %+v", updated)
	}
}

func TestHandlerCRUD(t *testing.T) {
	repo := newFakeRepo()
	spy := &spyAudits{}
	h := &Handler{repo: repo, audits: spy}

	// 创建：201 + 审计 create
	w := httptest.NewRecorder()
	h.Create(w, newJSONRequest(t, http.MethodPost, "/api/v1/api-security/flow-baselines", validCreateBody()))
	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body %s", w.Code, w.Body.String())
	}
	created := decodeData[Flow](t, w)
	if created.FlowID != "checkout" || created.Version != 1 || !created.Enabled ||
		len(created.Steps) != 2 || created.CreatedBy != "tester" {
		t.Fatalf("created = %+v", created)
	}
	if created.Steps[1].StateTo != "PAID" || len(created.Steps[1].Predecessors) != 1 {
		t.Fatalf("steps = %+v", created.Steps)
	}
	if len(spy.entries) != 1 || spy.entries[0].Action != "create" ||
		spy.entries[0].ObjectType != "api_flow_baseline" || spy.entries[0].Result != audits.ResultSuccess {
		t.Fatalf("audit entries = %+v", spy.entries)
	}

	// 同 flow_id 冲突：409
	w = httptest.NewRecorder()
	h.Create(w, newJSONRequest(t, http.MethodPost, "/api/v1/api-security/flow-baselines", validCreateBody()))
	if w.Code != http.StatusConflict {
		t.Fatalf("duplicate create status = %d, want 409", w.Code)
	}

	// 非法载荷（前置未声明）：400
	bad := strings.Replace(validCreateBody(), `"predecessors":["browse"]`, `"predecessors":["ghost"]`, 1)
	w = httptest.NewRecorder()
	h.Create(w, newJSONRequest(t, http.MethodPost, "/api/v1/api-security/flow-baselines", bad))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid payload status = %d, want 400 (body %s)", w.Code, w.Body.String())
	}

	// 详情：200 含步骤
	target := "/api/v1/api-security/flow-baselines/" + created.ID.String()
	w = httptest.NewRecorder()
	req := withTester(httptest.NewRequest(http.MethodGet, target, nil))
	req.SetPathValue("id", created.ID.String())
	h.Get(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("get status = %d", w.Code)
	}

	// 列表：200
	w = httptest.NewRecorder()
	h.List(w, withTester(httptest.NewRequest(http.MethodGet, "/api/v1/api-security/flow-baselines", nil)))
	if w.Code != http.StatusOK {
		t.Fatalf("list status = %d", w.Code)
	}
	listed := decodeData[struct {
		Items []Summary `json:"items"`
		Total int       `json:"total"`
	}](t, w)
	if listed.Total != 1 || listed.Items[0].StepCount != 2 {
		t.Fatalf("listed = %+v", listed)
	}

	// 整体替换：缺 expected_version 400；版本冲突 409；正确版本 200 且 version+1
	w = httptest.NewRecorder()
	put := newJSONRequest(t, http.MethodPut, target, `{"flow_id":"checkout","steps":[
		{"step_id":"browse","endpoint_id":"`+testEndpointID+`","sequence":1}]}`)
	put.SetPathValue("id", created.ID.String())
	h.Update(w, put)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("update without expected_version status = %d, want 400", w.Code)
	}
	w = httptest.NewRecorder()
	put = newJSONRequest(t, http.MethodPut, target, `{"flow_id":"checkout","enabled":false,"expected_version":99,"steps":[
		{"step_id":"browse","endpoint_id":"`+testEndpointID+`","sequence":1}]}`)
	put.SetPathValue("id", created.ID.String())
	h.Update(w, put)
	if w.Code != http.StatusConflict {
		t.Fatalf("update stale version status = %d, want 409", w.Code)
	}
	w = httptest.NewRecorder()
	put = newJSONRequest(t, http.MethodPut, target, `{"flow_id":"checkout","enabled":false,"expected_version":1,"steps":[
		{"step_id":"browse","endpoint_id":"`+testEndpointID+`","sequence":1}]}`)
	put.SetPathValue("id", created.ID.String())
	h.Update(w, put)
	if w.Code != http.StatusOK {
		t.Fatalf("update status = %d, body %s", w.Code, w.Body.String())
	}
	updated := decodeData[Flow](t, w)
	if updated.Version != 2 || updated.Enabled || len(updated.Steps) != 1 {
		t.Fatalf("updated = %+v", updated)
	}

	// 删除：200；再删 404；再查 404
	w = httptest.NewRecorder()
	del := withTester(httptest.NewRequest(http.MethodDelete, target, nil))
	del.SetPathValue("id", created.ID.String())
	h.Delete(w, del)
	if w.Code != http.StatusOK {
		t.Fatalf("delete status = %d", w.Code)
	}
	w = httptest.NewRecorder()
	del = withTester(httptest.NewRequest(http.MethodDelete, target, nil))
	del.SetPathValue("id", created.ID.String())
	h.Delete(w, del)
	if w.Code != http.StatusNotFound {
		t.Fatalf("second delete status = %d, want 404", w.Code)
	}
	// 审计：create/update/delete 各一条
	if len(spy.entries) != 3 || spy.entries[1].Action != "update" || spy.entries[2].Action != "delete" {
		t.Fatalf("audit entries = %+v", spy.entries)
	}
}
