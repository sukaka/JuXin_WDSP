// resolve_test.go 实例详情与管理恢复单测（NG-FLOW-03 D5/D9）：fake 仓储承载 HTTP
// 映射与权限路径（状态机真事务语义由 PG 契约测试覆盖）；证据裁剪双档、INDETERMINATE
// 语义词表、resolve 400/404/409 精确映射、越权 403（jiuzhang_admin 对照）。
package strongflow

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// ---------- ValidateResolveInput 边界 ----------

func TestValidateResolveInput(t *testing.T) {
	cases := []struct {
		name string
		in   ResolveInput
		want string // 空=合法
	}{
		{"CONFIRM_SUCCEEDED 合法", ResolveInput{Action: "CONFIRM_SUCCEEDED", Reason: "源站对账已入账", ExpectedVersion: 1}, ""},
		{"CONFIRM_NOT_EXECUTED 合法", ResolveInput{Action: "CONFIRM_NOT_EXECUTED", Reason: "源站无记录", ExpectedVersion: 2}, ""},
		{"KEEP_UNKNOWN 合法", ResolveInput{Action: "KEEP_UNKNOWN", Reason: "证据不足保持未知", ExpectedVersion: 1}, ""},
		{"小写 action 归一", ResolveInput{Action: "keep_unknown", Reason: "x", ExpectedVersion: 1}, ""},
		{"词表外", ResolveInput{Action: "FORCE_CLOSE", Reason: "x", ExpectedVersion: 1}, "词表外"},
		{"reason 空", ResolveInput{Action: "KEEP_UNKNOWN", Reason: "  ", ExpectedVersion: 1}, "reason 必填"},
		{"reason 超长", ResolveInput{Action: "KEEP_UNKNOWN", Reason: strings.Repeat("长", 300), ExpectedVersion: 1}, "512"},
		{"expected_version 零", ResolveInput{Action: "KEEP_UNKNOWN", Reason: "x", ExpectedVersion: 0}, "expected_version"},
	}
	for _, c := range cases {
		err := ValidateResolveInput(c.in)
		if c.want == "" && err != nil {
			t.Fatalf("%s 应合法: %v", c.name, err)
		}
		if c.want != "" {
			ve, ok := err.(*ValidationError)
			if !ok || !strings.Contains(ve.Msg, c.want) {
				t.Fatalf("%s 应含 %q: %v", c.name, c.want, err)
			}
		}
	}
}

// ---------- fake 扩展（实例详情/恢复） ----------

func (f *fakeRepo) seedInstance(d *InstanceDetail) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.instances == nil {
		f.instances = map[uuid.UUID]*InstanceDetail{}
	}
	f.instances[d.ID] = d
}

func (f *fakeRepo) GetInstance(_ context.Context, id uuid.UUID, withEvidence bool) (*InstanceDetail, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.instances[id]
	if !ok {
		return nil, ErrInstanceNotFound
	}
	// 模拟 store 裁剪语义：withEvidence=false → 明细档缺席（拷贝不污染种子）
	out := *d
	out.Steps = make([]StepEventView, len(d.Steps))
	for i, ev := range d.Steps {
		out.Steps[i] = ev
		if !withEvidence {
			out.Steps[i].FencingToken = nil
			out.Steps[i].ReasonCode = ""
			out.Steps[i].RequestID = ""
		}
	}
	return &out, f.err
}

func (f *fakeRepo) ResolveInstance(_ context.Context, id uuid.UUID, in ResolveInput, _ string) (*ResolveResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.instances[id]
	if !ok {
		return nil, ErrInstanceNotFound
	}
	res := &ResolveResult{InstanceID: id, BeforeStatus: d.Status, BeforeVersion: d.Version,
		Action: strings.ToUpper(strings.TrimSpace(in.Action))}
	if d.Status == "CONFIRMED" || d.Status == "CANCELLED" || d.Status == "FAILED" {
		return nil, ErrInstanceTerminal
	}
	if d.Version != in.ExpectedVersion {
		return nil, ErrVersionConflict
	}
	switch res.Action {
	case ResolveKeepUnknown:
		res.AfterStatus, res.AfterVersion = d.Status, d.Version
	case ResolveConfirmSucceeded:
		d.Status, d.Version = "CONFIRMED", d.Version+1
		now := time.Now().UTC()
		d.TerminatedAt = &now
		res.AfterStatus, res.AfterVersion = d.Status, d.Version
	case ResolveConfirmNotExecuted:
		d.Status, d.Version = "FAILED", d.Version+1
		now := time.Now().UTC()
		d.TerminatedAt = &now
		res.AfterStatus, res.AfterVersion = d.Status, d.Version
	}
	d.StatusSemantics, d.StatusMessage = statusSemantics(d.Status)
	return res, f.err
}

// ---------- 详情端点 ----------

func detailFixture(status string) *InstanceDetail {
	token := int64(3)
	d := &InstanceDetail{
		Instance: Instance{
			ID: uuid.New(), ApplicationID: uuid.New(), DefinitionID: uuid.New(),
			DefinitionName: "下单支付", DefinitionVersion: 2, InstanceKey: "sfref:" + strings.Repeat("a", 64),
			TenantRef: "tref:aa", PrincipalRef: "pref:bb", Status: status, Version: 2,
			CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
		},
		Steps: []StepEventView{
			{StepKey: "", Action: "INSTANCE_NEW", Result: "OK", OccurredAt: time.Now().UTC(), FencingToken: &token, RequestID: "req-1"},
			{StepKey: "pay", Action: "RESERVE", Result: "UNKNOWN", OccurredAt: time.Now().UTC(), ReasonCode: "UNKNOWN-001", RequestID: "req-2"},
		},
	}
	d.StatusSemantics, d.StatusMessage = statusSemantics(status)
	return d
}

// 详情：INDETERMINATE 语义词表逐字（未知，不显示安全通过——§9.4 红线）+ 证据裁剪双档 + 404。
func TestGetInstanceHTTP(t *testing.T) {
	repo := newFakeRepo()
	ind := detailFixture("INDETERMINATE")
	repo.seedInstance(ind)

	// 无 evidence_read：明细档缺席，语义词表出席
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPerms(PermFlowRead), NewHandler(repo, nil))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/api-security/strong-flows/instances/"+ind.ID.String(), nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("detail: %d %s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	data := got["data"].(map[string]any)
	if data["status"] != "INDETERMINATE" || data["status_semantics"] != "UNKNOWN_NOT_CONFIRMED" {
		t.Fatalf("语义词表: %v / %v", data["status"], data["status_semantics"])
	}
	if data["status_message"] != "未知，不显示安全通过" {
		t.Fatalf("INDETERMINATE 文案必须逐字不美化: %v", data["status_message"])
	}
	steps := data["steps"].([]any)
	for _, s := range steps {
		m := s.(map[string]any)
		for _, k := range []string{"fencing_token", "reason_code", "request_id"} {
			if _, present := m[k]; present {
				t.Fatalf("无 evidence_read 明细键 %s 必须缺席: %v", k, m)
			}
		}
		if m["step_key"] == nil || m["action"] == nil || m["result"] == nil || m["occurred_at"] == nil {
			t.Fatalf("摘要档四字段必须出席: %v", m)
		}
	}

	// 有 evidence_read：明细档带出
	mux2 := http.NewServeMux()
	RegisterRoutes(mux2, injectPerms(PermFlowRead, PermEvidenceRead), NewHandler(repo, nil))
	rr2 := httptest.NewRecorder()
	mux2.ServeHTTP(rr2, httptest.NewRequest(http.MethodGet, "/api/v1/api-security/strong-flows/instances/"+ind.ID.String(), nil))
	if rr2.Code != http.StatusOK {
		t.Fatalf("detail evidence: %d", rr2.Code)
	}
	var got2 map[string]any
	_ = json.Unmarshal(rr2.Body.Bytes(), &got2)
	steps2 := got2["data"].(map[string]any)["steps"].([]any)
	first := steps2[0].(map[string]any)
	if first["fencing_token"].(float64) != 3 || first["request_id"] != "req-1" {
		t.Fatalf("evidence_read 明细应带出: %v", first)
	}
	second := steps2[1].(map[string]any)
	if second["reason_code"] != "UNKNOWN-001" {
		t.Fatalf("reason_code 明细应带出: %v", second)
	}

	// 404
	rr3 := httptest.NewRecorder()
	mux.ServeHTTP(rr3, httptest.NewRequest(http.MethodGet, "/api/v1/api-security/strong-flows/instances/"+uuid.NewString(), nil))
	if rr3.Code != http.StatusNotFound {
		t.Fatalf("不存在应 404: %d", rr3.Code)
	}
}

// ---------- resolve 端点 ----------

func doResolve(t *testing.T, mux *http.ServeMux, id uuid.UUID, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-security/strong-flows/instances/"+id.String()+"/resolve", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// resolve HTTP 映射：三 action 200 与状态推进、KEEP_UNKNOWN 不推进、400/404/409 精确。
func TestResolveInstanceHTTP(t *testing.T) {
	repo := newFakeRepo()
	ind := detailFixture("INDETERMINATE")
	repo.seedInstance(ind)
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPerms(PermFlowRead, PermFlowManage), NewHandler(repo, nil))

	// 词表外 400
	if rr := doResolve(t, mux, ind.ID, `{"action":"FORCE_CLOSE","reason":"x","expected_version":2}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("词表外应 400: %d %s", rr.Code, rr.Body.String())
	}
	// reason 空 400
	if rr := doResolve(t, mux, ind.ID, `{"action":"KEEP_UNKNOWN","reason":" ","expected_version":2}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("reason 空应 400: %d", rr.Code)
	}
	// 乐观锁不匹配 409
	if rr := doResolve(t, mux, ind.ID, `{"action":"KEEP_UNKNOWN","reason":"x","expected_version":9}`); rr.Code != http.StatusConflict {
		t.Fatalf("版本冲突应 409: %d %s", rr.Code, rr.Body.String())
	}
	// 不存在 404
	if rr := doResolve(t, mux, uuid.New(), `{"action":"KEEP_UNKNOWN","reason":"x","expected_version":1}`); rr.Code != http.StatusNotFound {
		t.Fatalf("不存在应 404: %d", rr.Code)
	}
	// KEEP_UNKNOWN 200：状态不推进（INDETERMINATE 保持，version 不消费）
	rr := doResolve(t, mux, ind.ID, `{"action":"KEEP_UNKNOWN","reason":"证据不足保持未知","expected_version":2}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("KEEP_UNKNOWN: %d %s", rr.Code, rr.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	data := got["data"].(map[string]any)
	if data["status"] != "INDETERMINATE" || data["version"].(float64) != 2 {
		t.Fatalf("KEEP_UNKNOWN 不得推进: status=%v version=%v", data["status"], data["version"])
	}
	// CONFIRM_SUCCEEDED 200：推进终态 + version+1 + terminated_at
	rr = doResolve(t, mux, ind.ID, `{"action":"CONFIRM_SUCCEEDED","reason":"源站对账已入账","expected_version":2}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("CONFIRM_SUCCEEDED: %d %s", rr.Code, rr.Body.String())
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	data = got["data"].(map[string]any)
	if data["status"] != "CONFIRMED" || data["version"].(float64) != 3 || data["terminated_at"] == nil {
		t.Fatalf("CONFIRM_SUCCEEDED 推进: %v/%v/%v", data["status"], data["version"], data["terminated_at"])
	}
	// 终态重复恢复 409（幂等不误伤）
	if rr := doResolve(t, mux, ind.ID, `{"action":"CONFIRM_NOT_EXECUTED","reason":"x","expected_version":3}`); rr.Code != http.StatusConflict {
		t.Fatalf("终态重复应 409: %d %s", rr.Code, rr.Body.String())
	}

	// CONFIRM_NOT_EXECUTED 链（新实例 ACTIVE → FAILED）
	repo2 := newFakeRepo()
	act := detailFixture("ACTIVE")
	repo2.seedInstance(act)
	mux2 := http.NewServeMux()
	RegisterRoutes(mux2, injectPerms(PermFlowManage), NewHandler(repo2, nil))
	rr = doResolve(t, mux2, act.ID, `{"action":"CONFIRM_NOT_EXECUTED","reason":"源站无该单记录","expected_version":2}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("CONFIRM_NOT_EXECUTED: %d %s", rr.Code, rr.Body.String())
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	data = got["data"].(map[string]any)
	if data["status"] != "FAILED" || data["status_semantics"] != "FAILED" {
		t.Fatalf("CONFIRM_NOT_EXECUTED 应推 FAILED: %v", data["status"])
	}
}

// 越权对照（D9：jiuzhang_admin 形态详情/resolve 全 403）。
func TestStrongFlowInstanceEndpointsForbiddenForSysAdmin(t *testing.T) {
	repo := newFakeRepo()
	repo.seedInstance(detailFixture("ACTIVE"))
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPerms("system.read", "applications.edit"), NewHandler(repo, nil))
	id := uuid.NewString()
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/api-security/strong-flows/instances"},
		{http.MethodGet, "/api/v1/api-security/strong-flows/instances/" + id},
		{http.MethodPost, "/api/v1/api-security/strong-flows/instances/" + id + "/resolve"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{"action":"KEEP_UNKNOWN","reason":"x","expected_version":1}`))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s %s: 应 403, got %d", tc.method, tc.path, rr.Code)
		}
	}
}
