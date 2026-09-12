// handler_test.go 管理端点单测：令牌签发/撤销、Agent 禁用/删除、策略 CRUD 与绑定、
// 事件分页钳制、审计记录（module=traffic-agents，HIGH 级）。
// 仓储为内存 fake（AdminRepository 接口隔离）；权限中间件经注入式 authz 包装
// （与 apinodes handler_sync_test.go 同一模式）。
package agents

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
)

// fakeAdminStore AdminRepository 内存实现。
type fakeAdminStore struct {
	tokens     []EnrollmentToken
	createErr  error
	lastHash   string
	revokeErr  error
	revokedID  uuid.UUID
	agents     []Agent
	listFilter AgentFilter
	details    map[uuid.UUID]*AgentDetail
	disabled   map[uuid.UUID]bool
	deleted    []uuid.UUID
	events     []FlowEventRow
	eventsPage PageParams
	// Phase 3：HTTP 事件 fake 状态
	httpEvents []HTTPEventRow
	httpDetail *HTTPEventRow
	httpFilter HTTPEventFilter
	// v2：资产来源关系 fake 状态
	assetSources      []HTTPAssetSourceRow
	assetSourceFilter HTTPAssetSourceFilter
	policies          map[uuid.UUID]*Policy
	policyErr         error
	versions          map[uuid.UUID][]PolicyVersion
	binds             map[uuid.UUID]uuid.UUID // agent_id → policy_id
	unbindErr         error
	cfgBumped         int
	// Phase 4：定向采集规则 fake 状态
	overrides   map[uuid.UUID][]CaptureOverride // agent_id → 规则列表
	overrideErr error
}

func newFakeAdminStore() *fakeAdminStore {
	return &fakeAdminStore{
		details:   map[uuid.UUID]*AgentDetail{},
		disabled:  map[uuid.UUID]bool{},
		policies:  map[uuid.UUID]*Policy{},
		versions:  map[uuid.UUID][]PolicyVersion{},
		binds:     map[uuid.UUID]uuid.UUID{},
		overrides: map[uuid.UUID][]CaptureOverride{},
	}
}

func (f *fakeAdminStore) CreateEnrollmentToken(_ context.Context, tokenHash, label string, expiresAt time.Time, createdBy string) (*EnrollmentToken, error) {
	if f.createErr != nil {
		return nil, f.createErr
	}
	f.lastHash = tokenHash
	t := &EnrollmentToken{ID: uuid.New(), Label: label, ExpiresAt: expiresAt, CreatedBy: createdBy, CreatedAt: time.Now().UTC()}
	f.tokens = append(f.tokens, *t)
	return t, nil
}

func (f *fakeAdminStore) ListEnrollmentTokens(_ context.Context) ([]EnrollmentToken, error) {
	return f.tokens, nil
}

func (f *fakeAdminStore) RevokeEnrollmentToken(_ context.Context, id uuid.UUID, _ time.Time) error {
	if f.revokeErr != nil {
		return f.revokeErr
	}
	f.revokedID = id
	return nil
}

func (f *fakeAdminStore) Summary(_ context.Context) (Summary, error) {
	return Summary{Total: 4, Online: 1, Offline: 1, Degraded: 1, Disabled: 1}, nil
}

func (f *fakeAdminStore) ListAgents(_ context.Context, filter AgentFilter) ([]Agent, int64, error) {
	f.listFilter = filter
	return f.agents, int64(len(f.agents)), nil
}

func (f *fakeAdminStore) GetAgent(_ context.Context, agentID uuid.UUID) (*AgentDetail, error) {
	if d, ok := f.details[agentID]; ok {
		return d, nil
	}
	return nil, ErrAgentNotFound
}

func (f *fakeAdminStore) SetAgentDisabled(_ context.Context, agentID uuid.UUID, disabled bool) error {
	if _, ok := f.details[agentID]; !ok {
		return ErrAgentNotFound
	}
	f.disabled[agentID] = disabled
	return nil
}

func (f *fakeAdminStore) DeleteAgent(_ context.Context, agentID uuid.UUID) error {
	if _, ok := f.details[agentID]; !ok {
		return ErrAgentNotFound
	}
	f.deleted = append(f.deleted, agentID)
	return nil
}

func (f *fakeAdminStore) ListFlowEvents(_ context.Context, _ uuid.UUID, p PageParams) ([]FlowEventRow, int64, error) {
	f.eventsPage = p
	return f.events, int64(len(f.events)), nil
}

func (f *fakeAdminStore) ListHTTPEvents(_ context.Context, _ uuid.UUID, fl HTTPEventFilter) ([]HTTPEventRow, int64, error) {
	f.httpFilter = fl
	return f.httpEvents, int64(len(f.httpEvents)), nil
}

func (f *fakeAdminStore) GetHTTPEvent(_ context.Context, agentID uuid.UUID, id int64) (*HTTPEventRow, error) {
	if f.httpDetail != nil && f.httpDetail.AgentID == agentID && f.httpDetail.ID == id {
		return f.httpDetail, nil
	}
	return nil, ErrHTTPEventNotFound
}

func (f *fakeAdminStore) ListHTTPAssetSources(_ context.Context, _ uuid.UUID, fl HTTPAssetSourceFilter) ([]HTTPAssetSourceRow, int64, error) {
	f.assetSourceFilter = fl
	return f.assetSources, int64(len(f.assetSources)), nil
}

func (f *fakeAdminStore) CreatePolicy(_ context.Context, name string, config []byte, createdBy string) (*Policy, error) {
	if f.policyErr != nil {
		return nil, f.policyErr
	}
	for _, p := range f.policies {
		if p.Name == name {
			return nil, ErrPolicyNameConflict
		}
	}
	p := &Policy{ID: uuid.New(), Name: name, Config: config, Version: 1, CreatedBy: createdBy,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	f.policies[p.ID] = p
	f.versions[p.ID] = append(f.versions[p.ID], PolicyVersion{
		PolicyID: p.ID, Version: 1, Config: config, CreatedBy: createdBy, CreatedAt: time.Now().UTC(),
	})
	return p, nil
}

func (f *fakeAdminStore) ListPolicies(_ context.Context) ([]Policy, error) {
	out := []Policy{}
	for _, p := range f.policies {
		out = append(out, *p)
	}
	return out, nil
}

func (f *fakeAdminStore) GetPolicy(_ context.Context, id uuid.UUID) (*Policy, error) {
	if p, ok := f.policies[id]; ok {
		cp := *p
		return &cp, nil
	}
	return nil, ErrPolicyNotFound
}

func (f *fakeAdminStore) UpdatePolicy(_ context.Context, id uuid.UUID, name string, config []byte, actor string) (*Policy, error) {
	p, ok := f.policies[id]
	if !ok {
		return nil, ErrPolicyNotFound
	}
	cp := *p
	cp.Name = name
	cp.Config = config
	cp.Version++
	f.policies[id] = &cp
	f.versions[id] = append(f.versions[id], PolicyVersion{
		PolicyID: id, Version: cp.Version, Config: config, CreatedBy: actor, CreatedAt: time.Now().UTC(),
	})
	f.cfgBumped++
	return &cp, nil
}

func (f *fakeAdminStore) ListPolicyVersions(_ context.Context, policyID uuid.UUID) ([]PolicyVersion, error) {
	if _, ok := f.policies[policyID]; !ok {
		return nil, ErrPolicyNotFound
	}
	out := []PolicyVersion{}
	for i := len(f.versions[policyID]) - 1; i >= 0; i-- {
		out = append(out, f.versions[policyID][i])
	}
	return out, nil
}

func (f *fakeAdminStore) RollbackPolicy(_ context.Context, id uuid.UUID, version int, actor string) (*Policy, error) {
	p, ok := f.policies[id]
	if !ok {
		return nil, ErrPolicyNotFound
	}
	var config []byte
	for _, v := range f.versions[id] {
		if v.Version == version {
			config = v.Config
			break
		}
	}
	if config == nil {
		return nil, ErrPolicyVersionNotFound
	}
	cp := *p
	cp.Config = config
	cp.Version++
	f.policies[id] = &cp
	f.versions[id] = append(f.versions[id], PolicyVersion{
		PolicyID: id, Version: cp.Version, Config: config, CreatedBy: actor, CreatedAt: time.Now().UTC(),
	})
	f.cfgBumped++
	return &cp, nil
}

func (f *fakeAdminStore) DeletePolicy(_ context.Context, id uuid.UUID) error {
	if _, ok := f.policies[id]; !ok {
		return ErrPolicyNotFound
	}
	for _, pid := range f.binds {
		if pid == id {
			return ErrPolicyBound
		}
	}
	delete(f.policies, id)
	return nil
}

func (f *fakeAdminStore) BindPolicy(_ context.Context, agentID, policyID uuid.UUID, _ string) error {
	if _, ok := f.details[agentID]; !ok {
		return ErrAgentNotFound
	}
	if _, ok := f.policies[policyID]; !ok {
		return ErrPolicyNotFound
	}
	f.binds[agentID] = policyID
	f.cfgBumped++
	return nil
}

func (f *fakeAdminStore) UnbindPolicy(_ context.Context, agentID uuid.UUID) error {
	if f.unbindErr != nil {
		return f.unbindErr
	}
	if _, ok := f.details[agentID]; !ok {
		return ErrAgentNotFound
	}
	if _, ok := f.binds[agentID]; !ok {
		return ErrNoBinding
	}
	delete(f.binds, agentID)
	f.cfgBumped++
	return nil
}

// ListCaptureOverrides 规则列表（含已过期——管理端标注 inactive）。
func (f *fakeAdminStore) ListCaptureOverrides(_ context.Context, agentID uuid.UUID) ([]CaptureOverride, error) {
	return f.overrides[agentID], nil
}

// CreateCaptureOverride 创建规则（同事务 config_version+1 以 cfgBumped 计数模拟）。
func (f *fakeAdminStore) CreateCaptureOverride(_ context.Context, in CaptureOverrideInput) (*CaptureOverride, error) {
	if f.overrideErr != nil {
		return nil, f.overrideErr
	}
	if _, ok := f.details[in.AgentID]; !ok {
		return nil, ErrAgentNotFound
	}
	o := &CaptureOverride{
		ID:           uuid.New(),
		AgentID:      in.AgentID,
		Match:        in.Match,
		CaptureLevel: in.CaptureLevel,
		Note:         in.Note,
		CreatedBy:    in.CreatedBy,
		CreatedAt:    in.Now,
		ExpiresAt:    in.ExpiresAt,
	}
	f.overrides[in.AgentID] = append(f.overrides[in.AgentID], *o)
	f.cfgBumped++
	return o, nil
}

// DeleteCaptureOverride 删除规则（返回被删行供审计；同事务 config_version+1）。
func (f *fakeAdminStore) DeleteCaptureOverride(_ context.Context, agentID, overrideID uuid.UUID, _ time.Time) (*CaptureOverride, error) {
	if f.overrideErr != nil {
		return nil, f.overrideErr
	}
	list := f.overrides[agentID]
	for i, o := range list {
		if o.ID == overrideID {
			f.overrides[agentID] = append(list[:i], list[i+1:]...)
			f.cfgBumped++
			cp := o
			return &cp, nil
		}
	}
	return nil, ErrCaptureOverrideNotFound
}

// spyAudits 审计间谍。
type spyAudits struct{ entries []audits.RecordInput }

func (s *spyAudits) Record(_ context.Context, in audits.RecordInput) error {
	s.entries = append(s.entries, in)
	return nil
}

// injectPerms 注入式 authz（注入主体与权限集，替代真实会话链）。
func injectPerms(perms ...string) func(http.Handler) http.Handler {
	set := map[string]bool{}
	for _, p := range perms {
		set[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "admin-it", PermsSet: set}
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
		})
	}
}

func newAdminMux(h *Handler, inject func(http.Handler) http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterAdminRoutes(mux, inject, h)
	return mux
}

func doAdmin(t *testing.T, mux http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

// decodeEnvelope 解管理端统一响应信封（response.Body{code,message,data,request_id}），
// 将 data 载荷解码到 dst。管理端点自契约勘误后一律走信封（机器端点裸 JSON 不在此列）。
func decodeEnvelope(t *testing.T, rr *httptest.ResponseRecorder, dst interface{}) {
	t.Helper()
	var env struct {
		Code string          `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("信封解码失败: %v (body=%s)", err, rr.Body.String())
	}
	if env.Code != "SUCCESS" {
		t.Fatalf("信封 code = %q, want SUCCESS (body=%s)", env.Code, rr.Body.String())
	}
	if err := json.Unmarshal(env.Data, dst); err != nil {
		t.Fatalf("data 解码失败: %v", err)
	}
}

// seedAgentDetail 在 fake 中放入一个 Agent 详情。
func seedAgentDetail(f *fakeAdminStore, agentID uuid.UUID, disabled bool) {
	f.details[agentID] = &AgentDetail{
		Agent:      Agent{AgentID: agentID, Hostname: "web-prod-01", IP: "10.0.1.10", Disabled: disabled},
		Interfaces: []InterfaceInfo{{Name: "eth0", MTU: 1500}},
	}
}

// ---------- 注册令牌 ----------

// TestCreateToken 签发：ttl 范围校验；明文仅此一次返回；服务端只存摘要；HIGH 审计。
func TestCreateToken(t *testing.T) {
	t.Run("ttl 越界 400", func(t *testing.T) {
		for _, body := range []string{
			`{"label":"x","ttl_minutes":4}`,
			`{"label":"x","ttl_minutes":10081}`,
			`{"label":"x","ttl_minutes":0}`,
		} {
			store := newFakeAdminStore()
			h := NewHandler(store).SetAudits(&spyAudits{})
			rr := doAdmin(t, newAdminMux(h, injectPerms(PermAgentsManage)), http.MethodPost,
				"/api/v1/traffic/agents/enrollment-tokens", body)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("body=%s status = %d, want 400", body, rr.Code)
			}
			// 错误同样走统一信封（code=INVALID_ARGUMENT）
			var env struct {
				Code string `json:"code"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil || env.Code != "INVALID_ARGUMENT" {
				t.Fatalf("错误信封 code = %q, want INVALID_ARGUMENT (body=%s)", env.Code, rr.Body.String())
			}
		}
	})
	t.Run("ttl 边界放行", func(t *testing.T) {
		for _, ttl := range []int{5, 10080} {
			store := newFakeAdminStore()
			h := NewHandler(store).SetAudits(&spyAudits{})
			body := `{"label":"edge","ttl_minutes":` + strings.TrimSpace(strings.Repeat(" ", 0)) +
				strings.TrimSpace(jsonNumber(ttl)) + `}`
			rr := doAdmin(t, newAdminMux(h, injectPerms(PermAgentsManage)), http.MethodPost,
				"/api/v1/traffic/agents/enrollment-tokens", body)
			if rr.Code != http.StatusCreated {
				t.Fatalf("ttl=%d status = %d, want 201 (body=%s)", ttl, rr.Code, rr.Body.String())
			}
		}
	})
	t.Run("成功签发", func(t *testing.T) {
		store := newFakeAdminStore()
		spy := &spyAudits{}
		h := NewHandler(store).SetAudits(spy)
		rr := doAdmin(t, newAdminMux(h, injectPerms(PermAgentsManage)), http.MethodPost,
			"/api/v1/traffic/agents/enrollment-tokens", `{"label":"prod-web","ttl_minutes":60}`)
		if rr.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201 (body=%s)", rr.Code, rr.Body.String())
		}
		var resp struct {
			ID        string `json:"id"`
			Token     string `json:"token"`
			ExpiresAt string `json:"expires_at"`
		}
		decodeEnvelope(t, rr, &resp)
		if _, err := uuid.Parse(resp.ID); err != nil {
			t.Errorf("id 非 UUID: %q", resp.ID)
		}
		if !enrollmentTokenPattern.MatchString(resp.Token) {
			t.Errorf("token 明文格式非法: %q", resp.Token)
		}
		if _, err := time.Parse(time.RFC3339, resp.ExpiresAt); err != nil {
			t.Errorf("expires_at 非 RFC3339: %q", resp.ExpiresAt)
		}
		// 服务端只收摘要
		if store.lastHash != HashSecret(resp.Token) {
			t.Error("令牌未按 SHA-256 摘要落库")
		}
		// 审计：create / HIGH / module=traffic-agents / after 为合法 JSON 且不含明文
		if len(spy.entries) != 1 {
			t.Fatalf("audit entries = %d, want 1", len(spy.entries))
		}
		e := spy.entries[0]
		if e.Module != auditModule || e.Action != "create" || e.RiskLevel != audits.RiskHigh ||
			e.ObjectType != "agent_enrollment_token" || e.ObjectName != "prod-web" {
			t.Errorf("audit = %+v", e)
		}
		if !json.Valid([]byte(e.AfterSummary)) {
			t.Errorf("AfterSummary 非合法 JSON: %q", e.AfterSummary)
		}
		if strings.Contains(e.AfterSummary, resp.Token) {
			t.Error("审计摘要不得含令牌明文")
		}
	})
	t.Run("view 权限不足 403", func(t *testing.T) {
		store := newFakeAdminStore()
		h := NewHandler(store)
		rr := doAdmin(t, newAdminMux(h, injectPerms(PermAgentsView)), http.MethodPost,
			"/api/v1/traffic/agents/enrollment-tokens", `{"label":"x","ttl_minutes":60}`)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rr.Code)
		}
	})
}

// jsonNumber int → JSON 数字字面量（测试拼装辅助）。
func jsonNumber(n int) string {
	raw, _ := json.Marshal(n)
	return string(raw)
}

// TestRevokeToken 撤销：404 / 409 / 204+审计。
func TestRevokeToken(t *testing.T) {
	t.Run("不存在 404", func(t *testing.T) {
		store := newFakeAdminStore()
		store.revokeErr = ErrTokenNotFound
		h := NewHandler(store)
		rr := doAdmin(t, newAdminMux(h, injectPerms(PermAgentsManage)), http.MethodPost,
			"/api/v1/traffic/agents/enrollment-tokens/"+uuid.NewString()+"/revoke", "")
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rr.Code)
		}
	})
	t.Run("已使用/已撤销 409", func(t *testing.T) {
		store := newFakeAdminStore()
		store.revokeErr = ErrTokenState
		h := NewHandler(store)
		rr := doAdmin(t, newAdminMux(h, injectPerms(PermAgentsManage)), http.MethodPost,
			"/api/v1/traffic/agents/enrollment-tokens/"+uuid.NewString()+"/revoke", "")
		if rr.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409", rr.Code)
		}
	})
	t.Run("成功 204 + 审计", func(t *testing.T) {
		store := newFakeAdminStore()
		spy := &spyAudits{}
		h := NewHandler(store).SetAudits(spy)
		id := uuid.New()
		rr := doAdmin(t, newAdminMux(h, injectPerms(PermAgentsManage)), http.MethodPost,
			"/api/v1/traffic/agents/enrollment-tokens/"+id.String()+"/revoke", "")
		if rr.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", rr.Code)
		}
		if store.revokedID != id {
			t.Error("撤销未透传到仓储")
		}
		if len(spy.entries) != 1 || spy.entries[0].Action != "revoke" || spy.entries[0].RiskLevel != audits.RiskHigh {
			t.Fatalf("audit = %+v", spy.entries)
		}
	})
}

// TestListTokens 列表不含明文/摘要，含派生状态。
func TestListTokens(t *testing.T) {
	store := newFakeAdminStore()
	now := time.Now().UTC()
	usedAt := now.Add(-time.Hour)
	revokedAt := now.Add(-time.Minute)
	store.tokens = []EnrollmentToken{
		{ID: uuid.New(), Label: "active", ExpiresAt: now.Add(time.Hour)},
		{ID: uuid.New(), Label: "used", ExpiresAt: now.Add(time.Hour), UsedAt: &usedAt},
		{ID: uuid.New(), Label: "revoked", ExpiresAt: now.Add(time.Hour), RevokedAt: &revokedAt},
		{ID: uuid.New(), Label: "expired", ExpiresAt: now.Add(-time.Minute)},
	}
	h := NewHandler(store)
	rr := doAdmin(t, newAdminMux(h, injectPerms(PermAgentsView)), http.MethodGet,
		"/api/v1/traffic/agents/enrollment-tokens", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var resp struct {
		Items []struct {
			Label  string `json:"label"`
			Status string `json:"status"`
		} `json:"items"`
		Total int `json:"total"`
	}
	decodeEnvelope(t, rr, &resp)
	if resp.Total != 4 || len(resp.Items) != 4 {
		t.Fatalf("resp = %+v", resp)
	}
	want := map[string]string{"active": "ACTIVE", "used": "USED", "revoked": "REVOKED", "expired": "EXPIRED"}
	for _, it := range resp.Items {
		if want[it.Label] != it.Status {
			t.Errorf("label=%s status=%q, want %q", it.Label, it.Status, want[it.Label])
		}
	}
	if strings.Contains(rr.Body.String(), "token_hash") {
		t.Error("列表不得输出摘要字段")
	}
}

// ---------- Agent 管理 ----------

// TestDisableEnableAgent 禁用/启用：204 + before/after 审计；404。
func TestDisableEnableAgent(t *testing.T) {
	t.Run("禁用 204 + 审计", func(t *testing.T) {
		store := newFakeAdminStore()
		spy := &spyAudits{}
		agentID := uuid.New()
		seedAgentDetail(store, agentID, false)
		h := NewHandler(store).SetAudits(spy)
		rr := doAdmin(t, newAdminMux(h, injectPerms(PermAgentsManage)), http.MethodPost,
			"/api/v1/traffic/agents/"+agentID.String()+"/disable", "")
		if rr.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204 (body=%s)", rr.Code, rr.Body.String())
		}
		if !store.disabled[agentID] {
			t.Error("禁用未落库")
		}
		if len(spy.entries) != 1 {
			t.Fatalf("audit entries = %d, want 1", len(spy.entries))
		}
		e := spy.entries[0]
		if e.Module != auditModule || e.Action != "disable" || e.RiskLevel != audits.RiskHigh ||
			e.ObjectType != "agent" || e.ObjectID != agentID.String() || e.ObjectName != "web-prod-01" {
			t.Errorf("audit = %+v", e)
		}
		if e.BeforeSummary != `{"disabled":false}` || e.AfterSummary != `{"disabled":true}` {
			t.Errorf("before/after = %q -> %q", e.BeforeSummary, e.AfterSummary)
		}
	})
	t.Run("启用 204", func(t *testing.T) {
		store := newFakeAdminStore()
		agentID := uuid.New()
		seedAgentDetail(store, agentID, true)
		h := NewHandler(store).SetAudits(&spyAudits{})
		rr := doAdmin(t, newAdminMux(h, injectPerms(PermAgentsManage)), http.MethodPost,
			"/api/v1/traffic/agents/"+agentID.String()+"/enable", "")
		if rr.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", rr.Code)
		}
		if store.disabled[agentID] {
			t.Error("启用未落库")
		}
	})
	t.Run("不存在 404", func(t *testing.T) {
		store := newFakeAdminStore()
		h := NewHandler(store)
		rr := doAdmin(t, newAdminMux(h, injectPerms(PermAgentsManage)), http.MethodPost,
			"/api/v1/traffic/agents/"+uuid.NewString()+"/disable", "")
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rr.Code)
		}
	})
}

// TestDeleteAgent 删除：204 + 审计 before 含概要、不含 credential 摘要。
func TestDeleteAgent(t *testing.T) {
	store := newFakeAdminStore()
	spy := &spyAudits{}
	agentID := uuid.New()
	seedAgentDetail(store, agentID, false)
	h := NewHandler(store).SetAudits(spy)
	rr := doAdmin(t, newAdminMux(h, injectPerms(PermAgentsManage)), http.MethodDelete,
		"/api/v1/traffic/agents/"+agentID.String(), "")
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rr.Code)
	}
	if len(store.deleted) != 1 || store.deleted[0] != agentID {
		t.Fatalf("deleted = %v", store.deleted)
	}
	if len(spy.entries) != 1 || spy.entries[0].Action != "delete" {
		t.Fatalf("audit = %+v", spy.entries)
	}
	e := spy.entries[0]
	if !json.Valid([]byte(e.BeforeSummary)) || !strings.Contains(e.BeforeSummary, "web-prod-01") {
		t.Errorf("BeforeSummary = %q", e.BeforeSummary)
	}
	if strings.Contains(e.BeforeSummary, "credential") {
		t.Error("审计摘要不得含 credential 信息")
	}
}

// TestListAgentsFilter 列表：status 过滤值校验；q/分页透传钳制。
func TestListAgentsFilter(t *testing.T) {
	t.Run("status 非法 400", func(t *testing.T) {
		store := newFakeAdminStore()
		h := NewHandler(store)
		rr := doAdmin(t, newAdminMux(h, injectPerms(PermAgentsView)), http.MethodGet,
			"/api/v1/traffic/agents?status=SLEEPING", "")
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})
	t.Run("分页钳制透传", func(t *testing.T) {
		store := newFakeAdminStore()
		h := NewHandler(store)
		rr := doAdmin(t, newAdminMux(h, injectPerms(PermAgentsView)), http.MethodGet,
			"/api/v1/traffic/agents?status=ONLINE&q=web&page=-2&page_size=999", "")
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
		}
		f := store.listFilter
		if f.Status != "ONLINE" || f.Q != "web" || f.Page.Page != 1 || f.Page.PageSize != 100 {
			t.Errorf("filter = %+v, want status=ONLINE q=web page=1 size=100", f)
		}
	})
	t.Run("匿名 401", func(t *testing.T) {
		store := newFakeAdminStore()
		h := NewHandler(store)
		anon := func(next http.Handler) http.Handler { return next }
		rr := doAdmin(t, newAdminMux(h, anon), http.MethodGet, "/api/v1/traffic/agents", "")
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rr.Code)
		}
	})
}

// TestGetAgentDetail 详情含 interfaces 与 policy_binding，status 为派生。
func TestGetAgentDetail(t *testing.T) {
	store := newFakeAdminStore()
	agentID := uuid.New()
	seedAgentDetail(store, agentID, false)
	store.details[agentID].PolicyBinding = &PolicyBinding{
		PolicyID: uuid.New(), PolicyName: "production-web", PolicyVersion: 3, BoundAt: time.Now().UTC(),
	}
	h := NewHandler(store)
	rr := doAdmin(t, newAdminMux(h, injectPerms(PermAgentsView)), http.MethodGet,
		"/api/v1/traffic/agents/"+agentID.String(), "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
	}
	var resp struct {
		Status     string `json:"status"`
		Interfaces []struct {
			Name string `json:"name"`
		} `json:"interfaces"`
		PolicyBinding *struct {
			PolicyName string `json:"policy_name"`
		} `json:"policy_binding"`
	}
	decodeEnvelope(t, rr, &resp)
	if resp.Status != StatusOffline { // 从未心跳 → OFFLINE（DeriveStatus）
		t.Errorf("status = %q, want OFFLINE", resp.Status)
	}
	if len(resp.Interfaces) != 1 || resp.Interfaces[0].Name != "eth0" {
		t.Errorf("interfaces = %+v", resp.Interfaces)
	}
	if resp.PolicyBinding == nil || resp.PolicyBinding.PolicyName != "production-web" {
		t.Errorf("policy_binding = %+v", resp.PolicyBinding)
	}
}

// TestListEvents 事件分页：Agent 不存在 404；分页钳制透传。
func TestListEvents(t *testing.T) {
	t.Run("Agent 不存在 404", func(t *testing.T) {
		store := newFakeAdminStore()
		h := NewHandler(store)
		rr := doAdmin(t, newAdminMux(h, injectPerms(PermAgentsView)), http.MethodGet,
			"/api/v1/traffic/agents/"+uuid.NewString()+"/events", "")
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rr.Code)
		}
	})
	t.Run("分页钳制透传", func(t *testing.T) {
		store := newFakeAdminStore()
		agentID := uuid.New()
		seedAgentDetail(store, agentID, false)
		h := NewHandler(store)
		rr := doAdmin(t, newAdminMux(h, injectPerms(PermAgentsView)), http.MethodGet,
			"/api/v1/traffic/agents/"+agentID.String()+"/events?page=2&page_size=500", "")
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rr.Code)
		}
		if store.eventsPage.Page != 2 || store.eventsPage.PageSize != 100 {
			t.Errorf("page = %+v, want page=2 size=100", store.eventsPage)
		}
	})
}

// TestSummaryEndpoint 状态汇总透传。
func TestSummaryEndpoint(t *testing.T) {
	store := newFakeAdminStore()
	h := NewHandler(store)
	rr := doAdmin(t, newAdminMux(h, injectPerms(PermAgentsView)), http.MethodGet,
		"/api/v1/traffic/agents/summary", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	var sum Summary
	decodeEnvelope(t, rr, &sum)
	if sum.Total != 4 || sum.Online+sum.Offline+sum.Degraded+sum.Disabled != sum.Total {
		t.Errorf("summary = %+v", sum)
	}
}

// ---------- 策略 ----------

// policyBody 构造策略请求体（name + 契约 config）。
func policyBody(name string) string {
	var cfg map[string]interface{}
	_ = json.Unmarshal(validPolicyJSON(), &cfg)
	cfg["name"] = name
	rawCfg, _ := json.Marshal(cfg)
	raw, _ := json.Marshal(map[string]interface{}{"name": name, "config": json.RawMessage(rawCfg)})
	return string(raw)
}

// TestPolicyCRUD 策略 CRUD：校验失败 400 / 冲突 409 / 创建 201 / 修改 version+1 / 删除绑定 409。
func TestPolicyCRUD(t *testing.T) {
	t.Run("config 非法 400", func(t *testing.T) {
		store := newFakeAdminStore()
		h := NewHandler(store)
		raw, _ := json.Marshal(map[string]interface{}{
			"name":   "bad",
			"config": json.RawMessage(`{"name":"bad","capture":{"direction":"sideways"}}`),
		})
		rr := doAdmin(t, newAdminMux(h, injectPerms(PermAgentsManage)), http.MethodPost,
			"/api/v1/traffic/policies", string(raw))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})
	t.Run("name 与 config.name 不一致 400", func(t *testing.T) {
		store := newFakeAdminStore()
		h := NewHandler(store)
		raw, _ := json.Marshal(map[string]interface{}{
			"name":   "outer-name",
			"config": json.RawMessage(validPolicyJSON()), // 内层 name=production-web
		})
		rr := doAdmin(t, newAdminMux(h, injectPerms(PermAgentsManage)), http.MethodPost,
			"/api/v1/traffic/policies", string(raw))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rr.Code)
		}
	})
	t.Run("创建 201 + 审计", func(t *testing.T) {
		store := newFakeAdminStore()
		spy := &spyAudits{}
		h := NewHandler(store).SetAudits(spy)
		rr := doAdmin(t, newAdminMux(h, injectPerms(PermAgentsManage)), http.MethodPost,
			"/api/v1/traffic/policies", policyBody("production-web"))
		if rr.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201 (body=%s)", rr.Code, rr.Body.String())
		}
		var resp Policy
		decodeEnvelope(t, rr, &resp)
		if resp.Version != 1 || resp.Name != "production-web" {
			t.Errorf("policy = %+v", resp)
		}
		if len(spy.entries) != 1 || spy.entries[0].Action != "create" ||
			spy.entries[0].RiskLevel != audits.RiskHigh || spy.entries[0].Module != auditModule {
			t.Fatalf("audit = %+v", spy.entries)
		}
		if !json.Valid([]byte(spy.entries[0].AfterSummary)) {
			t.Errorf("AfterSummary 非合法 JSON: %q", spy.entries[0].AfterSummary)
		}
	})
	t.Run("重名 409", func(t *testing.T) {
		store := newFakeAdminStore()
		h := NewHandler(store)
		mux := newAdminMux(h, injectPerms(PermAgentsManage))
		if rr := doAdmin(t, mux, http.MethodPost, "/api/v1/traffic/policies", policyBody("dup")); rr.Code != http.StatusCreated {
			t.Fatalf("首次创建 status = %d", rr.Code)
		}
		rr := doAdmin(t, mux, http.MethodPost, "/api/v1/traffic/policies", policyBody("dup"))
		if rr.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409", rr.Code)
		}
	})
	t.Run("修改 version+1", func(t *testing.T) {
		store := newFakeAdminStore()
		spy := &spyAudits{}
		h := NewHandler(store).SetAudits(spy)
		mux := newAdminMux(h, injectPerms(PermAgentsManage))
		rr := doAdmin(t, mux, http.MethodPost, "/api/v1/traffic/policies", policyBody("p1"))
		if rr.Code != http.StatusCreated {
			t.Fatalf("创建 status = %d", rr.Code)
		}
		var created Policy
		decodeEnvelope(t, rr, &created)
		rr = doAdmin(t, mux, http.MethodPut, "/api/v1/traffic/policies/"+created.ID.String(), policyBody("p1"))
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", rr.Code, rr.Body.String())
		}
		var updated Policy
		decodeEnvelope(t, rr, &updated)
		if updated.Version != 2 {
			t.Errorf("version = %d, want 2", updated.Version)
		}
		if store.cfgBumped != 1 {
			t.Error("策略修改未触发绑定 Agent config_version 递增（仓储层调用）")
		}
		last := spy.entries[len(spy.entries)-1]
		if last.Action != "update" || !strings.Contains(last.BeforeSummary, `"version":1`) ||
			!strings.Contains(last.AfterSummary, `"version":2`) {
			t.Errorf("update audit = %+v", last)
		}
	})
	t.Run("删除被绑定策略 409", func(t *testing.T) {
		store := newFakeAdminStore()
		h := NewHandler(store)
		mux := newAdminMux(h, injectPerms(PermAgentsManage))
		rr := doAdmin(t, mux, http.MethodPost, "/api/v1/traffic/policies", policyBody("bound"))
		var created Policy
		decodeEnvelope(t, rr, &created)
		agentID := uuid.New()
		seedAgentDetail(store, agentID, false)
		store.binds[agentID] = created.ID
		rr = doAdmin(t, mux, http.MethodDelete, "/api/v1/traffic/policies/"+created.ID.String(), "")
		if rr.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409", rr.Code)
		}
	})
	t.Run("删除 204 + 审计", func(t *testing.T) {
		store := newFakeAdminStore()
		spy := &spyAudits{}
		h := NewHandler(store).SetAudits(spy)
		mux := newAdminMux(h, injectPerms(PermAgentsManage))
		rr := doAdmin(t, mux, http.MethodPost, "/api/v1/traffic/policies", policyBody("gone"))
		var created Policy
		decodeEnvelope(t, rr, &created)
		rr = doAdmin(t, mux, http.MethodDelete, "/api/v1/traffic/policies/"+created.ID.String(), "")
		if rr.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", rr.Code)
		}
		last := spy.entries[len(spy.entries)-1]
		if last.Action != "delete" || last.ObjectType != "agent_policy" || last.RiskLevel != audits.RiskHigh {
			t.Errorf("delete audit = %+v", last)
		}
	})
}

// TestPolicyBinding 绑定/换绑/解绑：404 矩阵与审计。
func TestPolicyBinding(t *testing.T) {
	setup := func() (*fakeAdminStore, *spyAudits, *http.ServeMux, uuid.UUID, uuid.UUID) {
		store := newFakeAdminStore()
		spy := &spyAudits{}
		h := NewHandler(store).SetAudits(spy)
		mux := newAdminMux(h, injectPerms(PermAgentsManage))
		rr := doAdmin(t, mux, http.MethodPost, "/api/v1/traffic/policies", policyBody("bind-me"))
		var created Policy
		decodeEnvelope(t, rr, &created)
		agentID := uuid.New()
		seedAgentDetail(store, agentID, false)
		return store, spy, mux, agentID, created.ID
	}

	t.Run("绑定 204 + 审计", func(t *testing.T) {
		store, spy, mux, agentID, policyID := setup()
		rr := doAdmin(t, mux, http.MethodPost, "/api/v1/traffic/agents/"+agentID.String()+"/policy",
			`{"policy_id":"`+policyID.String()+`"}`)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204 (body=%s)", rr.Code, rr.Body.String())
		}
		if store.binds[agentID] != policyID {
			t.Error("绑定未落库")
		}
		last := spy.entries[len(spy.entries)-1]
		if last.Action != "bind" || last.ObjectType != "agent_policy_binding" || last.RiskLevel != audits.RiskHigh {
			t.Errorf("bind audit = %+v", last)
		}
		if !json.Valid([]byte(last.BeforeSummary)) || !json.Valid([]byte(last.AfterSummary)) {
			t.Errorf("before/after 非合法 JSON: %q -> %q", last.BeforeSummary, last.AfterSummary)
		}
	})
	t.Run("换绑（重复绑定即换绑）", func(t *testing.T) {
		store, _, mux, agentID, policyID := setup()
		doAdmin(t, mux, http.MethodPost, "/api/v1/traffic/agents/"+agentID.String()+"/policy",
			`{"policy_id":"`+policyID.String()+`"}`)
		// 第二策略换绑
		rr := doAdmin(t, mux, http.MethodPost, "/api/v1/traffic/policies", policyBody("second"))
		var second Policy
		decodeEnvelope(t, rr, &second)
		rr = doAdmin(t, mux, http.MethodPost, "/api/v1/traffic/agents/"+agentID.String()+"/policy",
			`{"policy_id":"`+second.ID.String()+`"}`)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204", rr.Code)
		}
		if store.binds[agentID] != second.ID {
			t.Error("换绑未生效（每 Agent 应仅一条生效绑定）")
		}
	})
	t.Run("策略不存在 404", func(t *testing.T) {
		_, _, mux, agentID, _ := setup()
		rr := doAdmin(t, mux, http.MethodPost, "/api/v1/traffic/agents/"+agentID.String()+"/policy",
			`{"policy_id":"`+uuid.NewString()+`"}`)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rr.Code)
		}
	})
	t.Run("Agent 不存在 404", func(t *testing.T) {
		_, _, mux, _, policyID := setup()
		rr := doAdmin(t, mux, http.MethodPost, "/api/v1/traffic/agents/"+uuid.NewString()+"/policy",
			`{"policy_id":"`+policyID.String()+`"}`)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rr.Code)
		}
	})
	t.Run("解绑 204 + 审计", func(t *testing.T) {
		store, spy, mux, agentID, policyID := setup()
		store.binds[agentID] = policyID
		rr := doAdmin(t, mux, http.MethodDelete, "/api/v1/traffic/agents/"+agentID.String()+"/policy", "")
		if rr.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204 (body=%s)", rr.Code, rr.Body.String())
		}
		if _, ok := store.binds[agentID]; ok {
			t.Error("解绑未落库")
		}
		last := spy.entries[len(spy.entries)-1]
		if last.Action != "unbind" || last.RiskLevel != audits.RiskHigh {
			t.Errorf("unbind audit = %+v", last)
		}
	})
	t.Run("无绑定解绑 404", func(t *testing.T) {
		_, _, mux, agentID, _ := setup()
		rr := doAdmin(t, mux, http.MethodDelete, "/api/v1/traffic/agents/"+agentID.String()+"/policy", "")
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rr.Code)
		}
	})
}
