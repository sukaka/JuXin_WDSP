// agents_handler_test.go Agent 控制面管理接口单元测试（httptest + fake AgentRepository +
// spy 审计；覆盖令牌创建校验、列表过滤校验、撤销分支、策略发布版本/签名/审计纪律）。
package apm

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
)

// ---------- fake AgentRepository（内存版；记录调用、可注入错误） ----------

type fakeAgentRepo struct {
	mu sync.Mutex

	appExists    bool
	tokens       map[string]*EnrollmentTokenRow // hash → row
	agents       map[uuid.UUID]*AgentRow
	byFP         map[string]*AgentRow
	revokedFPs   map[string]bool
	policies     map[string][]*PolicyRow // scope → versions
	services     map[string]*AgentServiceRow
	superseded   int
	heartbeats   []uuid.UUID
	rotations    []string
	tokenErr     error
	policyErr    error
	claimErr     error // EnrollAgent 认领步骤注入错误（验证回滚语义）
	supersedeErr error // EnrollAgent 顶替步骤注入错误
	insertErr    error // EnrollAgent 登记步骤注入错误
	conflictVer  bool  // CreatePolicyVersion 恒返回版本冲突（竞态分支）
}

func newFakeAgentRepo() *fakeAgentRepo {
	return &fakeAgentRepo{
		appExists:  true,
		tokens:     map[string]*EnrollmentTokenRow{},
		agents:     map[uuid.UUID]*AgentRow{},
		byFP:       map[string]*AgentRow{},
		revokedFPs: map[string]bool{},
		policies:   map[string][]*PolicyRow{},
		services:   map[string]*AgentServiceRow{},
	}
}

func (f *fakeAgentRepo) ApplicationExists(context.Context, uuid.UUID) (bool, error) {
	return f.appExists, nil
}

func (f *fakeAgentRepo) CreateEnrollmentToken(_ context.Context, row *EnrollmentTokenRow, tokenHash string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	row.ID = uuid.New()
	row.CreatedAt = time.Now().UTC()
	row.UsedAt = nil
	f.tokens[tokenHash] = row
	return nil
}

func (f *fakeAgentRepo) ListAgents(_ context.Context, filter AgentsFilter, offlineAfter time.Duration, now time.Time) ([]AgentRow, int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []AgentRow{}
	for _, a := range f.agents {
		a.Status = DeriveAgentStatus(a.StoredStatus, a.LastHeartbeatAt, a.RegisteredAt, offlineAfter, now)
		if filter.Status != "" && a.Status != filter.Status {
			continue
		}
		out = append(out, *a)
	}
	return out, int64(len(out)), nil
}

func (f *fakeAgentRepo) GetAgent(_ context.Context, id uuid.UUID) (*AgentRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.agents[id]
	if !ok {
		return nil, ErrAgentNotFound
	}
	cp := *a
	return &cp, nil
}

func (f *fakeAgentRepo) RevokeAgent(_ context.Context, id uuid.UUID, reason string, now time.Time) (*AgentRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.agents[id]
	if !ok {
		return nil, ErrAgentNotFound
	}
	if a.StoredStatus == AgentStatusRevoked {
		return nil, ErrAgentAlreadyRevoked
	}
	a.StoredStatus = AgentStatusRevoked
	a.RevokedAt = &now
	a.RevokeReason = reason
	f.revokedFPs[a.CertFingerprint] = true
	cp := *a
	return &cp, nil
}

func (f *fakeAgentRepo) LatestPolicy(_ context.Context, scope string) (*PolicyRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.latestPolicyLocked(scope)
}

func (f *fakeAgentRepo) latestPolicyLocked(scope string) (*PolicyRow, error) {
	if f.policyErr != nil {
		return nil, f.policyErr
	}
	versions := f.policies[scope]
	if len(versions) == 0 {
		return nil, ErrPolicyNotFound
	}
	return versions[len(versions)-1], nil
}

func (f *fakeAgentRepo) CreatePolicyVersion(_ context.Context, scope string, policy map[string]interface{},
	signature, keyID string, issuedAt, expiresAt time.Time, expectedVersion *int64, createdBy *uuid.UUID) (*PolicyRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.createPolicyVersionLocked(scope, policy, signature, keyID, issuedAt, expiresAt, expectedVersion, createdBy)
}

func (f *fakeAgentRepo) createPolicyVersionLocked(scope string, policy map[string]interface{},
	signature, keyID string, issuedAt, expiresAt time.Time, expectedVersion *int64, createdBy *uuid.UUID) (*PolicyRow, error) {
	if f.conflictVer {
		return nil, ErrPolicyVersionConflict
	}
	current := int64(len(f.policies[scope]))
	if expectedVersion != nil && *expectedVersion != current {
		return nil, ErrPolicyVersionConflict
	}
	row := &PolicyRow{
		ID: uuid.New(), Scope: scope, Version: current + 1, Policy: policy,
		Signature: signature, KeyID: keyID, IssuedAt: issuedAt, ExpiresAt: expiresAt, CreatedBy: createdBy,
	}
	f.policies[scope] = append(f.policies[scope], row)
	return row, nil
}

// fakePolicyStore 注册"事务"内的策略存取面（对齐真实 txPolicyStore：不加锁——
// 外层 EnrollAgent 已持锁，复用加锁版会自死锁）。
type fakePolicyStore struct{ f *fakeAgentRepo }

func (p fakePolicyStore) LatestPolicy(_ context.Context, scope string) (*PolicyRow, error) {
	return p.f.latestPolicyLocked(scope)
}

func (p fakePolicyStore) CreatePolicyVersion(_ context.Context, scope string, policy map[string]interface{},
	signature, keyID string, issuedAt, expiresAt time.Time, expectedVersion *int64, createdBy *uuid.UUID) (*PolicyRow, error) {
	return p.f.createPolicyVersionLocked(scope, policy, signature, keyID, issuedAt, expiresAt, expectedVersion, createdBy)
}

// EnrollAgent fake 版注册事务：校验/解析全部先行，状态变更集中在末尾一次应用
// （模拟单事务语义——任一步失败令牌不消费、存量不顶替、新 Agent 不登记；
// 策略版本表快照回滚以对齐真实实现的惰性创建回滚）。
func (f *fakeAgentRepo) EnrollAgent(ctx context.Context, params *EnrollAgentParams, resolvePolicy PolicyResolver) (*EnrollAgentResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tokenErr != nil {
		return nil, f.tokenErr
	}
	token, ok := f.tokens[params.TokenHash]
	if !ok || token.UsedAt != nil || !token.ExpiresAt.After(params.Now) {
		return nil, ErrTokenInvalid
	}
	if !token.LanguageAllowed(params.Language) {
		return nil, ErrTokenLanguageNotAllowed
	}
	if f.claimErr != nil {
		return nil, f.claimErr
	}
	key := params.ServiceName + "|" + token.Environment
	svc, exists := f.services[key]
	if exists && svc.ApplicationID != nil && token.ApplicationID != nil && *svc.ApplicationID != *token.ApplicationID {
		return nil, ErrServiceClaimConflict
	}
	appID := token.ApplicationID
	if exists && svc.ApplicationID != nil {
		appID = svc.ApplicationID
	}
	policiesSnap := make(map[string][]*PolicyRow, len(f.policies))
	for k, v := range f.policies {
		policiesSnap[k] = v
	}
	policy, err := resolvePolicy(ctx, fakePolicyStore{f: f}, appID)
	if err != nil {
		f.policies = policiesSnap
		return nil, err
	}
	if f.supersedeErr != nil {
		f.policies = policiesSnap
		return nil, f.supersedeErr
	}
	if f.insertErr != nil {
		f.policies = policiesSnap
		return nil, f.insertErr
	}
	// —— 以下全部为状态变更（真实实现中同事务提交）——
	now := params.Now
	token.UsedAt = &now
	token.UsedByAgentID = &params.Agent.ID
	if !exists {
		svc = &AgentServiceRow{ID: uuid.New(), ServiceName: params.ServiceName, Environment: token.Environment, ClaimStatus: "UNCLAIMED"}
		f.services[key] = svc
	}
	if svc.ApplicationID == nil && token.ApplicationID != nil {
		svc.ApplicationID = token.ApplicationID
		svc.ClaimStatus = "CLAIMED"
	}
	superseded := 0
	for _, a := range f.agents {
		if a.ServiceID == svc.ID && a.InstanceID == params.Agent.InstanceID && a.StoredStatus != AgentStatusRevoked {
			a.StoredStatus = AgentStatusRevoked
			f.revokedFPs[a.CertFingerprint] = true
			superseded++
		}
	}
	f.superseded += superseded
	agent := *params.Agent
	agent.ServiceID = svc.ID
	agent.StoredStatus = AgentStatusConnectedBaseline
	// 与真实仓储的 join 读取对齐：服务视图字段（归属/环境/服务名）回填自服务行
	agent.ApplicationID = svc.ApplicationID
	agent.ServiceName = svc.ServiceName
	agent.Environment = svc.Environment
	f.agents[agent.ID] = &agent
	f.byFP[agent.CertFingerprint] = &agent
	return &EnrollAgentResult{Token: token, Service: svc, Agent: &agent, Policy: policy, Superseded: superseded}, nil
}

func (f *fakeAgentRepo) AgentByCertFingerprint(_ context.Context, fp string) (*AgentRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.byFP[fp]
	if !ok {
		return nil, ErrAgentNotFound
	}
	return a, nil
}

func (f *fakeAgentRepo) IsFingerprintRevoked(_ context.Context, fp string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.revokedFPs[fp], nil
}

func (f *fakeAgentRepo) RecordHeartbeat(_ context.Context, agentID uuid.UUID, _, _ string, _ NodeInfo, now time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.agents[agentID]
	if !ok {
		return ErrAgentNotFound
	}
	a.LastHeartbeatAt = &now
	if a.StoredStatus == AgentStatusEnrolling {
		a.StoredStatus = AgentStatusConnectedBaseline
	}
	f.heartbeats = append(f.heartbeats, agentID)
	return nil
}

func (f *fakeAgentRepo) RotateAgentCert(_ context.Context, agentID uuid.UUID, oldFP, newFP string, notAfter, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.agents[agentID]
	if !ok {
		return ErrAgentNotFound
	}
	if a.CertFingerprint != oldFP {
		return ErrCertFingerprintMismatch
	}
	if a.StoredStatus == AgentStatusRevoked {
		return ErrAgentAlreadyRevoked
	}
	f.revokedFPs[oldFP] = true
	delete(f.byFP, oldFP)
	a.CertFingerprint = newFP
	a.CertNotAfter = notAfter
	f.byFP[newFP] = a
	f.rotations = append(f.rotations, oldFP)
	return nil
}

// ---------- spy 审计 ----------

type spyAudits struct {
	mu     sync.Mutex
	inputs []audits.RecordInput
}

func (s *spyAudits) Record(_ context.Context, in audits.RecordInput) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inputs = append(s.inputs, in)
	return nil
}

func (s *spyAudits) last() (audits.RecordInput, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.inputs) == 0 {
		return audits.RecordInput{}, false
	}
	return s.inputs[len(s.inputs)-1], true
}

// ---------- 管理面测试 ----------

func newAdminMux(h *AgentAdminHandler, perms ...string) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterAgentAdminRoutes(mux, injectPrincipal(perms...), h)
	return mux
}

func doJSON(t *testing.T, mux http.Handler, method, path, body string) *httptest.ResponseRecorder {
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

func TestCreateEnrollmentToken(t *testing.T) {
	repo := newFakeAgentRepo()
	spy := &spyAudits{}
	h := NewAgentAdminHandler(repo, nil, NewAgentControlConfig("", 72, 10)).SetAudits(spy)
	mux := newAdminMux(h, PermAgentsManage)
	appID := uuid.New()

	// 成功：令牌原文仅本次返回；入库为摘要（原文 ≠ 摘要）
	rr := doJSON(t, mux, "POST", "/api/v1/apm/agents/enrollment-tokens",
		fmt.Sprintf(`{"application_id":%q,"environment":"prod","allowed_languages":["java","go"],"expires_in_minutes":30,"note":"灰度接入"}`, appID))
	if rr.Code != http.StatusOK {
		t.Fatalf("create token status = %d, body: %s", rr.Code, rr.Body.String())
	}
	data := dataOf(t, rr)
	token, _ := data["token"].(string)
	if !strings.HasPrefix(token, enrollmentTokenPrefix) {
		t.Errorf("token prefix missing: %q", token)
	}
	if _, ok := repo.tokens[token]; ok {
		t.Fatal("token plaintext must NOT be stored")
	}
	if _, ok := repo.tokens[HashEnrollmentToken(token)]; !ok {
		t.Fatal("token hash must be stored")
	}
	row := repo.tokens[HashEnrollmentToken(token)]
	if row.ExpiresAt.Sub(time.Now()) > 31*time.Minute || row.ExpiresAt.Sub(time.Now()) < 29*time.Minute {
		t.Errorf("expires_at not ~30min: %v", row.ExpiresAt)
	}
	// 高风险审计落位
	rec, ok := spy.last()
	if !ok {
		t.Fatal("audit not recorded")
	}
	if rec.Module != "apm" || rec.Action != "create" || rec.RiskLevel != audits.RiskHigh || rec.Result != audits.ResultSuccess {
		t.Errorf("audit = %+v", rec)
	}
	if strings.Contains(rec.AfterSummary, token) {
		t.Error("audit summary must not contain token plaintext")
	}

	// 非法语言 → 400 且不写审计
	rr = doJSON(t, mux, "POST", "/api/v1/apm/agents/enrollment-tokens", `{"allowed_languages":["rust"]}`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("bad language status = %d", rr.Code)
	}
	if len(spy.inputs) != 1 {
		t.Error("audit must not be recorded for rejected request")
	}
	// 有效期越界 → 400
	rr = doJSON(t, mux, "POST", "/api/v1/apm/agents/enrollment-tokens", `{"expires_in_minutes":3}`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("short ttl status = %d", rr.Code)
	}
	// 应用不存在 → 400
	repo.appExists = false
	rr = doJSON(t, mux, "POST", "/api/v1/apm/agents/enrollment-tokens",
		fmt.Sprintf(`{"application_id":%q}`, uuid.New()))
	if rr.Code != http.StatusBadRequest {
		t.Errorf("missing app status = %d", rr.Code)
	}
	// 无权限 → 403
	muxNoPerm := newAdminMux(h)
	if rr := doJSON(t, muxNoPerm, "POST", "/api/v1/apm/agents/enrollment-tokens", `{}`); rr.Code != http.StatusForbidden {
		t.Errorf("no-permission status = %d", rr.Code)
	}
}

func TestListAgents(t *testing.T) {
	repo := newFakeAgentRepo()
	h := NewAgentAdminHandler(repo, nil, NewAgentControlConfig("", 72, 10))
	mux := newAdminMux(h, PermAgentsManage)
	agentID := uuid.New()
	stale := time.Now().Add(-time.Hour)
	repo.agents[agentID] = &AgentRow{
		ID: agentID, InstanceID: "i-1", Language: "java",
		StoredStatus: AgentStatusConnectedBaseline, LastHeartbeatAt: &stale, RegisteredAt: stale,
		CertFingerprint: strings.Repeat("a", 64), CertNotAfter: time.Now().Add(72 * time.Hour),
	}

	rr := doGet(t, mux, "/api/v1/apm/agents", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list status = %d", rr.Code)
	}
	data := dataOf(t, rr)
	if data["total"] != float64(1) {
		t.Errorf("total = %v", data["total"])
	}
	// 心跳超时 → 展示态 OFFLINE（派生，不改存态）
	items, _ := data["items"].([]interface{})
	row, _ := items[0].(map[string]interface{})
	if row["status"] != AgentStatusOffline || row["stored_status"] != AgentStatusConnectedBaseline {
		t.Errorf("derived status = %v/%v", row["status"], row["stored_status"])
	}
	// status 过滤（派生态 OFFLINE）
	rr = doGet(t, mux, "/api/v1/apm/agents?status=OFFLINE", nil)
	if rr.Code != http.StatusOK || dataOf(t, rr)["total"] != float64(1) {
		t.Errorf("filter OFFLINE: status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = doGet(t, mux, "/api/v1/apm/agents?status=CONNECTED_BASELINE", nil)
	if dataOf(t, rr)["total"] != float64(0) {
		t.Errorf("filter CONNECTED_BASELINE total = %v", dataOf(t, rr)["total"])
	}
	// 非法过滤值 → 400
	if rr := doGet(t, mux, "/api/v1/apm/agents?status=BOGUS", nil); rr.Code != http.StatusBadRequest {
		t.Errorf("bad status filter = %d", rr.Code)
	}
	if rr := doGet(t, mux, "/api/v1/apm/agents?language=rust", nil); rr.Code != http.StatusBadRequest {
		t.Errorf("bad language filter = %d", rr.Code)
	}
	if rr := doGet(t, mux, "/api/v1/apm/agents?application_id=bad", nil); rr.Code != http.StatusBadRequest {
		t.Errorf("bad application_id filter = %d", rr.Code)
	}
	// 纯 GET 不审计：无需 spy 断言（无审计注入，调用不 panic 即为证）
}

func TestRevokeAgent(t *testing.T) {
	repo := newFakeAgentRepo()
	spy := &spyAudits{}
	h := NewAgentAdminHandler(repo, nil, NewAgentControlConfig("", 72, 10)).SetAudits(spy)
	mux := newAdminMux(h, PermAgentsManage)
	agentID := uuid.New()
	repo.agents[agentID] = &AgentRow{
		ID: agentID, ServiceName: "shop", InstanceID: "i-1",
		StoredStatus: AgentStatusConnectedBaseline, CertFingerprint: strings.Repeat("b", 64),
		CertNotAfter: time.Now().Add(72 * time.Hour), RegisteredAt: time.Now(),
	}

	// 成功：状态终态 + 指纹入撤销列表 + 高风险审计
	rr := doJSON(t, mux, "POST", "/api/v1/apm/agents/"+agentID.String()+"/revoke", `{"reason":"疑似失陷"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, body: %s", rr.Code, rr.Body.String())
	}
	if repo.agents[agentID].StoredStatus != AgentStatusRevoked {
		t.Error("agent not revoked")
	}
	if !repo.revokedFPs[strings.Repeat("b", 64)] {
		t.Error("cert fingerprint not in revocation list")
	}
	rec, _ := spy.last()
	if rec.Action != "revoke" || rec.RiskLevel != audits.RiskHigh || rec.ObjectType != "apm_agent" {
		t.Errorf("audit = %+v", rec)
	}
	// 重复撤销 → 409
	rr = doJSON(t, mux, "POST", "/api/v1/apm/agents/"+agentID.String()+"/revoke", "")
	if rr.Code != http.StatusConflict {
		t.Errorf("re-revoke status = %d", rr.Code)
	}
	// 不存在 → 404
	rr = doJSON(t, mux, "POST", "/api/v1/apm/agents/"+uuid.NewString()+"/revoke", "")
	if rr.Code != http.StatusNotFound {
		t.Errorf("missing agent status = %d", rr.Code)
	}
	// 非法 id → 400
	if rr := doJSON(t, mux, "POST", "/api/v1/apm/agents/bad/revoke", ""); rr.Code != http.StatusBadRequest {
		t.Errorf("bad id status = %d", rr.Code)
	}
}

func TestPolicyEndpoints(t *testing.T) {
	repo := newFakeAgentRepo()
	spy := &spyAudits{}
	ca, _ := newTestCA(t)
	h := NewAgentAdminHandler(repo, ca, NewAgentControlConfig("", 72, 10)).SetAudits(spy)
	mux := newAdminMux(h, PermSettingsManage)

	// 无版本 → 404
	if rr := doGet(t, mux, "/api/v1/apm/policies/global", nil); rr.Code != http.StatusNotFound {
		t.Errorf("missing policy status = %d", rr.Code)
	}
	// 非法作用域 → 400
	if rr := doGet(t, mux, "/api/v1/apm/policies/tenant:1", nil); rr.Code != http.StatusBadRequest {
		t.Errorf("bad scope status = %d", rr.Code)
	}
	// 非法策略（未知键）→ 400 且不写审计
	rr := doJSON(t, mux, "PUT", "/api/v1/apm/policies/global", `{"policy":{"trace_all_methods":true}}`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("invalid policy status = %d", rr.Code)
	}
	if len(spy.inputs) != 0 {
		t.Error("audit must not be recorded for rejected PUT")
	}
	// 发布 v1：版本单调递增起点 + 签名可验 + 高风险审计
	rr = doJSON(t, mux, "PUT", "/api/v1/apm/policies/global",
		`{"policy":{"sampling_rate":0.5,"signals":["traces","metrics"]}}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("put v1 status = %d, body: %s", rr.Code, rr.Body.String())
	}
	data := dataOf(t, rr)
	if data["version"] != float64(1) {
		t.Errorf("version = %v, want 1", data["version"])
	}
	v1sig, _ := data["signature"].(string)
	if v1sig == "" {
		t.Error("signature missing")
	}
	rec, _ := spy.last()
	if rec.Action != "put_policy" || rec.RiskLevel != audits.RiskHigh {
		t.Errorf("audit = %+v", rec)
	}
	// 发布 v2（同 scope 版本递增；v1 签名与 v2 不同）
	rr = doJSON(t, mux, "PUT", "/api/v1/apm/policies/global",
		`{"policy":{"sampling_rate":0.8,"signals":["traces"]}}`)
	if rr.Code != http.StatusOK || dataOf(t, rr)["version"] != float64(2) {
		t.Fatalf("put v2 status = %d version = %v", rr.Code, dataOf(t, rr)["version"])
	}
	// 版本回退拒绝：expected_version 过期 → 409（签名始终覆盖真实落库版本）
	rr = doJSON(t, mux, "PUT", "/api/v1/apm/policies/global",
		`{"policy":{"sampling_rate":0.9},"expected_version":1}`)
	if rr.Code != http.StatusConflict {
		t.Errorf("stale expected_version status = %d", rr.Code)
	}
	// 读取最新版本
	rr = doGet(t, mux, "/api/v1/apm/policies/global", nil)
	if rr.Code != http.StatusOK || dataOf(t, rr)["version"] != float64(2) {
		t.Errorf("get latest status = %d version = %v", rr.Code, dataOf(t, rr)["version"])
	}
	// 落库信封验签（签名覆盖版本与正文）
	row := repo.policies["global"][1]
	if err := VerifyPolicySignature(ca.PublicKeyHex(), row.Envelope()); err != nil {
		t.Errorf("stored policy signature invalid: %v", err)
	}
	// 应用级作用域：应用不存在 → 400
	repo.appExists = false
	rr = doJSON(t, mux, "PUT", "/api/v1/apm/policies/application:"+uuid.NewString(),
		`{"policy":{"sampling_rate":1}}`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("dangling application scope status = %d", rr.Code)
	}
	// 无权限 → 403
	muxNoPerm := newAdminMux(h)
	if rr := doJSON(t, muxNoPerm, "PUT", "/api/v1/apm/policies/global", `{"policy":{"sampling_rate":1}}`); rr.Code != http.StatusForbidden {
		t.Errorf("no-permission PUT status = %d", rr.Code)
	}
	if rr := doGet(t, muxNoPerm, "/api/v1/apm/policies/global", nil); rr.Code != http.StatusForbidden {
		t.Errorf("no-permission GET status = %d", rr.Code)
	}
}

// 确保 fake 完整实现接口（编译期断言）。
var _ AgentRepository = (*fakeAgentRepo)(nil)
