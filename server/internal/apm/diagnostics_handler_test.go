// diagnostics_handler_test.go 深度诊断会话管理接口单元测试（httptest + fake
// DiagnosticsRepository/AgentRepository + spy 审计 + fake 审计查询；覆盖 dry_run/confirm
// 纪律、校验/夹紧/护栏/kill switch 语义、状态迁移、审计风险分级与按对象关联查询）。
package apm

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
)

// ---------- fake DiagnosticsRepository（内存版；条件迁移语义与真实仓储对齐） ----------

type fakeDiagRepo struct {
	mu         sync.Mutex
	sessions   map[uuid.UUID]*DiagnosticSession
	policies   map[string][]*PolicyRow // scope → 版本（记录创建路径下发的叠加策略）
	killSwitch bool
	matched    []uuid.UUID
	matchErr   error
	stopErr    error
}

func newFakeDiagRepo() *fakeDiagRepo {
	return &fakeDiagRepo{sessions: map[uuid.UUID]*DiagnosticSession{}, policies: map[string][]*PolicyRow{}}
}

func (f *fakeDiagRepo) MatchOnlineAgents(context.Context, DiagnosticScope, time.Duration, time.Time) ([]uuid.UUID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uuid.UUID{}, f.matched...), f.matchErr
}

func (f *fakeDiagRepo) KillSwitchEnabled(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.killSwitch, nil
}

func (f *fakeDiagRepo) SetKillSwitch(_ context.Context, enabled bool, operatorID *uuid.UUID, now time.Time) ([]DiagnosticSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.killSwitch = enabled
	var killed []DiagnosticSession
	if enabled {
		for _, s := range f.sessions {
			if s.Status == DiagnosticStatusActive {
				s.Status = DiagnosticStatusKilled
				s.StoppedAt = ptrTime(now)
				s.StoppedBy = operatorID
				s.StopReason = diagnosticStopReasonKillSwitch
				killed = append(killed, *s)
			}
		}
	}
	return killed, nil
}

func (f *fakeDiagRepo) CreateSessionWithPolicy(_ context.Context, sess *DiagnosticSession, policy map[string]interface{},
	signature, keyID string, issuedAt time.Time, expectedVersion int64, _ []uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.killSwitch {
		return ErrDiagnosticKillSwitch
	}
	for _, s := range f.sessions {
		if s.Status == DiagnosticStatusActive && s.Scope.ApplicationID == sess.Scope.ApplicationID {
			return ErrDiagnosticScopeBusy
		}
	}
	sess.PolicyVersion = expectedVersion + 1
	cp := *sess
	f.sessions[sess.ID] = &cp
	scope := ApplicationPolicyScope(sess.Scope.ApplicationID)
	f.policies[scope] = append(f.policies[scope], &PolicyRow{
		ID: uuid.New(), Scope: scope, Version: sess.PolicyVersion, Policy: policy,
		Signature: signature, KeyID: keyID, IssuedAt: issuedAt, ExpiresAt: sess.ExpiresAt, CreatedBy: sess.CreatedBy,
	})
	return nil
}

func (f *fakeDiagRepo) GetSession(_ context.Context, id uuid.UUID) (*DiagnosticSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sessions[id]
	if !ok {
		return nil, ErrDiagnosticNotFound
	}
	cp := *s
	return &cp, nil
}

func (f *fakeDiagRepo) ListSessions(_ context.Context, status string, _, _ int) ([]DiagnosticSession, int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []DiagnosticSession{}
	for _, s := range f.sessions {
		if status == "" || s.Status == status {
			out = append(out, *s)
		}
	}
	return out, int64(len(out)), nil
}

func (f *fakeDiagRepo) StopSession(_ context.Context, id uuid.UUID, stoppedBy *uuid.UUID, reason string, now time.Time) (*DiagnosticSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stopErr != nil {
		return nil, f.stopErr
	}
	s, ok := f.sessions[id]
	if !ok || s.Status != DiagnosticStatusActive {
		return nil, ErrDiagnosticTerminal
	}
	s.Status = DiagnosticStatusStopped
	s.StoppedAt = ptrTime(now)
	s.StoppedBy = stoppedBy
	s.StopReason = reason
	cp := *s
	return &cp, nil
}

func (f *fakeDiagRepo) ExpireDueSessions(_ context.Context, now time.Time) ([]DiagnosticSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []DiagnosticSession
	for _, s := range f.sessions {
		if s.Status == DiagnosticStatusActive && !s.ExpiresAt.After(now) {
			s.Status = DiagnosticStatusExpired
			s.StoppedAt = ptrTime(now)
			s.StopReason = diagnosticStopReasonExpired
			out = append(out, *s)
		}
	}
	return out, nil
}

func (f *fakeDiagRepo) ListPendingRestore(_ context.Context, _ int) ([]DiagnosticSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []DiagnosticSession{}
	for _, s := range f.sessions {
		if s.Status != DiagnosticStatusActive && !s.BaselineRestored {
			out = append(out, *s)
		}
	}
	return out, nil
}

func (f *fakeDiagRepo) MarkBaselineRestored(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sessions[id]
	if !ok {
		return ErrDiagnosticNotFound
	}
	s.BaselineRestored = true
	return nil
}

func ptrTime(t time.Time) *time.Time { return &t }

// ---------- fake 审计查询 ----------

type fakeAuditLister struct {
	entries    []audits.Entry
	lastFilter audits.ListFilter
	err        error
}

func (f *fakeAuditLister) List(_ context.Context, fl audits.ListFilter) ([]audits.Entry, int64, error) {
	f.lastFilter = fl
	return f.entries, int64(len(f.entries)), f.err
}

// ---------- 装配 ----------

func newDiagMux(h *DiagnosticsHandler, perms ...string) *http.ServeMux {
	mux := http.NewServeMux()
	RegisterDiagnosticRoutes(mux, injectPrincipal(perms...), h)
	return mux
}

func newDiagHandler(t *testing.T) (*DiagnosticsHandler, *fakeDiagRepo, *fakeAgentRepo, *spyAudits, *fakeAuditLister) {
	t.Helper()
	diag := newFakeDiagRepo()
	diag.matched = []uuid.UUID{uuid.New()}
	agents := newFakeAgentRepo()
	ca, _ := newTestCA(t)
	spy := &spyAudits{}
	lister := &fakeAuditLister{}
	h := NewDiagnosticsHandler(diag, agents, ca, NewAgentControlConfig("", 72, 10)).
		SetAudits(spy).SetAuditLister(lister)
	return h, diag, agents, spy, lister
}

// ---------- 创建 ----------

func TestDiagnosticCreateDryRunAndConfirm(t *testing.T) {
	h, diag, _, spy, _ := newDiagHandler(t)
	mux := newDiagMux(h, PermDiagnosticsManage)
	appID := uuid.NewString()

	// dry_run：夹紧值回显 + 预估 + 匹配实例数；不落库、不审计
	rr := doJSON(t, mux, "POST", "/api/v1/apm/diagnostic-sessions",
		`{"scope":{"application_id":"`+appID+`"},"capabilities":["sql_detail"],"sampling_rate":0.05,"duration_minutes":5,"dry_run":true}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("dry_run status = %d, body: %s", rr.Code, rr.Body.String())
	}
	data := dataOf(t, rr)
	est, _ := data["estimated_overhead"].(map[string]interface{})
	if est == nil || est["cpu_hint"] == "" || est["spans_per_s_hint"] == "" || est["data_volume_hint"] == "" {
		t.Fatalf("estimated_overhead = %v", data)
	}
	riskNotes, _ := est["risk_notes"].([]interface{})
	if len(riskNotes) == 0 {
		t.Error("risk_notes 不能为空")
	}
	effective, _ := data["effective"].(map[string]interface{})
	if effective["sampling_rate"] != 0.1 || effective["duration_minutes"] != float64(15) {
		t.Errorf("effective（夹紧回显）= %v，want 0.1/15", effective)
	}
	if data["matched_instances"] != float64(1) {
		t.Errorf("matched_instances = %v", data["matched_instances"])
	}
	if len(diag.sessions) != 0 {
		t.Error("dry_run 不得落库会话")
	}
	if len(spy.inputs) != 0 {
		t.Error("dry_run 不得写审计")
	}

	// 缺 confirm → 400
	rr = doJSON(t, mux, "POST", "/api/v1/apm/diagnostic-sessions",
		`{"scope":{"application_id":"`+appID+`"},"capabilities":["sql_detail"],"sampling_rate":0.5}`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("no-confirm status = %d", rr.Code)
	}
}

func TestDiagnosticCreateValidationAndGuards(t *testing.T) {
	h, diag, agents, _, _ := newDiagHandler(t)
	mux := newDiagMux(h, PermDiagnosticsManage)
	appID := uuid.NewString()

	cases := []struct {
		name string
		body string
		want int
	}{
		{"未知能力 400", `{"scope":{"application_id":"` + appID + `"},"capabilities":["heap_dump"],"confirm":true}`, 400},
		{"空能力 400", `{"scope":{"application_id":"` + appID + `"},"capabilities":[],"confirm":true}`, 400},
		{"坏UUID 400", `{"scope":{"application_id":"bad"},"capabilities":["sql_detail"],"confirm":true}`, 400},
		{"坏实例ID 400", `{"scope":{"application_id":"` + appID + `","instance_ids":["bad id"]},"capabilities":["sql_detail"],"confirm":true}`, 400},
		{"函数探针大范围 422", `{"scope":{"application_id":"` + appID + `"},"capabilities":["function_probe"],"sampling_rate":0.3,"confirm":true}`, 422},
		{"函数探针超采样上限 422", `{"scope":{"application_id":"` + appID + `","service":"shop-svc"},"capabilities":["function_probe"],"sampling_rate":0.8,"confirm":true}`, 422},
		{"采样率超总上限 422", `{"scope":{"application_id":"` + appID + `"},"capabilities":["sql_detail"],"sampling_rate":2.0,"confirm":true}`, 422},
		{"时长超上限 422", `{"scope":{"application_id":"` + appID + `"},"capabilities":["sql_detail"],"duration_minutes":300,"confirm":true}`, 422},
	}
	for _, c := range cases {
		if rr := doJSON(t, mux, "POST", "/api/v1/apm/diagnostic-sessions", c.body); rr.Code != c.want {
			t.Errorf("%s：status = %d, want %d, body: %s", c.name, rr.Code, c.want, rr.Body.String())
		}
	}

	// 无匹配在线 Agent → 422
	diag.matched = nil
	rr := doJSON(t, mux, "POST", "/api/v1/apm/diagnostic-sessions",
		`{"scope":{"application_id":"`+appID+`"},"capabilities":["sql_detail"],"confirm":true}`)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("no matched agents status = %d", rr.Code)
	}

	// kill switch 开启 → 422
	diag.matched = []uuid.UUID{uuid.New()}
	diag.killSwitch = true
	rr = doJSON(t, mux, "POST", "/api/v1/apm/diagnostic-sessions",
		`{"scope":{"application_id":"`+appID+`"},"capabilities":["sql_detail"],"confirm":true}`)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("kill switch on status = %d", rr.Code)
	}
	diag.killSwitch = false

	// 应用不存在 → 400
	agents.appExists = false
	rr = doJSON(t, mux, "POST", "/api/v1/apm/diagnostic-sessions",
		`{"scope":{"application_id":"`+appID+`"},"capabilities":["sql_detail"],"confirm":true}`)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("dangling application status = %d", rr.Code)
	}

	// 无权限 → 403
	muxNoPerm := newDiagMux(h)
	if rr := doJSON(t, muxNoPerm, "POST", "/api/v1/apm/diagnostic-sessions", `{}`); rr.Code != http.StatusForbidden {
		t.Errorf("no-permission status = %d", rr.Code)
	}
}

func TestDiagnosticCreateSuccess(t *testing.T) {
	h, diag, _, spy, _ := newDiagHandler(t)
	mux := newDiagMux(h, PermDiagnosticsManage)
	appID := uuid.New()

	rr := doJSON(t, mux, "POST", "/api/v1/apm/diagnostic-sessions",
		`{"scope":{"application_id":"`+appID.String()+`","service":"shop-svc"},"capabilities":["sql_detail"],"sampling_rate":0.5,"duration_minutes":30,"confirm":true}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("create status = %d, body: %s", rr.Code, rr.Body.String())
	}
	data := dataOf(t, rr)
	if data["status"] != DiagnosticStatusActive || data["policy_version"] != float64(1) {
		t.Errorf("session = %v", data)
	}
	sessID, _ := data["id"].(string)
	// 诊断叠加策略落库：应用级作用域 v1、信封硬截止=会话 expires_at、签名可验
	scope := ApplicationPolicyScope(appID)
	rows := diag.policies[scope]
	if len(rows) != 1 {
		t.Fatalf("policy versions = %d", len(rows))
	}
	row := rows[0]
	diagTree, _ := row.Policy["diagnostics"].(map[string]interface{})
	if diagTree["enabled"] != true {
		t.Errorf("overlay diagnostics.enabled = %v", diagTree["enabled"])
	}
	sessionTree, _ := diagTree["session"].(map[string]interface{})
	if sessionTree["id"] != sessID {
		t.Errorf("overlay session.id = %v", sessionTree["id"])
	}
	if err := VerifyPolicySignature(h.ca.PublicKeyHex(), row.Envelope()); err != nil {
		t.Errorf("诊断策略签名无效: %v", err)
	}
	sess := diag.sessions[uuid.MustParse(sessID)]
	if !row.ExpiresAt.Equal(sess.ExpiresAt) {
		t.Errorf("信封 expires_at = %v, 会话硬截止 = %v（须一致）", row.ExpiresAt, sess.ExpiresAt)
	}
	// 高风险审计
	rec, ok := spy.last()
	if !ok || rec.Action != "create" || rec.ObjectType != "apm_diagnostic_session" || rec.RiskLevel != audits.RiskHigh {
		t.Errorf("audit = %+v", rec)
	}

	// 同应用第二个 ACTIVE 会话 → 409
	rr = doJSON(t, mux, "POST", "/api/v1/apm/diagnostic-sessions",
		`{"scope":{"application_id":"`+appID.String()+`"},"capabilities":["gc_detail"],"confirm":true}`)
	if rr.Code != http.StatusConflict {
		t.Errorf("scope busy status = %d", rr.Code)
	}
}

// ---------- 列表 / 详情 ----------

func TestDiagnosticListAndDetail(t *testing.T) {
	h, diag, _, _, lister := newDiagHandler(t)
	mux := newDiagMux(h, PermDiagnosticsManage)
	appID := uuid.New()
	sess := testSession(t, appID)
	diag.sessions[sess.ID] = sess
	stopped := testSession(t, uuid.New())
	stopped.Status = DiagnosticStatusStopped
	diag.sessions[stopped.ID] = stopped

	// 列表：行 + kill_switch_enabled
	rr := doGet(t, mux, "/api/v1/apm/diagnostic-sessions", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list status = %d", rr.Code)
	}
	data := dataOf(t, rr)
	if data["total"] != float64(2) || data["kill_switch_enabled"] != false {
		t.Errorf("list = %v", data)
	}
	// status 过滤
	rr = doGet(t, mux, "/api/v1/apm/diagnostic-sessions?status=ACTIVE", nil)
	if dataOf(t, rr)["total"] != float64(1) {
		t.Errorf("filter ACTIVE total = %v", dataOf(t, rr)["total"])
	}
	if rr := doGet(t, mux, "/api/v1/apm/diagnostic-sessions?status=BOGUS", nil); rr.Code != http.StatusBadRequest {
		t.Errorf("bad status filter = %d", rr.Code)
	}
	diag.killSwitch = true
	rr = doGet(t, mux, "/api/v1/apm/diagnostic-sessions", nil)
	if dataOf(t, rr)["kill_switch_enabled"] != true {
		t.Error("kill_switch_enabled 应如实反映开启态")
	}
	diag.killSwitch = false

	// 详情：会话全字段 + 关联审计条目（按对象查询过滤器如实传递）
	lister.entries = []audits.Entry{{ID: uuid.New(), Action: "create", ObjectID: sess.ID.String()}}
	rr = doGet(t, mux, "/api/v1/apm/diagnostic-sessions/"+sess.ID.String(), nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("detail status = %d", rr.Code)
	}
	data = dataOf(t, rr)
	if data["id"] != sess.ID.String() || data["policy_version"] != float64(sess.PolicyVersion) {
		t.Errorf("detail = %v", data)
	}
	entries, _ := data["audits"].([]interface{})
	if len(entries) != 1 {
		t.Errorf("audits = %v", data["audits"])
	}
	if lister.lastFilter.Module != "apm" || lister.lastFilter.ObjectType != "apm_diagnostic_session" ||
		lister.lastFilter.ObjectID != sess.ID.String() {
		t.Errorf("audit filter = %+v", lister.lastFilter)
	}
	// 不存在 → 404；非法 id → 400
	if rr := doGet(t, mux, "/api/v1/apm/diagnostic-sessions/"+uuid.NewString(), nil); rr.Code != http.StatusNotFound {
		t.Errorf("missing session status = %d", rr.Code)
	}
	if rr := doGet(t, mux, "/api/v1/apm/diagnostic-sessions/bad", nil); rr.Code != http.StatusBadRequest {
		t.Errorf("bad id status = %d", rr.Code)
	}
}

// ---------- 停止 ----------

func TestDiagnosticStopSession(t *testing.T) {
	h, diag, agents, spy, _ := newDiagHandler(t)
	mux := newDiagMux(h, PermDiagnosticsManage)
	appID := uuid.New()
	sess := testSession(t, appID)
	diag.sessions[sess.ID] = sess
	// 既有诊断叠加策略 v1（创建路径产物）
	overlay, _ := overlayDiagnosticPolicy(DefaultBaselinePolicy(), sess)
	if _, err := publishScopedPolicy(context.Background(), agents, h.ca, ApplicationPolicyScope(appID), overlay, sess.ExpiresAt, time.Now(), nil); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	rr := doJSON(t, mux, "POST", "/api/v1/apm/diagnostic-sessions/"+sess.ID.String()+"/stop", `{"reason":"定位完成"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("stop status = %d, body: %s", rr.Code, rr.Body.String())
	}
	data := dataOf(t, rr)
	if data["status"] != DiagnosticStatusStopped || data["baseline_restored"] != true {
		t.Errorf("stopped session = %v", data)
	}
	// 基线恢复策略：新版本 v2、诊断叠加剥除、签名可验
	rows := agents.policies[ApplicationPolicyScope(appID)]
	if len(rows) != 2 {
		t.Fatalf("policy versions = %d, want 2", len(rows))
	}
	restored := rows[1]
	if restored.Version != 2 || restored.Policy["diagnostics"].(map[string]interface{})["enabled"] != false {
		t.Errorf("restored policy = version %d diag %v", restored.Version, restored.Policy["diagnostics"])
	}
	if err := VerifyPolicySignature(h.ca.PublicKeyHex(), restored.Envelope()); err != nil {
		t.Errorf("恢复策略签名无效: %v", err)
	}
	// 高风险审计
	rec, ok := spy.last()
	if !ok || rec.Action != "stop" || rec.RiskLevel != audits.RiskHigh || rec.ObjectID != sess.ID.String() {
		t.Errorf("audit = %+v", rec)
	}
	// 终态重复停止 → 409；不存在 → 404
	rr = doJSON(t, mux, "POST", "/api/v1/apm/diagnostic-sessions/"+sess.ID.String()+"/stop", "")
	if rr.Code != http.StatusConflict {
		t.Errorf("re-stop status = %d", rr.Code)
	}
	rr = doJSON(t, mux, "POST", "/api/v1/apm/diagnostic-sessions/"+uuid.NewString()+"/stop", "")
	if rr.Code != http.StatusNotFound {
		t.Errorf("stop missing status = %d", rr.Code)
	}
}

// ---------- kill switch ----------

func TestDiagnosticKillSwitch(t *testing.T) {
	h, diag, agents, spy, _ := newDiagHandler(t)
	mux := newDiagMux(h, PermDiagnosticsManage)

	// 两个应用各一个 ACTIVE 会话（各有叠加策略 v1）
	for range 2 {
		sess := testSession(t, uuid.New())
		diag.sessions[sess.ID] = sess
		overlay, _ := overlayDiagnosticPolicy(DefaultBaselinePolicy(), sess)
		if _, err := publishScopedPolicy(context.Background(), agents, h.ca,
			ApplicationPolicyScope(sess.Scope.ApplicationID), overlay, sess.ExpiresAt, time.Now(), nil); err != nil {
			t.Fatalf("seed policy: %v", err)
		}
	}

	// enable=true：全部 ACTIVE → KILLED + 逐应用恢复基线 + Critical 审计
	rr := doJSON(t, mux, "POST", "/api/v1/apm/diagnostics/kill-switch", `{"enable":true}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("kill switch status = %d, body: %s", rr.Code, rr.Body.String())
	}
	data := dataOf(t, rr)
	if data["kill_switch_enabled"] != true || data["killed_sessions"] != float64(2) {
		t.Errorf("kill switch response = %v", data)
	}
	for _, s := range diag.sessions {
		if s.Status != DiagnosticStatusKilled || !s.BaselineRestored {
			t.Errorf("session = %s/%v", s.Status, s.BaselineRestored)
		}
		if rows := agents.policies[ApplicationPolicyScope(s.Scope.ApplicationID)]; len(rows) != 2 {
			t.Errorf("恢复策略未发布: versions = %d", len(rows))
		}
	}
	// 审计：1 条 Critical kill_switch + 2 条 HIGH kill（逐会话）
	var critical, kill int
	for _, in := range spy.inputs {
		if in.Action == "kill_switch" && in.RiskLevel == audits.RiskCritical {
			critical++
		}
		if in.Action == "kill" && in.RiskLevel == audits.RiskHigh {
			kill++
		}
	}
	if critical != 1 || kill != 2 {
		t.Errorf("audits critical=%d kill=%d", critical, kill)
	}

	// 开启中拒绝新建 → 422
	diag.matched = []uuid.UUID{uuid.New()}
	rr = doJSON(t, mux, "POST", "/api/v1/apm/diagnostic-sessions",
		`{"scope":{"application_id":"`+uuid.NewString()+`"},"capabilities":["sql_detail"],"confirm":true}`)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("create while kill switch on = %d", rr.Code)
	}

	// enable=false：解除封锁
	rr = doJSON(t, mux, "POST", "/api/v1/apm/diagnostics/kill-switch", `{"enable":false}`)
	if rr.Code != http.StatusOK || dataOf(t, rr)["kill_switch_enabled"] != false {
		t.Errorf("disable status = %d body = %s", rr.Code, rr.Body.String())
	}
	rr = doJSON(t, mux, "POST", "/api/v1/apm/diagnostic-sessions",
		`{"scope":{"application_id":"`+uuid.NewString()+`"},"capabilities":["sql_detail"],"confirm":true}`)
	if rr.Code != http.StatusOK {
		t.Errorf("create after disable = %d, body: %s", rr.Code, rr.Body.String())
	}

	// 无权限 → 403
	muxNoPerm := newDiagMux(h)
	if rr := doJSON(t, muxNoPerm, "POST", "/api/v1/apm/diagnostics/kill-switch", `{"enable":true}`); rr.Code != http.StatusForbidden {
		t.Errorf("no-permission kill switch = %d", rr.Code)
	}
}

// 确保 fake 完整实现接口（编译期断言）。
var _ DiagnosticsRepository = (*fakeDiagRepo)(nil)
var _ auditLister = (*fakeAuditLister)(nil)
