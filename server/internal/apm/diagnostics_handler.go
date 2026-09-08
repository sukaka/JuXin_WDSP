// diagnostics_handler.go APM 阶段4 深度诊断会话控制面管理接口（设计 §6.3 深度诊断流程、
// §16.2 管理接口、§21.2 深度诊断性能预算）。
//
// 全部挂在 APM_ENABLED 开关内、会话 + RBAC 链上（RegisterDiagnosticRoutes 注入 authz），
// 权限点 apm.diagnostics.manage（迁移 000093 种子，仅 SECURITY_ADMIN）：
//
//	POST /api/v1/apm/diagnostic-sessions            创建诊断会话（dry_run 预估 / confirm 正式创建）
//	GET  /api/v1/apm/diagnostic-sessions            会话分页列表（响应级携带 kill_switch_enabled）
//	GET  /api/v1/apm/diagnostic-sessions/{id}       会话详情 + 关联操作审计条目
//	POST /api/v1/apm/diagnostic-sessions/{id}/stop  提前停止（下发基线恢复策略）
//	POST /api/v1/apm/diagnostics/kill-switch        全局 kill switch（开启即终止全部活跃会话并拒绝新建）
//
// 审计纪律：创建/停止/kill switch 全部写高风险操作审计，kill switch 动作为 Critical；
// 纯 GET 不审计（沿用既有惯例）。
//
// 错误码约定：参数形态错误 400；语义拦截（无匹配在线 Agent / 开销护栏 / kill switch
// 开启中拒绝新建）422；会话不存在 404；终态重复操作与同应用并发会话 409
// （422 语义先例：license 验签失败）。
package apm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// PermDiagnosticsManage 深度诊断管理权限点（迁移 000093 种子）。
const PermDiagnosticsManage = "apm.diagnostics.manage"

// 诊断接口请求体上限（scope 实例清单 + 能力数组，8KB 充足）。
const maxDiagnosticBodyBytes = 8192

// 会话详情关联审计条目上限（按对象查询，时间倒序）。
const diagnosticDetailAuditLimit = 50

// auditLister 操作审计按对象查询（*audits.Service 实现；单测注入 fake）。
type auditLister interface {
	List(ctx context.Context, f audits.ListFilter) ([]audits.Entry, int64, error)
}

// DiagnosticsHandler 深度诊断会话管理接口处理器。
type DiagnosticsHandler struct {
	store     DiagnosticsRepository
	agents    AgentRepository // 策略读取/发布（LatestPolicy / CreatePolicyVersion）
	ca        *AgentCA
	cfg       AgentControlConfig
	audits    auditRecorder // nil 时写操作不记审计（仅测试便利；生产装配必须注入）
	auditList auditLister   // nil 时详情不含审计条目（仅测试便利）
	now       func() time.Time
}

// NewDiagnosticsHandler 创建诊断会话处理器。
func NewDiagnosticsHandler(store DiagnosticsRepository, agents AgentRepository, ca *AgentCA, cfg AgentControlConfig) *DiagnosticsHandler {
	return &DiagnosticsHandler{store: store, agents: agents, ca: ca, cfg: cfg, now: time.Now}
}

// SetAudits 注入操作审计记录器（生产由 app 装配 *audits.Service）。
func (h *DiagnosticsHandler) SetAudits(a auditRecorder) *DiagnosticsHandler { h.audits = a; return h }

// SetAuditLister 注入审计查询器（生产由 app 装配 *audits.Service；详情接口关联条目用）。
func (h *DiagnosticsHandler) SetAuditLister(l auditLister) *DiagnosticsHandler {
	h.auditList = l
	return h
}

// RegisterDiagnosticRoutes 注册深度诊断路由（authz = 会话认证 + CSRF + 授权门控链；
// 全部接口挂 apm.diagnostics.manage）。
func RegisterDiagnosticRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *DiagnosticsHandler) {
	mux.Handle("POST /api/v1/apm/diagnostic-sessions",
		authz(middleware.RequirePermission(PermDiagnosticsManage)(http.HandlerFunc(h.CreateSession))))
	mux.Handle("GET /api/v1/apm/diagnostic-sessions",
		authz(middleware.RequirePermission(PermDiagnosticsManage)(http.HandlerFunc(h.ListSessions))))
	mux.Handle("GET /api/v1/apm/diagnostic-sessions/{id}",
		authz(middleware.RequirePermission(PermDiagnosticsManage)(http.HandlerFunc(h.GetSession))))
	mux.Handle("POST /api/v1/apm/diagnostic-sessions/{id}/stop",
		authz(middleware.RequirePermission(PermDiagnosticsManage)(http.HandlerFunc(h.StopSession))))
	mux.Handle("POST /api/v1/apm/diagnostics/kill-switch",
		authz(middleware.RequirePermission(PermDiagnosticsManage)(http.HandlerFunc(h.KillSwitch))))
}

// ---------- 创建 ----------

// createSessionRequest 创建入参（合同字段逐字对应；dry_run=true 只预估不落库）。
type createSessionRequest struct {
	Scope           diagnosticScopeInput `json:"scope"`
	Capabilities    []string             `json:"capabilities"`
	SamplingRate    float64              `json:"sampling_rate"`
	DurationMinutes int                  `json:"duration_minutes"`
	DryRun          bool                 `json:"dry_run"`
	Confirm         bool                 `json:"confirm"`
}

// CreateSession POST /api/v1/apm/diagnostic-sessions（权限 apm.diagnostics.manage，高风险审计）。
// 流程（§6.3）：校验/夹紧 → 开销护栏（422）→ dry_run 返回预估 / 正式创建要求 confirm=true
// → kill switch 开启拒绝（422）→ scope 须匹配 ≥1 在线 Agent（422）→ 单事务写会话（ACTIVE）
// + 发布更高版本签名诊断叠加策略（应用级作用域，信封 expires_at=会话硬截止）→
// 匹配 Agent 置 DIAGNOSING。
func (h *DiagnosticsHandler) CreateSession(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req createSessionRequest
	if err := response.DecodeJSON(w, r, &req, maxDiagnosticBodyBytes); err != nil {
		badRequest(w, r, "请求格式错误")
		return
	}
	scope, err := normalizeDiagnosticScope(req.Scope)
	if err != nil {
		badRequest(w, r, err.Error())
		return
	}
	caps, err := normalizeDiagnosticCapabilities(req.Capabilities)
	if err != nil {
		badRequest(w, r, err.Error())
		return
	}
	rate := clampDiagnosticSamplingRate(req.SamplingRate)
	durationMin := clampDiagnosticDurationMinutes(req.DurationMinutes)
	if err := checkDiagnosticOverheadGuards(caps, scope, rate, durationMin); err != nil {
		diagnosticGuardError(w, r, err)
		return
	}
	now := h.now().UTC()
	matched, err := h.store.MatchOnlineAgents(r.Context(), scope, h.cfg.OfflineAfter, now)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	killOn, err := h.store.KillSwitchEnabled(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if req.DryRun {
		est := EstimateDiagnosticOverhead(caps, rate, durationMin, len(matched))
		if killOn {
			est.RiskNotes = append([]string{"kill switch 当前已开启：正式创建将被拒绝（422）"}, est.RiskNotes...)
		}
		response.JSON(w, r, http.StatusOK, map[string]interface{}{
			"estimated_overhead": est,
			// 生效值回显（夹紧后），供二次确认页如实展示
			"effective":         map[string]interface{}{"sampling_rate": rate, "duration_minutes": durationMin},
			"matched_instances": len(matched),
		})
		return
	}
	if !req.Confirm {
		badRequest(w, r, "创建诊断会话需先 dry_run 预估开销并显式确认（confirm=true）")
		return
	}
	if killOn {
		response.Error(w, r, http.StatusUnprocessableEntity, response.CodeInvalidArgument, ErrDiagnosticKillSwitch.Error())
		return
	}
	if len(matched) == 0 {
		response.Error(w, r, http.StatusUnprocessableEntity, response.CodeInvalidArgument, ErrDiagnosticNoAgents.Error())
		return
	}
	if exists, err := h.agents.ApplicationExists(r.Context(), scope.ApplicationID); err != nil {
		response.InternalError(w, r, err)
		return
	} else if !exists {
		badRequest(w, r, "scope.application_id 指向的应用不存在")
		return
	}
	baseline, err := resolveBaselineForDiagnostic(r.Context(), h.agents, scope.ApplicationID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	sess := &DiagnosticSession{
		ID: uuid.New(), Scope: scope, Capabilities: caps,
		SamplingRate: rate, DurationMinutes: durationMin, Status: DiagnosticStatusActive,
		CreatedBy: &p.UserID, CreatedAt: now, ExpiresAt: now.Add(time.Duration(durationMin) * time.Minute),
	}
	overlay, err := overlayDiagnosticPolicy(baseline, sess)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	// 版本须先于签名确定（版本号在签名覆盖范围内）；仓储在事务+作用域咨询锁内复核
	// expectedVersion——并发下他人先发新版则冲突拒绝，保证落库版本与签名覆盖的版本号
	// 严格一致（与 PutPolicy 同一纪律）。
	policyScope := diagnosticPolicyScope(sess)
	current, err := h.agents.LatestPolicy(r.Context(), policyScope)
	if err != nil && !errors.Is(err, ErrPolicyNotFound) {
		response.InternalError(w, r, err)
		return
	}
	var currentVersion int64
	if current != nil {
		currentVersion = current.Version
	}
	env := &PolicyEnvelope{
		Scope: policyScope, Version: currentVersion + 1, KeyID: PolicySignKeyID,
		IssuedAt: now, ExpiresAt: sess.ExpiresAt, Policy: overlay,
	}
	if err := h.ca.SignPolicy(env); err != nil {
		response.InternalError(w, r, err)
		return
	}
	if err := h.store.CreateSessionWithPolicy(r.Context(), sess, overlay, env.Signature, env.KeyID,
		env.IssuedAt, currentVersion, matched); err != nil {
		switch {
		case errors.Is(err, ErrPolicyVersionConflict):
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "策略已被他人更新，请刷新后重试")
		case errors.Is(err, ErrDiagnosticScopeBusy):
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, ErrDiagnosticScopeBusy.Error())
		case errors.Is(err, ErrDiagnosticKillSwitch):
			response.Error(w, r, http.StatusUnprocessableEntity, response.CodeInvalidArgument, ErrDiagnosticKillSwitch.Error())
		default:
			response.InternalError(w, r, err)
		}
		return
	}
	after, _ := json.Marshal(map[string]interface{}{
		"scope": sess.Scope, "capabilities": sess.Capabilities,
		"sampling_rate": sess.SamplingRate, "duration_minutes": sess.DurationMinutes,
		"expires_at": sess.ExpiresAt.Format(time.RFC3339), "policy_version": sess.PolicyVersion,
		"matched_agents": len(matched),
	})
	h.recordAudit(r, p, "create", "apm_diagnostic_session", sess.ID.String(),
		fmt.Sprintf("%s/%s", scope.ApplicationID, scope.Service),
		"", string(after), audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, sess)
}

// ---------- 列表 / 详情 ----------

// ListSessions GET /api/v1/apm/diagnostic-sessions（权限 apm.diagnostics.manage；纯查询不审计）。
// status 过滤取值 ACTIVE/EXPIRED/STOPPED/KILLED；响应级携带 kill_switch_enabled。
func (h *DiagnosticsHandler) ListSessions(w http.ResponseWriter, r *http.Request) {
	status := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("status")))
	if status != "" {
		switch status {
		case DiagnosticStatusActive, DiagnosticStatusExpired, DiagnosticStatusStopped, DiagnosticStatusKilled:
		default:
			badRequest(w, r, "无效的 status（支持 ACTIVE/EXPIRED/STOPPED/KILLED）")
			return
		}
	}
	page, pageSize := parsePage(r)
	list, total, err := h.store.ListSessions(r.Context(), status, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	killOn, err := h.store.KillSwitchEnabled(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"items":               list,
		"page":                page,
		"page_size":           pageSize,
		"total":               total,
		"kill_switch_enabled": killOn,
	})
}

// diagnosticDetail 详情响应（会话行全字段 + 关联操作审计条目）。
type diagnosticDetail struct {
	DiagnosticSession
	Audits []audits.Entry `json:"audits"`
}

// GetSession GET /api/v1/apm/diagnostic-sessions/{id}（权限 apm.diagnostics.manage；
// 详情 + operation_audits 按对象（module=apm, object_type=apm_diagnostic_session,
// object_id=会话 ID）时间倒序，上限 50 条）。
func (h *DiagnosticsHandler) GetSession(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		badRequest(w, r, "无效的 id")
		return
	}
	sess, err := h.store.GetSession(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrDiagnosticNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "诊断会话不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	detail := diagnosticDetail{DiagnosticSession: *sess, Audits: []audits.Entry{}}
	if h.auditList != nil {
		entries, _, err := h.auditList.List(r.Context(), audits.ListFilter{
			Module: "apm", ObjectType: "apm_diagnostic_session", ObjectID: id.String(),
			Page: 1, PageSize: diagnosticDetailAuditLimit,
		})
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
		detail.Audits = entries
	}
	response.JSON(w, r, http.StatusOK, detail)
}

// ---------- 停止 ----------

// stopSessionRequest 提前停止入参（reason 可选，落审计与会话行）。
type stopSessionRequest struct {
	Reason string `json:"reason"`
}

// StopSession POST /api/v1/apm/diagnostic-sessions/{id}/stop（权限 apm.diagnostics.manage，
// 高风险审计）。仅 ACTIVE 可停止（终态重复停止 409）；停止即下发基线恢复策略
// （新版本，诊断叠加剥除）——发布失败不翻转已落库终态，由到期扫描任务按
// baseline_restored=false 对账重试（响应行 baseline_restored 如实反映）。
func (h *DiagnosticsHandler) StopSession(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		badRequest(w, r, "无效的 id")
		return
	}
	var req stopSessionRequest
	if r.Body != nil && r.ContentLength != 0 {
		if err := response.DecodeJSON(w, r, &req, 2048); err != nil {
			badRequest(w, r, "请求格式错误")
			return
		}
	}
	reason := strings.TrimSpace(req.Reason)
	if len(reason) > 200 {
		badRequest(w, r, "reason 不能超过 200 字符")
		return
	}
	current, err := h.store.GetSession(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrDiagnosticNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "诊断会话不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	if current.Status != DiagnosticStatusActive {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict,
			fmt.Sprintf("诊断会话已处于终态 %s", current.Status))
		return
	}
	if reason == "" {
		reason = diagnosticStopReasonManual
	}
	now := h.now().UTC()
	stopped, err := h.store.StopSession(r.Context(), id, &p.UserID, reason, now)
	if err != nil {
		if errors.Is(err, ErrDiagnosticTerminal) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "诊断会话已被并发终止，请刷新")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	restored := h.restoreBaseline(r.Context(), stopped, now, &p.UserID)
	before, _ := json.Marshal(map[string]interface{}{"status": DiagnosticStatusActive})
	after, _ := json.Marshal(map[string]interface{}{
		"status": DiagnosticStatusStopped, "reason": reason, "baseline_restored": restored,
	})
	h.recordAudit(r, p, "stop", "apm_diagnostic_session", id.String(),
		fmt.Sprintf("%s/%s", stopped.Scope.ApplicationID, stopped.Scope.Service),
		string(before), string(after), audits.ResultSuccess, audits.RiskHigh)
	// 回读以如实反映 baseline_restored（恢复发布成功后已置位）
	if refreshed, err := h.store.GetSession(r.Context(), id); err == nil {
		stopped = refreshed
	}
	response.JSON(w, r, http.StatusOK, stopped)
}

// ---------- kill switch ----------

// killSwitchRequest kill switch 入参。
type killSwitchRequest struct {
	Enable bool `json:"enable"`
}

// KillSwitch POST /api/v1/apm/diagnostics/kill-switch（权限 apm.diagnostics.manage，
// Critical 审计）。enable=true：全部 ACTIVE 会话置 KILLED（同事务）+ 逐应用下发基线
// 恢复策略 + 后续新建一律 422；enable=false：仅解除新建封锁（不回放任何诊断叠加）。
func (h *DiagnosticsHandler) KillSwitch(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req killSwitchRequest
	if err := response.DecodeJSON(w, r, &req, 1024); err != nil {
		badRequest(w, r, "请求格式错误")
		return
	}
	now := h.now().UTC()
	killed, err := h.store.SetKillSwitch(r.Context(), req.Enable, &p.UserID, now)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	killedIDs := make([]string, 0, len(killed))
	for i := range killed {
		killedIDs = append(killedIDs, killed[i].ID.String())
		h.restoreBaseline(r.Context(), &killed[i], now, &p.UserID)
		// 逐会话审计（object=会话，详情接口可关联溯源——§6.3 结果保留会话 ID）
		killAfter, _ := json.Marshal(map[string]interface{}{
			"status": DiagnosticStatusKilled, "reason": diagnosticStopReasonKillSwitch,
		})
		h.recordAudit(r, p, "kill", "apm_diagnostic_session", killed[i].ID.String(),
			fmt.Sprintf("%s/%s", killed[i].Scope.ApplicationID, killed[i].Scope.Service),
			`{"status":"ACTIVE"}`, string(killAfter), audits.ResultSuccess, audits.RiskHigh)
	}
	switchAfter, _ := json.Marshal(map[string]interface{}{
		"enable": req.Enable, "killed_sessions": killedIDs,
	})
	h.recordAudit(r, p, "kill_switch", "apm_diagnostics", killSwitchKey, "apm_diagnostics.kill_switch",
		"", string(switchAfter), audits.ResultSuccess, audits.RiskCritical)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"kill_switch_enabled": req.Enable,
		"killed_sessions":     len(killed),
	})
}

// restoreBaseline 下发基线恢复策略并标记会话（失败如实记日志，由到期扫描任务对账
// 重试——Agent 侧另有策略信封硬截止兜底，会话数据面不会失控）。返回是否完成恢复。
func (h *DiagnosticsHandler) restoreBaseline(ctx context.Context, sess *DiagnosticSession, now time.Time, operatorID *uuid.UUID) bool {
	row, err := restoreBaselinePolicy(ctx, h.agents, h.ca, sess.Scope.ApplicationID, h.cfg.PolicyValidity, now, operatorID)
	if err != nil {
		slog.Warn("apm diagnostics: 基线恢复策略下发失败，待扫描任务对账重试",
			"session_id", sess.ID, "error", err)
		return false
	}
	if row == nil {
		slog.Warn("apm diagnostics: 作用域无策略版本，无需恢复（异常态，如实记录）",
			"session_id", sess.ID, "application_id", sess.Scope.ApplicationID)
	}
	if err := h.store.MarkBaselineRestored(ctx, sess.ID); err != nil {
		slog.Warn("apm diagnostics: 标记 baseline_restored 失败", "session_id", sess.ID, "error", err)
		return false
	}
	return true
}

// diagnosticGuardError 输出 422 语义拦截（无匹配 Agent / 开销护栏）。
func diagnosticGuardError(w http.ResponseWriter, r *http.Request, err error) {
	response.Error(w, r, http.StatusUnprocessableEntity, response.CodeInvalidArgument, err.Error())
}

// recordAudit 记录操作审计（口径与 AgentAdminHandler.recordAudit 一致：审计未接线时
// 安全跳过——仅测试场景；审计写失败不阻断已完成的变更）。
func (h *DiagnosticsHandler) recordAudit(r *http.Request, p *authz.Principal, action, objType, objID, objName, before, after, result, risk string) {
	if h.audits == nil || p == nil {
		return
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "apm",
		Action:        action,
		ObjectType:    objType,
		ObjectID:      objID,
		ObjectName:    objName,
		BeforeSummary: before,
		AfterSummary:  after,
		Result:        result,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}
