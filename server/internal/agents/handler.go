// handler.go 管理端点（契约 §4；会话 + RBAC，走标准 authChain）：
//
//	POST   /api/v1/traffic/agents/enrollment-tokens            签发注册令牌（明文仅此一次返回）
//	GET    /api/v1/traffic/agents/enrollment-tokens            令牌列表（不含明文/摘要，含派生状态）
//	POST   /api/v1/traffic/agents/enrollment-tokens/{id}/revoke 撤销令牌
//	GET    /api/v1/traffic/agents/summary                      状态汇总
//	GET    /api/v1/traffic/agents                              分页列表（status/q 过滤）
//	GET    /api/v1/traffic/agents/{agent_id}                   详情（含 interfaces 与 policy_binding）
//	POST   /api/v1/traffic/agents/{agent_id}/disable           禁用
//	POST   /api/v1/traffic/agents/{agent_id}/enable            启用
//	DELETE /api/v1/traffic/agents/{agent_id}                   删除（吊销 credential，级联网卡/绑定/事件）
//	GET    /api/v1/traffic/agents/{agent_id}/events            流量事件分页（ts 倒序）
//	POST   /api/v1/traffic/agents/{agent_id}/policy            绑定/换绑策略
//	DELETE /api/v1/traffic/agents/{agent_id}/policy            解绑
//	GET    /api/v1/traffic/policies                            策略列表
//	POST   /api/v1/traffic/policies                            创建策略
//	GET    /api/v1/traffic/policies/{id}                       策略详情
//	PUT    /api/v1/traffic/policies/{id}                       修改策略（version+1，绑定 Agent config_version+1）
//	DELETE /api/v1/traffic/policies/{id}                       删除策略（被绑定则 409）
//
// 写操作全部 HIGH 级审计（module=traffic-agents——契约 §4）。
//
// 响应格式（勘误，见契约 §2/§4 附注）：管理端点一律使用仓库统一信封
// response.Body{code,message,data,request_id}（成功 data 承载契约所载结构，
// 204 No Content 不变）；机器端点（machine_handler.go）保持契约裸 JSON 不变。
package agents

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// auditModule 操作审计模块名（契约 §4 冻结）。
const auditModule = "traffic-agents"

// 管理端请求体上限。
const adminMaxBody = 131072

// auditRecorder 操作审计记录接口（由 *audits.Service 实现；单测注入 spy）。
type auditRecorder interface {
	Record(ctx context.Context, in audits.RecordInput) error
}

// Handler 管理端点处理器。
type Handler struct {
	store       AdminRepository
	audits      auditRecorder         // nil 时写操作不记审计（仅测试便利；生产装配必须注入）
	pkgStore    *PackageStore         // 跨平台安装包分发目录（nil/空=不可用）
	endpointCfg InstallEndpointConfig // WDSP 接入地址自动探测与默认地址配置
	now         func() time.Time
}

// NewHandler 创建管理端点处理器。
func NewHandler(store AdminRepository) *Handler {
	return &Handler{store: store, now: time.Now}
}

// SetAudits 注入操作审计记录器（生产由 app 装配 *audits.Service）。
func (h *Handler) SetAudits(a auditRecorder) *Handler { h.audits = a; return h }

// decodeAdminJSON 解析管理端 JSON 请求体。
func decodeAdminJSON(w http.ResponseWriter, r *http.Request, dst interface{}) bool {
	body, err := readMachineBody(w, r, adminMaxBody)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求体过大或读取失败")
		return false
	}
	if err := decodeMachineJSON(body, dst); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return false
	}
	return true
}

// adminInternal 内部错误（不泄露细节，如实记日志）。
func (h *Handler) adminInternal(w http.ResponseWriter, r *http.Request, err error) {
	response.InternalError(w, r, err)
}

// writeStoreError 仓储错误 → HTTP 状态映射。
func (h *Handler) writeStoreError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrAgentNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "Agent 不存在")
	case errors.Is(err, ErrTokenNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "注册令牌不存在")
	case errors.Is(err, ErrPolicyNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "策略不存在")
	case errors.Is(err, ErrPolicyVersionNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "策略历史版本不存在")
	case errors.Is(err, ErrNoBinding):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "Agent 当前无生效策略绑定")
	case errors.Is(err, ErrHTTPEventNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "HTTP 事件不存在")
	case errors.Is(err, ErrCaptureOverrideNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "定向采集规则不存在")
	case errors.Is(err, ErrTokenState):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "令牌已使用或已撤销，不可再撤销")
	case errors.Is(err, ErrPolicyNameConflict):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "策略名称已存在")
	case errors.Is(err, ErrPolicyBound):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "策略仍被 Agent 绑定，请先解绑")
	default:
		h.adminInternal(w, r, err)
	}
}

// parseAgentID 解析路径 agent_id。
func parseAgentID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("agent_id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "agent_id 非法")
		return uuid.Nil, false
	}
	return id, true
}

// ---------- 注册令牌 ----------

// createTokenRequest 签发令牌入参（ttl_minutes 范围 5–10080——契约 §4）。
type createTokenRequest struct {
	Label      string `json:"label"`
	TTLMinutes int    `json:"ttl_minutes"`
}

// CreateToken POST /api/v1/traffic/agents/enrollment-tokens（明文仅此一次返回）。
func (h *Handler) CreateToken(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req createTokenRequest
	if !decodeAdminJSON(w, r, &req) {
		return
	}
	req.Label = strings.TrimSpace(req.Label)
	if len(req.Label) > 128 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "label 超过 128 字符")
		return
	}
	if req.TTLMinutes < 5 || req.TTLMinutes > 10080 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "ttl_minutes 须在 5~10080")
		return
	}
	plain, err := GenerateEnrollmentToken()
	if err != nil {
		h.adminInternal(w, r, err)
		return
	}
	createdBy := ""
	if p != nil {
		createdBy = p.Username
	}
	expiresAt := h.now().UTC().Add(time.Duration(req.TTLMinutes) * time.Minute)
	token, err := h.store.CreateEnrollmentToken(r.Context(), HashSecret(plain), req.Label, expiresAt, createdBy)
	if err != nil {
		h.adminInternal(w, r, err)
		return
	}
	h.recordAudit(r, p, "create", "agent_enrollment_token", token.ID.String(), req.Label,
		"", tokenAuditSummary(req.Label, expiresAt), audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusCreated, map[string]interface{}{
		"id":         token.ID.String(),
		"token":      plain,
		"expires_at": token.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

// tokenAuditSummary 令牌审计摘要（合法 JSON；不含明文与摘要）。
func tokenAuditSummary(label string, expiresAt time.Time) string {
	raw, _ := json.Marshal(map[string]interface{}{
		"label":      label,
		"expires_at": expiresAt.UTC().Format(time.RFC3339),
	})
	return string(raw)
}

// tokenItem 令牌列表项（含派生状态；永不含明文/摘要）。
type tokenItem struct {
	EnrollmentToken
	Status string `json:"status"`
}

// ListTokens GET /api/v1/traffic/agents/enrollment-tokens。
func (h *Handler) ListTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := h.store.ListEnrollmentTokens(r.Context())
	if err != nil {
		h.adminInternal(w, r, err)
		return
	}
	now := h.now().UTC()
	items := make([]tokenItem, 0, len(tokens))
	for i := range tokens {
		items = append(items, tokenItem{EnrollmentToken: tokens[i], Status: tokens[i].TokenStatus(now)})
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": items, "total": len(items)})
}

// RevokeToken POST /api/v1/traffic/agents/enrollment-tokens/{id}/revoke。
func (h *Handler) RevokeToken(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "令牌 ID 非法")
		return
	}
	if err := h.store.RevokeEnrollmentToken(r.Context(), id, h.now().UTC()); err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "revoke", "agent_enrollment_token", id.String(), "",
		"", `{"revoked":true}`, audits.ResultSuccess, audits.RiskHigh)
	w.WriteHeader(http.StatusNoContent)
}

// ---------- Agent 查询 ----------

// Summary GET /api/v1/traffic/agents/summary。
func (h *Handler) Summary(w http.ResponseWriter, r *http.Request) {
	sum, err := h.store.Summary(r.Context())
	if err != nil {
		h.adminInternal(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, sum)
}

// validAgentStatusFilter 列表 status 过滤合法值（派生状态全集）。
func validAgentStatusFilter(s string) bool {
	switch s {
	case StatusOnline, StatusDegraded, StatusError, StatusOffline, StatusDisabled:
		return true
	}
	return false
}

// ListAgents GET /api/v1/traffic/agents?status=&q=&page=&page_size=。
func (h *Handler) ListAgents(w http.ResponseWriter, r *http.Request) {
	f := AgentFilter{
		Status: strings.TrimSpace(r.URL.Query().Get("status")),
		Q:      strings.TrimSpace(r.URL.Query().Get("q")),
		Page:   ParsePageParams(r.URL.Query().Get),
	}
	if f.Status != "" && !validAgentStatusFilter(f.Status) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "status 过滤值非法")
		return
	}
	if len(f.Q) > 200 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "q 超过 200 字符")
		return
	}
	items, total, err := h.store.ListAgents(r.Context(), f)
	if err != nil {
		h.adminInternal(w, r, err)
		return
	}
	// status 已由 SQL 按契约 §5 派生（与 DeriveStatus 同口径）；此处仅补健康评分。
	for i := range items {
		items[i].FillHealth()
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": items, "total": total})
}

// GetAgent GET /api/v1/traffic/agents/{agent_id}（详情：+interfaces +policy_binding）。
func (h *Handler) GetAgent(w http.ResponseWriter, r *http.Request) {
	id, ok := parseAgentID(w, r)
	if !ok {
		return
	}
	detail, err := h.store.GetAgent(r.Context(), id)
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	detail.FillStatus(h.now().UTC())
	detail.FillHealth()
	response.JSON(w, r, http.StatusOK, detail)
}

// ---------- Agent 禁用 / 启用 / 删除 ----------

// setDisabled 禁用/启用共用实现（before 取当前态供审计；操作幂等——同状态重复调用仍 204）。
func (h *Handler) setDisabled(w http.ResponseWriter, r *http.Request, disabled bool) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parseAgentID(w, r)
	if !ok {
		return
	}
	before, err := h.store.GetAgent(r.Context(), id)
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	if err := h.store.SetAgentDisabled(r.Context(), id, disabled); err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	action := "enable"
	if disabled {
		action = "disable"
	}
	h.recordAudit(r, p, action, "agent", id.String(), before.Hostname,
		boolAuditSummary("disabled", before.Disabled), boolAuditSummary("disabled", disabled),
		audits.ResultSuccess, audits.RiskHigh)
	w.WriteHeader(http.StatusNoContent)
}

// DisableAgent POST /api/v1/traffic/agents/{agent_id}/disable。
func (h *Handler) DisableAgent(w http.ResponseWriter, r *http.Request) { h.setDisabled(w, r, true) }

// EnableAgent POST /api/v1/traffic/agents/{agent_id}/enable。
func (h *Handler) EnableAgent(w http.ResponseWriter, r *http.Request) { h.setDisabled(w, r, false) }

// boolAuditSummary 单字段布尔审计摘要（合法 JSON）。
func boolAuditSummary(key string, v bool) string {
	raw, _ := json.Marshal(map[string]bool{key: v})
	return string(raw)
}

// DeleteAgent DELETE /api/v1/traffic/agents/{agent_id}
// （吊销 credential、级联删除绑定/网卡/流量事件；操作审计保留——契约 §4）。
func (h *Handler) DeleteAgent(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parseAgentID(w, r)
	if !ok {
		return
	}
	before, err := h.store.GetAgent(r.Context(), id)
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	if err := h.store.DeleteAgent(r.Context(), id); err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete", "agent", id.String(), before.Hostname,
		agentAuditSummary(before), "", audits.ResultSuccess, audits.RiskHigh)
	w.WriteHeader(http.StatusNoContent)
}

// agentAuditSummary Agent 审计摘要（合法 JSON；不含 credential 摘要）。
func agentAuditSummary(d *AgentDetail) string {
	raw, _ := json.Marshal(map[string]interface{}{
		"hostname": d.Hostname,
		"ip":       d.IP,
		"version":  d.Version,
		"disabled": d.Disabled,
	})
	return string(raw)
}

// ListEvents GET /api/v1/traffic/agents/{agent_id}/events（ts 倒序分页——契约 §4）。
func (h *Handler) ListEvents(w http.ResponseWriter, r *http.Request) {
	id, ok := parseAgentID(w, r)
	if !ok {
		return
	}
	if _, err := h.store.GetAgent(r.Context(), id); err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	page := ParsePageParams(r.URL.Query().Get)
	items, total, err := h.store.ListFlowEvents(r.Context(), id, page)
	if err != nil {
		h.adminInternal(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": items, "total": total})
}

// ---------- 策略 CRUD ----------

// policyRequest 策略创建/修改入参（config 为契约 §3.3 policy JSON）。
type policyRequest struct {
	Name   string          `json:"name"`
	Config json.RawMessage `json:"config"`
}

// validate 策略入参校验（name 与 config.name 必须一致——避免行名与载荷名双源漂移）。
func (req *policyRequest) validate() error {
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 128 {
		return errors.New("name 缺失或超过 128 字符")
	}
	if err := ValidatePolicyConfigJSON(req.Config); err != nil {
		return err
	}
	var cfg PolicyConfig
	_ = json.Unmarshal(req.Config, &cfg)
	if cfg.Name != req.Name {
		return errors.New("name 与 config.name 不一致")
	}
	return nil
}

// CreatePolicy POST /api/v1/traffic/policies。
func (h *Handler) CreatePolicy(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req policyRequest
	if !decodeAdminJSON(w, r, &req) {
		return
	}
	if err := req.validate(); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	createdBy := ""
	if p != nil {
		createdBy = p.Username
	}
	policy, err := h.store.CreatePolicy(r.Context(), req.Name, req.Config, createdBy)
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "create", "agent_policy", policy.ID.String(), policy.Name,
		"", policyAuditSummary(policy), audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusCreated, policy)
}

// policyAuditSummary 策略审计摘要（合法 JSON；含全量 config 便于溯源）。
func policyAuditSummary(p *Policy) string {
	raw, _ := json.Marshal(map[string]interface{}{
		"name":    p.Name,
		"version": p.Version,
		"config":  json.RawMessage(p.Config),
	})
	return string(raw)
}

// ListPolicies GET /api/v1/traffic/policies。
func (h *Handler) ListPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := h.store.ListPolicies(r.Context())
	if err != nil {
		h.adminInternal(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": policies, "total": len(policies)})
}

// GetPolicy GET /api/v1/traffic/policies/{id}。
func (h *Handler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "策略 ID 非法")
		return
	}
	policy, err := h.store.GetPolicy(r.Context(), id)
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, policy)
}

// UpdatePolicy PUT /api/v1/traffic/policies/{id}（version+1；绑定 Agent config_version+1）。
func (h *Handler) UpdatePolicy(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "策略 ID 非法")
		return
	}
	var req policyRequest
	if !decodeAdminJSON(w, r, &req) {
		return
	}
	if err := req.validate(); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	before, err := h.store.GetPolicy(r.Context(), id)
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	updated, err := h.store.UpdatePolicy(r.Context(), id, req.Name, req.Config, principalName(p))
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "update", "agent_policy", id.String(), updated.Name,
		policyAuditSummary(before), policyAuditSummary(updated), audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, updated)
}

// DeletePolicy DELETE /api/v1/traffic/policies/{id}（被绑定 → 409）。
func (h *Handler) DeletePolicy(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "策略 ID 非法")
		return
	}
	before, err := h.store.GetPolicy(r.Context(), id)
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	if err := h.store.DeletePolicy(r.Context(), id); err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete", "agent_policy", id.String(), before.Name,
		policyAuditSummary(before), "", audits.ResultSuccess, audits.RiskHigh)
	w.WriteHeader(http.StatusNoContent)
}

// ---------- 策略绑定 ----------

// bindPolicyRequest 绑定入参。
type bindPolicyRequest struct {
	PolicyID string `json:"policy_id"`
}

// BindPolicy POST /api/v1/traffic/agents/{agent_id}/policy
// （每 Agent 同时仅一条生效绑定，重复绑定即换绑——契约 §4）。
func (h *Handler) BindPolicy(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	agentID, ok := parseAgentID(w, r)
	if !ok {
		return
	}
	var req bindPolicyRequest
	if !decodeAdminJSON(w, r, &req) {
		return
	}
	policyID, err := uuid.Parse(strings.TrimSpace(req.PolicyID))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "policy_id 非法")
		return
	}
	before, err := h.store.GetAgent(r.Context(), agentID)
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	if err := h.store.BindPolicy(r.Context(), agentID, policyID, principalName(p)); err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "bind", "agent_policy_binding", agentID.String(), before.Hostname,
		bindingAuditSummary(before.PolicyBinding), bindingAuditSummary(&PolicyBinding{PolicyID: policyID}),
		audits.ResultSuccess, audits.RiskHigh)
	w.WriteHeader(http.StatusNoContent)
}

// UnbindPolicy DELETE /api/v1/traffic/agents/{agent_id}/policy。
func (h *Handler) UnbindPolicy(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	agentID, ok := parseAgentID(w, r)
	if !ok {
		return
	}
	before, err := h.store.GetAgent(r.Context(), agentID)
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	if err := h.store.UnbindPolicy(r.Context(), agentID); err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "unbind", "agent_policy_binding", agentID.String(), before.Hostname,
		bindingAuditSummary(before.PolicyBinding), "", audits.ResultSuccess, audits.RiskHigh)
	w.WriteHeader(http.StatusNoContent)
}

// bindingAuditSummary 绑定审计摘要（合法 JSON；nil → "{}"）。
func bindingAuditSummary(b *PolicyBinding) string {
	if b == nil {
		return "{}"
	}
	raw, _ := json.Marshal(map[string]interface{}{
		"policy_id":      b.PolicyID.String(),
		"policy_name":    b.PolicyName,
		"policy_version": b.PolicyVersion,
	})
	return string(raw)
}

// principalName 审计 bound_by（无主体时兜底空串——仅测试场景）。
func principalName(p *authz.Principal) string {
	if p == nil {
		return ""
	}
	return p.Username
}

// recordAudit 记录操作审计（审计未接线时安全跳过——仅测试场景；写入失败走兜底日志/计数，
// 与 apinodes.recordAudit 同一纪律：审计写失败不阻断已完成的管理操作）。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objType, objID, objName, before, after, result, risk string) {
	if h.audits == nil || p == nil {
		return
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        auditModule,
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
