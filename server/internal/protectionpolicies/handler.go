package protectionpolicies

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Handler 是防护策略处理器。
type Handler struct {
	store  *Store
	audits *audits.Service
}

// NewHandler 创建处理器。
func NewHandler(store *Store, au *audits.Service) *Handler {
	return &Handler{store: store, audits: au}
}

// List 策略列表。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	keyword := r.URL.Query().Get("keyword")
	mode := r.URL.Query().Get("protection_mode")
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	list, total, err := h.store.List(r.Context(), keyword, mode, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	items := make([]map[string]interface{}, 0, len(list))
	for _, p := range list {
		usage, _ := h.store.CountUsage(r.Context(), p.ID)
		items = append(items, policyItem(&p, usage))
	}
	response.Page(w, r, items, total, page, pageSize)
}

type policyRequest struct {
	Code                     string `json:"code"`
	Name                     string `json:"name"`
	Description              string `json:"description"`
	ProtectionMode           string `json:"protection_mode"`
	ParanoiaLevel            *int   `json:"paranoia_level"`
	InboundAnomalyThreshold  *int   `json:"inbound_anomaly_threshold"`
	OutboundAnomalyThreshold *int   `json:"outbound_anomaly_threshold"`
	RequestBodyAccess        *bool  `json:"request_body_access"`
	ResponseBodyAccess       *bool  `json:"response_body_access"`
	Version                  int    `json:"version"`
}

// Create 创建策略。
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req policyRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	// 显式非法值校验（区分"未提供"与"显式非法"）
	if req.ProtectionMode != "" && req.ProtectionMode != ModeOff && req.ProtectionMode != ModeObserve && req.ProtectionMode != ModeProtect {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的防护模式")
		return
	}
	if req.ParanoiaLevel != nil && (*req.ParanoiaLevel < 1 || *req.ParanoiaLevel > 4) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "执行等级必须在1至4之间")
		return
	}
	if req.InboundAnomalyThreshold != nil && (*req.InboundAnomalyThreshold < 1 || *req.InboundAnomalyThreshold > 100) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "入站异常阈值必须在1至100之间")
		return
	}
	if req.OutboundAnomalyThreshold != nil && (*req.OutboundAnomalyThreshold < 1 || *req.OutboundAnomalyThreshold > 100) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "出站异常阈值必须在1至100之间")
		return
	}
	policy := &Policy{
		Code:                     req.Code,
		Name:                     req.Name,
		Description:              req.Description,
		Status:                   "ACTIVE",
		ProtectionMode:           defaultMode(req.ProtectionMode),
		ParanoiaLevel:            defaultIntPtr(req.ParanoiaLevel, 1),
		InboundAnomalyThreshold:  defaultIntPtr(req.InboundAnomalyThreshold, 5),
		OutboundAnomalyThreshold: defaultIntPtr(req.OutboundAnomalyThreshold, 4),
		RequestBodyAccess:        true,
		ResponseBodyAccess:       false,
		RequestBodyLimit:         13107200,
		RequestBodyNoFilesLimit:  131072,
		ResponseBodyLimit:        524288,
		UploadFileLimit:          13107200,
		JSONParserEnabled:        true,
		XMLParserEnabled:         true,
		MultipartParserEnabled:   true,
		AuditLogEnabled:          true,
		AuditLogRelevantStatus:   "^(?:(5|4)(0|1)[0-9])$",
		AuditLogParts:            "ABIJDEFHZ",
		BlockingStatusCode:       403,
		BlockingPageID:           "default",
		CreatedBy:                &p.UserID,
	}
	if req.RequestBodyAccess != nil {
		policy.RequestBodyAccess = *req.RequestBodyAccess
	}
	if req.ResponseBodyAccess != nil {
		policy.ResponseBodyAccess = *req.ResponseBodyAccess
	}
	if err := h.store.Create(r.Context(), policy); err != nil {
		if errors.Is(err, ErrCodeExists) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "策略编码已存在")
			return
		}
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	h.recordAudit(r, p, "protection_policies", "create", "policy", policy.ID.String(), policy.Code, policySummary(policy), audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, policyItem(policy, 0))
}

// Get 策略详情。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的策略ID")
		return
	}
	policy, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "策略不存在")
		return
	}
	usage, _ := h.store.CountUsage(r.Context(), id)
	appIDs, _ := h.store.ListApplicationIDs(r.Context(), id)
	item := policyItem(policy, usage)
	item["application_ids"] = appIDs
	response.JSON(w, r, http.StatusOK, item)
}

// Update 更新策略。
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的策略ID")
		return
	}
	var req policyRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	policy, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "策略不存在")
		return
	}
	if req.Version != policy.Version {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "策略已被其他人修改，请刷新后重试")
		return
	}
	before := policySummary(policy)
	policy.Name = req.Name
	policy.Description = req.Description
	if req.ProtectionMode != "" {
		policy.ProtectionMode = defaultMode(req.ProtectionMode)
	}
	if req.ParanoiaLevel != nil {
		policy.ParanoiaLevel = *req.ParanoiaLevel
	}
	if req.InboundAnomalyThreshold != nil {
		policy.InboundAnomalyThreshold = *req.InboundAnomalyThreshold
	}
	if req.OutboundAnomalyThreshold != nil {
		policy.OutboundAnomalyThreshold = *req.OutboundAnomalyThreshold
	}
	if req.RequestBodyAccess != nil {
		policy.RequestBodyAccess = *req.RequestBodyAccess
	}
	if req.ResponseBodyAccess != nil {
		policy.ResponseBodyAccess = *req.ResponseBodyAccess
	}
	if err := h.store.Update(r.Context(), policy); err != nil {
		if errors.Is(err, ErrBuiltin) {
			response.Error(w, r, http.StatusForbidden, response.CodePermissionDenied, "内置策略不允许修改")
			return
		}
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	h.recordAudit(r, p, "protection_policies", "update", "policy", id.String(), policy.Code, policySummary(policy), audits.ResultSuccess, audits.RiskMedium)
	_ = before
	response.JSON(w, r, http.StatusOK, policyItem(policy, 0))
}

// Delete 删除策略。
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的策略ID")
		return
	}
	policy, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "策略不存在")
		return
	}
	if err := h.store.Delete(r.Context(), id); err != nil {
		if errors.Is(err, ErrBuiltin) {
			response.Error(w, r, http.StatusForbidden, response.CodePermissionDenied, "内置策略不允许删除")
			return
		}
		if errors.Is(err, ErrInUse) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "策略正在被应用引用，无法删除")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "protection_policies", "delete", "policy", id.String(), policy.Code, policySummary(policy), audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "策略已删除"})
}

// Copy 复制策略。
func (h *Handler) Copy(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的策略ID")
		return
	}
	np, err := h.store.Copy(r.Context(), id, p.UserID)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "策略不存在")
		return
	}
	h.recordAudit(r, p, "protection_policies", "copy", "policy", np.ID.String(), np.Code, policySummary(np), audits.ResultSuccess, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, policyItem(np, 0))
}

// ListApplications 查询策略绑定的应用。
func (h *Handler) ListApplications(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的策略ID")
		return
	}
	appIDs, err := h.store.ListApplicationIDs(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"application_ids": appIDs, "count": len(appIDs)})
}

// BindApplication 将策略绑定到应用（一应用一活动策略）。
func (h *Handler) BindApplication(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	policyID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的策略ID")
		return
	}
	var req struct {
		ApplicationID string `json:"application_id"`
	}
	if err := response.DecodeJSON(w, r, &req, 1024); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	appID, err := uuid.Parse(req.ApplicationID)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的应用ID")
		return
	}
	if _, err := h.store.GetByID(r.Context(), policyID); err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "策略不存在")
		return
	}
	if err := h.store.BindApplication(r.Context(), appID, policyID, p.UserID); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "protection_policies", "bind", "policy", policyID.String(), appID.String(),
		`{"application_id":"`+appID.String()+`"}`, audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "策略已绑定到应用，请发布配置后生效"})
}

// UnbindApplication 解绑应用上的防护策略。
func (h *Handler) UnbindApplication(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	policyID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的策略ID")
		return
	}
	appID, err := uuid.Parse(r.PathValue("app_id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的应用ID")
		return
	}
	// 仅当该应用当前绑定本策略时解绑
	bound, err := h.store.GetApplicationPolicy(r.Context(), appID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if bound == nil || bound.ID != policyID {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "应用未绑定该策略")
		return
	}
	if err := h.store.UnbindApplication(r.Context(), appID); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "protection_policies", "unbind", "policy", policyID.String(), appID.String(),
		`{"application_id":"`+appID.String()+`"}`, audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "策略已解绑，请发布配置后生效"})
}

func policyItem(p *Policy, usage int) map[string]interface{} {
	return map[string]interface{}{
		"id": p.ID, "code": p.Code, "name": p.Name, "description": p.Description,
		"is_builtin": p.IsBuiltin, "status": p.Status, "protection_mode": p.ProtectionMode,
		"paranoia_level": p.ParanoiaLevel, "inbound_anomaly_threshold": p.InboundAnomalyThreshold,
		"outbound_anomaly_threshold": p.OutboundAnomalyThreshold,
		"request_body_access":        p.RequestBodyAccess, "response_body_access": p.ResponseBodyAccess,
		"blocking_status_code": p.BlockingStatusCode, "usage_count": usage,
		"created_at": p.CreatedAt, "updated_at": p.UpdatedAt, "version": p.Version,
	}
}

func policySummary(p *Policy) string {
	return `{"code":"` + p.Code + `","name":"` + p.Name + `","mode":"` + p.ProtectionMode + `"}`
}

func defaultMode(m string) string {
	if m == ModeOff || m == ModeObserve || m == ModeProtect {
		return m
	}
	return ModeObserve
}

func defaultIntPtr(v *int, def int) int {
	if v == nil || *v <= 0 {
		return def
	}
	return *v
}

func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, module, action, objType, objID, objName, summary, result, risk string) {
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:       &p.UserID,
		Username:     p.Username,
		SourceIP:     middleware.RemoteIP(r),
		ConnectionIP: middleware.ConnectionIP(r),
		UserAgent:    r.UserAgent(),
		Module:       module,
		Action:       action,
		ObjectType:   objType,
		ObjectID:     objID,
		ObjectName:   objName,
		AfterSummary: summary,
		Result:       result,
		RiskLevel:    risk,
		RequestID:    response.RequestIDFrom(r),
	})
}

func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
