package ratelimitpolicies

import (
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// 模拟测试边界
const (
	maxSimRequests = 10000
	maxSimIPs      = 10
	defSimRequests = 100
)

// Handler 是CC防护（限速）策略处理器。
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
	f := ListFilter{
		ScopeType: r.URL.Query().Get("scope_type"),
		Status:    r.URL.Query().Get("status"),
		Action:    r.URL.Query().Get("action"),
		Keyword:   r.URL.Query().Get("keyword"),
		Page:      queryInt(r, "page", 1),
		PageSize:  queryInt(r, "page_size", 20),
	}
	if v := r.URL.Query().Get("application_id"); v != "" {
		appID, err := uuid.Parse(v)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的应用ID")
			return
		}
		f.ApplicationID = &appID
	}
	list, total, err := h.store.List(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, f.Page, f.PageSize)
}

// Get 策略详情。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的策略ID")
		return
	}
	p, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "策略不存在")
		return
	}
	response.JSON(w, r, http.StatusOK, p)
}

// policyRequest 是创建/更新/校验请求体。
type policyRequest struct {
	Name                 string     `json:"name"`
	Description          string     `json:"description"`
	ScopeType            string     `json:"scope_type"`
	ApplicationID        *uuid.UUID `json:"application_id"`
	URIMatchType         string     `json:"uri_match_type"`
	URIPattern           string     `json:"uri_pattern"`
	Dimension            string     `json:"dimension"`
	Algorithm            string     `json:"algorithm"`
	RequestsLimit        int        `json:"requests_limit"`
	WindowSeconds        int        `json:"window_seconds"`
	BurstCapacity        int        `json:"burst_capacity"`
	Action               string     `json:"action"`
	BlockDurationSeconds int        `json:"block_duration_seconds"`
	ObserveOnly          bool       `json:"observe_only"`
	Priority             int        `json:"priority"`
	EffectiveFrom        *time.Time `json:"effective_from"`
	EffectiveUntil       *time.Time `json:"effective_until"`
	Version              int        `json:"version"`
}

func buildPolicy(req *policyRequest) *Policy {
	return &Policy{
		Name:                 req.Name,
		Description:          req.Description,
		ScopeType:            req.ScopeType,
		ApplicationID:        req.ApplicationID,
		URIMatchType:         req.URIMatchType,
		URIPattern:           req.URIPattern,
		Dimension:            req.Dimension,
		Algorithm:            req.Algorithm,
		RequestsLimit:        req.RequestsLimit,
		WindowSeconds:        req.WindowSeconds,
		BurstCapacity:        req.BurstCapacity,
		Action:               req.Action,
		BlockDurationSeconds: req.BlockDurationSeconds,
		ObserveOnly:          req.ObserveOnly,
		Priority:             req.Priority,
		EffectiveFrom:        req.EffectiveFrom,
		EffectiveUntil:       req.EffectiveUntil,
	}
}

// Create 创建策略。
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req policyRequest
	if err := response.DecodeJSON(w, r, &req, 16384); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	policy := buildPolicy(&req)
	policy.Status = StatusActive
	if err := h.store.Create(r.Context(), policy, p.UserID); err != nil {
		h.writeSaveError(w, r, err)
		return
	}
	h.recordAudit(r, p, "create", policy.ID.String(), policy.Name, audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, policy)
}

// Update 更新策略（乐观锁）。
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
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
	var req policyRequest
	if err := response.DecodeJSON(w, r, &req, 16384); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if req.Version != policy.Version {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "策略已被其他人修改，请刷新后重试")
		return
	}
	updated := buildPolicy(&req)
	updated.ID = policy.ID
	updated.Version = policy.Version
	updated.Status = policy.Status // 状态只能通过 Enable/Disable 变更
	if err := h.store.Update(r.Context(), updated, p.UserID); err != nil {
		if errors.Is(err, ErrNotFound) {
			// 预检后发生并发修改/删除
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "策略已被其他人修改，请刷新后重试")
			return
		}
		h.writeSaveError(w, r, err)
		return
	}
	h.recordAudit(r, p, "update", id.String(), updated.Name, audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, updated)
}

// Delete 删除策略（软删除）。
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
	if err := h.store.SoftDelete(r.Context(), id, p.UserID); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete", id.String(), policy.Name, audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "策略已删除"})
}

// Enable 启用策略。
func (h *Handler) Enable(w http.ResponseWriter, r *http.Request) {
	h.setStatus(w, r, StatusActive, "enable")
}

// Disable 停用策略。
func (h *Handler) Disable(w http.ResponseWriter, r *http.Request) {
	h.setStatus(w, r, StatusDisabled, "disable")
}

func (h *Handler) setStatus(w http.ResponseWriter, r *http.Request, status, action string) {
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
	if err := h.store.SetStatus(r.Context(), id, p.UserID, status); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, action, id.String(), policy.Name, audits.ResultSuccess, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "操作成功"})
}

// Validate 校验策略配置（不保存，与创建前置校验共用）。
// 返回 {valid, errors[]}，errors 为字段级错误列表。
func (h *Handler) Validate(w http.ResponseWriter, r *http.Request) {
	var req policyRequest
	if err := response.DecodeJSON(w, r, &req, 16384); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	errs := ValidateInput(buildPolicy(&req))
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"valid":  len(errs) == 0,
		"errors": errs,
	})
}

// testRequest 是模拟测试请求体。
type testRequest struct {
	Requests  int      `json:"requests"`
	ClientIPs []string `json:"client_ips"`
	URI       string   `json:"uri"`
}

// Test 干跑模拟测试（不真实请求网关）。
func (h *Handler) Test(w http.ResponseWriter, r *http.Request) {
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
	var req testRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if req.Requests == 0 {
		req.Requests = defSimRequests
	}
	if req.Requests < 0 || req.Requests > maxSimRequests {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"模拟请求数必须在 1~"+strconv.Itoa(maxSimRequests)+" 之间")
		return
	}
	if len(req.ClientIPs) > maxSimIPs {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"模拟客户端IP最多 "+strconv.Itoa(maxSimIPs)+" 个")
		return
	}
	for _, ip := range req.ClientIPs {
		if _, err := netip.ParseAddr(ip); err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的模拟客户端IP: "+ip)
			return
		}
	}
	if req.URI != "" && (req.URI[0] != '/' || hasControlChar(req.URI)) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "模拟URI必须以 / 开头且不含控制字符")
		return
	}
	result := Simulate(policy, SimInput{
		Requests:  req.Requests,
		ClientIPs: req.ClientIPs,
		URI:       req.URI,
	})
	response.JSON(w, r, http.StatusOK, result)
}

// writeSaveError 统一处理保存错误：校验错误返回字段细节，其余按内部错误处理（不泄露SQL细节）。
func (h *Handler) writeSaveError(w http.ResponseWriter, r *http.Request, err error) {
	var ve *ValidationError
	if errors.As(err, &ve) {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "策略校验未通过", ve.Errors)
		return
	}
	response.InternalError(w, r, err)
}

func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objID, objName string, result, risk string) {
	_ = h.audits.Record(r.Context(), audits.RecordInput{
		UserID:       &p.UserID,
		Username:     p.Username,
		SourceIP:     middleware.RemoteIP(r),
		ConnectionIP: middleware.RemoteIP(r),
		UserAgent:    r.UserAgent(),
		Module:       "access_control",
		Action:       action,
		ObjectType:   "rate_limit_policy",
		ObjectID:     objID,
		ObjectName:   objName,
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
