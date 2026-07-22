package trustedproxies

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Handler 是可信代理处理器。
type Handler struct {
	store  *Store
	audits *audits.Service
}

// NewHandler 创建处理器。
func NewHandler(store *Store, auditSvc *audits.Service) *Handler {
	return &Handler{store: store, audits: auditSvc}
}

// List 可信代理列表。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	f := ListFilter{
		Status:     r.URL.Query().Get("status"),
		HeaderType: r.URL.Query().Get("header_type"),
		Keyword:    r.URL.Query().Get("keyword"),
		Page:       queryInt(r, "page", 1),
		PageSize:   queryInt(r, "page_size", 20),
	}
	list, total, err := h.store.List(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if list == nil {
		list = []TrustedProxy{}
	}
	response.Page(w, r, list, total, f.Page, f.PageSize)
}

// Get 可信代理详情。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的可信代理ID")
		return
	}
	p, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "可信代理不存在")
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"proxy": p})
}

type proxyRequest struct {
	Name             string `json:"name"`
	CIDR             string `json:"cidr"`
	HeaderType       string `json:"header_type"`
	CustomHeaderName string `json:"custom_header_name"`
	Priority         int    `json:"priority"`
	Scope            string `json:"scope"`
	NodeName         string `json:"node_name"`
	Description      string `json:"description"`
	Version          int    `json:"version"`
}

// Create 创建可信代理。
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req proxyRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	tp := &TrustedProxy{
		Name:             req.Name,
		CIDR:             req.CIDR,
		HeaderType:       req.HeaderType,
		CustomHeaderName: req.CustomHeaderName,
		Priority:         req.Priority,
		Status:           StatusEnabled,
		Scope:            req.Scope,
		NodeName:         req.NodeName,
		Description:      req.Description,
		CreatedBy:        &p.UserID,
	}
	if tp.Scope == "" {
		tp.Scope = ScopeGlobal
	}
	if err := h.store.Create(r.Context(), tp); err != nil {
		if errors.Is(err, ErrCIDRConflict) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "相同地址与节点的可信代理已存在")
			return
		}
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	h.recordAudit(r, p, "create", tp.ID.String(), tp.Name, "", proxySummary(tp), audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"proxy": tp})
}

// Update 更新可信代理（乐观锁）。
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的可信代理ID")
		return
	}
	var req proxyRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	tp, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "可信代理不存在")
		return
	}
	if req.Version != tp.Version {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "可信代理已被其他人修改，请刷新后重试")
		return
	}
	before := proxySummary(tp)
	tp.Name = req.Name
	tp.CIDR = req.CIDR
	tp.HeaderType = req.HeaderType
	tp.CustomHeaderName = req.CustomHeaderName
	tp.Priority = req.Priority
	if req.Scope != "" {
		tp.Scope = req.Scope
	}
	tp.NodeName = req.NodeName
	tp.Description = req.Description
	tp.UpdatedBy = &p.UserID
	if err := h.store.Update(r.Context(), tp); err != nil {
		if errors.Is(err, ErrVersionConflict) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "可信代理已被其他人修改，请刷新后重试")
			return
		}
		if errors.Is(err, ErrCIDRConflict) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "相同地址与节点的可信代理已存在")
			return
		}
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	h.recordAudit(r, p, "update", id.String(), tp.Name, before, proxySummary(tp), audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"proxy": tp})
}

// Delete 删除可信代理（软删除）。
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的可信代理ID")
		return
	}
	tp, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "可信代理不存在")
		return
	}
	if err := h.store.SoftDelete(r.Context(), id, p.UserID); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete", id.String(), tp.Name, proxySummary(tp), "", audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "可信代理已删除"})
}

// Enable 启用可信代理。
func (h *Handler) Enable(w http.ResponseWriter, r *http.Request) {
	h.setStatus(w, r, StatusEnabled, "enable", audits.RiskLow)
}

// Disable 停用可信代理（改变真实IP识别信任边界，中风险）。
func (h *Handler) Disable(w http.ResponseWriter, r *http.Request) {
	h.setStatus(w, r, StatusDisabled, "disable", audits.RiskMedium)
}

func (h *Handler) setStatus(w http.ResponseWriter, r *http.Request, status, action, risk string) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的可信代理ID")
		return
	}
	tp, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "可信代理不存在")
		return
	}
	if err := h.store.SetStatus(r.Context(), id, status, p.UserID); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, action, id.String(), tp.Name,
		fmt.Sprintf(`{"status":%q}`, tp.Status), fmt.Sprintf(`{"status":%q}`, status),
		audits.ResultSuccess, risk)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "操作成功"})
}

// ---------- 命中测试 ----------

type testRequest struct {
	CIDR    string   `json:"cidr"`
	TestIPs []string `json:"test_ips"`
}

// TestIPResult 是单个测试 IP 的命中结果。
type TestIPResult struct {
	IP             string             `json:"ip"`
	Valid          bool               `json:"valid"`
	Matched        bool               `json:"matched"`         // 是否被本次输入的 CIDR 命中
	MatchedProxies []TestMatchedProxy `json:"matched_proxies"` // 库中启用代理的命中结果
}

// TestMatchedProxy 是命中测试 IP 的库内启用代理。
type TestMatchedProxy struct {
	ID       uuid.UUID `json:"id"`
	Name     string    `json:"name"`
	CIDR     string    `json:"cidr"`
	Scope    string    `json:"scope"`
	NodeName string    `json:"node_name"`
}

// Test 可信代理命中测试（纯计算，不落库、不审计）。
// 输入 {cidr, test_ips}，返回每个测试 IP 是否被该 CIDR 命中，
// 以及当前库中全部启用代理对该 IP 的匹配结果。
func (h *Handler) Test(w http.ResponseWriter, r *http.Request) {
	var req testRequest
	if err := response.DecodeJSON(w, r, &req, 16384); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	normalized, _, err := NormalizeCIDR(req.CIDR)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if len(req.TestIPs) == 0 || len(req.TestIPs) > 100 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "测试IP数量必须在1-100之间")
		return
	}
	enabled, err := h.store.ListEnabled(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	results := make([]TestIPResult, 0, len(req.TestIPs))
	for _, ip := range req.TestIPs {
		item := TestIPResult{IP: ip, MatchedProxies: []TestMatchedProxy{}}
		if !isValidIPLiteral(ip) {
			results = append(results, item)
			continue
		}
		item.Valid = true
		item.Matched = MatchCIDR(normalized, ip)
		for _, tp := range enabled {
			if MatchCIDR(tp.CIDR, ip) {
				item.MatchedProxies = append(item.MatchedProxies, TestMatchedProxy{
					ID: tp.ID, Name: tp.Name, CIDR: tp.CIDR, Scope: tp.Scope, NodeName: tp.NodeName,
				})
			}
		}
		results = append(results, item)
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"cidr":    normalized,
		"results": results,
	})
}

func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objID, objName, before, after, result, risk string) {
	_ = h.audits.Record(r.Context(), audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.RemoteIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "access_control",
		Action:        action,
		ObjectType:    "trusted_proxy",
		ObjectID:      objID,
		ObjectName:    objName,
		BeforeSummary: before,
		AfterSummary:  after,
		Result:        result,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}

// proxySummary 生成审计摘要（JSON，敏感字段由审计服务统一脱敏）。
func proxySummary(p *TrustedProxy) string {
	data, err := json.Marshal(map[string]interface{}{
		"name":        p.Name,
		"cidr":        p.CIDR,
		"ip_version":  p.IPVersion,
		"header_type": p.HeaderType,
		"priority":    p.Priority,
		"status":      p.Status,
		"scope":       p.Scope,
		"node_name":   p.NodeName,
	})
	if err != nil {
		return ""
	}
	return string(data)
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
