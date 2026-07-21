package applications

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
	"github.com/jiuzhang-waf/server/internal/validation"
)

// Handler 是应用管理处理器。
type Handler struct {
	store  *Store
	audits *audits.Service
	// certBinder 证书绑定能力（避免循环依赖，以接口注入）
	certBinder CertBinder
}

// CertBinder 是证书绑定接口（由 certificates.Store 实现）。
type CertBinder interface {
	BindApplication(ctx context.Context, appID, certID, operatorID uuid.UUID, appDomains []string) error
	UnbindApplication(ctx context.Context, appID uuid.UUID) error
}

// NewHandler 创建应用管理处理器。
func NewHandler(store *Store, au *audits.Service, binder CertBinder) *Handler {
	return &Handler{store: store, audits: au, certBinder: binder}
}

// ---------- 应用 ----------

// List 应用列表。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	f := ListFilter{
		Keyword:  r.URL.Query().Get("keyword"),
		Status:   r.URL.Query().Get("status"),
		Mode:     r.URL.Query().Get("protection_mode"),
		Page:     queryInt(r, "page", 1),
		PageSize: queryInt(r, "page_size", 20),
	}
	list, total, err := h.store.List(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	items := make([]map[string]interface{}, 0, len(list))
	for _, a := range list {
		domainCount, _ := h.store.CountActiveDomains(r.Context(), a.ID)
		upstreamCount, _ := h.store.CountActiveUpstreams(r.Context(), a.ID)
		items = append(items, appItem(&a, domainCount, upstreamCount))
	}
	response.Page(w, r, items, total, f.Page, f.PageSize)
}

type createAppRequest struct {
	Code           string `json:"code"`
	Name           string `json:"name"`
	Description    string `json:"description"`
	BusinessOwner  string `json:"business_owner"`
	TechnicalOwner string `json:"technical_owner"`
	ProtectionMode string `json:"protection_mode"`
}

// Create 创建应用。
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req createAppRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if err := validation.ValidateAppCode(req.Code); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	a := &Application{
		Code:           req.Code,
		Name:           req.Name,
		Description:    req.Description,
		BusinessOwner:  req.BusinessOwner,
		TechnicalOwner: req.TechnicalOwner,
		Status:         StatusDraft,
		ProtectionMode: defaultMode(req.ProtectionMode),
		CreatedBy:      &p.UserID,
	}
	if err := h.store.Create(r.Context(), a); err != nil {
		if errors.Is(err, ErrCodeExists) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "应用编码已存在")
			return
		}
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	h.recordAudit(r, p, "applications", "create", "application", a.ID.String(), a.Code, "", appSummary(a), audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, appItem(a, 0, 0))
}

// Get 应用详情。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的应用ID")
		return
	}
	a, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "应用不存在")
		return
	}
	domainCount, _ := h.store.CountActiveDomains(r.Context(), id)
	upstreamCount, _ := h.store.CountActiveUpstreams(r.Context(), id)
	domains, _ := h.store.ListDomains(r.Context(), id)
	upstreams, _ := h.store.ListUpstreams(r.Context(), id)
	item := appItem(a, domainCount, upstreamCount)
	item["domains"] = domains
	item["upstreams"] = upstreams
	response.JSON(w, r, http.StatusOK, item)
}

type updateAppRequest struct {
	Name           string `json:"name"`
	Description    string `json:"description"`
	BusinessOwner  string `json:"business_owner"`
	TechnicalOwner string `json:"technical_owner"`
	ProtectionMode string `json:"protection_mode"`
	Version        int    `json:"version"`
}

// Update 更新应用。
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的应用ID")
		return
	}
	var req updateAppRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	a, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "应用不存在")
		return
	}
	if req.Version != a.Version {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "应用已被其他人修改，请刷新后重试")
		return
	}
	before := appSummary(a)
	a.Name = req.Name
	a.Description = req.Description
	a.BusinessOwner = req.BusinessOwner
	a.TechnicalOwner = req.TechnicalOwner
	if req.ProtectionMode != "" {
		a.ProtectionMode = defaultMode(req.ProtectionMode)
	}
	if err := h.store.Update(r.Context(), a); err != nil {
		response.InternalError(w, r, err)
		return
	}
	risk := audits.RiskLow
	if req.ProtectionMode != "" {
		risk = audits.RiskHigh
	}
	h.recordAudit(r, p, "applications", "update", "application", id.String(), a.Code, before, appSummary(a), audits.ResultSuccess, risk)
	response.JSON(w, r, http.StatusOK, appItem(a, 0, 0))
}

// Enable 启用应用。
func (h *Handler) Enable(w http.ResponseWriter, r *http.Request) {
	h.setStatus(w, r, StatusActive, "enable")
}

// Disable 停用应用。
func (h *Handler) Disable(w http.ResponseWriter, r *http.Request) {
	h.setStatus(w, r, StatusDisabled, "disable")
}

func (h *Handler) setStatus(w http.ResponseWriter, r *http.Request, status, action string) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的应用ID")
		return
	}
	a, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "应用不存在")
		return
	}
	if err := h.store.SetStatus(r.Context(), id, status); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "applications", action, "application", id.String(), a.Code, "status="+a.Status, "status="+status, audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "操作成功"})
}

// Copy 复制应用。
func (h *Handler) Copy(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的应用ID")
		return
	}
	src, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "应用不存在")
		return
	}
	// 新编码
	newCode := src.Code + "-copy"
	for i := 2; ; i++ {
		if _, err := h.store.GetByCode(r.Context(), newCode); err != nil {
			break
		}
		newCode = src.Code + "-copy" + intToStr(i)
		if i > 100 {
			break
		}
	}
	newApp := &Application{
		Code:           newCode,
		Name:           src.Name + "（副本）",
		Description:    src.Description,
		BusinessOwner:  src.BusinessOwner,
		TechnicalOwner: src.TechnicalOwner,
		Status:         StatusDraft,
		ProtectionMode: src.ProtectionMode,
		CreatedBy:      &p.UserID,
	}
	if err := h.store.Create(r.Context(), newApp); err != nil {
		response.InternalError(w, r, err)
		return
	}
	// 复制域名
	domains, _ := h.store.ListDomains(r.Context(), id)
	for _, d := range domains {
		nd := d
		nd.ApplicationID = newApp.ID
		nd.ID = uuid.Nil
		_ = h.store.AddDomain(r.Context(), &nd)
	}
	// 复制源站
	upstreams, _ := h.store.ListUpstreams(r.Context(), id)
	for _, u := range upstreams {
		nu := u
		nu.ApplicationID = newApp.ID
		nu.ID = uuid.Nil
		nu.CreatedBy = &p.UserID
		_ = h.store.AddUpstream(r.Context(), &nu)
	}
	h.recordAudit(r, p, "applications", "copy", "application", newApp.ID.String(), newApp.Code, appSummary(src), appSummary(newApp), audits.ResultSuccess, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, appItem(newApp, len(domains), len(upstreams)))
}

// Delete 删除应用（逻辑删除，需先下线）。
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的应用ID")
		return
	}
	a, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "应用不存在")
		return
	}
	// 已发布且活动状态的应用需先停用并下线
	if a.DeploymentStatus == DeployPublished && a.Status == StatusActive {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict,
			"应用已发布且处于活动状态，请先停用并执行下线后再删除")
		return
	}
	if err := h.store.SoftDelete(r.Context(), id); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "applications", "delete", "application", id.String(), a.Code, appSummary(a), "deleted=true", audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "应用已删除"})
}

// ---------- 域名 ----------

// ListDomains 域名列表。
func (h *Handler) ListDomains(w http.ResponseWriter, r *http.Request) {
	appID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的应用ID")
		return
	}
	domains, err := h.store.ListDomains(r.Context(), appID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": domains})
}

type domainRequest struct {
	Hostname            string `json:"hostname"`
	IsPrimary           bool   `json:"is_primary"`
	HTTPEnabled         bool   `json:"http_enabled"`
	HTTPSEnabled        bool   `json:"https_enabled"`
	HTTPPort            *int   `json:"http_port"`
	HTTPSPort           *int   `json:"https_port"`
	RedirectHTTPToHTTPS bool   `json:"redirect_http_to_https"`
}

// AddDomain 添加域名。
func (h *Handler) AddDomain(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	appID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的应用ID")
		return
	}
	if _, err := h.store.GetByID(r.Context(), appID); err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "应用不存在")
		return
	}
	var req domainRequest
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	d := &Domain{
		ApplicationID:       appID,
		Hostname:            req.Hostname,
		IsPrimary:           req.IsPrimary,
		HTTPEnabled:         req.HTTPEnabled,
		HTTPSEnabled:        req.HTTPSEnabled,
		HTTPPort:            req.HTTPPort,
		HTTPSPort:           req.HTTPSPort,
		RedirectHTTPToHTTPS: req.RedirectHTTPToHTTPS,
		Status:              "ACTIVE",
	}
	if err := h.store.AddDomain(r.Context(), d); err != nil {
		if errors.Is(err, ErrDomainConflict) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, err.Error())
			return
		}
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	h.recordAudit(r, p, "applications", "add_domain", "domain", d.ID.String(), d.Hostname, "", domainSummary(d), audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, d)
}

// UpdateDomain 更新域名。
func (h *Handler) UpdateDomain(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	domainID, err := uuid.Parse(r.PathValue("domain_id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的域名ID")
		return
	}
	d, err := h.store.GetDomain(r.Context(), domainID)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "域名不存在")
		return
	}
	var req domainRequest
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	before := domainSummary(d)
	d.Hostname = req.Hostname
	d.IsPrimary = req.IsPrimary
	d.HTTPEnabled = req.HTTPEnabled
	d.HTTPSEnabled = req.HTTPSEnabled
	d.HTTPPort = req.HTTPPort
	d.HTTPSPort = req.HTTPSPort
	d.RedirectHTTPToHTTPS = req.RedirectHTTPToHTTPS
	if err := h.store.UpdateDomain(r.Context(), d); err != nil {
		if errors.Is(err, ErrDomainConflict) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, err.Error())
			return
		}
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	h.recordAudit(r, p, "applications", "update_domain", "domain", d.ID.String(), d.Hostname, before, domainSummary(d), audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, d)
}

// DeleteDomain 删除域名。
func (h *Handler) DeleteDomain(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	domainID, err := uuid.Parse(r.PathValue("domain_id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的域名ID")
		return
	}
	d, err := h.store.GetDomain(r.Context(), domainID)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "域名不存在")
		return
	}
	if err := h.store.DeleteDomain(r.Context(), domainID); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "applications", "delete_domain", "domain", d.ID.String(), d.Hostname, domainSummary(d), "", audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "域名已删除"})
}

// ---------- 源站 ----------

// ListUpstreams 源站列表。
func (h *Handler) ListUpstreams(w http.ResponseWriter, r *http.Request) {
	appID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的应用ID")
		return
	}
	upstreams, err := h.store.ListUpstreams(r.Context(), appID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": upstreams})
}

type upstreamRequest struct {
	Name                       string `json:"name"`
	Scheme                     string `json:"scheme"`
	Host                       string `json:"host"`
	Port                       int    `json:"port"`
	Weight                     *int   `json:"weight"`
	Priority                   int    `json:"priority"`
	HealthCheckEnabled         bool   `json:"health_check_enabled"`
	HealthCheckPath            string `json:"health_check_path"`
	HealthCheckMethod          string `json:"health_check_method"`
	HealthCheckIntervalSeconds int    `json:"health_check_interval_seconds"`
	HealthCheckTimeoutSeconds  int    `json:"health_check_timeout_seconds"`
	ExpectedStatusCodes        string `json:"expected_status_codes"`
	ConnectTimeoutMs           int    `json:"connect_timeout_ms"`
	ResponseHeaderTimeoutMs    int    `json:"response_header_timeout_ms"`
	TLSServerName              string `json:"tls_server_name"`
	TLSVerify                  bool   `json:"tls_verify"`
	MaxRetries                 int    `json:"max_retries"`
	Version                    int    `json:"version"`
}

// AddUpstream 添加源站。
func (h *Handler) AddUpstream(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	appID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的应用ID")
		return
	}
	if _, err := h.store.GetByID(r.Context(), appID); err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "应用不存在")
		return
	}
	var req upstreamRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	u := buildUpstream(&req, appID, &p.UserID)
	if err := h.store.AddUpstream(r.Context(), u); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	h.recordAudit(r, p, "upstreams", "create", "upstream", u.ID.String(), u.Name, "", upstreamSummary(u), audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, u)
}

// UpdateUpstream 更新源站。
func (h *Handler) UpdateUpstream(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的源站ID")
		return
	}
	u, err := h.store.GetUpstream(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "源站不存在")
		return
	}
	var req upstreamRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if req.Version != u.Version {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "源站已被其他人修改，请刷新后重试")
		return
	}
	before := upstreamSummary(u)
	applyUpstreamRequest(u, &req)
	if err := h.store.UpdateUpstream(r.Context(), u); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	risk := audits.RiskLow
	if req.Weight != nil {
		risk = audits.RiskMedium
	}
	h.recordAudit(r, p, "upstreams", "update", "upstream", id.String(), u.Name, before, upstreamSummary(u), audits.ResultSuccess, risk)
	response.JSON(w, r, http.StatusOK, u)
}

// EnableUpstream 启用源站。
func (h *Handler) EnableUpstream(w http.ResponseWriter, r *http.Request) {
	h.setUpstreamStatus(w, r, "ACTIVE", "enable")
}

// DisableUpstream 停用源站。
func (h *Handler) DisableUpstream(w http.ResponseWriter, r *http.Request) {
	h.setUpstreamStatus(w, r, "DISABLED", "disable")
}

func (h *Handler) setUpstreamStatus(w http.ResponseWriter, r *http.Request, status, action string) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的源站ID")
		return
	}
	u, err := h.store.GetUpstream(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "源站不存在")
		return
	}
	if err := h.store.SetUpstreamStatus(r.Context(), id, status); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "upstreams", action, "upstream", id.String(), u.Name, "status="+u.Status, "status="+status, audits.ResultSuccess, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "操作成功"})
}

// DeleteUpstream 删除源站。
func (h *Handler) DeleteUpstream(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的源站ID")
		return
	}
	u, err := h.store.GetUpstream(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "源站不存在")
		return
	}
	if err := h.store.DeleteUpstream(r.Context(), id); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "upstreams", "delete", "upstream", id.String(), u.Name, upstreamSummary(u), "", audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "源站已删除"})
}

// ---------- 证书绑定 ----------

type bindCertRequest struct {
	CertificateID string `json:"certificate_id"`
}

// BindCertificate 绑定证书到应用（校验域名匹配）。
func (h *Handler) BindCertificate(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	appID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的应用ID")
		return
	}
	app, err := h.store.GetByID(r.Context(), appID)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "应用不存在")
		return
	}
	var req bindCertRequest
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	certID, err := uuid.Parse(req.CertificateID)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的证书ID")
		return
	}
	if h.certBinder == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "证书服务未配置")
		return
	}
	// 收集应用域名用于匹配校验
	domains, err := h.store.ListDomains(r.Context(), appID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	var hostnames []string
	for _, d := range domains {
		if d.HTTPSEnabled {
			hostnames = append(hostnames, d.NormalizedHostname)
		}
	}
	if len(hostnames) == 0 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "应用未启用 HTTPS 域名，无法绑定证书")
		return
	}
	if err := h.certBinder.BindApplication(r.Context(), appID, certID, p.UserID, hostnames); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	h.recordAudit(r, p, "certificates", "bind", "certificate", certID.String(), app.Code,
		"", "bound_to="+app.Code, audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "证书已绑定"})
}

// UnbindCertificate 解绑应用证书。
func (h *Handler) UnbindCertificate(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	appID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的应用ID")
		return
	}
	app, err := h.store.GetByID(r.Context(), appID)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "应用不存在")
		return
	}
	if h.certBinder == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "证书服务未配置")
		return
	}
	if err := h.certBinder.UnbindApplication(r.Context(), appID); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "certificates", "unbind", "certificate", appID.String(), app.Code,
		"bound_to="+app.Code, "", audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "证书已解绑"})
}

// ---------- 辅助 ----------

func buildUpstream(req *upstreamRequest, appID uuid.UUID, createdBy *uuid.UUID) *Upstream {
	weight := 10
	if req.Weight != nil {
		weight = *req.Weight
	}
	u := &Upstream{
		ApplicationID:              appID,
		Name:                       req.Name,
		Scheme:                     defaultStr(req.Scheme, "http"),
		Host:                       req.Host,
		Port:                       req.Port,
		Weight:                     weight,
		Priority:                   req.Priority,
		Status:                     "ACTIVE",
		HealthCheckEnabled:         req.HealthCheckEnabled,
		HealthCheckPath:            defaultStr(req.HealthCheckPath, "/health"),
		HealthCheckMethod:          defaultStr(req.HealthCheckMethod, "GET"),
		HealthCheckIntervalSeconds: defaultInt(req.HealthCheckIntervalSeconds, 30),
		HealthCheckTimeoutSeconds:  defaultInt(req.HealthCheckTimeoutSeconds, 5),
		ExpectedStatusCodes:        defaultStr(req.ExpectedStatusCodes, "200"),
		ConnectTimeoutMs:           defaultInt(req.ConnectTimeoutMs, 3000),
		ResponseHeaderTimeoutMs:    defaultInt(req.ResponseHeaderTimeoutMs, 10000),
		TLSServerName:              req.TLSServerName,
		TLSVerify:                  req.TLSVerify,
		MaxRetries:                 defaultInt(req.MaxRetries, 1),
		CreatedBy:                  createdBy,
	}
	return u
}

func applyUpstreamRequest(u *Upstream, req *upstreamRequest) {
	u.Name = req.Name
	u.Scheme = req.Scheme
	u.Host = req.Host
	u.Port = req.Port
	if req.Weight != nil {
		u.Weight = *req.Weight
	}
	u.Priority = req.Priority
	u.HealthCheckEnabled = req.HealthCheckEnabled
	u.HealthCheckPath = req.HealthCheckPath
	u.HealthCheckMethod = req.HealthCheckMethod
	u.HealthCheckIntervalSeconds = req.HealthCheckIntervalSeconds
	u.HealthCheckTimeoutSeconds = req.HealthCheckTimeoutSeconds
	u.ExpectedStatusCodes = req.ExpectedStatusCodes
	u.ConnectTimeoutMs = req.ConnectTimeoutMs
	u.ResponseHeaderTimeoutMs = req.ResponseHeaderTimeoutMs
	u.TLSServerName = req.TLSServerName
	u.TLSVerify = req.TLSVerify
	u.MaxRetries = req.MaxRetries
}

func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, module, action, objType, objID, objName, before, after, result, risk string) {
	_ = h.audits.Record(r.Context(), audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.RemoteIP(r),
		UserAgent:     r.UserAgent(),
		Module:        module,
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

func appItem(a *Application, domainCount, upstreamCount int) map[string]interface{} {
	return map[string]interface{}{
		"id": a.ID, "code": a.Code, "name": a.Name, "description": a.Description,
		"business_owner": a.BusinessOwner, "technical_owner": a.TechnicalOwner,
		"status": a.Status, "protection_mode": a.ProtectionMode,
		"deployment_status": a.DeploymentStatus, "health_status": a.HealthStatus,
		"current_version_id": a.CurrentVersionID, "last_publish_at": a.LastPublishAt,
		"last_publish_result": a.LastPublishResult,
		"domain_count":        domainCount, "upstream_count": upstreamCount,
		"created_at": a.CreatedAt, "updated_at": a.UpdatedAt, "version": a.Version,
	}
}

func appSummary(a *Application) string {
	return `{"code":"` + a.Code + `","name":"` + a.Name + `","status":"` + a.Status + `","mode":"` + a.ProtectionMode + `"}`
}

func domainSummary(d *Domain) string {
	return `{"hostname":"` + d.NormalizedHostname + `","type":"` + d.DomainType + `"}`
}

func upstreamSummary(u *Upstream) string {
	return `{"name":"` + u.Name + `","host":"` + u.NormalizedHost + `","port":` + intToStr(u.Port) + `,"weight":` + intToStr(u.Weight) + `}`
}

func defaultMode(m string) string {
	if m == ModeOff || m == ModeObserve || m == ModeProtect {
		return m
	}
	return ModeObserve
}

func defaultStr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func defaultInt(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

func intToStr(v int) string {
	return strconv.Itoa(v)
}

func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n := 0
	for _, c := range v {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	if n <= 0 {
		return def
	}
	return n
}
