package certificates

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// DomainLister 提供应用域名查询（由 applications.Store 实现，绑定前域名匹配校验用）。
type DomainLister interface {
	ListDomains(ctx context.Context, appID uuid.UUID) ([]applications.Domain, error)
}

// Handler 是证书管理处理器。
type Handler struct {
	store  *Store
	audits *audits.Service
	apps   DomainLister
}

// NewHandler 创建证书管理处理器。
func NewHandler(store *Store, au *audits.Service) *Handler {
	return &Handler{store: store, audits: au}
}

// SetDomainLister 注入应用域名查询（绑定/解绑独立接口使用）。
func (h *Handler) SetDomainLister(apps DomainLister) {
	h.apps = apps
}

// List 证书列表。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	status := r.URL.Query().Get("status")
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	list, total, err := h.store.List(r.Context(), name, status, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	items := make([]map[string]interface{}, 0, len(list))
	for _, c := range list {
		usage, _ := h.store.CountUsage(r.Context(), c.ID)
		items = append(items, certItem(&c, usage))
	}
	response.Page(w, r, items, total, page, pageSize)
}

// Get 证书详情（不含私钥）。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的证书ID")
		return
	}
	c, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "证书不存在")
		return
	}
	usage, _ := h.store.CountUsage(r.Context(), id)
	appIDs, _ := h.store.ListApplicationIDs(r.Context(), id)
	item := certItem(c, usage)
	item["application_ids"] = appIDs
	response.JSON(w, r, http.StatusOK, item)
}

type uploadCertRequest struct {
	Name     string `json:"name"`
	CertPEM  string `json:"cert_pem"`
	KeyPEM   string `json:"key_pem"`
	ChainPEM string `json:"chain_pem"`
}

// Upload 上传证书。
func (h *Handler) Upload(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req uploadCertRequest
	if err := response.DecodeJSON(w, r, &req, 128*1024); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误或文件过大")
		return
	}
	c, err := h.store.Upload(r.Context(), UploadInput{
		Name:      req.Name,
		CertPEM:   req.CertPEM,
		KeyPEM:    req.KeyPEM,
		ChainPEM:  req.ChainPEM,
		CreatedBy: p.UserID,
	})
	if err != nil {
		if errors.Is(err, ErrNameExists) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "证书名称已存在")
			return
		}
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	h.recordAudit(r, p, "certificates", "upload", "certificate", c.ID.String(), c.Name,
		"", certSummary(c), audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, certItem(c, 0))
}

// Delete 删除证书（未使用）。
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的证书ID")
		return
	}
	c, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "证书不存在")
		return
	}
	if err := h.store.Delete(r.Context(), id); err != nil {
		if errors.Is(err, ErrInUse) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "证书正在使用中，无法删除")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "certificates", "delete", "certificate", id.String(), c.Name, certSummary(c), "", audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "证书已删除"})
}

// ListApplications 查询证书绑定的应用。
func (h *Handler) ListApplications(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的证书ID")
		return
	}
	appIDs, err := h.store.ListApplicationIDs(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"application_ids": appIDs, "count": len(appIDs)})
}

// GetApplication 查询应用当前活动证书；未绑定时 certificate=null。
func (h *Handler) GetApplication(w http.ResponseWriter, r *http.Request) {
	appID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的应用ID")
		return
	}
	cert, err := h.store.GetApplicationCertificate(r.Context(), appID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	var item map[string]interface{}
	if cert != nil {
		item = certItem(cert, 1)
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"certificate": item})
}

// ---------- 辅助 ----------

func certItem(c *Certificate, usage int) map[string]interface{} {
	return map[string]interface{}{
		"id": c.ID, "name": c.Name, "certificate_type": c.CertificateType,
		"common_name": c.CommonName, "subject": c.Subject, "issuer": c.Issuer,
		"serial_number": c.SerialNumber, "not_before": c.NotBefore, "not_after": c.NotAfter,
		"fingerprint_sha256": c.FingerprintSHA256, "public_key_algorithm": c.PublicKeyAlgorithm,
		"public_key_bits": c.PublicKeyBits, "signature_algorithm": c.SignatureAlgorithm,
		"san_domains": c.SANDomains, "status": c.Status, "usage_count": usage,
		"created_at": c.CreatedAt, "updated_at": c.UpdatedAt, "version": c.Version,
	}
}

func certSummary(c *Certificate) string {
	return `{"name":"` + c.Name + `","cn":"` + c.CommonName + `","fingerprint":"` + c.FingerprintSHA256[:16] + `"}`
}

// bindRequest 是绑定/解绑请求体。
type bindRequest struct {
	ApplicationID string `json:"application_id"`
}

// Bind 绑定证书到应用（独立接口，权限 certificates.bind）。
func (h *Handler) Bind(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	certID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的证书ID")
		return
	}
	var req bindRequest
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	appID, err := uuid.Parse(req.ApplicationID)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的应用ID")
		return
	}
	if h.apps == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "应用服务未配置")
		return
	}
	if _, err := h.store.GetByID(r.Context(), certID); err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "证书不存在")
		return
	}
	// 收集应用 HTTPS 域名用于匹配校验
	domains, err := h.apps.ListDomains(r.Context(), appID)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "应用不存在")
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
	if err := h.store.BindApplication(r.Context(), appID, certID, p.UserID, hostnames); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	h.recordAudit(r, p, "certificates", "bind", "certificate", certID.String(), certID.String(),
		"", "bound_to="+appID.String(), audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "证书已绑定"})
}

// Unbind 解绑应用证书（独立接口，权限 certificates.bind）。
func (h *Handler) Unbind(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	if _, err := uuid.Parse(r.PathValue("id")); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的证书ID")
		return
	}
	var req bindRequest
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	appID, err := uuid.Parse(req.ApplicationID)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的应用ID")
		return
	}
	if err := h.store.UnbindApplication(r.Context(), appID); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "certificates", "unbind", "certificate", r.PathValue("id"), r.PathValue("id"),
		"bound_to="+appID.String(), "", audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "证书已解绑"})
}

func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, module, action, objType, objID, objName, before, after, result, risk string) {
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
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
