package certificates

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

const (
	// maxCertUploadBodyBytes 证书上传请求体上限（兼容国密双证 4×64KB + 证书链 128KB + multipart 封装开销）。
	maxCertUploadBodyBytes = 512 * 1024
	// maxCertFileBytes 单张证书/私钥文件上限（64KB，与 Store.Upload 保持一致）。
	maxCertFileBytes = 64 * 1024
	// maxChainFileBytes 证书链文件上限（128KB，与 Store.Upload 保持一致）。
	maxChainFileBytes = 128 * 1024
)

// DomainLister 提供应用域名查询（由 applications.Store 实现，绑定前域名匹配校验用）。
type DomainLister interface {
	ListDomains(ctx context.Context, appID uuid.UUID) ([]applications.Domain, error)
}

// Handler 是证书管理处理器。
type Handler struct {
	store    *Store
	audits   *audits.Service
	apps     DomainLister
	uploadFn func(ctx context.Context, in UploadInput) (*Certificate, error)
}

// NewHandler 创建证书管理处理器。
func NewHandler(store *Store, au *audits.Service) *Handler {
	return &Handler{store: store, audits: au}
}

// SetDomainLister 注入应用域名查询（绑定/解绑独立接口使用）。
func (h *Handler) SetDomainLister(apps DomainLister) {
	h.apps = apps
}

// List 证书列表（支持 name、status、protocol_type、include_replaced 筛选）。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	status := r.URL.Query().Get("status")
	protocolType := r.URL.Query().Get("protocol_type")
	includeReplaced := r.URL.Query().Get("include_replaced") == "true" || status == StatusReplaced
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	list, total, err := h.store.ListWithFilter(r.Context(), name, status, protocolType, includeReplaced, page, pageSize)
	if err != nil {
		if errors.Is(err, ErrInvalidProtocolType) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "证书协议类型参数无效，仅支持 INTERNATIONAL 或 SM_TLCP")
			return
		}
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
	Name         string `json:"name"`
	ProtocolType string `json:"protocol_type"`
	CertPEM      string `json:"cert_pem"`
	KeyPEM       string `json:"key_pem"`
	EncCertPEM   string `json:"enc_cert_pem"`
	EncKeyPEM    string `json:"enc_key_pem"`
	ChainPEM     string `json:"chain_pem"`
}

// Upload 上传证书（支持 multipart/form-data 文件上传与 application/json PEM 提交，
// 兼容国际通用单证与国密 SM_TLCP 签名+加密双证）。
func (h *Handler) Upload(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	req, ok := parseUploadRequest(w, r)
	if !ok {
		return
	}
	var createdBy uuid.UUID
	if p != nil {
		createdBy = p.UserID
	}
	upload := h.uploadFn
	if upload == nil {
		upload = h.store.Upload
	}
	c, err := upload(r.Context(), UploadInput{
		Name:         req.Name,
		ProtocolType: req.ProtocolType,
		CertPEM:      req.CertPEM,
		KeyPEM:       req.KeyPEM,
		EncCertPEM:   req.EncCertPEM,
		EncKeyPEM:    req.EncKeyPEM,
		ChainPEM:     req.ChainPEM,
		CreatedBy:    createdBy,
	})
	if err != nil {
		if errors.Is(err, ErrNameExists) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "证书名称已存在")
			return
		}
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if p != nil {
		h.recordAudit(r, p, "certificates", "upload", "certificate", c.ID.String(), c.Name,
			"", certSummary(c), audits.ResultSuccess, audits.RiskMedium)
	}
	response.JSON(w, r, http.StatusOK, certItem(c, 0))
}

func isMultipartFormData(contentType string) bool {
	if contentType == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && strings.EqualFold(mediaType, "multipart/form-data")
}

// parseUploadRequest 解析证书上传请求：multipart/form-data 按文件读取并规范化为 PEM，
// 其余 Content-Type 按向后兼容的 JSON 请求体解析。
func parseUploadRequest(w http.ResponseWriter, r *http.Request) (*uploadCertRequest, bool) {
	if isMultipartFormData(r.Header.Get("Content-Type")) {
		return parseMultipartUploadRequest(w, r)
	}
	var req uploadCertRequest
	if err := response.DecodeJSON(w, r, &req, maxCertUploadBodyBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误或文件过大")
		return nil, false
	}
	req.Name = strings.TrimSpace(req.Name)
	req.CertPEM = stripUTF8BOMString(req.CertPEM)
	req.KeyPEM = stripUTF8BOMString(req.KeyPEM)
	req.EncCertPEM = stripUTF8BOMString(req.EncCertPEM)
	req.EncKeyPEM = stripUTF8BOMString(req.EncKeyPEM)
	req.ChainPEM = stripUTF8BOMString(req.ChainPEM)
	return &req, true
}

func parseMultipartUploadRequest(w http.ResponseWriter, r *http.Request) (*uploadCertRequest, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxCertUploadBodyBytes)
	if err := r.ParseMultipartForm(maxCertUploadBodyBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误或上传文件总大小超限")
		return nil, false
	}
	defer func() {
		if r.MultipartForm != nil {
			_ = r.MultipartForm.RemoveAll()
		}
	}()

	protoType, err := NormalizeProtocolType(r.FormValue("protocol_type"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "证书协议类型参数无效，仅支持 INTERNATIONAL 或 SM_TLCP")
		return nil, false
	}
	isGM := protoType == ProtocolSMTLCP

	certLabel := "证书文件"
	keyLabel := "私钥文件"
	if isGM {
		certLabel = "签名证书文件"
		keyLabel = "签名私钥文件"
	}

	certBytes, err := readRequiredMultipartFile(r, "cert_file", certLabel, maxCertFileBytes)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return nil, false
	}
	certPEM, err := NormalizeCertFileToPEM(certBytes, protoType)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, fmt.Sprintf("%s：%s", certLabel, err.Error()))
		return nil, false
	}

	keyBytes, err := readRequiredMultipartFile(r, "key_file", keyLabel, maxCertFileBytes)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return nil, false
	}
	keyPEM, err := NormalizeKeyFileToPEM(keyBytes, protoType)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, fmt.Sprintf("%s：%s", keyLabel, err.Error()))
		return nil, false
	}

	req := &uploadCertRequest{
		Name:         strings.TrimSpace(r.FormValue("name")),
		ProtocolType: protoType,
		CertPEM:      certPEM,
		KeyPEM:       keyPEM,
	}

	if isGM {
		encCertBytes, err := readRequiredMultipartFile(r, "enc_cert_file", "加密证书文件", maxCertFileBytes)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
			return nil, false
		}
		encCertPEM, err := NormalizeCertFileToPEM(encCertBytes, protoType)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, fmt.Sprintf("加密证书文件：%s", err.Error()))
			return nil, false
		}

		encKeyBytes, err := readRequiredMultipartFile(r, "enc_key_file", "加密私钥文件", maxCertFileBytes)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
			return nil, false
		}
		encKeyPEM, err := NormalizeKeyFileToPEM(encKeyBytes, protoType)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, fmt.Sprintf("加密私钥文件：%s", err.Error()))
			return nil, false
		}
		req.EncCertPEM = encCertPEM
		req.EncKeyPEM = encKeyPEM
	}

	chainBytes, hasChain, err := readOptionalMultipartFile(r, "chain_file", "证书链文件", maxChainFileBytes)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return nil, false
	}
	if hasChain {
		chainPEM, err := NormalizeChainFileToPEM(chainBytes, protoType)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, fmt.Sprintf("证书链文件：%s", err.Error()))
			return nil, false
		}
		req.ChainPEM = chainPEM
	}

	return req, true
}

func readRequiredMultipartFile(r *http.Request, fieldName, label string, maxBytes int) ([]byte, error) {
	data, present, err := readOptionalMultipartFile(r, fieldName, label, maxBytes)
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, fmt.Errorf("请上传%s", label)
	}
	return data, nil
}

func readOptionalMultipartFile(r *http.Request, fieldName, label string, maxBytes int) ([]byte, bool, error) {
	f, _, err := r.FormFile(fieldName)
	if err != nil {
		if errors.Is(err, http.ErrMissingFile) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("读取%s失败", label)
	}
	defer func() { _ = f.Close() }()

	data, err := io.ReadAll(io.LimitReader(f, int64(maxBytes)+1))
	if err != nil {
		return nil, false, fmt.Errorf("读取%s失败", label)
	}
	if len(data) == 0 {
		return nil, false, fmt.Errorf("%s不能为空", label)
	}
	if len(data) > maxBytes {
		return nil, false, fmt.Errorf("%s超过 %dKB 限制", label, maxBytes/1024)
	}
	return data, true, nil
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

// GetApplication 查询应用当前活动证书（向后兼容 certificate=国际证书，同时返回 gm_certificate 与 bindings 双槽位视图）。
func (h *Handler) GetApplication(w http.ResponseWriter, r *http.Request) {
	appID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的应用ID")
		return
	}
	bindings, err := h.store.GetApplicationCertificates(r.Context(), appID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	var intlItem, gmItem map[string]interface{}
	if bindings != nil && bindings.International != nil {
		intlItem = certItem(bindings.International, 1)
	}
	if bindings != nil && bindings.GM != nil {
		gmItem = certItem(bindings.GM, 1)
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"certificate":    intlItem,
		"gm_certificate": gmItem,
		"bindings": map[string]interface{}{
			"international": intlItem,
			"gm":            gmItem,
		},
	})
}

// ---------- 辅助 ----------

func certItem(c *Certificate, usage int) map[string]interface{} {
	managedBy := c.ManagedBy
	if managedBy == "" {
		managedBy = ManagedByManual
	}
	protoType := c.EffectiveProtocolType()
	item := map[string]interface{}{
		"id": c.ID, "name": c.Name, "certificate_type": c.CertificateType,
		"protocol_type": protoType,
		"common_name": c.CommonName, "subject": c.Subject, "issuer": c.Issuer,
		"serial_number": c.SerialNumber, "not_before": c.NotBefore, "not_after": c.NotAfter,
		"effective_not_after": c.EffectiveNotAfter(),
		"fingerprint_sha256": c.FingerprintSHA256, "public_key_algorithm": c.PublicKeyAlgorithm,
		"public_key_bits": c.PublicKeyBits, "signature_algorithm": c.SignatureAlgorithm,
		"san_domains": c.SANDomains, "status": c.Status, "usage_count": usage,
		"managed_by": managedBy, "acme_provider": c.ACMEProvider,
		"acme_directory_url": c.ACMEDirectoryURL, "auto_renew": c.AutoRenew,
		"renew_before_days": c.RenewBeforeDays,
		"replaces_certificate_id": c.ReplacesCertificateID,
		"superseded_by": c.SupersededBy, "last_renewed_at": c.LastRenewedAt,
		"created_at": c.CreatedAt, "updated_at": c.UpdatedAt, "version": c.Version,
	}
	if protoType == ProtocolSMTLCP {
		item["enc_common_name"] = c.EncCommonName
		item["enc_subject"] = c.EncSubject
		item["enc_issuer"] = c.EncIssuer
		item["enc_serial_number"] = c.EncSerialNumber
		item["enc_not_before"] = c.EncNotBefore
		item["enc_not_after"] = c.EncNotAfter
		item["enc_fingerprint_sha256"] = c.EncFingerprintSHA256
	}
	return item
}

func certSummary(c *Certificate) string {
	fp := c.FingerprintSHA256
	if len(fp) > 16 {
		fp = fp[:16]
	}
	b, err := json.Marshal(struct {
		Name         string `json:"name"`
		ProtocolType string `json:"protocol_type"`
		CN           string `json:"cn"`
		Fingerprint  string `json:"fingerprint"`
	}{
		Name:         c.Name,
		ProtocolType: c.EffectiveProtocolType(),
		CN:           c.CommonName,
		Fingerprint:  fp,
	})
	if err != nil {
		return "{}"
	}
	return string(b)
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

// Unbind 解绑应用证书（独立接口，权限 certificates.bind；仅解绑路径指定的证书）。
func (h *Handler) Unbind(w http.ResponseWriter, r *http.Request) {
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
	if err := h.store.UnbindCertificate(r.Context(), appID, certID); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "certificates", "unbind", "certificate", certID.String(), certID.String(),
		"bound_to="+appID.String(), "", audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "证书已解绑"})
}

func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, module, action, objType, objID, objName, before, after, result, risk string) {
	if h.audits == nil || p == nil {
		return
	}
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
