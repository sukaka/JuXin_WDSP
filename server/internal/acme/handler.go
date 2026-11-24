package acme

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/certificates"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Handler 提供自动 SSL / ACME 管理的 HTTP 接口。
type Handler struct {
	svc    *Service
	audits *audits.Service
}

// NewHandler 创建 ACME HTTP 处理器。
func NewHandler(svc *Service, au *audits.Service) *Handler {
	return &Handler{svc: svc, audits: au}
}

// GetConfig GET /api/v1/certificates/acme/config
func (h *Handler) GetConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.svc.GetConfig(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, cfg)
}

type updateConfigRequest struct {
	Enabled                  bool   `json:"enabled"`
	Provider                 string `json:"provider"`
	DirectoryURL             string `json:"directory_url"`
	CustomDirectoryAllowlist string `json:"custom_directory_allowlist"`
	Email                    string `json:"email"`
	TOSAgreed                bool   `json:"tos_agreed"`
	EABKID                   string `json:"eab_kid"`
	EABHMACKey               string `json:"eab_hmac_key"`
	ClearEABHMACKey          bool   `json:"clear_eab_hmac_key"`
	KeyType                  string `json:"key_type"`
	RenewBeforeDays          int    `json:"renew_before_days"`
	AutoPublish              bool   `json:"auto_publish"`
	Version                  int    `json:"version"`
}

// UpdateConfig PUT /api/v1/certificates/acme/config
func (h *Handler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req updateConfigRequest
	if err := response.DecodeJSON(w, r, &req, 16*1024); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	beforeCfg, _ := h.svc.GetConfig(r.Context())
	updated, err := h.svc.UpdateConfig(r.Context(), ConfigUpdateInput{
		Enabled:                  req.Enabled,
		Provider:                 req.Provider,
		DirectoryURL:             req.DirectoryURL,
		CustomDirectoryAllowlist: req.CustomDirectoryAllowlist,
		Email:                    req.Email,
		TOSAgreed:                req.TOSAgreed,
		EABKID:                   req.EABKID,
		EABHMACKey:               req.EABHMACKey,
		ClearEABHMACKey:          req.ClearEABHMACKey,
		KeyType:                  req.KeyType,
		RenewBeforeDays:          req.RenewBeforeDays,
		AutoPublish:              req.AutoPublish,
		UpdatedBy:                p.UserID,
		ExpectedVersion:          req.Version,
	})
	if err != nil {
		if errors.Is(err, ErrVersionConflict) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, err.Error())
			return
		}
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	h.recordAudit(r, p, "acme_config_update", "acme_config", "global", updated.Provider,
		configAuditSummary(beforeCfg), configAuditSummary(updated), audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, updated)
}

type testConfigRequest struct {
	Provider                 string `json:"provider"`
	DirectoryURL             string `json:"directory_url"`
	CustomDirectoryAllowlist string `json:"custom_directory_allowlist"`
}

// TestConfig POST /api/v1/certificates/acme/config/test
func (h *Handler) TestConfig(w http.ResponseWriter, r *http.Request) {
	var req testConfigRequest
	if err := response.DecodeJSON(w, r, &req, 8*1024); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	res, err := h.svc.TestConfig(r.Context(), req.Provider, req.DirectoryURL, req.CustomDirectoryAllowlist)
	if err != nil {
		if res != nil {
			response.JSON(w, r, http.StatusOK, res)
			return
		}
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	response.JSON(w, r, http.StatusOK, res)
}

// ListOrders GET /api/v1/certificates/acme/orders
func (h *Handler) ListOrders(w http.ResponseWriter, r *http.Request) {
	f := OrderFilter{
		Status:   r.URL.Query().Get("status"),
		Page:     queryInt(r, "page", 1),
		PageSize: queryInt(r, "page_size", 20),
	}
	if appIDStr := r.URL.Query().Get("application_id"); appIDStr != "" {
		appID, err := uuid.Parse(appIDStr)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的应用ID")
			return
		}
		f.ApplicationID = &appID
	}
	items, total, err := h.svc.ListOrders(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, items, total, f.Page, f.PageSize)
}

// GetAppAutoSSL GET /api/v1/applications/{id}/auto-ssl
func (h *Handler) GetAppAutoSSL(w http.ResponseWriter, r *http.Request) {
	appID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的应用ID")
		return
	}
	st, err := h.svc.GetAppAutoSSL(r.Context(), appID)
	if err != nil {
		if errors.Is(err, applications.ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "应用不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, st)
}

type updateAppAutoSSLRequest struct {
	Enabled         bool   `json:"enabled"`
	ChallengeType   string `json:"challenge_type"`
	RenewBeforeDays *int   `json:"renew_before_days"`
}

// UpdateAppAutoSSL PUT /api/v1/applications/{id}/auto-ssl
func (h *Handler) UpdateAppAutoSSL(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	appID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的应用ID")
		return
	}
	var req updateAppAutoSSLRequest
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	st, err := h.svc.UpdateAppAutoSSL(r.Context(), appID, req.Enabled, req.ChallengeType, req.RenewBeforeDays)
	if err != nil {
		if errors.Is(err, applications.ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "应用不存在")
			return
		}
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	after, _ := json.Marshal(map[string]any{
		"enabled":           st.Enabled,
		"challenge_type":    st.ChallengeType,
		"renew_before_days": st.RenewBeforeDays,
	})
	h.recordAudit(r, p, "auto_ssl_update", "application", appID.String(), appID.String(),
		"", string(after), audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, st)
}

// IssueAppCert POST /api/v1/applications/{id}/auto-ssl/issue
func (h *Handler) IssueAppCert(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	appID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的应用ID")
		return
	}
	order, err := h.svc.TriggerAppIssue(r.Context(), appID, TriggerManualIssue, &p.UserID, response.RequestIDFrom(r))
	if err != nil {
		handleTriggerError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusAccepted, order)
}

// RenewCert POST /api/v1/certificates/{id}/renew
func (h *Handler) RenewCert(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	certID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的证书ID")
		return
	}
	order, err := h.svc.TriggerCertRenew(r.Context(), certID, &p.UserID, response.RequestIDFrom(r))
	if err != nil {
		handleTriggerError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusAccepted, order)
}

func handleTriggerError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, applications.ErrNotFound), errors.Is(err, certificates.ErrNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, err.Error())
	case errors.Is(err, ErrOrderInProgress):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, err.Error())
	default:
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
	}
}

// configAuditSummary 构造不含任何密钥明文的 ACME 配置审计摘要。
func configAuditSummary(c *Config) string {
	if c == nil {
		return ""
	}
	b, _ := json.Marshal(struct {
		Enabled         bool   `json:"enabled"`
		Provider        string `json:"provider"`
		DirectoryURL    string `json:"directory_url"`
		Email           string `json:"email"`
		KeyType         string `json:"key_type"`
		RenewBeforeDays int    `json:"renew_before_days"`
		AutoPublish     bool   `json:"auto_publish"`
		EABConfigured   bool   `json:"eab_hmac_configured"`
	}{
		Enabled:         c.Enabled,
		Provider:        c.Provider,
		DirectoryURL:    c.EffectiveDirectoryURL,
		Email:           c.Email,
		KeyType:         c.KeyType,
		RenewBeforeDays: c.RenewBeforeDays,
		AutoPublish:     c.AutoPublish,
		EABConfigured:   c.EABHMACConfigured,
	})
	return string(b)
}

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
		Module:        "certificates",
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
