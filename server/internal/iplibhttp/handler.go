// handler.go IP 库共享出站与代理设置 HTTP 接口：
//   - GET /api/v1/ip-libraries/outbound-settings（geoip.read 或 threat_intel.read）
//   - PUT /api/v1/ip-libraries/outbound-settings（geoip.manage，写审计日志，脱敏代理凭据）
package iplibhttp

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/outboundhttp"
	"github.com/jiuzhang-waf/server/internal/response"
)

const (
	// PermGeoIPRead 查看 GeoIP 归属地库权限。
	PermGeoIPRead = "geoip.read"
	// PermGeoIPManage 管理 GeoIP 归属地库与 IP 库出站设置权限。
	PermGeoIPManage = "geoip.manage"
	// PermThreatIntelRead 查看威胁情报 IP 黑名单库权限。
	PermThreatIntelRead = "threat_intel.read"

	maxOutboundSettingsBodyBytes = 16 << 10
)

// Handler 是 IP 库共享出站设置的 HTTP 处理器。
type Handler struct {
	store    SettingsStore
	cipher   SecretCipher
	audits   *audits.Service
	resolver outboundhttp.Resolver
}

// NewHandler 创建 IP 库出站设置处理器。
func NewHandler(store SettingsStore, cipher SecretCipher, auditSvc *audits.Service) *Handler {
	return &Handler{
		store:  store,
		cipher: cipher,
		audits: auditSvc,
	}
}

// SetResolver 注入 DNS 解析器（主要用于测试注入假解析器）。
func (h *Handler) SetResolver(r outboundhttp.Resolver) *Handler {
	h.resolver = r
	return h
}

// RegisterRoutes 注册 IP 库出站设置 HTTP 路由。
func RegisterRoutes(mux *http.ServeMux, authzMw func(http.Handler) http.Handler, h *Handler) {
	mux.Handle("GET /api/v1/ip-libraries/outbound-settings",
		authzMw(requireAnyPermission(PermGeoIPRead, PermThreatIntelRead)(http.HandlerFunc(h.Get))))
	mux.Handle("PUT /api/v1/ip-libraries/outbound-settings",
		authzMw(middleware.RequirePermission(PermGeoIPManage)(http.HandlerFunc(h.Update))))
}

// Get GET /api/v1/ip-libraries/outbound-settings
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.store == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "出站设置服务未初始化")
		return
	}
	cfg := LoadSettings(r.Context(), h.store)
	response.JSON(w, r, http.StatusOK, cfg)
}

// Update PUT /api/v1/ip-libraries/outbound-settings
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.store == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "出站设置服务未初始化")
		return
	}
	var req UpdateOutboundSettingsRequest
	if err := response.DecodeJSON(w, r, &req, maxOutboundSettingsBodyBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求体必须是合法 JSON")
		return
	}

	p := authz.PrincipalFrom(r.Context())
	var opID uuid.UUID
	if p != nil {
		opID = p.UserID
	}

	saved, authUpdated, authCleared, err := SaveSettings(r.Context(), h.store, h.cipher, h.resolver, req, opID)
	if err != nil {
		h.writeAudit(r, p, audits.ResultFailure, map[string]any{
			"outbound_allowlist":         req.OutboundAllowlist,
			"allow_insecure_http_mirror": req.AllowInsecureHTTPMirror,
			"proxy_url":                  req.ProxyURL,
			"proxy_auth_provided":        req.ProxyAuth != "",
			"clear_proxy_auth":           req.ClearProxyAuth,
			"error":                      err.Error(),
		})
		switch {
		case errors.Is(err, ErrInvalidSettings), errors.Is(err, outboundhttp.ErrDenied):
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		case errors.Is(err, ErrCipherUnavailable):
			response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, err.Error())
		default:
			response.InternalError(w, r, err)
		}
		return
	}

	// 审计摘要严格脱敏：只记录是否有代理凭据以及是否变更/清空，绝不写入明文或密文。
	h.writeAudit(r, p, audits.ResultSuccess, map[string]any{
		"outbound_allowlist":         saved.OutboundAllowlist,
		"allow_insecure_http_mirror": saved.AllowInsecureHTTPMirror,
		"proxy_url":                  saved.ProxyURL,
		"has_proxy_auth":             saved.HasProxyAuth,
		"proxy_auth_updated":         authUpdated,
		"proxy_auth_cleared":         authCleared,
		"http_timeout_seconds":       saved.HTTPTimeoutSeconds,
	})

	response.JSON(w, r, http.StatusOK, saved)
}

func (h *Handler) writeAudit(r *http.Request, p *authz.Principal, result string, summary map[string]any) {
	if h.audits == nil {
		return
	}
	var uid *uuid.UUID
	username := ""
	if p != nil && p.UserID != uuid.Nil {
		id := p.UserID
		uid = &id
		username = p.Username
	}
	summaryBytes, _ := json.Marshal(summary)
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:       uid,
		Username:     username,
		SourceIP:     middleware.RemoteIP(r),
		ConnectionIP: middleware.ConnectionIP(r),
		UserAgent:    r.UserAgent(),
		Module:       "access_control",
		Action:       "ip_library_outbound_settings_update",
		ObjectType:   "system_settings",
		ObjectID:     SettingsGroup,
		ObjectName:   SettingsGroup,
		AfterSummary: string(summaryBytes),
		Result:       result,
		RiskLevel:    audits.RiskMedium,
		RequestID:    response.RequestIDFrom(r),
	})
}

// requireAnyPermission 任一权限满足即放行（兼容 GeoIP 只读与威胁情报只读角色查看共享出站设置）。
func requireAnyPermission(perms ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := authz.PrincipalFrom(r.Context())
			if p == nil {
				response.Error(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "未登录或会话已过期")
				return
			}
			for _, perm := range perms {
				if p.HasPermission(perm) {
					next.ServeHTTP(w, r)
					return
				}
			}
			response.Error(w, r, http.StatusForbidden, response.CodePermissionDenied, "无权执行该操作")
		})
	}
}
