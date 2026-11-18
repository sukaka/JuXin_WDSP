package requestpcap

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
	"github.com/jiuzhang-waf/server/internal/security"
	"github.com/jiuzhang-waf/server/internal/users"
)

const (
	PermissionRead     = "request_pcap.read"
	PermissionVerify   = "request_pcap.verify"
	PermissionDownload = "request_pcap.download"
	PermissionManage   = "request_pcap.manage"
)

type pcapService interface {
	Query(context.Context, string) (EvidenceStatus, error)
	Verify(context.Context, string, uuid.UUID, uuid.UUID) (EvidenceItem, error)
	CreateGrant(context.Context, string, uuid.UUID, uuid.UUID, string, string, string) (DownloadGrant, error)
	PrepareDownload(context.Context, string, uuid.UUID, uuid.UUID, uuid.UUID, string) (*PreparedDownload, error)
}

type userGetter interface {
	GetByID(context.Context, uuid.UUID) (*users.User, error)
}

type auditRecorder interface {
	Record(context.Context, audits.RecordInput) error
}

type Handler struct {
	service pcapService
	users   userGetter
	audits  auditRecorder
	rotate  func() error
}

func NewHandler(service pcapService, users userGetter, audits auditRecorder) *Handler {
	return &Handler{service: service, users: users, audits: audits}
}

func (h *Handler) RegisterRoutes(mux *http.ServeMux, authChain, rateLimit func(http.Handler) http.Handler) {
	mux.Handle("GET /api/v1/request-pcap/lookup", authChain(middleware.RequirePermission(PermissionRead)(http.HandlerFunc(h.Lookup))))
	mux.Handle("GET /api/v1/request-pcap/artifacts/{id}/manifest", authChain(middleware.RequirePermission(PermissionRead)(http.HandlerFunc(h.Manifest))))
	mux.Handle("POST /api/v1/request-pcap/artifacts/{id}/verify", authChain(rateLimit(middleware.RequirePermission(PermissionVerify)(http.HandlerFunc(h.Verify)))))
	mux.Handle("POST /api/v1/request-pcap/artifacts/{id}/download-grants", authChain(rateLimit(middleware.RequirePermission(PermissionDownload)(http.HandlerFunc(h.CreateGrant)))))
	mux.Handle("GET /api/v1/request-pcap/artifacts/{id}/download", authChain(rateLimit(middleware.RequirePermission(PermissionDownload)(http.HandlerFunc(h.Download)))))
	mux.Handle("POST /api/v1/request-pcap/keys/rotate", authChain(rateLimit(middleware.RequirePermission(PermissionManage)(http.HandlerFunc(h.RotateKeys)))))
}

func (h *Handler) principal(w http.ResponseWriter, r *http.Request) *authz.Principal {
	principal := authz.PrincipalFrom(r.Context())
	if principal == nil || principal.UserID == uuid.Nil || principal.SessionID == "" {
		response.Error(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "未登录或会话已过期")
		return nil
	}
	if h.service == nil || h.users == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "PCAP溯源功能未配置")
		return nil
	}
	return principal
}

func (h *Handler) Lookup(w http.ResponseWriter, r *http.Request) {
	if h.principal(w, r) == nil {
		return
	}
	requestID := strings.TrimSpace(r.URL.Query().Get("request_id"))
	if requestID == "" || len(requestID) > 64 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "业务请求ID不能为空且不超过64字符")
		return
	}
	result, err := h.service.Query(r.Context(), requestID)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, result)
}

func (h *Handler) Manifest(w http.ResponseWriter, r *http.Request) {
	if h.principal(w, r) == nil {
		return
	}
	artifactID, requestID, ok := h.evidenceIdentity(w, r, strings.TrimSpace(r.URL.Query().Get("request_id")))
	if !ok {
		return
	}
	result, err := h.service.Query(r.Context(), requestID)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	for _, item := range result.Items {
		if item.ArtifactID == artifactID {
			response.JSON(w, r, http.StatusOK, item)
			return
		}
	}
	response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "请求与PCAP证据的关联不存在")
}

type evidenceActionRequest struct {
	RequestID string `json:"request_id"`
	Reason    string `json:"reason"`
	Password  string `json:"password,omitempty"`
}

func (h *Handler) Verify(w http.ResponseWriter, r *http.Request) {
	principal := h.principal(w, r)
	if principal == nil {
		return
	}
	var input evidenceActionRequest
	if err := response.DecodeJSON(w, r, &input, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	artifactID, requestID, ok := h.evidenceIdentity(w, r, input.RequestID)
	if !ok {
		return
	}
	if !validReason(strings.TrimSpace(input.Reason)) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请填写1至500字符的核验理由")
		return
	}
	item, err := h.service.Verify(r.Context(), requestID, artifactID, principal.UserID)
	h.record(r, principal, "request_pcap.verify", artifactID, err, "核验未通过", audits.RiskHigh)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, item)
}

func (h *Handler) CreateGrant(w http.ResponseWriter, r *http.Request) {
	principal := h.principal(w, r)
	if principal == nil {
		return
	}
	var input evidenceActionRequest
	if err := response.DecodeJSON(w, r, &input, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	artifactID, requestID, ok := h.evidenceIdentity(w, r, input.RequestID)
	if !ok {
		return
	}
	if !validReason(strings.TrimSpace(input.Reason)) || input.Password == "" || len(input.Password) > 256 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请填写1至500字符的下载理由和密码")
		return
	}
	user, err := h.users.GetByID(r.Context(), principal.UserID)
	if err != nil || user.Status != users.StatusActive {
		response.Error(w, r, http.StatusForbidden, response.CodePermissionDenied, "当前用户不可用")
		return
	}
	if err := security.VerifyPassword(input.Password, user.PasswordHash); err != nil {
		h.record(r, principal, "request_pcap.download_grant", artifactID, errors.New("password rejected"), "密码校验失败", audits.RiskCritical)
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "密码错误")
		return
	}
	grant, err := h.service.CreateGrant(r.Context(), requestID, artifactID, principal.UserID, principal.SessionID, input.Reason, middleware.RemoteIP(r))
	h.record(r, principal, "request_pcap.download_grant", artifactID, err, "授权未创建", audits.RiskCritical)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusCreated, map[string]interface{}{"grant_id": grant.ID, "expires_at": grant.ExpiresAt, "artifact_id": grant.ArtifactID, "request_id": grant.RequestID})
}

func (h *Handler) Download(w http.ResponseWriter, r *http.Request) {
	principal := h.principal(w, r)
	if principal == nil {
		return
	}
	artifactID, requestID, ok := h.evidenceIdentity(w, r, strings.TrimSpace(r.URL.Query().Get("request_id")))
	if !ok {
		return
	}
	grantID, err := uuid.Parse(strings.TrimSpace(r.URL.Query().Get("grant_id")))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的下载授权ID")
		return
	}
	prepared, err := h.service.PrepareDownload(r.Context(), requestID, artifactID, grantID, principal.UserID, principal.SessionID)
	if err != nil {
		h.record(r, principal, "request_pcap.download", artifactID, err, "下载授权或证据复核未通过", audits.RiskCritical)
		h.writeError(w, r, err)
		return
	}
	defer prepared.Close()
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", `attachment; filename="`+prepared.Filename+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	packets, err := prepared.WriteTo(w)
	h.record(r, principal, "request_pcap.download", artifactID, err, "派生下载中断或完整性核验失败", audits.RiskCritical)
	if err != nil {
		slog.Warn("PCAP derivative download failed", "artifact_id", artifactID, "error", err)
		return
	}
	slog.Info("PCAP derivative downloaded", "artifact_id", artifactID, "packet_count", packets)
}

func (h *Handler) evidenceIdentity(w http.ResponseWriter, r *http.Request, requestID string) (uuid.UUID, string, bool) {
	artifactID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的证据ID")
		return uuid.Nil, "", false
	}
	if requestID == "" || len(requestID) > 64 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "业务请求ID不能为空且不超过64字符")
		return uuid.Nil, "", false
	}
	return artifactID, requestID, true
}

func validReason(reason string) bool {
	return len(reason) > 0 && len(reason) <= 500
}

func (h *Handler) writeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrEvidenceNotFound), errors.Is(err, ErrArtifactNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "PCAP证据不存在")
	case errors.Is(err, ErrOperationBusy):
		response.Error(w, r, http.StatusTooManyRequests, response.CodeRateLimited, "已有核验或下载正在执行，请稍后重试")
	case errors.Is(err, ErrGrantNotAvailable):
		response.Error(w, r, http.StatusForbidden, response.CodePermissionDenied, "下载授权无效、已过期或已使用")
	case errors.Is(err, ErrEvidenceUnavailable):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "证据当前不可下载，请检查完整性、关联、包范围和到期状态")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return
	default:
		response.InternalError(w, r, err)
	}
}

func (h *Handler) record(r *http.Request, principal *authz.Principal, action string, artifactID uuid.UUID, err error, failureReason, risk string, reason ...string) {
	if h.audits == nil {
		return
	}
	result := audits.ResultSuccess
	if err != nil {
		result = audits.ResultFailure
	} else {
		failureReason = ""
	}
	objectID := ""
	if artifactID != uuid.Nil {
		objectID = artifactID.String()
	}
	afterSummary := ""
	if len(reason) > 0 && strings.TrimSpace(reason[0]) != "" {
		afterSummary = "操作理由：" + strings.TrimSpace(reason[0])
	}
	if err := h.audits.Record(context.WithoutCancel(r.Context()), audits.RecordInput{UserID: &principal.UserID,
		Username: principal.Username, SourceIP: middleware.RemoteIP(r), ConnectionIP: middleware.ConnectionIP(r),
		UserAgent: r.UserAgent(), Module: "api_audit", Action: action, ObjectType: "request_pcap",
		ObjectID: objectID, AfterSummary: afterSummary, Result: result, FailureReason: failureReason, RiskLevel: risk,
		RequestID: response.RequestIDFrom(r)}); err != nil {
		slog.Error("record PCAP evidence audit failed", "action", action, "error", err)
	}
}
