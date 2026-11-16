package riskpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

type OverrideRepository interface {
	GetApplicationOverride(context.Context, uuid.UUID) (*Policy, error)
	PutApplicationOverride(context.Context, *Policy, int, string) (*Policy, error)
	DeleteApplicationOverride(context.Context, uuid.UUID, int) error
}

type OverrideHandler struct {
	store   OverrideRepository
	audits  *audits.Service
	publish PublishFunc
}

func NewOverrideHandler(store OverrideRepository, audit *audits.Service) *OverrideHandler {
	return &OverrideHandler{store: store, audits: audit}
}

func (h *OverrideHandler) SetPublishFunc(fn PublishFunc) { h.publish = fn }

func RegisterOverrideRoutes(mux *http.ServeMux, authzFn func(http.Handler) http.Handler, h *OverrideHandler) {
	mux.Handle("GET /api/v1/security/risk-policy/applications/{id}", authzFn(middleware.RequirePermission("risk_policy.read")(http.HandlerFunc(h.Get))))
	mux.Handle("PUT /api/v1/security/risk-policy/applications/{id}", authzFn(middleware.RequirePermission("risk_policy.edit")(http.HandlerFunc(h.Put))))
	mux.Handle("DELETE /api/v1/security/risk-policy/applications/{id}", authzFn(middleware.RequirePermission("risk_policy.edit")(http.HandlerFunc(h.Delete))))
}

func (h *OverrideHandler) Get(w http.ResponseWriter, r *http.Request) {
	applicationID, ok := overrideApplicationID(w, r)
	if !ok {
		return
	}
	policy, err := h.store.GetApplicationOverride(r.Context(), applicationID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"policy": policy})
}

func (h *OverrideHandler) Put(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	applicationID, ok := overrideApplicationID(w, r)
	if !ok {
		return
	}
	before, err := h.store.GetApplicationOverride(r.Context(), applicationID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	var req updateRequest
	if err := response.DecodeJSON(w, r, &req, 16384); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if req.Scope != "" && req.Scope != ScopeApplication {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "应用覆盖的 scope 必须为 APPLICATION")
		return
	}
	if before == nil && req.Version != 0 || before != nil && req.Version != before.Version {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "策略已被其他人修改，请刷新后重试")
		return
	}
	updated := &Policy{
		ApplicationID: &applicationID, Scope: ScopeApplication,
		Enabled: req.Enabled, Mode: req.Mode, Version: req.Version,
		BlockThreshold: req.BlockThreshold, RateLimitThreshold: req.RateLimitThreshold,
		RateLimitRPS: req.RateLimitRPS, SignalWindowSeconds: req.SignalWindowSeconds,
		SharedDeviceAccountLimit: req.SharedDeviceAccountLimit,
		Scores:                   req.Scores, RiskLevels: req.RiskLevels,
	}
	if before != nil {
		updated.ID = before.ID
		updated.CreatedAt = before.CreatedAt
	}
	if errs := Validate(updated); len(errs) > 0 {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "策略校验未通过", errs)
		return
	}
	updated.UpdatedBy = principal.Username
	updated, err = h.store.PutApplicationOverride(r.Context(), updated, req.Version, principal.Username)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	h.recordAudit(r, principal, before, updated, "update_override")
	h.publishOverride(updated, principal.UserID)
	response.JSON(w, r, http.StatusOK, map[string]any{"policy": updated})
}

func (h *OverrideHandler) Delete(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())
	applicationID, ok := overrideApplicationID(w, r)
	if !ok {
		return
	}
	version, err := strconv.Atoi(r.URL.Query().Get("version"))
	if err != nil || version <= 0 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "需要有效的版本号")
		return
	}
	before, err := h.store.GetApplicationOverride(r.Context(), applicationID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if before == nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "应用风险覆盖不存在")
		return
	}
	if before.Version != version {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "策略已被其他人修改，请刷新后重试")
		return
	}
	if err := h.store.DeleteApplicationOverride(r.Context(), applicationID, version); err != nil {
		h.writeError(w, r, err)
		return
	}
	h.recordAudit(r, principal, before, nil, "delete_override")
	if h.publish != nil {
		h.publish(context.Background(), principal.UserID, "risk-policy-override-delete-"+before.ID.String())
	} else {
		slog.Warn("risk policy override deleted but publish channel unavailable")
	}
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "已删除应用覆盖，将继承全局策略"})
}

func overrideApplicationID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的应用ID")
		return uuid.Nil, false
	}
	return id, true
}

func (h *OverrideHandler) writeError(w http.ResponseWriter, r *http.Request, err error) {
	var validation *ValidationError
	switch {
	case errors.As(err, &validation):
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "策略校验未通过", validation.Errors)
	case errors.Is(err, ErrConflict):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "策略已被其他人修改，请刷新后重试")
	case errors.Is(err, ErrNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "应用或风险覆盖不存在")
	case errors.Is(err, ErrApplicationRequired):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
	default:
		response.InternalError(w, r, err)
	}
}

func (h *OverrideHandler) publishOverride(policy *Policy, userID uuid.UUID) {
	if h.publish != nil {
		h.publish(context.Background(), userID, "risk-policy-override-"+policy.ID.String()+"-v"+strconv.Itoa(policy.Version))
		return
	}
	slog.Warn("risk policy override saved but publish channel unavailable")
}

func (h *OverrideHandler) recordAudit(r *http.Request, principal *authz.Principal, before, after *Policy, action string) {
	if h.audits == nil || principal == nil {
		return
	}
	beforeJSON, _ := json.Marshal(before)
	afterJSON, _ := json.Marshal(after)
	risk := audits.RiskMedium
	if after != nil && after.Mode == ModeProtect && (before == nil || before.Mode != ModeProtect) {
		risk = audits.RiskHigh
	}
	objectID := ""
	objectName := ""
	if after != nil {
		objectID = after.ID.String()
		objectName = after.ApplicationID.String()
	} else if before != nil {
		objectID = before.ID.String()
		objectName = before.ApplicationID.String()
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID: &principal.UserID, Username: principal.Username,
		SourceIP: middleware.RemoteIP(r), ConnectionIP: middleware.ConnectionIP(r), UserAgent: r.UserAgent(),
		Module: "security", Action: action, ObjectType: "risk_policy_override",
		ObjectID: objectID, ObjectName: objectName,
		BeforeSummary: string(beforeJSON), AfterSummary: string(afterJSON),
		Result: audits.ResultSuccess, RiskLevel: risk, RequestID: response.RequestIDFrom(r),
	})
}
