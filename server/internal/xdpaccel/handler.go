// handler.go 内核级 eBPF/XDP 快速丢包加速管理面 HTTP 接口（Phase 9D-2；路由在 app.go 注册）：
//
//	GET  /api/v1/xdp-acceleration/config 读取当前 XDP 加速配置（xdp_accel.read）
//	PUT  /api/v1/xdp-acceleration/config 校验并保存 XDP 配置 + 尽力 fail-open 同步（xdp_accel.manage）
//	GET  /api/v1/xdp-acceleration/status 探测已配置 Unix Socket 的守护进程状态与丢包遥测（xdp_accel.read）
//	POST /api/v1/xdp-acceleration/sync   立即向 xdpguard 推送一次全局黑名单同步（xdp_accel.manage）
package xdpaccel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// auditRecorder 操作审计记录接口（*audits.Service 实现；单测可注入 spy）。
type auditRecorder interface {
	Record(ctx context.Context, in audits.RecordInput) error
}

// Handler 是内核级 XDP 加速管理面 HTTP 处理器。
type Handler struct {
	store  Repository
	client DaemonClient
	syncer *Syncer
	audits auditRecorder
}

// NewHandler 创建处理器（默认使用生产受控 UnixClient）。
func NewHandler(store Repository, client DaemonClient, syncer *Syncer, au *audits.Service) *Handler {
	if client == nil {
		client = NewUnixClient(defaultStatusTimeout, defaultSyncTimeout)
	}
	if syncer == nil && store != nil {
		syncer = NewSyncer(store, client)
	}
	h := &Handler{
		store:  store,
		client: client,
		syncer: syncer,
	}
	if au != nil {
		h.audits = au
	}
	return h
}

type putConfigRequest struct {
	Enabled             bool     `json:"enabled"`
	SocketPath          *string  `json:"socket_path"`
	Interfaces          []string `json:"interfaces"`
	AttachMode          string   `json:"attach_mode"`
	SyncIntervalSeconds int      `json:"sync_interval_seconds"`
	Reason              string   `json:"reason"`
}

// GetConfig GET /api/v1/xdp-acceleration/config
func (h *Handler) GetConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.store.GetConfig(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, cfg)
}

// PutConfig PUT /api/v1/xdp-acceleration/config
func (h *Handler) PutConfig(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())

	var req putConfigRequest
	if err := response.DecodeJSON(w, r, &req, 64<<10); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)

	socketPath := DefaultSocketPath
	if req.SocketPath != nil {
		socketPath = *req.SocketPath
	}

	cfg := &Config{
		Enabled:             req.Enabled,
		SocketPath:          socketPath,
		Interfaces:          req.Interfaces,
		AttachMode:          req.AttachMode,
		SyncIntervalSeconds: req.SyncIntervalSeconds,
	}
	NormalizeConfig(cfg)

	errs := validateConfigWithSocketValidator(cfg, h.client.ValidateSocketPath)
	if reasonErr := ValidateReason(req.Reason); reasonErr != "" {
		errs = append(errs, FieldError{Field: "reason", Message: reasonErr})
	}
	if len(errs) > 0 {
		response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "XDP 加速配置校验未通过", errs)
		return
	}

	before, err := h.store.GetConfig(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}

	var operatorID uuid.UUID
	if principal != nil {
		operatorID = principal.UserID
	}
	saved, err := h.store.SaveConfig(r.Context(), cfg, operatorID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}

	h.recordConfigAudit(r, principal, before, saved, req.Reason)

	out := UpdateConfigResponse{Config: saved}
	if h.syncer != nil {
		syncRes, syncErr := h.syncer.SyncOnce(r.Context())
		if syncErr != nil {
			out.SyncWarning = sanitizeStatusString(syncErr.Error(), 256)
		} else {
			out.SyncResult = syncRes
			if !syncRes.Synced && syncRes.Error != "" {
				out.SyncWarning = syncRes.Error
			}
		}
	}

	response.JSON(w, r, http.StatusOK, out)
}

// GetStatus GET /api/v1/xdp-acceleration/status
func (h *Handler) GetStatus(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.store.GetConfig(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	st := h.client.ProbeStatus(r.Context(), cfg.SocketPath)
	if st.AttachModeRequested == "" {
		st.AttachModeRequested = cfg.AttachMode
	}
	if st.Interfaces == nil {
		st.Interfaces = []InterfaceStatus{}
	}
	response.JSON(w, r, http.StatusOK, st)
}

// PostSync POST /api/v1/xdp-acceleration/sync
func (h *Handler) PostSync(w http.ResponseWriter, r *http.Request) {
	principal := authz.PrincipalFrom(r.Context())

	res, err := h.syncer.SyncOnce(r.Context())
	if err != nil {
		h.recordSyncAudit(r, principal, nil, err)
		if errors.Is(err, ErrInvalidSocketPath) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, sanitizeStatusString(err.Error(), 256))
			return
		}
		if errors.Is(err, ErrDaemonUnavailable) {
			response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, sanitizeStatusString(err.Error(), 256))
			return
		}
		response.InternalError(w, r, err)
		return
	}

	h.recordSyncAudit(r, principal, res, nil)
	response.JSON(w, r, http.StatusOK, res)
}

func summarizeConfig(cfg *Config, reason string) map[string]interface{} {
	if cfg == nil {
		return nil
	}
	out := map[string]interface{}{
		"enabled":               cfg.Enabled,
		"socket_path":           cfg.SocketPath,
		"interfaces":            nonNilStrings(cfg.Interfaces),
		"attach_mode":           cfg.AttachMode,
		"sync_interval_seconds": cfg.SyncIntervalSeconds,
		"version":               cfg.Version,
	}
	if reason != "" {
		out["reason"] = reason
	}
	return out
}

func (h *Handler) recordConfigAudit(r *http.Request, p *authz.Principal, before, after *Config, reason string) {
	if p == nil || h.audits == nil {
		return
	}
	var beforeJSON, afterJSON []byte
	if before != nil {
		beforeJSON, _ = json.Marshal(summarizeConfig(before, ""))
	}
	if after != nil {
		afterJSON, _ = json.Marshal(summarizeConfig(after, reason))
	}
	risk := audits.RiskMedium
	if after != nil && after.Enabled {
		risk = audits.RiskHigh
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "xdp_acceleration",
		Action:        "UPDATE",
		ObjectType:    "xdp_acceleration_config",
		ObjectID:      "xdp_acceleration",
		ObjectName:    "xdp_acceleration",
		BeforeSummary: string(beforeJSON),
		AfterSummary:  string(afterJSON),
		Result:        audits.ResultSuccess,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}

func (h *Handler) recordSyncAudit(r *http.Request, p *authz.Principal, res *SyncResult, syncErr error) {
	if p == nil || h.audits == nil {
		return
	}
	result := audits.ResultSuccess
	var failureReason string
	var afterJSON []byte
	if syncErr != nil {
		result = audits.ResultFailure
		failureReason = sanitizeStatusString(syncErr.Error(), 256)
		afterJSON, _ = json.Marshal(map[string]interface{}{
			"error": failureReason,
		})
	} else if res != nil {
		afterJSON, _ = json.Marshal(map[string]interface{}{
			"synced":                       res.Synced,
			"mode":                         res.Mode,
			"kernel_attached":              res.KernelAttached,
			"attached_interfaces":          nonNilStrings(res.AttachedInterfaces),
			"synced_v4_cidrs":              res.SyncedV4CIDRs,
			"synced_v6_cidrs":              res.SyncedV6CIDRs,
			"excluded_protected_count":     res.ExcludedProtectedCount,
			"control_plane_excluded_count": res.ControlPlaneExcludedCount,
			"invalid_cidrs_skipped":        res.InvalidCIDRsSkipped,
		})
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "xdp_acceleration",
		Action:        "SYNC",
		ObjectType:    "xdp_acceleration_config",
		ObjectID:      "xdp_acceleration",
		ObjectName:    "xdp_acceleration",
		AfterSummary:  string(afterJSON),
		Result:        result,
		FailureReason: failureReason,
		RiskLevel:     audits.RiskMedium,
		RequestID:     response.RequestIDFrom(r),
	})
}
