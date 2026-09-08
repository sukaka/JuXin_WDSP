// handler.go API 主动扫描 HTTP 处理器（目标/授权/任务/发现/复测桥接）。
// 安全纪律：全部接口登录 + 权限点 + 参数校验（词表白名单）；建标与授权双人分离；
// 授权撤销/紧急停止联动停止在跑任务；复测桥接 apiweakness 状态机，不伪造结论。
package apiscan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jiuzhang-waf/server/internal/apiweakness"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// auditRecorder 操作审计记录接口（由 *audits.Service 实现；单测注入 spy）。
type auditRecorder interface {
	Record(ctx context.Context, in audits.RecordInput) error
}

// JobController 任务执行控制接口（*Worker 实现；未装配时 start 返回 503，
// stop/revoke 降级为库内状态语义——执行侧 Guard 下批复查兜底）。
type JobController interface {
	Enabled(ctx context.Context) bool
	StartJob(ctx context.Context, jobID uuid.UUID) error
	StopJob(ctx context.Context, jobID uuid.UUID) (*Job, error)
	EmergencyStop(ctx context.Context, jobID uuid.UUID) (*Authorization, int64, error)
	RevokeAuthorization(ctx context.Context, authorizationID uuid.UUID) (*Authorization, int64, error)
}

// Handler 主动扫描处理器。
type Handler struct {
	store      Repository
	audits     auditRecorder
	settings   SettingsProvider
	controller JobController // nil 时 start 不可用（503）
	// 复测桥接（SetRetest 装配；未装配时 retest 返回 503）
	engine Engine
	signer *Signer
	retest RetestWriter
}

// NewHandler 创建处理器（audit 为 nil 时不写审计）。
func NewHandler(store Repository, audit *audits.Service) *Handler {
	h := &Handler{store: store}
	if audit != nil {
		h.audits = audit // 避免 typed-nil 接口导致 recordAudit 空调用
	}
	return h
}

// SetSettings 设置开关读取（应用装配时使用；与 controller 二选一，controller 优先）。
func (h *Handler) SetSettings(s SettingsProvider) *Handler { h.settings = s; return h }

// SetController 设置任务执行控制器（应用装配 Worker 时使用）。
func (h *Handler) SetController(c JobController) *Handler { h.controller = c; return h }

// SetRetest 设置复测执行依赖（引擎 + 签名器 + 弱点复测回写器；应用装配时使用）。
func (h *Handler) SetRetest(e Engine, s *Signer, w RetestWriter) *Handler {
	h.engine, h.signer, h.retest = e, s, w
	return h
}

// enabled 扫描能力整体开关（默认关）。
func (h *Handler) enabled(ctx context.Context) bool {
	if h.controller != nil {
		return h.controller.Enabled(ctx)
	}
	if h.settings != nil {
		return h.settings.GetBool(ctx, settingsGroup, settingsKeyEnabled, false)
	}
	return false
}

// ---------- 目标 ----------

// ListTargets GET /targets（过滤 application_id/status + 分页）。
func (h *Handler) ListTargets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var appID *uuid.UUID
	if raw := strings.TrimSpace(q.Get("application_id")); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 application_id")
			return
		}
		appID = &id
	}
	status := strings.ToUpper(strings.TrimSpace(q.Get("status")))
	if status != "" && status != TargetStatusEnabled && status != TargetStatusDisabled {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 status 取值（ENABLED/DISABLED）")
		return
	}
	page, pageSize := queryInt(r, "page", 1), queryPageSize(r, 20)
	list, total, err := h.store.ListTargets(r.Context(), appID, status, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// targetRequest 目标创建/更新请求体。
type targetRequest struct {
	ApplicationID string   `json:"application_id"`
	Name          string   `json:"name"`
	BaseURL       string   `json:"base_url"`
	AllowedPaths  []string `json:"allowed_paths"`
	Status        string   `json:"status"`
}

// validateTargetRequest 校验目标请求体（返回归一化后的值）。
func validateTargetRequest(w http.ResponseWriter, r *http.Request, req *targetRequest, forCreate bool) (*Target, bool) {
	t := &Target{}
	if forCreate {
		appID, err := uuid.Parse(strings.TrimSpace(req.ApplicationID))
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "application_id 必填且为合法 UUID")
			return nil, false
		}
		t.ApplicationID = appID
	}
	t.Name = strings.TrimSpace(req.Name)
	if n := utf8.RuneCountInString(t.Name); n == 0 || n > 128 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "name 必填且不超过 128 字符")
		return nil, false
	}
	t.BaseURL = strings.TrimSpace(req.BaseURL)
	u, err := url.Parse(t.BaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "base_url 必须为合法 http/https 地址")
		return nil, false
	}
	if len(req.AllowedPaths) > 64 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "allowed_paths 不能超过 64 条")
		return nil, false
	}
	t.AllowedPaths = []string{}
	for _, p := range req.AllowedPaths {
		p = strings.TrimSpace(p)
		if !strings.HasPrefix(p, "/") || utf8.RuneCountInString(p) > 512 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "allowed_paths 每项须以 / 开头且不超过 512 字符")
			return nil, false
		}
		t.AllowedPaths = append(t.AllowedPaths, p)
	}
	if !forCreate {
		t.Status = strings.ToUpper(strings.TrimSpace(req.Status))
		if t.Status != TargetStatusEnabled && t.Status != TargetStatusDisabled {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "status 取值须为 ENABLED/DISABLED")
			return nil, false
		}
	}
	return t, true
}

// CreateTarget POST /targets。
func (h *Handler) CreateTarget(w http.ResponseWriter, r *http.Request) {
	var req targetRequest
	if !decodeRequired(w, r, &req) {
		return
	}
	t, ok := validateTargetRequest(w, r, &req, true)
	if !ok {
		return
	}
	p := authz.PrincipalFrom(r.Context())
	if p != nil {
		t.CreatedBy = &p.UserID
	}
	if err := h.store.CreateTarget(r.Context(), t); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "应用不存在（application_id 外键校验失败）")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "scan_target_create", t.ID.String(), t.Name, "", fmt.Sprintf("base_url=%s paths=%d", t.BaseURL, len(t.AllowedPaths)), audits.RiskMedium)
	response.JSON(w, r, http.StatusCreated, map[string]any{"target": t})
}

// GetTarget GET /targets/{id}。
func (h *Handler) GetTarget(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r, "目标")
	if !ok {
		return
	}
	t, err := h.store.GetTarget(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "扫描目标不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"target": t})
}

// UpdateTarget PUT /targets/{id}（维护/停用；application_id 不可改）。
func (h *Handler) UpdateTarget(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r, "目标")
	if !ok {
		return
	}
	var req targetRequest
	if !decodeRequired(w, r, &req) {
		return
	}
	p := authz.PrincipalFrom(r.Context())
	before, err := h.store.GetTarget(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "扫描目标不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	t, ok := validateTargetRequest(w, r, &req, false)
	if !ok {
		return
	}
	t.ID, t.ApplicationID, t.CreatedBy = id, before.ApplicationID, before.CreatedBy
	if err := h.store.UpdateTarget(r.Context(), t); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "scan_target_update", id.String(), t.Name,
		fmt.Sprintf("status=%s base_url=%s", before.Status, before.BaseURL),
		fmt.Sprintf("status=%s base_url=%s", t.Status, t.BaseURL), audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]any{"target": t})
}

// ---------- 授权 ----------

// authorizeRequest 签发授权请求体。
type authorizeRequest struct {
	Allowlist      []string   `json:"allowlist"`
	WindowStart    *time.Time `json:"window_start"`
	WindowEnd      *time.Time `json:"window_end"`
	MaxQPS         int        `json:"max_qps"`
	MaxConcurrency int        `json:"max_concurrency"`
	TestProfile    string     `json:"test_profile"`
	ExpiresAt      time.Time  `json:"expires_at"`
}

// Authorize POST /targets/{id}/authorize（双人分离：建标人不得自审自批）。
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r, "目标")
	if !ok {
		return
	}
	var req authorizeRequest
	if !decodeRequired(w, r, &req) {
		return
	}
	p := authz.PrincipalFrom(r.Context())
	t, err := h.store.GetTarget(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "扫描目标不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if p != nil {
		// 双人分离 fail-closed：建标人信息缺失时无法完成校验，拒绝授权
		if t.CreatedBy == nil {
			response.Error(w, r, http.StatusForbidden, response.CodePermissionDenied, "目标缺少建标人信息，无法执行双人分离校验")
			return
		}
		if *t.CreatedBy == p.UserID {
			response.Error(w, r, http.StatusForbidden, response.CodePermissionDenied, "建标人与授权人不得为同一人（双人分离）")
			return
		}
	}
	if req.ExpiresAt.IsZero() || !req.ExpiresAt.After(time.Now()) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "expires_at 必填且须为未来时间")
		return
	}
	if req.MaxQPS == 0 {
		req.MaxQPS = 5
	}
	if req.MaxQPS < 1 || req.MaxQPS > 100 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "max_qps 取值范围 1~100")
		return
	}
	if req.MaxConcurrency == 0 {
		req.MaxConcurrency = 1
	}
	if req.MaxConcurrency < 1 || req.MaxConcurrency > 16 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "max_concurrency 取值范围 1~16")
		return
	}
	profile, err := parseProbeSetList(req.TestProfile)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if len(req.Allowlist) > 64 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "allowlist 不能超过 64 条")
		return
	}
	for _, item := range req.Allowlist {
		if n := utf8.RuneCountInString(strings.TrimSpace(item)); n == 0 || n > 255 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "allowlist 每项须为 1~255 字符的域名/IP")
			return
		}
	}
	if req.WindowStart != nil && req.WindowEnd != nil && !req.WindowStart.Before(*req.WindowEnd) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "window_start 须早于 window_end")
		return
	}
	a := &Authorization{
		TargetID:       id,
		Allowlist:      req.Allowlist,
		TimeWindow:     TimeWindow{Start: req.WindowStart, End: req.WindowEnd},
		MaxQPS:         req.MaxQPS,
		MaxConcurrency: req.MaxConcurrency,
		TestProfile:    strings.Join(profile, ","),
		ExpiresAt:      req.ExpiresAt,
	}
	if p != nil {
		a.AuthorizedBy = p.UserID
	}
	if a.Allowlist == nil {
		a.Allowlist = []string{}
	}
	if err := h.store.CreateAuthorization(r.Context(), a); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "scan_authorize", a.ID.String(), t.Name,
		"", fmt.Sprintf("target=%s expires_at=%s max_qps=%d profile=%s", t.Name, a.ExpiresAt, a.MaxQPS, a.TestProfile), audits.RiskHigh)
	response.JSON(w, r, http.StatusCreated, map[string]any{"authorization": a})
}

// ListAuthorizations GET /targets/{id}/authorizations。
func (h *Handler) ListAuthorizations(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r, "目标")
	if !ok {
		return
	}
	page, pageSize := queryInt(r, "page", 1), queryPageSize(r, 20)
	list, total, err := h.store.ListAuthorizations(r.Context(), id, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// RevokeAuthorization POST /authorizations/{id}/revoke（撤销即停：联动停止在跑任务）。
func (h *Handler) RevokeAuthorization(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r, "授权")
	if !ok {
		return
	}
	p := authz.PrincipalFrom(r.Context())
	var (
		a       *Authorization
		stopped int64
		err     error
	)
	if h.controller != nil {
		a, stopped, err = h.controller.RevokeAuthorization(r.Context(), id)
	} else {
		// 控制器未装配：降级为库内状态语义（执行侧 Guard 下批复查兜底停发）
		a, err = h.store.RevokeAuthorization(r.Context(), id, time.Now().UTC())
		if err == nil {
			stopped, err = h.store.StopJobsByAuthorization(r.Context(), id, time.Now().UTC())
		}
	}
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "授权单不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "scan_authorization_revoke", id.String(), "",
		"", fmt.Sprintf("revoked_at=%s stopped_jobs=%d", a.RevokedAt, stopped), audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]any{"authorization": a, "stopped_jobs": stopped})
}

// ---------- 任务 ----------

// ListJobs GET /jobs（过滤 target_id/status + 分页）。
func (h *Handler) ListJobs(w http.ResponseWriter, r *http.Request) {
	f := JobFilter{
		Status:   strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("status"))),
		Page:     queryInt(r, "page", 1),
		PageSize: queryPageSize(r, 20),
	}
	switch f.Status {
	case "", JobStatusPending, JobStatusRunning, JobStatusPaused, JobStatusStopped, JobStatusCompleted, JobStatusFailed:
	default:
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 status 取值")
		return
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("target_id")); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 target_id")
			return
		}
		f.TargetID = &id
	}
	list, total, err := h.store.ListJobs(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, f.Page, f.PageSize)
}

// createJobRequest 发起任务请求体。
type createJobRequest struct {
	TargetID        string `json:"target_id"`
	AuthorizationID string `json:"authorization_id"`
	ProbeSet        string `json:"probe_set"`
}

// CreateJob POST /jobs（开关关闭时拒绝创建；授权/白名单/探针集画像强校验）。
func (h *Handler) CreateJob(w http.ResponseWriter, r *http.Request) {
	if !h.enabled(r.Context()) {
		response.Error(w, r, http.StatusForbidden, response.CodePermissionDenied, "主动扫描能力未启用（settings api_scan.enabled）")
		return
	}
	var req createJobRequest
	if !decodeRequired(w, r, &req) {
		return
	}
	targetID, err := uuid.Parse(strings.TrimSpace(req.TargetID))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "target_id 必填且为合法 UUID")
		return
	}
	authzID, err := uuid.Parse(strings.TrimSpace(req.AuthorizationID))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "authorization_id 必填且为合法 UUID")
		return
	}
	t, err := h.store.GetTarget(r.Context(), targetID)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "扫描目标不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if t.Status != TargetStatusEnabled {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "目标已停用，不能发起扫描")
		return
	}
	a, err := h.store.GetAuthorization(r.Context(), authzID)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "授权单不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if a.TargetID != targetID {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "授权单与目标不匹配")
		return
	}
	if reason := a.InactiveReason(time.Now()); reason != "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "授权无效："+reason)
		return
	}
	if !hostAllowed(t.BaseURL, a.Allowlist) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "目标主机不在授权 allowlist 内")
		return
	}
	sets, err := resolveProbeSets(req.ProbeSet, a.TestProfile)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	p := authz.PrincipalFrom(r.Context())
	j := &Job{
		TargetID:        targetID,
		AuthorizationID: authzID,
		ProbeSet:        strings.Join(sets, ","),
		Status:          JobStatusPending,
	}
	if p != nil {
		j.CreatedBy = &p.UserID
	}
	if err := h.store.CreateJob(r.Context(), j); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "scan_job_create", j.ID.String(), t.Name,
		"", fmt.Sprintf("probe_sets=%s", j.ProbeSet), audits.RiskMedium)
	response.JSON(w, r, http.StatusCreated, map[string]any{"job": j})
}

// GetJob GET /jobs/{id}（含进度与计数）。
func (h *Handler) GetJob(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r, "任务")
	if !ok {
		return
	}
	j, err := h.store.GetJob(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "扫描任务不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"job": j})
}

// StartJob POST /jobs/{id}/start（手动启动：置 RUNNING 并后台执行；控制器未装配返回 503）。
func (h *Handler) StartJob(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r, "任务")
	if !ok {
		return
	}
	if h.controller == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "扫描执行器未装配")
		return
	}
	p := authz.PrincipalFrom(r.Context())
	if err := h.controller.StartJob(r.Context(), id); err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "扫描任务不存在")
			return
		}
		if errors.Is(err, ErrInvalidTransition) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "当前状态不允许启动（仅 PENDING/PAUSED 可启动）")
			return
		}
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, err.Error())
		return
	}
	j, err := h.store.GetJob(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "scan_job_start", id.String(), "", "", "status=RUNNING", audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]any{"job": j})
}

// StopJob POST /jobs/{id}/stop（停止：任务置 STOPPED 并取消执行上下文；授权保留）。
func (h *Handler) StopJob(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r, "任务")
	if !ok {
		return
	}
	p := authz.PrincipalFrom(r.Context())
	var (
		j   *Job
		err error
	)
	if h.controller != nil {
		j, err = h.controller.StopJob(r.Context(), id)
	} else {
		j, err = h.store.StopJob(r.Context(), id, time.Now().UTC())
	}
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "扫描任务不存在")
		return
	}
	if errors.Is(err, ErrInvalidTransition) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "任务已终结，无法停止")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "scan_job_stop", id.String(), "", "", "status=STOPPED", audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]any{"job": j})
}

// EmergencyStop POST /jobs/{id}/emergency-stop（紧急停止：STOP + 撤销授权 + 停止该授权下全部任务）。
func (h *Handler) EmergencyStop(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r, "任务")
	if !ok {
		return
	}
	p := authz.PrincipalFrom(r.Context())
	var (
		a       *Authorization
		stopped int64
		err     error
	)
	if h.controller != nil {
		a, stopped, err = h.controller.EmergencyStop(r.Context(), id)
	} else {
		// 控制器未装配：降级为库内状态语义
		var j *Job
		j, err = h.store.GetJob(r.Context(), id)
		if err == nil {
			a, err = h.store.RevokeAuthorization(r.Context(), j.AuthorizationID, time.Now().UTC())
			if err == nil {
				stopped, err = h.store.StopJobsByAuthorization(r.Context(), j.AuthorizationID, time.Now().UTC())
			}
		}
	}
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "扫描任务不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "scan_emergency_stop", id.String(), "", "",
		fmt.Sprintf("authorization_revoked=%s stopped_jobs=%d", a.ID, stopped), audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]any{"authorization": a, "stopped_jobs": stopped})
}

// ---------- 发现 ----------

// ListFindings GET /findings（过滤 job_id/status/severity/template + 分页）。
func (h *Handler) ListFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := FindingFilter{
		Status:   strings.ToUpper(strings.TrimSpace(q.Get("status"))),
		Severity: strings.ToUpper(strings.TrimSpace(q.Get("severity"))),
		Template: strings.ToUpper(strings.TrimSpace(q.Get("template"))),
		Page:     queryInt(r, "page", 1),
		PageSize: queryPageSize(r, 20),
	}
	if f.Status != "" && !IsValidFindingStatus(f.Status) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 status 取值（NEW/CONFIRMED/FALSE_POSITIVE/RETIRED）")
		return
	}
	if f.Severity != "" && !IsValidSeverity(f.Severity) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 severity 取值（INFO/LOW/MEDIUM/HIGH/CRITICAL）")
		return
	}
	if f.Template != "" && !IsValidProbeSet(f.Template) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 template 取值（探针集词表外）")
		return
	}
	if raw := strings.TrimSpace(q.Get("job_id")); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 job_id")
			return
		}
		f.JobID = &id
	}
	list, total, err := h.store.ListFindings(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, f.Page, f.PageSize)
}

// confirmFindingRequest 确认发现请求体（可关联弱点）。
type confirmFindingRequest struct {
	WeaknessID string `json:"weakness_id"`
}

// ConfirmFinding POST /findings/{id}/confirm（NEW → CONFIRMED，可携带 weakness_id 关联弱点）。
func (h *Handler) ConfirmFinding(w http.ResponseWriter, r *http.Request) {
	var req confirmFindingRequest
	if !decodeOptional(w, r, &req) {
		return
	}
	var weaknessID *uuid.UUID
	if raw := strings.TrimSpace(req.WeaknessID); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 weakness_id")
			return
		}
		weaknessID = &id
	}
	h.setFindingStatus(w, r, FindingStatusConfirmed, weaknessID, "scan_finding_confirm")
}

// FalsePositiveFinding POST /findings/{id}/false-positive（NEW → FALSE_POSITIVE）。
func (h *Handler) FalsePositiveFinding(w http.ResponseWriter, r *http.Request) {
	h.setFindingStatus(w, r, FindingStatusFalsePositive, nil, "scan_finding_false_positive")
}

// setFindingStatus 发现处置公共路径。
func (h *Handler) setFindingStatus(w http.ResponseWriter, r *http.Request, status string, weaknessID *uuid.UUID, auditAction string) {
	id, ok := parsePathID(w, r, "发现")
	if !ok {
		return
	}
	p := authz.PrincipalFrom(r.Context())
	f, err := h.store.SetFindingStatus(r.Context(), id, status, weaknessID)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "扫描发现不存在")
		return
	}
	if errors.Is(err, ErrInvalidTransition) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "仅 NEW 状态发现可处置")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, auditAction, id.String(), f.EndpointKey, "status=NEW", "status="+status, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]any{"finding": f})
}

// ---------- 复测桥接 ----------

// retestRequest 复测请求体。
type retestRequest struct {
	Note string `json:"note"`
}

// RetestFinding POST /findings/{id}/retest（设计稿 §十：对关联弱点做定向复测并回写
// apiweakness 状态机）。真实重探发现端点：复现 → RETEST_FAIL；未复现 → RETEST_PASS。
// note 长度与弱点状态（须 FIXED）在发包前校验，必败请求不产生探测流量；
// 授权失效 / 执行器未装配 / 回写失败时如实报错，不伪造复测结论。
func (h *Handler) RetestFinding(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r, "发现")
	if !ok {
		return
	}
	var req retestRequest
	if !decodeOptional(w, r, &req) {
		return
	}
	// 纯入参校验先行：note 超长的请求必败，不得走到真实发包
	note := strings.TrimSpace(req.Note)
	if utf8.RuneCountInString(note) > 512 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "note 长度不能超过 512 字符")
		return
	}
	if h.engine == nil || h.retest == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "扫描复测执行器未装配")
		return
	}
	if !h.enabled(r.Context()) {
		response.Error(w, r, http.StatusForbidden, response.CodePermissionDenied, "主动扫描能力未启用（settings api_scan.enabled）")
		return
	}
	p := authz.PrincipalFrom(r.Context())
	f, err := h.store.GetFinding(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "扫描发现不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if f.WeaknessID == nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "发现未关联弱点，无法复测（先 confirm 并携带 weakness_id）")
		return
	}
	// 弱点状态发包前预检：仅 FIXED 可复测，状态不满足的请求必败，不得真实发包
	// （写回时状态机仍做权威校验，此处仅避免必败请求产生探测流量）
	ws, err := h.retest.WeaknessStatus(r.Context(), *f.WeaknessID)
	if errors.Is(err, apiweakness.ErrNotFound) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "关联弱点不存在，无法复测")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if ws != apiweakness.StatusFixed {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "弱点当前状态不允许复测（仅 FIXED 待复测状态可发起）")
		return
	}
	if note == "" {
		note = fmt.Sprintf("扫描定向复测（finding=%s）", f.ID)
	}
	if !IsValidProbeSet(f.Template) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "发现来源探针集不在内置词表，无法复测")
		return
	}
	job, err := h.store.GetJob(r.Context(), f.JobID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	target, err := h.store.GetTarget(r.Context(), job.TargetID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	authz, err := h.store.GetAuthorization(r.Context(), job.AuthorizationID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if reason := authz.InactiveReason(time.Now()); reason != "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "授权无效，拒绝复测："+reason)
		return
	}
	// 复测目标端点：从发现 endpoint_key 还原路径（"METHOD /path"）
	path := findingPath(f)
	if path == "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "发现端点键无法解析，无法复测")
		return
	}
	if !pathInScope(path, target.AllowedPaths) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "复测端点已不在目标允许路径内，拒绝复测")
		return
	}
	guard := func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		cur, err := h.store.GetAuthorization(ctx, authz.ID)
		if err != nil {
			return err
		}
		if cur.RevokedAt != nil {
			return errAuthorizationRevoked
		}
		if reason := cur.InactiveReason(time.Now()); reason != "" {
			return fmt.Errorf("%w: %s", errAuthorizationInactive, reason)
		}
		return nil
	}
	reproduced := false
	emit := func(res *ProbeResult) error {
		if res.Template == f.Template {
			reproduced = true
		}
		return nil
	}
	task := &ProbeTask{
		JobID:          uuid.New(), // 复测为一次性定向探测，不复用原任务 ID 签名
		BaseURL:        target.BaseURL,
		Paths:          []string{path},
		ProbeSets:      []string{f.Template},
		MaxQPS:         authz.MaxQPS,
		MaxConcurrency: 1,
		Signer:         h.signer,
		Guard:          guard,
	}
	if _, err := h.engine.Run(r.Context(), task, emit); err != nil {
		slog.Warn("复测探测执行失败", "request_id", response.RequestIDFrom(r), "finding_id", id.String(), "error", err)
		response.Error(w, r, http.StatusBadGateway, response.CodeServiceUnavailable, "复测探测执行失败，请确认目标可访问后重试")
		return
	}
	pass := !reproduced
	actor := "system"
	if p != nil {
		actor = p.Username
	}
	if err := h.retest.RetestWeakness(r.Context(), *f.WeaknessID, pass, actor, note); err != nil {
		// 复测回写失败（如弱点非 FIXED）：如实报错，不伪造结论
		slog.Warn("弱点复测回写失败", "request_id", response.RequestIDFrom(r), "weakness_id", f.WeaknessID.String(), "error", err)
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "弱点复测回写失败，弱点当前状态不允许该结论")
		return
	}
	result := RetestResultPass
	if !pass {
		result = RetestResultFail
	}
	h.recordAudit(r, p, "scan_finding_retest", id.String(), f.EndpointKey, "",
		fmt.Sprintf("weakness_id=%s result=%s", f.WeaknessID, result), audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]any{
		"result":      result,
		"reproduced":  reproduced,
		"weakness_id": f.WeaknessID,
	})
}

// 复测结果取值（响应体 result 字段）。
const (
	RetestResultPass = "PASS"
	RetestResultFail = "FAIL"
)

// findingPath 从发现 endpoint_key（"METHOD /path"）还原路径。
func findingPath(f *Finding) string {
	if f == nil {
		return ""
	}
	_, path, ok := strings.Cut(f.EndpointKey, " ")
	if !ok || !strings.HasPrefix(path, "/") {
		return ""
	}
	return path
}

// pathInScope 复测端点须仍落在目标允许路径内（精确匹配——allowed_paths 每项为具体路径，
// 引擎按原样探测，无通配符语义）。
func pathInScope(path string, allowed []string) bool {
	for _, p := range allowed {
		if path == p {
			return true
		}
	}
	return false
}

// ---------- 通用 ----------

// parsePathID 解析路径参数 id（非法返回 400）。
func parsePathID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的"+name+"ID")
		return uuid.Nil, false
	}
	return id, true
}

// decodeOptional 解码可选 JSON 请求体（空 body 视为零值；非法 JSON 返回 400）。
func decodeOptional(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Body == nil || r.ContentLength == 0 {
		return true
	}
	return decodeRequired(w, r, v)
}

// decodeRequired 解码必填 JSON 请求体（非法/为空返回 400）。
func decodeRequired(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := response.DecodeJSON(w, r, v, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return false
	}
	return true
}

// parseProbeSetList 解析逗号分隔探针集（词表校验，大写归一）。
func parseProbeSetList(s string) ([]string, error) {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.ToUpper(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if !IsValidProbeSet(p) {
			return nil, fmt.Errorf("词表外探针集: %q", p)
		}
		out = append(out, p)
	}
	return out, nil
}

// recordAudit 写操作审计（未注入或无操作者上下文时跳过，不影响主流程）。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objID, objName, before, after, risk string) {
	if h.audits == nil || p == nil {
		return
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "api_scan",
		Action:        action,
		ObjectType:    "api_scan",
		ObjectID:      objID,
		ObjectName:    objName,
		BeforeSummary: before,
		AfterSummary:  after,
		Result:        audits.ResultSuccess,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}

// queryPageSize 分页大小（夹取 ≤100，非法回退默认值；与兄弟包上限口径一致）。
func queryPageSize(r *http.Request, def int) int {
	n := queryInt(r, "page_size", def)
	if n > 100 {
		n = 100
	}
	return n
}

// queryInt 查询参数整型（正数，非法回退默认值）。
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
