// handler.go 容器运维管理接口：列表/日志/启停/更新。
// 写操作要求密码二次确认（update 另需确认文本「更新容器」），审计口径：
// list/logs MEDIUM，control HIGH，update CRITICAL，失败同样记录。
// 通道未配置（CONTAINEROPS_SOCKET 为空）时返回明确 503，不伪造空列表。
package containerops

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
	"github.com/jiuzhang-waf/server/internal/security"
	"github.com/jiuzhang-waf/server/internal/users"
)

// opsClient 是 sidecar 调用接口（*Client 实现；单测注入 stub）。
type opsClient interface {
	Available() bool
	ListContainers(ctx context.Context) ([]Container, error)
	ContainerLogs(ctx context.Context, service string, tail int, since int64) (*LogsResult, error)
	SubmitAction(ctx context.Context, service, action string, delaySeconds int) (*ActionJob, error)
	ActionStatus(ctx context.Context, jobID string) (*ActionJob, error)
}

// userGetter 按 ID 查询用户（含密码哈希），由 *users.Store 实现；单测注入 stub。
type userGetter interface {
	GetByID(ctx context.Context, id uuid.UUID) (*users.User, error)
}

// auditRecorder 操作审计记录接口（由 *audits.Service 实现；单测注入 spy）。
type auditRecorder interface {
	Record(ctx context.Context, in audits.RecordInput) error
}

// 审计动作名
const (
	auditList    = "containers.list"
	auditLogs    = "containers.logs"
	auditStart   = "containers.start"
	auditStop    = "containers.stop"
	auditRestart = "containers.restart"
	auditUpdate  = "containers.update"
)

const (
	auditModule     = "system"
	auditObjectType = "container"
)

// maxDelaySeconds 动作延迟执行上限（秒）。
const maxDelaySeconds = 300

var (
	serviceNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)
	jobIDRe       = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

// Handler 容器运维处理器。
type Handler struct {
	ops    opsClient
	users  userGetter
	audits auditRecorder
}

// NewHandler 创建处理器。ops 为 nil 或 Available()==false 时接口返回 503 降级。
func NewHandler(ops opsClient, ug userGetter, au auditRecorder) *Handler {
	return &Handler{ops: ops, users: ug, audits: au}
}

// RegisterRoutes 注册容器运维路由（认证链 + 权限点强制校验，同 systemops 口径）。
// 注意：Go ServeMux 不允许 "actions/{job_id}" 与 "{service}/logs" 两个 GET 模式并存
// （同时命中 /containers/actions/logs 且互不更具体），因此两段 GET 收进单一模式内按段分发，
// 对外路由形态保持不变：GET /containers/{service}/logs 与 GET /containers/actions/{job_id}。
func (h *Handler) RegisterRoutes(mux *http.ServeMux, authChain func(http.Handler) http.Handler) {
	mux.Handle("GET /api/v1/system/containers",
		authChain(middleware.RequirePermission(PermRead)(http.HandlerFunc(h.ListContainers))))
	mux.Handle("GET /api/v1/system/containers/{seg1}/{seg2}",
		authChain(http.HandlerFunc(h.dispatchContainerGET)))
	mux.Handle("POST /api/v1/system/containers/{service}/start",
		authChain(middleware.RequirePermission(PermControl)(http.HandlerFunc(h.Start))))
	mux.Handle("POST /api/v1/system/containers/{service}/stop",
		authChain(middleware.RequirePermission(PermControl)(http.HandlerFunc(h.Stop))))
	mux.Handle("POST /api/v1/system/containers/{service}/restart",
		authChain(middleware.RequirePermission(PermControl)(http.HandlerFunc(h.Restart))))
	mux.Handle("POST /api/v1/system/containers/{service}/update",
		authChain(middleware.RequirePermission(PermUpdate)(http.HandlerFunc(h.Update))))
}

// dispatchContainerGET 按路径段分发两段 GET 子路由并套用对应权限点。
func (h *Handler) dispatchContainerGET(w http.ResponseWriter, r *http.Request) {
	seg1, seg2 := r.PathValue("seg1"), r.PathValue("seg2")
	switch {
	case seg1 == "actions":
		middleware.RequirePermission(PermRead)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.ActionStatus(w, r, seg2)
		})).ServeHTTP(w, r)
	case seg2 == "logs":
		middleware.RequirePermission(PermLogs)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.ContainerLogs(w, r, seg1)
		})).ServeHTTP(w, r)
	default:
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "接口不存在")
	}
}

// available 报告通道是否可用。
func (h *Handler) available() bool {
	return h.ops != nil && h.ops.Available()
}

// writeOpsError 把 sidecar 错误映射为 API 响应。
// 不可达 → 503；上游结构化错误按状态码透传（本地受信 sidecar 的明确文案）。
func writeOpsError(w http.ResponseWriter, r *http.Request, err error) {
	if IsUnavailable(err) {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable,
			"容器运维通道不可用（containerops 未部署或未配置）")
		return
	}
	var ce *Error
	if errors.As(err, &ce) && ce.Kind == KindUpstream {
		switch ce.Status {
		case http.StatusBadRequest:
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, ce.Message)
		case http.StatusForbidden:
			response.Error(w, r, http.StatusForbidden, response.CodePermissionDenied, ce.Message)
		case http.StatusNotFound:
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, ce.Message)
		case http.StatusServiceUnavailable:
			response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, ce.Message)
		default:
			response.Error(w, r, http.StatusBadGateway, response.CodeServiceUnavailable, "容器运维服务异常，请稍后重试")
		}
		return
	}
	response.InternalError(w, r, err)
}

// unavailable 输出 503 降级响应。
func unavailable(w http.ResponseWriter, r *http.Request) {
	response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable,
		"容器运维功能未配置（CONTAINEROPS_SOCKET 为空或 sidecar 未部署）")
}

// ListContainers GET /api/v1/system/containers
func (h *Handler) ListContainers(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	if p == nil {
		response.Error(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "未登录或会话已过期")
		return
	}
	if !h.available() {
		h.recordAudit(r, p, auditList, "", audits.ResultFailure, "容器运维通道未配置", audits.RiskMedium)
		unavailable(w, r)
		return
	}
	containers, err := h.ops.ListContainers(r.Context())
	if err != nil {
		h.recordAudit(r, p, auditList, "", audits.ResultFailure, "容器列表获取失败", audits.RiskMedium)
		writeOpsError(w, r, err)
		return
	}
	if containers == nil {
		containers = []Container{}
	}
	h.recordAudit(r, p, auditList, "", audits.ResultSuccess, "", audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"containers": containers})
}

// ContainerLogs GET /api/v1/system/containers/{service}/logs?tail&since
func (h *Handler) ContainerLogs(w http.ResponseWriter, r *http.Request, service string) {
	p := authz.PrincipalFrom(r.Context())
	if p == nil {
		response.Error(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "未登录或会话已过期")
		return
	}
	if !serviceNameRe.MatchString(service) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "服务名格式不合法")
		return
	}
	tail, errMsg := parseIntParam(r, "tail", DefaultLogTail, 0, MaxLogTail)
	if errMsg != "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, errMsg)
		return
	}
	since64, errMsg := parseInt64Param(r, "since", 0, 0)
	if errMsg != "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, errMsg)
		return
	}
	if !h.available() {
		h.recordAudit(r, p, auditLogs, service, audits.ResultFailure, "容器运维通道未配置", audits.RiskMedium)
		unavailable(w, r)
		return
	}
	result, err := h.ops.ContainerLogs(r.Context(), service, tail, since64)
	if err != nil {
		h.recordAudit(r, p, auditLogs, service, audits.ResultFailure, "容器日志获取失败", audits.RiskMedium)
		writeOpsError(w, r, err)
		return
	}
	h.recordAudit(r, p, auditLogs, service, audits.ResultSuccess, "", audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, result)
}

// ActionStatus GET /api/v1/system/containers/actions/{job_id}
// 任务状态轮询属高频只读查询，不记操作审计（审计口径仅覆盖 list/logs/control/update）。
func (h *Handler) ActionStatus(w http.ResponseWriter, r *http.Request, jobID string) {
	p := authz.PrincipalFrom(r.Context())
	if p == nil {
		response.Error(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "未登录或会话已过期")
		return
	}
	if !jobIDRe.MatchString(jobID) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "任务 ID 格式不合法")
		return
	}
	if !h.available() {
		unavailable(w, r)
		return
	}
	job, err := h.ops.ActionStatus(r.Context(), jobID)
	if err != nil {
		writeOpsError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, job)
}

// controlRequest 写操作请求体。
type controlRequest struct {
	Password     string `json:"password"`
	ConfirmText  string `json:"confirmText"`
	DelaySeconds int    `json:"delaySeconds"`
}

// Start POST /api/v1/system/containers/{service}/start
func (h *Handler) Start(w http.ResponseWriter, r *http.Request) {
	h.control(w, r, "start", auditStart)
}

// Stop POST /api/v1/system/containers/{service}/stop
func (h *Handler) Stop(w http.ResponseWriter, r *http.Request) {
	h.control(w, r, "stop", auditStop)
}

// Restart POST /api/v1/system/containers/{service}/restart
func (h *Handler) Restart(w http.ResponseWriter, r *http.Request) {
	h.control(w, r, "restart", auditRestart)
}

// Update POST /api/v1/system/containers/{service}/update（另需确认文本「更新容器」）。
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	h.control(w, r, "update", auditUpdate)
}

// control 写操作公共流程：服务名校验 → body 解析 → 密码二次校验 →（update）确认文本 →
// 通道可用性 → 受理动作 → 审计 → 202。
func (h *Handler) control(w http.ResponseWriter, r *http.Request, action, auditAction string) {
	p := authz.PrincipalFrom(r.Context())
	if p == nil {
		response.Error(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "未登录或会话已过期")
		return
	}
	risk := audits.RiskHigh
	if action == "update" {
		risk = audits.RiskCritical
	}
	service := r.PathValue("service")
	if !serviceNameRe.MatchString(service) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "服务名格式不合法")
		return
	}
	var req controlRequest
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if req.Password == "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "密码不能为空")
		return
	}
	if req.DelaySeconds < 0 || req.DelaySeconds > maxDelaySeconds {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"delaySeconds 须在 0~"+strconv.Itoa(maxDelaySeconds)+" 秒之间")
		return
	}

	user, err := h.users.GetByID(r.Context(), p.UserID)
	if err != nil {
		if errors.Is(err, users.ErrNotFound) {
			response.Error(w, r, http.StatusForbidden, response.CodePermissionDenied, "当前用户不可用")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	if err := security.VerifyPassword(req.Password, user.PasswordHash); err != nil {
		h.recordAudit(r, p, auditAction, service, audits.ResultFailure, "密码校验失败", risk)
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "密码错误")
		return
	}
	if action == "update" && req.ConfirmText != UpdateConfirmText {
		h.recordAudit(r, p, auditAction, service, audits.ResultFailure, "确认文本不匹配", risk)
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"确认文本错误，请输入「"+UpdateConfirmText+"」")
		return
	}
	if !h.available() {
		h.recordAudit(r, p, auditAction, service, audits.ResultFailure, "容器运维通道未配置", risk)
		unavailable(w, r)
		return
	}
	job, err := h.ops.SubmitAction(r.Context(), service, action, req.DelaySeconds)
	if err != nil {
		h.recordAudit(r, p, auditAction, service, audits.ResultFailure, "动作受理失败", risk)
		writeOpsError(w, r, err)
		return
	}
	h.recordAudit(r, p, auditAction, service, audits.ResultSuccess, "", risk)
	response.JSON(w, r, http.StatusAccepted, job)
}

// parseIntParam 解析可选 int 查询参数并夹紧到 [min, max]；非法值返回错误文案。
func parseIntParam(r *http.Request, name string, def, minVal, maxVal int) (int, string) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def, ""
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < minVal {
		return 0, name + " 必须为不小于 " + strconv.Itoa(minVal) + " 的整数"
	}
	if maxVal > 0 && n > maxVal {
		n = maxVal
	}
	return n, ""
}

// parseInt64Param 解析可选 int64 查询参数（不小于 minVal）。
func parseInt64Param(r *http.Request, name string, def, minVal int64) (int64, string) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def, ""
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < minVal {
		return 0, name + " 必须为不小于 " + strconv.FormatInt(minVal, 10) + " 的整数"
	}
	return n, ""
}

// recordAudit 写入操作审计；持久化失败仅记日志，不影响主流程结果。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, service, result, failReason, risk string) {
	if h.audits == nil {
		return
	}
	if err := h.audits.Record(r.Context(), audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        auditModule,
		Action:        action,
		ObjectType:    auditObjectType,
		ObjectName:    service,
		Result:        result,
		FailureReason: failReason,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	}); err != nil {
		slog.Error("record containerops audit failed", "action", action, "error", err)
	}
}
