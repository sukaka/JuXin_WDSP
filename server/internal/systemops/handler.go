// handler.go 系统控制接口：重启/关机/恢复出厂设置（密码二次确认 + 高危审计）。
package systemops

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
	"github.com/jiuzhang-waf/server/internal/security"
	"github.com/jiuzhang-waf/server/internal/users"
)

// userGetter 按 ID 查询用户（含密码哈希），由 *users.Store 实现；单测注入 stub。
type userGetter interface {
	GetByID(ctx context.Context, id uuid.UUID) (*users.User, error)
}

// auditRecorder 操作审计记录接口（由 *audits.Service 实现；单测注入 spy）。
type auditRecorder interface {
	Record(ctx context.Context, in audits.RecordInput) error
}

// Handler 系统控制处理器。
type Handler struct {
	users  userGetter
	audits auditRecorder
	dir    string
}

// NewHandler 创建处理器。dir 为宿主控制指令标志文件目录（HOSTCTL_DIR）。
func NewHandler(ug userGetter, au auditRecorder, dir string) *Handler {
	return &Handler{users: ug, audits: au, dir: dir}
}

// RegisterRoutes 注册系统控制路由。authChain 为认证链（会话解析+CSRF+认证+授权门控），
// 权限控制在路由层按权限点强制校验。
func (h *Handler) RegisterRoutes(mux *http.ServeMux, authChain func(http.Handler) http.Handler) {
	mux.Handle("POST /api/v1/system/reboot", authChain(middleware.RequirePermission("system.reboot")(http.HandlerFunc(h.Reboot))))
	mux.Handle("POST /api/v1/system/shutdown", authChain(middleware.RequirePermission("system.shutdown")(http.HandlerFunc(h.Shutdown))))
	mux.Handle("POST /api/v1/system/factory-reset", authChain(middleware.RequirePermission("system.factory_reset")(http.HandlerFunc(h.FactoryReset))))
}

type controlRequest struct {
	Password    string `json:"password"`
	ConfirmText string `json:"confirmText"`
}

// Reboot 系统重启。
func (h *Handler) Reboot(w http.ResponseWriter, r *http.Request) {
	h.handle(w, r, ActionReboot, false)
}

// Shutdown 系统关机。
func (h *Handler) Shutdown(w http.ResponseWriter, r *http.Request) {
	h.handle(w, r, ActionShutdown, false)
}

// FactoryReset 恢复出厂设置（额外要求确认文本）。
func (h *Handler) FactoryReset(w http.ResponseWriter, r *http.Request) {
	h.handle(w, r, ActionFactoryReset, true)
}

// handle 是三个控制端点的公共流程：
// 解析并校验 body → 密码二次校验 → （恢复出厂）确认文本校验 →
// 原子写宿主控制标志文件 → 审计 → 202 受理响应。
func (h *Handler) handle(w http.ResponseWriter, r *http.Request, action string, needConfirm bool) {
	p := authz.PrincipalFrom(r.Context())
	if p == nil {
		response.Error(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "未登录或会话已过期")
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
		h.recordAudit(r, p, action, audits.ResultFailure, "密码校验失败")
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "密码错误")
		return
	}
	if needConfirm && req.ConfirmText != FactoryResetConfirmText {
		h.recordAudit(r, p, action, audits.ResultFailure, "确认文本不匹配")
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"确认文本错误，请输入「"+FactoryResetConfirmText+"」")
		return
	}

	cmd := Command{
		Action:       action,
		RequestedBy:  p.Username,
		UserID:       p.UserID.String(),
		RequestID:    response.RequestIDFrom(r),
		RequestedAt:  time.Now().UTC().Format(time.RFC3339),
		DelaySeconds: delaySeconds,
	}
	if _, err := WriteFlagFile(h.dir, cmd); err != nil {
		h.recordAudit(r, p, action, audits.ResultFailure, "控制指令标志文件写入失败")
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, action, audits.ResultSuccess, "")
	response.JSON(w, r, http.StatusAccepted, map[string]interface{}{
		"message": "指令已受理，系统将在数秒后执行，请稍后重新连接",
		"action":  action,
	})
}

// recordAudit 写入操作审计（高危，CRITICAL）。持久化失败仅记日志，不影响主流程结果。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, result, failReason string) {
	if h.audits == nil {
		return
	}
	if err := h.audits.Record(r.Context(), audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "system",
		Action:        action,
		ObjectType:    "system",
		Result:        result,
		FailureReason: failReason,
		RiskLevel:     audits.RiskCritical,
		RequestID:     response.RequestIDFrom(r),
	}); err != nil {
		slog.Error("record systemops audit failed", "action", action, "error", err)
	}
}
