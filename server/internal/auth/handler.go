package auth

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
	"log/slog"

	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
	"github.com/jiuzhang-waf/server/internal/security"
	"github.com/jiuzhang-waf/server/internal/sessions"
	"github.com/jiuzhang-waf/server/internal/users"
)

// Handler 是认证相关 HTTP 处理器。
type Handler struct {
	svc      *Service
	sessions *sessions.Service
	users    *users.Store
	captcha  *security.CaptchaService
	secure   bool
}

// NewHandler 创建认证处理器。
func NewHandler(svc *Service, sess *sessions.Service, u *users.Store, cap *security.CaptchaService, secureCookie bool) *Handler {
	return &Handler{svc: svc, sessions: sess, users: u, captcha: cap, secure: secureCookie}
}

// SessionCookieName 是会话 Cookie 名。
const SessionCookieName = "jiuzhang_session"

type loginRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	CaptchaID   string `json:"captcha_id"`
	CaptchaCode string `json:"captcha_code"`
}

// Captcha 生成图形验证码。
func (h *Handler) Captcha(w http.ResponseWriter, r *http.Request) {
	policy := h.svc.settings.LoginPolicy(r.Context())
	if !policy.CaptchaEnabled {
		response.JSON(w, r, http.StatusOK, map[string]interface{}{
			"enabled": false,
		})
		return
	}
	cap, err := h.captcha.Generate(r.Context(), 4, policy.CaptchaExpireSecs)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"enabled":    true,
		"captcha_id": cap.ID,
		"image":      cap.Image,
		"expires_in": cap.ExpiresIn,
	})
}

// Login 处理登录。
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if req.Username == "" || req.Password == "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "用户名和密码不能为空")
		return
	}

	result, err := h.svc.Login(r.Context(), LoginInput{
		Username:    req.Username,
		Password:    req.Password,
		CaptchaID:   req.CaptchaID,
		CaptchaCode: req.CaptchaCode,
		SourceIP:    middleware.RemoteIP(r),
		UserAgent:   r.UserAgent(),
		RequestID:   response.RequestIDFrom(r),
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrCaptchaFailed):
			response.Error(w, r, http.StatusBadRequest, response.CodeCaptchaInvalid, "验证码错误或已过期")
		case errors.Is(err, ErrAccountUnavailable):
			response.Error(w, r, http.StatusForbidden, response.CodeAccountLocked, "账号不可用，请联系管理员")
		case errors.Is(err, ErrPasswordReused):
			response.Error(w, r, http.StatusForbidden, response.CodePasswordExpired, "密码已过期，请联系管理员重置")
		default:
			// 统一提示，不区分用户不存在/密码错误
			slog.Warn("login failed", "request_id", response.RequestIDFrom(r), "err", err)
			response.Error(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "用户名或密码错误")
		}
		return
	}

	// 签发 CSRF Token
	csrfToken, err := h.svc.IssueCSRFToken(r.Context(), result.Session.ID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}

	// 设置会话 Cookie
	h.setSessionCookie(w, result.Session.ID, result.Session.AbsoluteExpiry)

	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"user":                buildUserResponse(result.User, result.Roles, result.Permissions),
		"csrf_token":          csrfToken,
		"password_expiring":   result.PasswordExpiring,
		"password_expires_at": result.PasswordExpiresAt,
	})
}

// Logout 处理退出。
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	if p != nil {
		_ = h.svc.Logout(r.Context(), p.SessionID)
	}
	h.clearSessionCookie(w)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "已退出登录"})
}

// Me 返回当前登录用户信息。
func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	if p == nil {
		response.Error(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "未登录")
		return
	}
	user, err := h.users.GetByID(r.Context(), p.UserID)
	if err != nil {
		response.Error(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "会话无效")
		return
	}
	roles, _ := h.users.GetRoles(r.Context(), p.UserID)
	perms, _ := h.users.GetPermissions(r.Context(), p.UserID)

	// 检查密码过期
	policy := h.svc.settings.PasswordPolicy(r.Context())
	expiring := false
	if user.PasswordExpiresAt != nil {
		remindBefore := time.Now().Add(time.Duration(policy.ExpireRemindDays) * 24 * time.Hour)
		expiring = user.PasswordExpiresAt.Before(remindBefore)
	}

	// 签发新 CSRF Token（幂等）
	csrfToken, err := h.svc.IssueCSRFToken(r.Context(), p.SessionID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}

	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"user":                buildUserResponse(user, roles, perms),
		"csrf_token":          csrfToken,
		"password_expiring":   expiring,
		"password_expires_at": user.PasswordExpiresAt,
	})
}

type changePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// ChangePassword 修改密码。
func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	if p == nil {
		response.Error(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "未登录")
		return
	}
	var req changePasswordRequest
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if req.OldPassword == "" || req.NewPassword == "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "密码不能为空")
		return
	}
	err := h.svc.ChangePassword(r.Context(), ChangePasswordInput{
		UserID:      p.UserID,
		OldPassword: req.OldPassword,
		NewPassword: req.NewPassword,
		SourceIP:    middleware.RemoteIP(r),
		RequestID:   response.RequestIDFrom(r),
		SessionID:   p.SessionID,
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrOldPasswordWrong):
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "原密码错误")
		case errors.Is(err, ErrPasswordReused):
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "新密码不得与最近使用的密码重复")
		default:
			if perr, ok := err.(*security.PolicyError); ok {
				response.ErrorWithDetails(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
					"密码不符合安全策略", perr.Reasons)
			} else {
				response.InternalError(w, r, err)
			}
		}
		return
	}

	// 修改密码后重新创建会话（原会话失效）
	_ = h.svc.Logout(r.Context(), p.SessionID)
	h.clearSessionCookie(w)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"message":          "密码修改成功，请重新登录",
		"relogin_required": true,
	})
}

// Sessions 返回当前用户的会话列表。
func (h *Handler) Sessions(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	if p == nil {
		response.Error(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "未登录")
		return
	}
	list, err := h.sessions.ListForUser(r.Context(), p.UserID, 20)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	currentHash := sessions.HashSessionID(p.SessionID)
	type item struct {
		sessions.Summary
		IsCurrent bool `json:"is_current"`
	}
	items := make([]item, 0, len(list))
	for _, s := range list {
		items = append(items, item{Summary: s, IsCurrent: s.SessionHash == currentHash})
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": items})
}

// RevokeSession 结束指定会话（仅能操作自己的会话）。
func (h *Handler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	if p == nil {
		response.Error(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "未登录")
		return
	}
	idStr := r.PathValue("id")
	summaryID, err := uuid.Parse(idStr)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的会话标识")
		return
	}
	// 通过摘要 ID 查会话哈希，再反查实际会话（仅能操作自己的）
	list, err := h.sessions.ListForUser(r.Context(), p.UserID, 100)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	for _, s := range list {
		if s.ID == summaryID {
			sessID, err := h.sessions.FindSessionIDByHash(r.Context(), p.UserID, s.SessionHash)
			if err != nil {
				response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "会话不存在或已结束")
				return
			}
			if err := h.sessions.Revoke(r.Context(), sessID, "user_revoke_self"); err != nil {
				response.InternalError(w, r, err)
				return
			}
			response.JSON(w, r, http.StatusOK, map[string]string{"message": "会话已结束"})
			return
		}
	}
	response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "会话不存在")
}

func (h *Handler) setSessionCookie(w http.ResponseWriter, sessionID string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionID,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   h.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *Handler) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func buildUserResponse(u *users.User, roles []users.RoleInfo, perms []string) map[string]interface{} {
	roleList := make([]map[string]string, len(roles))
	for i, r := range roles {
		roleList[i] = map[string]string{"code": r.Code, "name": r.Name}
	}
	return map[string]interface{}{
		"id":                   u.ID,
		"username":             u.Username,
		"display_name":         u.DisplayName,
		"status":               u.Status,
		"roles":                roleList,
		"permissions":          perms,
		"must_change_password": u.MustChangePassword,
		"last_login_at":        u.LastLoginAt,
		"last_login_ip":        u.LastLoginIP,
	}
}
