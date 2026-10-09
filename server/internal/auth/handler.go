package auth

import (
	"errors"
	"net/http"
	"strings"
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
		Username:     req.Username,
		Password:     req.Password,
		CaptchaID:    req.CaptchaID,
		CaptchaCode:  req.CaptchaCode,
		SourceIP:     middleware.RemoteIP(r),
		ConnectionIP: middleware.ConnectionIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    response.RequestIDFrom(r),
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

	if result.TOTPRequired {
		// 已开启双因子认证：不下发会话，返回一次性挑战令牌进入第二步验证
		response.JSONWithCode(w, r, http.StatusOK, response.CodeTOTPRequired, "账号已开启双因子认证，请完成动态令牌验证", map[string]interface{}{
			"challenge_token": result.ChallengeToken,
		})
		return
	}

	// 签发 CSRF Token 并下发会话 Cookie（与 TOTP 第二步验证共用同一出口）
	h.writeLoginSuccess(w, r, result)
}

// writeLoginSuccess 签发 CSRF Token、设置会话 Cookie 并输出登录结果。
func (h *Handler) writeLoginSuccess(w http.ResponseWriter, r *http.Request, result *LoginResult) {
	csrfToken, err := h.svc.IssueCSRFToken(r.Context(), result.Session.ID)
	if err != nil {
		response.InternalError(w, r, errors.Join(err, h.svc.Logout(r.Context(), result.Session.ID)))
		return
	}

	// 设置会话 Cookie
	h.setSessionCookie(w, r, result.Session.ID, result.Session.AbsoluteExpiry)

	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"user":                buildUserResponse(result.User, result.Roles, result.Permissions),
		"csrf_token":          csrfToken,
		"password_expiring":   result.PasswordExpiring,
		"password_expires_at": result.PasswordExpiresAt,
	})
}

type totpVerifyRequest struct {
	ChallengeToken string `json:"challenge_token"`
	Code           string `json:"code"`
}

// TOTPVerify 登录第二步：校验挑战令牌与动态令牌/恢复码，通过后建立会话。
func (h *Handler) TOTPVerify(w http.ResponseWriter, r *http.Request) {
	var req totpVerifyRequest
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if req.ChallengeToken == "" || req.Code == "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "挑战令牌与验证码不能为空")
		return
	}

	result, err := h.svc.VerifyTOTPLogin(r.Context(), TOTPVerifyInput{
		ChallengeToken: req.ChallengeToken,
		Code:           req.Code,
		SourceIP:       middleware.RemoteIP(r),
		ConnectionIP:   middleware.ConnectionIP(r),
		UserAgent:      r.UserAgent(),
		RequestID:      response.RequestIDFrom(r),
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrTOTPChallengeInvalid):
			response.Error(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "验证会话已过期，请重新登录")
		case errors.Is(err, ErrAccountUnavailable):
			response.Error(w, r, http.StatusForbidden, response.CodeAccountLocked, "账号不可用，请联系管理员")
		case errors.Is(err, ErrTOTPInvalid):
			// 动态令牌/恢复码错误：挑战令牌在 TTL 内仍有效，可重试；连续失败由服务层计入账号锁定
			response.Error(w, r, http.StatusUnauthorized, response.CodeTOTPInvalid, "动态令牌或恢复码错误")
		default:
			response.InternalError(w, r, err)
		}
		return
	}

	// 与登录一致的 CSRF 签发与 Cookie 下发
	h.writeLoginSuccess(w, r, result)
}

// TOTPSetup 生成待启用 TOTP 密钥与恢复码（明文仅此一次返回）。
func (h *Handler) TOTPSetup(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	if p == nil {
		response.Error(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "未登录")
		return
	}
	result, err := h.svc.SetupTOTP(r.Context(), h.totpSelfInput(r, p, ""))
	if err != nil {
		if errors.Is(err, ErrTOTPAlreadyEnabled) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "已开启双因子认证，请先关闭后再重新设置")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"secret":         result.Secret,
		"otpauth_url":    result.OTPAuthURL,
		"recovery_codes": result.RecoveryCodes,
		"notice":         "密钥与恢复码仅本次显示，请立即妥善保存",
	})
}

type totpCodeRequest struct {
	Code string `json:"code"`
}

// TOTPEnable 用待启用密钥验证动态令牌，通过后正式开启双因子认证。
func (h *Handler) TOTPEnable(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	if p == nil {
		response.Error(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "未登录")
		return
	}
	var req totpCodeRequest
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if !security.IsTOTPCodeFormat(req.Code) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "动态令牌为 6 位数字")
		return
	}
	err := h.svc.EnableTOTP(r.Context(), h.totpSelfInput(r, p, req.Code))
	if err != nil {
		switch {
		case errors.Is(err, users.ErrNoTOTPPending):
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "请先生成双因子密钥")
		case errors.Is(err, ErrTOTPAlreadyEnabled):
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "已开启双因子认证")
		case errors.Is(err, ErrTOTPInvalid):
			response.Error(w, r, http.StatusBadRequest, response.CodeTOTPInvalid, "动态令牌错误或已过期")
		default:
			response.InternalError(w, r, err)
		}
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "双因子认证已开启"})
}

// TOTPDisable 验证动态令牌或恢复码后关闭双因子认证（高危操作）。
func (h *Handler) TOTPDisable(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	if p == nil {
		response.Error(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "未登录")
		return
	}
	var req totpCodeRequest
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if req.Code == "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "验证码不能为空")
		return
	}
	err := h.svc.DisableTOTP(r.Context(), h.totpSelfInput(r, p, req.Code))
	if err != nil {
		switch {
		case errors.Is(err, ErrTOTPNotEnabled):
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "未开启双因子认证")
		case errors.Is(err, ErrTOTPInvalid):
			response.Error(w, r, http.StatusBadRequest, response.CodeTOTPInvalid, "动态令牌或恢复码错误")
		default:
			response.InternalError(w, r, err)
		}
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "双因子认证已关闭"})
}

// totpSelfInput 组装双因子自助管理输入（含审计上下文）。
func (h *Handler) totpSelfInput(r *http.Request, p *authz.Principal, code string) TOTPSelfInput {
	return TOTPSelfInput{
		UserID:       p.UserID,
		Username:     p.Username,
		Code:         code,
		SourceIP:     middleware.RemoteIP(r),
		ConnectionIP: middleware.ConnectionIP(r),
		UserAgent:    r.UserAgent(),
		RequestID:    response.RequestIDFrom(r),
	}
}

// Logout 处理退出。
func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var err error
	if p != nil {
		err = h.svc.Logout(r.Context(), p.SessionID)
	}
	h.clearSessionCookie(w, r)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
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
	// 角色/权限查询失败如实返回 500：若吞错返回空权限，前端会误判为无权限而把用户踢出。
	roles, err := h.users.GetRoles(r.Context(), p.UserID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	perms, err := h.users.GetPermissions(r.Context(), p.UserID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}

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
		UserID:       p.UserID,
		OldPassword:  req.OldPassword,
		NewPassword:  req.NewPassword,
		SourceIP:     middleware.RemoteIP(r),
		ConnectionIP: middleware.ConnectionIP(r),
		RequestID:    response.RequestIDFrom(r),
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

	// 服务层已在改密事务中吊销含当前会话在内的全部会话（持久化 + Valkey 缓存清理）。
	h.clearSessionCookie(w, r)
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

func (h *Handler) setSessionCookie(w http.ResponseWriter, r *http.Request, sessionID string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionID,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   h.secure && requestIsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *Handler) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.secure && requestIsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// requestIsHTTPS 判定当前请求是否经 HTTPS 到达：直连看 r.TLS，前置反代
// （管理面 web 容器 / 网关）看其写入的 X-Forwarded-Proto。
// 会话 Cookie 的 Secure 属性据此动态下发——纯 HTTP 部署（如离线包默认控制台）
// 带 Secure 的 Cookie 会被浏览器静默丢弃，登录态无法保持。
func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https")
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
		"totp_enabled":         u.TOTPEnabled,
		"last_login_at":        u.LastLoginAt,
		"last_login_ip":        u.LastLoginIP,
	}
}
