package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/cache"
	"github.com/jiuzhang-waf/server/internal/loginlogs"
	"github.com/jiuzhang-waf/server/internal/security"
	"github.com/jiuzhang-waf/server/internal/sessions"
	"github.com/jiuzhang-waf/server/internal/settings"
	"github.com/jiuzhang-waf/server/internal/users"
)

// 认证错误（对外统一提示，不泄露账号状态细节）
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrCaptchaFailed      = errors.New("captcha failed")
	ErrAccountUnavailable = errors.New("account unavailable")
	ErrPasswordReused     = errors.New("password reused")
	ErrOldPasswordWrong   = errors.New("old password wrong")
)

// Service 是认证服务。
type Service struct {
	users    *users.Store
	sessions *sessions.Service
	settings *settings.Service
	logs     *loginlogs.Service
	audits   *audits.Service
	captcha  *security.CaptchaService
	cache    *cache.Client
}

// NewService 创建认证服务。
func NewService(u *users.Store, sess *sessions.Service, st *settings.Service,
	lg *loginlogs.Service, au *audits.Service, cap *security.CaptchaService, c *cache.Client) *Service {
	return &Service{users: u, sessions: sess, settings: st, logs: lg, audits: au, captcha: cap, cache: c}
}

// LoginInput 是登录输入。
type LoginInput struct {
	Username     string
	Password     string
	CaptchaID    string
	CaptchaCode  string
	SourceIP     string
	ConnectionIP string
	UserAgent    string
	RequestID    string
}

// LoginResult 是登录结果。
type LoginResult struct {
	User              *users.User
	Roles             []users.RoleInfo
	Permissions       []string
	Session           *sessions.Session
	PasswordExpiresAt *time.Time
	PasswordExpiring  bool // 即将过期提醒
}

// Login 执行登录认证。
// 失败统一返回 ErrInvalidCredentials，内部通过登录日志区分具体原因。
func (s *Service) Login(ctx context.Context, in LoginInput) (*LoginResult, error) {
	policy := s.settings.LoginPolicy(ctx)

	// 1. 验证码
	if policy.CaptchaEnabled {
		if in.CaptchaID == "" || in.CaptchaCode == "" {
			s.recordLog(ctx, in, nil, loginlogs.EventCaptchaFailure, loginlogs.ResultFailure, "CAPTCHA_REQUIRED")
			return nil, ErrCaptchaFailed
		}
		if err := s.captcha.Verify(ctx, in.CaptchaID, in.CaptchaCode, policy.CaptchaCaseSensitive); err != nil {
			s.recordLog(ctx, in, nil, loginlogs.EventCaptchaFailure, loginlogs.ResultFailure, "CAPTCHA_INVALID")
			return nil, ErrCaptchaFailed
		}
	}

	// 2. 用户查询
	user, err := s.users.GetByUsername(ctx, in.Username)
	if err != nil {
		s.recordLog(ctx, in, nil, loginlogs.EventLoginFailure, loginlogs.ResultFailure, "BAD_CREDENTIALS")
		return nil, ErrInvalidCredentials
	}

	// 3. 清理过期锁定
	if err := s.users.ClearExpiredLock(ctx, user.ID); err != nil {
		return nil, fmt.Errorf("clear expired account lock: %w", err)
	}

	// 4. 状态检查
	if user.Status == users.StatusDisabled {
		s.recordLog(ctx, in, &user.ID, loginlogs.EventLoginFailure, loginlogs.ResultFailure, "ACCOUNT_DISABLED")
		return nil, ErrAccountUnavailable
	}
	if user.Status == users.StatusLocked && user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
		s.recordLog(ctx, in, &user.ID, loginlogs.EventLoginFailure, loginlogs.ResultFailure, "ACCOUNT_LOCKED")
		return nil, ErrAccountUnavailable
	}

	// 5. 密码校验
	if err := security.VerifyPassword(in.Password, user.PasswordHash); err != nil {
		locked, recordErr := s.users.RecordLoginFailure(ctx, user.ID, policy.MaxFailedAttempts,
			time.Duration(policy.LockMinutes)*time.Minute)
		if recordErr != nil {
			return nil, fmt.Errorf("record login failure: %w", recordErr)
		}
		if locked {
			s.recordLog(ctx, in, &user.ID, loginlogs.EventAccountLocked, loginlogs.ResultFailure, "MAX_FAILED_ATTEMPTS")
		} else {
			s.recordLog(ctx, in, &user.ID, loginlogs.EventLoginFailure, loginlogs.ResultFailure, "BAD_CREDENTIALS")
		}
		return nil, ErrInvalidCredentials
	}

	// 6. 密码过期检查
	pwdPolicy := s.settings.PasswordPolicy(ctx)
	if user.PasswordExpiresAt != nil && user.PasswordExpiresAt.Before(time.Now()) {
		s.recordLog(ctx, in, &user.ID, loginlogs.EventLoginFailure, loginlogs.ResultFailure, "PASSWORD_EXPIRED")
		return nil, ErrPasswordReused // 复用错误类型，handler 区分提示
	}

	// 7. 角色与权限
	roles, err := s.users.GetRoles(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("get roles: %w", err)
	}
	perms, err := s.users.GetPermissions(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("get permissions: %w", err)
	}

	// 8. 创建会话
	sessPolicy := s.sessionPolicy(ctx)
	roleCodes := make([]string, len(roles))
	for i, r := range roles {
		roleCodes[i] = r.Code
	}
	sess, err := s.sessions.Create(ctx, user.ID, user.Username, roleCodes, perms,
		in.SourceIP, in.UserAgent, user.MustChangePassword, sessPolicy)
	if err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	// 9. 记录成功
	if err := s.users.RecordLoginSuccess(ctx, user.ID, in.SourceIP); err != nil {
		return nil, errors.Join(err, s.sessions.Revoke(ctx, sess.ID, "login_record_failed"))
	}
	s.recordLog(ctx, in, &user.ID, loginlogs.EventLoginSuccess, loginlogs.ResultSuccess, "")

	// 密码即将到期提醒
	expiring := false
	if user.PasswordExpiresAt != nil {
		remindBefore := time.Now().Add(time.Duration(pwdPolicy.ExpireRemindDays) * 24 * time.Hour)
		expiring = user.PasswordExpiresAt.Before(remindBefore)
	}

	return &LoginResult{
		User:              user,
		Roles:             roles,
		Permissions:       perms,
		Session:           sess,
		PasswordExpiresAt: user.PasswordExpiresAt,
		PasswordExpiring:  expiring,
	}, nil
}

// Logout 注销会话。
func (s *Service) Logout(ctx context.Context, sessionID string) error {
	return s.sessions.Revoke(ctx, sessionID, "logout")
}

// ChangePasswordInput 是修改密码输入。
type ChangePasswordInput struct {
	UserID       uuid.UUID
	OldPassword  string
	NewPassword  string
	SourceIP     string
	ConnectionIP string
	RequestID    string
	SessionID    string
}

// ChangePassword 修改密码。
func (s *Service) ChangePassword(ctx context.Context, in ChangePasswordInput) error {
	user, err := s.users.GetByID(ctx, in.UserID)
	if err != nil {
		return err
	}
	// 旧密码校验
	if err := security.VerifyPassword(in.OldPassword, user.PasswordHash); err != nil {
		return ErrOldPasswordWrong
	}
	// 策略校验
	policy := s.settings.PasswordPolicy(ctx)
	if perr := security.ValidatePassword(in.NewPassword, user.Username, policy); perr != nil {
		return perr
	}
	// 历史密码校验
	histories, err := s.users.GetPasswordHistories(ctx, in.UserID, policy.HistoryCount)
	if err != nil {
		return err
	}
	for _, h := range histories {
		if err := security.VerifyPassword(in.NewPassword, h); err == nil {
			return ErrPasswordReused
		}
	}
	// 生成新哈希
	newHash, err := security.HashPassword(in.NewPassword)
	if err != nil {
		return err
	}
	var expiresAt *time.Time
	if policy.ExpireDays > 0 {
		t := time.Now().Add(time.Duration(policy.ExpireDays) * 24 * time.Hour)
		expiresAt = &t
	}
	revokeOnChange := s.settings.GetBool(ctx, "session", "revoke_on_password_change", true)
	if err := s.users.ChangePassword(
		ctx,
		in.UserID,
		newHash,
		user.PasswordHash,
		expiresAt,
		sessions.HashSessionID(in.SessionID),
		revokeOnChange,
	); err != nil {
		return err
	}
	// 持久化撤销已和密码更新原子提交；此处只确保缓存尽快清理。
	if revokeOnChange {
		if err := s.sessions.RevokeOtherForUser(ctx, in.UserID, in.SessionID, "password_changed"); err != nil {
			slog.Warn("password changed but session cache cleanup failed",
				"user_id", in.UserID, "error", err)
		}
	}
	s.recordPwdLog(ctx, in, loginlogs.EventPasswordChange)
	return nil
}

// sessionPolicy 从设置构造会话策略。
func (s *Service) sessionPolicy(ctx context.Context) sessions.Policy {
	idleMin, absHours, maxPerUser, allowMulti := s.settings.SessionPolicyValues(ctx)
	return sessions.Policy{
		IdleTimeout:     time.Duration(idleMin) * time.Minute,
		AbsoluteTimeout: time.Duration(absHours) * time.Hour,
		MaxPerUser:      maxPerUser,
		AllowMulti:      allowMulti,
	}
}

// SessionPolicy 导出会话策略（供中间件使用）。
func (s *Service) SessionPolicy(ctx context.Context) sessions.Policy {
	return s.sessionPolicy(ctx)
}

func (s *Service) recordLog(ctx context.Context, in LoginInput, userID *uuid.UUID, eventType, result, failureCode string) {
	_ = s.logs.Record(ctx, loginlogs.RecordInput{
		Username:     in.Username,
		UserID:       userID,
		SourceIP:     in.SourceIP,
		ConnectionIP: in.ConnectionIP,
		UserAgent:    in.UserAgent,
		EventType:    eventType,
		Result:       result,
		FailureCode:  failureCode,
		RequestID:    in.RequestID,
	})
}

func (s *Service) recordPwdLog(ctx context.Context, in ChangePasswordInput, eventType string) {
	_ = s.logs.Record(ctx, loginlogs.RecordInput{
		Username:     "",
		UserID:       &in.UserID,
		SourceIP:     in.SourceIP,
		ConnectionIP: in.ConnectionIP,
		EventType:    eventType,
		Result:       loginlogs.ResultSuccess,
		RequestID:    in.RequestID,
	})
}

// CSRF Token 服务

const csrfKeyPrefix = "jiuzhang:csrf:"

// IssueCSRFToken 为会话签发 CSRF Token。
func (s *Service) IssueCSRFToken(ctx context.Context, sessionID string) (string, error) {
	token, err := security.NewRandomToken(32)
	if err != nil {
		return "", err
	}
	key := csrfKeyPrefix + hashSessionForCSRF(sessionID)
	if err := s.cache.Set(ctx, key, token, 8*time.Hour); err != nil {
		return "", err
	}
	return token, nil
}

// ValidateCSRFToken 校验会话的 CSRF Token。
func (s *Service) ValidateCSRFToken(ctx context.Context, sessionID, token string) bool {
	if token == "" {
		return false
	}
	key := csrfKeyPrefix + hashSessionForCSRF(sessionID)
	stored, err := s.cache.Get(ctx, key)
	if err != nil {
		return false
	}
	return stored == token
}

func hashSessionForCSRF(sessionID string) string {
	sum := sha256.Sum256([]byte("jiuzhang-csrf:" + sessionID))
	return hex.EncodeToString(sum[:])
}
