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
	"github.com/jiuzhang-waf/server/internal/encryption"
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

// userStore 是认证服务依赖的用户仓储接口（由 *users.Store 实现，测试可注入 fake）。
type userStore interface {
	GetByUsername(ctx context.Context, username string) (*users.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*users.User, error)
	ClearExpiredLock(ctx context.Context, id uuid.UUID) error
	RecordLoginSuccess(ctx context.Context, id uuid.UUID, sourceIP string) error
	RecordLoginFailure(ctx context.Context, id uuid.UUID, maxAttempts int, lockDuration time.Duration) (bool, error)
	GetRoles(ctx context.Context, userID uuid.UUID) ([]users.RoleInfo, error)
	GetPermissions(ctx context.Context, userID uuid.UUID) ([]string, error)
	GetPasswordHistories(ctx context.Context, userID uuid.UUID, limit int) ([]string, error)
	ChangePassword(ctx context.Context, userID uuid.UUID, newHash, oldHash string,
		expiresAt *time.Time, revokeSessions bool) error
	SaveTOTPPending(ctx context.Context, userID uuid.UUID, pendingEnc string, recoveryHashes []string) error
	EnableTOTP(ctx context.Context, userID uuid.UUID) error
	ClearTOTP(ctx context.Context, userID uuid.UUID) error
	ConsumeTOTPRecoveryCode(ctx context.Context, userID uuid.UUID, hash string) (bool, error)
}

// sessionService 是认证服务依赖的会话接口（由 *sessions.Service 实现）。
type sessionService interface {
	Create(ctx context.Context, userID uuid.UUID, username string, roles, permissions []string,
		sourceIP, userAgent string, mustChangePwd bool, policy sessions.Policy) (*sessions.Session, error)
	Revoke(ctx context.Context, id, reason string) error
	RevokeAllForUser(ctx context.Context, userID uuid.UUID, reason string) error
}

// settingsService 是认证服务依赖的系统设置接口（由 *settings.Service 实现）。
type settingsService interface {
	LoginPolicy(ctx context.Context) settings.LoginPolicy
	PasswordPolicy(ctx context.Context) security.PasswordPolicy
	SessionPolicyValues(ctx context.Context) (idleMin, absHours, maxPerUser int, allowMulti bool)
	GetBool(ctx context.Context, group, key string, def bool) bool
}

// loginLogger 是登录日志记录接口（由 *loginlogs.Service 实现）。
type loginLogger interface {
	Record(ctx context.Context, in loginlogs.RecordInput) error
}

// auditRecorder 是操作审计记录接口（由 *audits.Service 实现）。
type auditRecorder interface {
	Record(ctx context.Context, in audits.RecordInput) error
}

// captchaVerifier 是图形验证码校验接口（由 *security.CaptchaService 实现）。
type captchaVerifier interface {
	Verify(ctx context.Context, id, code string, caseSensitive bool) error
}

// kvCache 是键值缓存接口（由 *cache.Client 实现）。
type kvCache interface {
	Get(ctx context.Context, key string) (string, error)
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	Del(ctx context.Context, keys ...string) error
}

// secretCipher 是敏感字段加解密接口（由 *encryption.Service 实现，AES-256-GCM）。
type secretCipher interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(encoded string) (string, error)
}

// Service 是认证服务。
type Service struct {
	users    userStore
	sessions sessionService
	settings settingsService
	logs     loginLogger
	audits   auditRecorder
	captcha  captchaVerifier
	cache    kvCache
	enc      secretCipher
	// bruteForceAlert 登录暴破告警回调（装配层闭包注入告警引擎，本包不依赖
	// systemalerts，避免循环导入；仿 syslog 外发 setter 注入模式）。nil 时跳过告警。
	bruteForceAlert BruteForceAlertFunc
}

// BruteForceAlertFunc 是登录暴破告警回调：账号因连续失败被锁定时调用。
// 实现方负责内部错误处理（记录日志），不得把告警失败扩散到登录主流程。
type BruteForceAlertFunc func(ctx context.Context, username, sourceIP string, lockMinutes int)

// SetBruteForceAlertFunc 注入登录暴破告警回调（应用装配时使用，可为 nil）。
func (s *Service) SetBruteForceAlertFunc(fn BruteForceAlertFunc) { s.bruteForceAlert = fn }

// notifyAccountLocked 账号锁定触发登录暴破告警（未注入回调时跳过）。
func (s *Service) notifyAccountLocked(ctx context.Context, in LoginInput, lockMinutes int) {
	if s.bruteForceAlert == nil {
		return
	}
	s.bruteForceAlert(ctx, in.Username, in.SourceIP, lockMinutes)
}

// NewService 创建认证服务。
func NewService(u *users.Store, sess *sessions.Service, st *settings.Service,
	lg *loginlogs.Service, au *audits.Service, cap *security.CaptchaService, c *cache.Client,
	enc *encryption.Service) *Service {
	return &Service{users: u, sessions: sess, settings: st, logs: lg, audits: au, captcha: cap, cache: c, enc: enc}
}

// dummyPasswordHash 是预设的 Argon2id 假哈希（参数与 security.HashPassword 一致），
// 用于用户不存在时仍执行一次完整的密码校验运算，拉平登录耗时侧信道。
// 哈希原文非任何真实口令，仅保证格式合法、校验必失败。
const dummyPasswordHash = "$argon2id$v=19$m=65536,t=3,p=2$qANYNfNKqQXAuvwFMnK6fg$kt9cwgv6qvJdJ26Sa0PQVjvfxBcf0/95bqHJ34A1cv0"

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
	// 双因子认证：密码校验通过且已开启 TOTP 时为 true，此时未创建会话，
	// ChallengeToken 为一次性挑战令牌（5 分钟有效），须凭它完成第二步验证。
	TOTPRequired   bool
	ChallengeToken string
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
		// 对预设假哈希执行一次真实 VerifyPassword，拉平「用户不存在」与
		// 「用户存在但密码错误」两条路径的耗时，消除用户名枚举时间侧信道。
		_ = security.VerifyPassword(in.Password, dummyPasswordHash)
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
			// 登录暴破告警（通知二期 / Tier 2）：锁定时触发 LOGIN_BRUTE_FORCE
			s.notifyAccountLocked(ctx, in, policy.LockMinutes)
		} else {
			s.recordLog(ctx, in, &user.ID, loginlogs.EventLoginFailure, loginlogs.ResultFailure, "BAD_CREDENTIALS")
		}
		return nil, ErrInvalidCredentials
	}

	// 6. 密码过期检查
	if user.PasswordExpiresAt != nil && user.PasswordExpiresAt.Before(time.Now()) {
		s.recordLog(ctx, in, &user.ID, loginlogs.EventLoginFailure, loginlogs.ResultFailure, "PASSWORD_EXPIRED")
		return nil, ErrPasswordReused // 复用错误类型，handler 区分提示
	}

	// 6.5 双因子认证分支：已开启 TOTP 时签发一次性挑战令牌，会话创建推迟到第二步验证
	if user.TOTPEnabled {
		token, err := s.issueTOTPChallenge(ctx, user.ID, in.SourceIP, in.UserAgent)
		if err != nil {
			return nil, fmt.Errorf("issue totp challenge: %w", err)
		}
		s.recordLog(ctx, in, &user.ID, loginlogs.EventLoginTOTPChallenge, loginlogs.ResultSuccess, "")
		return &LoginResult{User: user, TOTPRequired: true, ChallengeToken: token}, nil
	}

	return s.completeLogin(ctx, user, in)
}

// completeLogin 完成登录：查询角色权限、创建会话并记录成功日志。
// 普通登录与 TOTP 第二步验证（VerifyTOTPLogin）共用同一会话建立与日志路径。
func (s *Service) completeLogin(ctx context.Context, user *users.User, in LoginInput) (*LoginResult, error) {
	pwdPolicy := s.settings.PasswordPolicy(ctx)

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
		revokeOnChange,
	); err != nil {
		return err
	}
	// 持久化撤销（含当前会话）已和密码更新原子提交；此处确保 Valkey 缓存同步清理。
	// 改密即视为密码可能泄露，任何旧会话（含发起改密的会话）都不得继续有效。
	if revokeOnChange {
		if err := s.sessions.RevokeAllForUser(ctx, in.UserID, "password_changed"); err != nil {
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
	// 日志写库失败不阻断登录主流程；loginlogs.Record 失败路径自身会 Warn
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
