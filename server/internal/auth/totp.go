package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/loginlogs"
	"github.com/jiuzhang-waf/server/internal/security"
	"github.com/jiuzhang-waf/server/internal/users"
)

// 双因子认证（TOTP）错误
var (
	ErrTOTPChallengeInvalid = errors.New("totp challenge invalid or expired")
	ErrTOTPInvalid          = errors.New("totp or recovery code invalid")
	ErrTOTPAlreadyEnabled   = errors.New("totp already enabled")
	ErrTOTPNotEnabled       = errors.New("totp not enabled")
)

const (
	// 挑战令牌键纪律与 jiuzhang:csrf: / jiuzhang:captcha: 一致：前缀 + 随机令牌
	totpChallengePrefix   = "jiuzhang:totp:challenge:"
	totpChallengeTTL      = 5 * time.Minute
	totpRecoveryCodeCount = 10
	// totpIssuer 是 otpauth:// 链接中的发行方（令牌 App 内展示名）
	totpIssuer = "九章WEB应用智能防护系统"
)

// TOTPVerifyInput 是登录第二步验证输入。
type TOTPVerifyInput struct {
	ChallengeToken string
	Code           string
	SourceIP       string
	ConnectionIP   string
	UserAgent      string
	RequestID      string
}

// TOTPSelfInput 是登录态下自助管理双因子的输入（附带审计上下文）。
type TOTPSelfInput struct {
	UserID       uuid.UUID
	Username     string
	Code         string
	SourceIP     string
	ConnectionIP string
	UserAgent    string
	RequestID    string
}

// TOTPSetupResult 是 setup 输出（明文密钥与恢复码仅此一次返回）。
type TOTPSetupResult struct {
	Secret        string
	OTPAuthURL    string
	RecoveryCodes []string
}

// totpChallenge 是挑战令牌的存储值：绑定首步登录的来源 IP 与 UA，
// 防止令牌在 TTL 内被转移到其他机器完成第二步验证。
type totpChallenge struct {
	UserID    uuid.UUID `json:"u"`
	SourceIP  string    `json:"ip"`
	UserAgent string    `json:"ua"`
}

// issueTOTPChallenge 签发登录第二步挑战令牌（32 字节随机 hex，Valkey 存绑定信息，一次性）。
func (s *Service) issueTOTPChallenge(ctx context.Context, userID uuid.UUID, sourceIP, userAgent string) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate totp challenge: %w", err)
	}
	token := hex.EncodeToString(buf)
	value, err := json.Marshal(totpChallenge{UserID: userID, SourceIP: sourceIP, UserAgent: userAgent})
	if err != nil {
		return "", fmt.Errorf("encode totp challenge: %w", err)
	}
	if err := s.cache.Set(ctx, totpChallengePrefix+token, string(value), totpChallengeTTL); err != nil {
		return "", fmt.Errorf("store totp challenge: %w", err)
	}
	return token, nil
}

// lookupTOTPChallenge 查询挑战令牌（不删除，验证失败可在 TTL 内重试）。
func (s *Service) lookupTOTPChallenge(ctx context.Context, token string) (*totpChallenge, error) {
	if token == "" {
		return nil, ErrTOTPChallengeInvalid
	}
	value, err := s.cache.Get(ctx, totpChallengePrefix+token)
	if err != nil {
		return nil, ErrTOTPChallengeInvalid
	}
	var ch totpChallenge
	if err := json.Unmarshal([]byte(value), &ch); err != nil || ch.UserID == uuid.Nil {
		return nil, ErrTOTPChallengeInvalid
	}
	return &ch, nil
}

// consumeTOTPChallenge 删除挑战令牌（验证成功后一次性消费）。
func (s *Service) consumeTOTPChallenge(ctx context.Context, token string) {
	if err := s.cache.Del(ctx, totpChallengePrefix+token); err != nil {
		slog.Warn("totp challenge consume failed", "error", err)
	}
}

// VerifyTOTPLogin 完成登录第二步：校验挑战令牌 + 动态令牌/恢复码，通过后创建会话。
// 失败计入登录失败次数（与密码失败同一锁定策略），恢复码命中即原子消费。
func (s *Service) VerifyTOTPLogin(ctx context.Context, in TOTPVerifyInput) (*LoginResult, error) {
	logIn := LoginInput{
		SourceIP:     in.SourceIP,
		ConnectionIP: in.ConnectionIP,
		UserAgent:    in.UserAgent,
		RequestID:    in.RequestID,
	}

	ch, err := s.lookupTOTPChallenge(ctx, in.ChallengeToken)
	if err != nil {
		s.recordLog(ctx, logIn, nil, loginlogs.EventLoginFailure, loginlogs.ResultFailure, "TOTP_CHALLENGE_INVALID")
		return nil, ErrTOTPChallengeInvalid
	}
	// 挑战令牌绑定首步来源：IP/UA 不一致视为令牌被转移，拒绝但不消费（首步机器仍可重试）
	if ch.SourceIP != in.SourceIP || ch.UserAgent != in.UserAgent {
		s.recordLog(ctx, logIn, &ch.UserID, loginlogs.EventLoginFailure, loginlogs.ResultFailure, "TOTP_CHALLENGE_ORIGIN_MISMATCH")
		slog.Warn("totp challenge origin mismatch", "user_id", ch.UserID, "request_id", in.RequestID)
		return nil, ErrTOTPChallengeInvalid
	}
	userID := ch.UserID
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || !user.TOTPEnabled {
		// 挑战有效期内用户被删除或双因子被关闭/重置，挑战作废
		s.consumeTOTPChallenge(ctx, in.ChallengeToken)
		s.recordLog(ctx, logIn, &userID, loginlogs.EventLoginFailure, loginlogs.ResultFailure, "TOTP_CHALLENGE_INVALID")
		return nil, ErrTOTPChallengeInvalid
	}
	logIn.Username = user.Username

	// 状态检查（挑战签发后账号可能被停用/锁定）
	if err := s.users.ClearExpiredLock(ctx, user.ID); err != nil {
		return nil, fmt.Errorf("clear expired account lock: %w", err)
	}
	if user.Status == users.StatusDisabled {
		s.consumeTOTPChallenge(ctx, in.ChallengeToken)
		s.recordLog(ctx, logIn, &user.ID, loginlogs.EventLoginFailure, loginlogs.ResultFailure, "ACCOUNT_DISABLED")
		return nil, ErrAccountUnavailable
	}
	if user.Status == users.StatusLocked && user.LockedUntil != nil && user.LockedUntil.After(time.Now()) {
		s.recordLog(ctx, logIn, &user.ID, loginlogs.EventLoginFailure, loginlogs.ResultFailure, "ACCOUNT_LOCKED")
		return nil, ErrAccountUnavailable
	}

	if !s.verifyTOTPCredential(ctx, user, in.Code) {
		policy := s.settings.LoginPolicy(ctx)
		locked, recordErr := s.users.RecordLoginFailure(ctx, user.ID, policy.MaxFailedAttempts,
			time.Duration(policy.LockMinutes)*time.Minute)
		if recordErr != nil {
			return nil, fmt.Errorf("record login failure: %w", recordErr)
		}
		if locked {
			s.recordLog(ctx, logIn, &user.ID, loginlogs.EventAccountLocked, loginlogs.ResultFailure, "MAX_FAILED_ATTEMPTS")
			// 登录暴破告警（通知二期 / Tier 2）：锁定时触发 LOGIN_BRUTE_FORCE
			s.notifyAccountLocked(ctx, logIn, policy.LockMinutes)
		} else {
			s.recordLog(ctx, logIn, &user.ID, loginlogs.EventLoginFailure, loginlogs.ResultFailure, "TOTP_INVALID")
		}
		return nil, ErrTOTPInvalid
	}

	// 验证通过：消费挑战令牌（一次性），走与登录完全一致的会话建立与成功日志路径
	s.consumeTOTPChallenge(ctx, in.ChallengeToken)
	return s.completeLogin(ctx, user, logIn)
}

// verifyTOTPCredential 校验已启用密钥的动态令牌，或一次性恢复码（命中即消费）。
func (s *Service) verifyTOTPCredential(ctx context.Context, user *users.User, code string) bool {
	code = strings.TrimSpace(code)
	switch {
	case security.IsTOTPCodeFormat(code):
		if user.TOTPSecretEncrypted == nil {
			return false
		}
		secret, err := s.enc.Decrypt(*user.TOTPSecretEncrypted)
		if err != nil {
			slog.Error("decrypt totp secret failed", "user_id", user.ID, "error", err)
			return false
		}
		return security.VerifyTOTP(secret, code, time.Now())
	case security.IsRecoveryCodeFormat(code):
		// 恢复码哈希为 Argon2id（随机盐），无法按哈希等值反查：先逐条匹配出命中的
		// 存储哈希（兼容存量无盐 SHA-256），再按该哈希原子消费，保证一次性语义。
		var matched string
		for _, h := range user.TOTPRecoveryCodeHashes {
			if security.MatchRecoveryCode(code, h) {
				matched = h
				break
			}
		}
		if matched == "" {
			return false
		}
		ok, err := s.users.ConsumeTOTPRecoveryCode(ctx, user.ID, matched)
		if err != nil {
			slog.Error("consume totp recovery code failed", "user_id", user.ID, "error", err)
			return false
		}
		return ok
	default:
		return false
	}
}

// SetupTOTP 生成待启用密钥与恢复码（密钥加密、恢复码只存哈希落库，明文仅本次返回）。
func (s *Service) SetupTOTP(ctx context.Context, in TOTPSelfInput) (*TOTPSetupResult, error) {
	user, err := s.users.GetByID(ctx, in.UserID)
	if err != nil {
		return nil, err
	}
	if user.TOTPEnabled {
		return nil, ErrTOTPAlreadyEnabled
	}
	secret, err := security.GenerateTOTPSecret()
	if err != nil {
		return nil, err
	}
	encSecret, err := s.enc.Encrypt(secret)
	if err != nil {
		return nil, fmt.Errorf("encrypt totp secret: %w", err)
	}
	codes, err := security.GenerateRecoveryCodes(totpRecoveryCodeCount)
	if err != nil {
		return nil, err
	}
	hashes := make([]string, len(codes))
	for i, c := range codes {
		hashes[i], err = security.HashRecoveryCode(c)
		if err != nil {
			return nil, fmt.Errorf("hash recovery code: %w", err)
		}
	}
	if err := s.users.SaveTOTPPending(ctx, in.UserID, encSecret, hashes); err != nil {
		return nil, err
	}
	s.recordTOTPAudit(ctx, in, "totp_setup", "", "pending_secret_saved", audits.RiskLow)
	return &TOTPSetupResult{
		Secret:        secret,
		OTPAuthURL:    security.TOTPAuthURL(totpIssuer, user.Username, secret),
		RecoveryCodes: codes,
	}, nil
}

// EnableTOTP 用待启用密钥验证动态令牌，通过后转正并正式开启双因子。
func (s *Service) EnableTOTP(ctx context.Context, in TOTPSelfInput) error {
	user, err := s.users.GetByID(ctx, in.UserID)
	if err != nil {
		return err
	}
	if user.TOTPEnabled {
		return ErrTOTPAlreadyEnabled
	}
	if user.TOTPPendingSecretEncrypted == nil {
		return users.ErrNoTOTPPending
	}
	secret, err := s.enc.Decrypt(*user.TOTPPendingSecretEncrypted)
	if err != nil {
		return fmt.Errorf("decrypt pending totp secret: %w", err)
	}
	if !security.VerifyTOTP(secret, in.Code, time.Now()) {
		return ErrTOTPInvalid
	}
	if err := s.users.EnableTOTP(ctx, in.UserID); err != nil {
		return err
	}
	s.recordTOTPAudit(ctx, in, "totp_enable", "", "totp_enabled=true", audits.RiskMedium)
	return nil
}

// DisableTOTP 验证动态令牌或恢复码后关闭双因子并清除密钥与恢复码（高危操作）。
func (s *Service) DisableTOTP(ctx context.Context, in TOTPSelfInput) error {
	user, err := s.users.GetByID(ctx, in.UserID)
	if err != nil {
		return err
	}
	if !user.TOTPEnabled {
		return ErrTOTPNotEnabled
	}
	if !s.verifyTOTPCredential(ctx, user, in.Code) {
		return ErrTOTPInvalid
	}
	if err := s.users.ClearTOTP(ctx, in.UserID); err != nil {
		return err
	}
	s.recordTOTPAudit(ctx, in, "totp_disable", "totp_enabled=true", "totp_enabled=false", audits.RiskHigh)
	return nil
}

// recordTOTPAudit 记录双因子自助管理操作审计（不泄露密钥/恢复码）。
func (s *Service) recordTOTPAudit(ctx context.Context, in TOTPSelfInput, action, before, after, risk string) {
	audits.RecordWithFallback(ctx, s.audits, audits.RecordInput{
		UserID:        &in.UserID,
		Username:      in.Username,
		SourceIP:      in.SourceIP,
		ConnectionIP:  in.ConnectionIP,
		UserAgent:     in.UserAgent,
		Module:        "auth",
		Action:        action,
		ObjectType:    "user",
		ObjectID:      in.UserID.String(),
		ObjectName:    in.Username,
		BeforeSummary: before,
		AfterSummary:  after,
		Result:        audits.ResultSuccess,
		RiskLevel:     risk,
		RequestID:     in.RequestID,
	})
}
