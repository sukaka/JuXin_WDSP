// Package security 提供密码哈希、密码策略、验证码、令牌等安全基础能力。
package security

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id 参数（OWASP 推荐基线，可按环境调整）
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MB
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16
)

// ErrPasswordMismatch 密码不匹配。
var ErrPasswordMismatch = errors.New("password mismatch")

// HashPassword 使用 Argon2id 生成密码哈希。
// 格式: $argon2id$v=19$m=65536,t=3,p=2$<salt-b64>$<hash-b64>
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("empty password")
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash)), nil
}

// VerifyPassword 校验密码与哈希是否匹配（常量时间比较）。
func VerifyPassword(password, encoded string) error {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		return errors.New("invalid hash format")
	}
	var memory uint32
	var time uint32
	var threads uint8
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return fmt.Errorf("parse version: %w", err)
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return fmt.Errorf("parse params: %w", err)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return fmt.Errorf("decode salt: %w", err)
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return fmt.Errorf("decode hash: %w", err)
	}
	actual := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(expected)))
	if subtle.ConstantTimeCompare(actual, expected) != 1 {
		return ErrPasswordMismatch
	}
	return nil
}

// PasswordPolicy 是可配置密码策略。
type PasswordPolicy struct {
	MinLength        int
	RequireUpper     bool
	RequireLower     bool
	RequireDigit     bool
	RequireSpecial   bool
	HistoryCount     int
	ExpireDays       int
	ExpireRemindDays int
	CheckWeak        bool
}

// DefaultPasswordPolicy 返回默认策略（与种子设置一致）。
func DefaultPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinLength:        12,
		RequireUpper:     true,
		RequireLower:     true,
		RequireDigit:     true,
		RequireSpecial:   true,
		HistoryCount:     5,
		ExpireDays:       90,
		ExpireRemindDays: 7,
		CheckWeak:        true,
	}
}

// PolicyError 是密码策略违反错误，携带用户可读原因。
type PolicyError struct {
	Reasons []string
}

func (e *PolicyError) Error() string {
	return "密码不符合策略: " + strings.Join(e.Reasons, "; ")
}

// 常见弱口令清单（小写）。完整清单可扩展，此处覆盖高频弱口令。
var weakPasswords = map[string]bool{
	"password": true, "password1": true, "password123": true,
	"123456": true, "12345678": true, "123456789": true, "1234567890": true,
	"qwerty": true, "qwerty123": true, "admin": true, "admin123": true,
	"root": true, "root123": true, "letmein": true, "welcome": true,
	"iloveyou": true, "dragon": true, "monkey": true, "abc123": true,
	"111111": true, "000000": true, "654321": true, "1q2w3e4r": true,
	"qazwsx": true, "p@ssw0rd": true, "p@ssword": true, "passw0rd": true,
	"changeme": true, "default": true, "jiuzhang": true, "jiuzhang123": true,
}

// ValidatePassword 校验密码是否符合策略。
// username 用于防止密码与用户名相同或包含用户名。
func ValidatePassword(password, username string, policy PasswordPolicy) *PolicyError {
	var reasons []string

	if len(password) < policy.MinLength {
		reasons = append(reasons, fmt.Sprintf("长度不能少于%d位", policy.MinLength))
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, c := range password {
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}
	if policy.RequireUpper && !hasUpper {
		reasons = append(reasons, "必须包含大写字母")
	}
	if policy.RequireLower && !hasLower {
		reasons = append(reasons, "必须包含小写字母")
	}
	if policy.RequireDigit && !hasDigit {
		reasons = append(reasons, "必须包含数字")
	}
	if policy.RequireSpecial && !hasSpecial {
		reasons = append(reasons, "必须包含特殊字符")
	}

	lowerPwd := strings.ToLower(password)
	lowerName := strings.ToLower(username)
	if username != "" && lowerPwd == lowerName {
		reasons = append(reasons, "不得与用户名相同")
	}
	if username != "" && len(username) >= 3 && strings.Contains(lowerPwd, lowerName) {
		reasons = append(reasons, "不得包含完整用户名")
	}
	if policy.CheckWeak && weakPasswords[lowerPwd] {
		reasons = append(reasons, "不得使用常见弱口令")
	}

	if len(reasons) > 0 {
		return &PolicyError{Reasons: reasons}
	}
	return nil
}

// GenerateTemporaryPassword 生成满足策略的随机临时密码。
// 由大小写字母、数字、特殊字符组成，保证各类字符至少出现一次。
func GenerateTemporaryPassword(length int) (string, error) {
	if length < 12 {
		length = 16
	}
	const (
		upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ"
		lower   = "abcdefghijkmnpqrstuvwxyz"
		digits  = "23456789"
		special = "!@#$%^&*-_=+?"
		all     = upper + lower + digits + special
	)
	pick := func(set string) (byte, error) {
		var b [1]byte
		if _, err := rand.Read(b[:]); err != nil {
			return 0, err
		}
		return set[int(b[0])%len(set)], nil
	}
	buf := make([]byte, 0, length)
	// 保证四类字符各至少一位
	for _, set := range []string{upper, lower, digits, special} {
		c, err := pick(set)
		if err != nil {
			return "", err
		}
		buf = append(buf, c)
	}
	for len(buf) < length {
		c, err := pick(all)
		if err != nil {
			return "", err
		}
		buf = append(buf, c)
	}
	// 打乱顺序
	for i := len(buf) - 1; i > 0; i-- {
		var rb [1]byte
		if _, err := rand.Read(rb[:]); err != nil {
			return "", err
		}
		j := int(rb[0]) % (i + 1)
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf), nil
}

// NewRandomToken 生成 URL 安全的随机令牌。
func NewRandomToken(bytesLen int) (string, error) {
	if bytesLen <= 0 {
		bytesLen = 32
	}
	b := make([]byte, bytesLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
