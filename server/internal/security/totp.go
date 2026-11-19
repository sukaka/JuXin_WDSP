package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// TOTP 参数（RFC 6238，兼容 Google Authenticator 等标准令牌 App）
const (
	totpPeriod    = 30 // 时间步长（秒）
	totpDigits    = 6  // 验证码位数
	totpSecretLen = 20 // 密钥长度（160 bit）
	totpSkewSteps = 1  // 允许的时间步容差（±1 步）
)

// ErrTOTPSecretInvalid 密钥编码非法。
var ErrTOTPSecretInvalid = errors.New("invalid totp secret")

// totpCodePattern 是 6 位数字动态令牌格式。
var totpCodePattern = regexp.MustCompile(`^\d{6}$`)

// recoveryCodePattern 是恢复码格式（xxxx-xxxx，不区分大小写）。
var recoveryCodePattern = regexp.MustCompile(`^[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}$`)

// 恢复码字符集（去除易混淆字符 0/o、1/i/l）
const recoveryCodeCharset = "abcdefghjkmnpqrstuvwxyz23456789"

// GenerateTOTPSecret 生成 160 bit 随机密钥，返回 Base32（无填充）编码。
func GenerateTOTPSecret() (string, error) {
	buf := make([]byte, totpSecretLen)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate totp secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

// IsTOTPCodeFormat 判断输入是否为 6 位数字动态令牌格式。
func IsTOTPCodeFormat(code string) bool {
	return totpCodePattern.MatchString(strings.TrimSpace(code))
}

// IsRecoveryCodeFormat 判断输入是否为恢复码格式（xxxx-xxxx）。
func IsRecoveryCodeFormat(code string) bool {
	return recoveryCodePattern.MatchString(strings.TrimSpace(code))
}

// TOTPCode 计算指定时刻的 6 位动态验证码（HMAC-SHA1，30 秒步长）。
func TOTPCode(secret string, at time.Time) (string, error) {
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		return "", err
	}
	counter := uint64(at.Unix()) / totpPeriod
	return hotpCode(key, counter), nil
}

// VerifyTOTP 校验动态验证码，允许 ±totpSkewSteps 个时间步容差（常量时间比较）。
func VerifyTOTP(secret, code string, at time.Time) bool {
	_, ok := VerifyTOTPWithStep(secret, code, at)
	return ok
}

// VerifyTOTPWithStep 校验动态验证码并返回命中的时间步（Unix / 30s），
// 供调用方记录 totp_used:<userID>:<step> 防重放（阻断 ±1 步 90s 窗口内同一验证码重放）。
func VerifyTOTPWithStep(secret, code string, at time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	if !totpCodePattern.MatchString(code) {
		return 0, false
	}
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		return 0, false
	}
	counter := at.Unix() / totpPeriod
	for step := int64(-totpSkewSteps); step <= int64(totpSkewSteps); step++ {
		matchedStep := counter + step
		if matchedStep < 0 {
			continue
		}
		expected := hotpCode(key, uint64(matchedStep))
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return matchedStep, true
		}
	}
	return 0, false
}

// TOTPAuthURL 生成 otpauth:// 链接（供令牌 App 扫码/手动录入）。
// issuer 为产品名，account 为用户名。
func TOTPAuthURL(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// GenerateRecoveryCodes 生成 n 个一次性恢复码（格式 xxxx-xxxx）。
func GenerateRecoveryCodes(n int) ([]string, error) {
	if n <= 0 {
		n = 10
	}
	codes := make([]string, 0, n)
	for i := 0; i < n; i++ {
		buf := make([]byte, 8)
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("generate recovery code: %w", err)
		}
		var b strings.Builder
		for j, v := range buf {
			if j == 4 {
				b.WriteByte('-')
			}
			b.WriteByte(recoveryCodeCharset[int(v)%len(recoveryCodeCharset)])
		}
		codes = append(codes, b.String())
	}
	return codes, nil
}

// HashRecoveryCode 计算恢复码的存储哈希（Argon2id，复用密码哈希设施，每码随机盐）。
// 输入先做规范化（去空白、转小写），用户输入大小写/空格差异不影响命中。
// 恢复码仅 8 字符约 40bit 熵，无盐快速哈希在 DB 泄漏后可被离线暴破，故必须使用慢哈希。
func HashRecoveryCode(code string) (string, error) {
	return HashPassword(normalizeRecoveryCode(code))
}

// MatchRecoveryCode 校验恢复码是否命中某个存储哈希（常量时间比较/慢哈希校验）。
// 兼容存量数据：旧格式为无盐 SHA-256 hex（64 位十六进制），新格式为 Argon2id 编码串。
// 旧格式命中后由调用方消费该哈希（一次性），剩余旧码在用户下次 setup 时自然全部换新。
func MatchRecoveryCode(code, storedHash string) bool {
	if strings.HasPrefix(storedHash, "$argon2id$") {
		return VerifyPassword(normalizeRecoveryCode(code), storedHash) == nil
	}
	expected := legacyHashRecoveryCode(code)
	return subtle.ConstantTimeCompare([]byte(expected), []byte(storedHash)) == 1
}

// legacyHashRecoveryCode 是存量恢复码的无盐 SHA-256 哈希（仅用于校验旧数据，禁止再写入）。
func legacyHashRecoveryCode(code string) string {
	sum := sha256.Sum256([]byte("jiuzhang-recovery:" + normalizeRecoveryCode(code)))
	return hex.EncodeToString(sum[:])
}

func normalizeRecoveryCode(code string) string {
	return strings.ToLower(strings.TrimSpace(code))
}

// decodeTOTPSecret 解码 Base32 密钥（容忍填充与小写输入）。
func decodeTOTPSecret(secret string) ([]byte, error) {
	normalized := strings.ToUpper(strings.TrimSpace(secret))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(normalized)
	if err != nil {
		return nil, ErrTOTPSecretInvalid
	}
	if len(key) == 0 {
		return nil, ErrTOTPSecretInvalid
	}
	return key, nil
}

// hotpCode 计算 HOTP 值（RFC 4226 动态截断，取低 6 位）。
func hotpCode(key []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binCode := (uint32(sum[offset]&0x7f) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
	otp := binCode % 1000000
	return fmt.Sprintf("%06d", otp)
}
