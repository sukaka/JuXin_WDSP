package security

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 附录B 测试密钥（ASCII "12345678901234567890" 的 Base32 编码，SHA1 用）
const rfc6238Secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

// TestTOTPCodeRFC6238Vectors 使用 RFC 6238 附录B 测试向量（SHA1/30s，取低 6 位）。
func TestTOTPCodeRFC6238Vectors(t *testing.T) {
	cases := []struct {
		unix int64
		want string // RFC 8 位验证码的低 6 位
	}{
		{59, "287082"},          // 94287082
		{1111111109, "081804"},  // 07081804
		{1111111111, "050471"},  // 14050471
		{1234567890, "005924"},  // 89005924
		{2000000000, "279037"},  // 69279037
		{20000000000, "353130"}, // 65353130
	}
	for _, c := range cases {
		got, err := TOTPCode(rfc6238Secret, time.Unix(c.unix, 0).UTC())
		if err != nil {
			t.Fatalf("TOTPCode(%d) error: %v", c.unix, err)
		}
		if got != c.want {
			t.Errorf("TOTPCode(%d) = %s, want %s", c.unix, got, c.want)
		}
	}
}

// TestVerifyTOTPTimeSkew 验证 ±1 时间步容差与超出容差拒绝。
func TestVerifyTOTPTimeSkew(t *testing.T) {
	base := time.Unix(1000000000, 0).UTC()
	code, err := TOTPCode(rfc6238Secret, base)
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}
	// 同一步、前后各一步（±30s）内应通过
	for _, offset := range []int64{-30, 0, 30} {
		if !VerifyTOTP(rfc6238Secret, code, base.Add(time.Duration(offset)*time.Second)) {
			t.Errorf("VerifyTOTP(offset=%ds) = false, want true", offset)
		}
	}
	// 超出 ±1 步应拒绝
	for _, offset := range []int64{-60, 60, 300} {
		if VerifyTOTP(rfc6238Secret, code, base.Add(time.Duration(offset)*time.Second)) {
			t.Errorf("VerifyTOTP(offset=%ds) = true, want false", offset)
		}
	}
}

// TestH19VerifyTOTPWithStepReturnsExactMatchedStep 验证返回命中的精确时间步，供防重放登记使用。
func TestH19VerifyTOTPWithStepReturnsExactMatchedStep(t *testing.T) {
	base := time.Unix(1000000000, 0).UTC()
	wantStep := base.Unix() / totpPeriod
	code, err := TOTPCode(rfc6238Secret, base)
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}
	for _, offset := range []int64{-30, 0, 30} {
		step, ok := VerifyTOTPWithStep(rfc6238Secret, code, base.Add(time.Duration(offset)*time.Second))
		if !ok {
			t.Fatalf("VerifyTOTPWithStep(offset=%ds) = false, want true", offset)
		}
		if step != wantStep {
			t.Fatalf("VerifyTOTPWithStep(offset=%ds) step = %d, want %d", offset, step, wantStep)
		}
	}
	if step, ok := VerifyTOTPWithStep(rfc6238Secret, code, base.Add(60*time.Second)); ok || step != 0 {
		t.Fatalf("out-of-window VerifyTOTPWithStep = (%d, %v), want (0, false)", step, ok)
	}
	if step, ok := VerifyTOTPWithStep(rfc6238Secret, "invalid", base); ok || step != 0 {
		t.Fatalf("malformed VerifyTOTPWithStep = (%d, %v), want (0, false)", step, ok)
	}
}

// TestVerifyTOTPRejectsMalformed 非法格式与错误验证码拒绝。
func TestVerifyTOTPRejectsMalformed(t *testing.T) {
	now := time.Now()
	if VerifyTOTP(rfc6238Secret, "12345", now) {
		t.Error("accepted 5-digit code")
	}
	if VerifyTOTP(rfc6238Secret, "abcdef", now) {
		t.Error("accepted non-digit code")
	}
	if VerifyTOTP(rfc6238Secret, "", now) {
		t.Error("accepted empty code")
	}
	if VerifyTOTP("!!bad-secret!!", "123456", now) {
		t.Error("accepted invalid secret")
	}
}

// TestGenerateTOTPSecret 密钥为 Base32 编码且可解码回 160bit。
func TestGenerateTOTPSecret(t *testing.T) {
	s1, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("GenerateTOTPSecret: %v", err)
	}
	if len(s1) != 32 { // 20 字节 → 32 个 Base32 字符
		t.Errorf("secret length = %d, want 32", len(s1))
	}
	key, err := decodeTOTPSecret(s1)
	if err != nil {
		t.Fatalf("decodeTOTPSecret: %v", err)
	}
	if len(key) != 20 {
		t.Errorf("decoded key length = %d, want 20", len(key))
	}
	s2, _ := GenerateTOTPSecret()
	if s1 == s2 {
		t.Error("two generated secrets identical")
	}
}

// TestTOTPAuthURL 校验 otpauth:// 链接格式。
func TestTOTPAuthURL(t *testing.T) {
	u := TOTPAuthURL("九章WAF", "admin", rfc6238Secret)
	if !strings.HasPrefix(u, "otpauth://totp/") {
		t.Errorf("url = %s, want otpauth://totp/ prefix", u)
	}
	for _, want := range []string{"secret=" + rfc6238Secret, "algorithm=SHA1", "digits=6", "period=30", "issuer="} {
		if !strings.Contains(u, want) {
			t.Errorf("url missing %q: %s", want, u)
		}
	}
}

// TestRecoveryCodes 恢复码格式、唯一性与哈希匹配。
func TestRecoveryCodes(t *testing.T) {
	codes, err := GenerateRecoveryCodes(10)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}
	if len(codes) != 10 {
		t.Fatalf("got %d codes, want 10", len(codes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if !IsRecoveryCodeFormat(c) {
			t.Errorf("code %q not in xxxx-xxxx format", c)
		}
		if seen[c] {
			t.Errorf("duplicate code %q", c)
		}
		seen[c] = true
		// Argon2id 哈希带随机盐，逐码不同；匹配大小写不敏感
		h, err := HashRecoveryCode(c)
		if err != nil {
			t.Fatalf("HashRecoveryCode(%q): %v", c, err)
		}
		if !strings.HasPrefix(h, "$argon2id$") {
			t.Errorf("hash of %q not argon2id encoded: %q", c, h)
		}
		if !MatchRecoveryCode(strings.ToUpper(c), h) {
			t.Errorf("match failed for case variant of %q", c)
		}
	}
	// 不同恢复码互不命中
	h0, err := HashRecoveryCode(codes[0])
	if err != nil {
		t.Fatalf("HashRecoveryCode: %v", err)
	}
	if MatchRecoveryCode(codes[1], h0) {
		t.Error("distinct recovery code matched another code's hash")
	}
	// 恢复码不会被当成 6 位动态令牌
	if IsTOTPCodeFormat(codes[0]) {
		t.Error("recovery code misclassified as totp code")
	}
}

// TestMatchRecoveryCodeLegacyCompat 存量无盐 SHA-256 哈希仍可命中（一次性消费后自然迁移）。
func TestMatchRecoveryCodeLegacyCompat(t *testing.T) {
	code := "abcd-efgh"
	legacy := legacyHashRecoveryCode(code)
	if !MatchRecoveryCode(code, legacy) {
		t.Error("legacy sha256 hash not matched")
	}
	if !MatchRecoveryCode(strings.ToUpper(code)+" ", legacy) {
		t.Error("legacy match should be case/space insensitive")
	}
	if MatchRecoveryCode("wxyz-1234", legacy) {
		t.Error("wrong code matched legacy hash")
	}
	// 旧格式不得再生成：新哈希必须是 Argon2id
	h, err := HashRecoveryCode(code)
	if err != nil {
		t.Fatalf("HashRecoveryCode: %v", err)
	}
	if h == legacy {
		t.Error("new hash must not use legacy sha256 scheme")
	}
}
