// scan_verify_test.go 扫描流量识别密钥下发（W9-GW）单测：
// 加载器解密路径正反、发布侧 fail-hard（未注入/未配置不下发、解密失败中止发布）、快照脱敏断言。
package guardconfig

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// scanTestKeyHex 测试用签名密钥（32 字节 hex，与 apiscan.GenerateSigningKey 产物同形态）。
var scanTestKeyHex = hex.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))

// fakeSettingsGet 内存版设置读取（group/key → 值）。
type fakeSettingsGet struct {
	kv map[string]string
}

func (f *fakeSettingsGet) get(ctx context.Context, group, key, def string) string {
	_ = ctx
	if v, ok := f.kv[group+"/"+key]; ok {
		return v
	}
	return def
}

// fakeDecrypt 记录型解密函数（可注入错误路径）；密文约定 "enc:" 前缀模拟。
func fakeDecrypt(encoded string) (string, error) {
	if !strings.HasPrefix(encoded, "enc:") {
		return "", errors.New("bad ciphertext")
	}
	return strings.TrimPrefix(encoded, "enc:"), nil
}

// TestNewScanVerificationLoader 加载器：未配置 → 空串不下发；密文解密 → 明文 hex；
// 解密失败/密钥格式非法 → 如实报错（发布侧中止发布）；密文不泄入错误信息之外的产物。
func TestNewScanVerificationLoader(t *testing.T) {
	kv := &fakeSettingsGet{kv: map[string]string{}}
	// 未配置签名密钥
	l := NewScanVerificationLoader(kv.get, fakeDecrypt)
	if got, err := l(context.Background()); err != nil || got != "" {
		t.Fatalf("unset key must yield empty: %q, %v", got, err)
	}
	// 密文 → 明文 hex（规范化为标准 hex 编码）
	kv.kv["api_scan/signing_key"] = "enc:" + scanTestKeyHex
	got, err := l(context.Background())
	if err != nil || got != scanTestKeyHex {
		t.Fatalf("decrypt failed: %q, %v", got, err)
	}
	// 解密失败 → 错误
	kv.kv["api_scan/signing_key"] = "not-a-ciphertext"
	if _, err = l(context.Background()); err == nil {
		t.Fatal("decrypt failure must error")
	}
	// 明文 hex 长度非法（非 32 字节）→ 错误
	kv.kv["api_scan/signing_key"] = "enc:abcd"
	if _, err = l(context.Background()); err == nil {
		t.Fatal("short key must error")
	}
	// 非 hex 明文 → 错误
	kv.kv["api_scan/signing_key"] = "enc:" + strings.Repeat("zz", 32)
	if _, err = l(context.Background()); err == nil {
		t.Fatal("non-hex key must error")
	}
}

// TestLoadAPIScanVerificationFailHard 发布侧纪律：未注入 nil；加载失败（解密链路不通）
// 如实报错、中止发布（fail-hard：降级为仅按头存在性识别会放行伪造扫描头投毒学习样本）；
// 空串不下发；正常读取透传。
func TestLoadAPIScanVerificationFailHard(t *testing.T) {
	// 未注入
	p := &Provider{}
	got, err := p.loadAPIScanVerification(context.Background())
	if got != nil || err != nil {
		t.Fatalf("nil loader must yield nil, nil: %v, %v", got, err)
	}
	// 解密失败 → 如实报错（中止发布，不静默降级）
	p = &Provider{scanVerification: func(ctx context.Context) (string, error) {
		return "", errors.New("decrypt failed")
	}}
	if got, err = p.loadAPIScanVerification(context.Background()); err == nil || got != nil {
		t.Fatalf("loader failure must error: %v, %v", got, err)
	}
	// 未配置（空串）→ 不下发
	p = &Provider{scanVerification: func(ctx context.Context) (string, error) { return "", nil }}
	if got, err = p.loadAPIScanVerification(context.Background()); got != nil || err != nil {
		t.Fatalf("empty key must yield nil, nil: %v, %v", got, err)
	}
	// 正常读取
	p = &Provider{scanVerification: func(ctx context.Context) (string, error) { return scanTestKeyHex, nil }}
	got, err = p.loadAPIScanVerification(context.Background())
	if err != nil || got == nil || got.KeyHex != scanTestKeyHex {
		t.Fatalf("verification = %+v, %v", got, err)
	}
}

// TestRedactGuardConfigStripsScanKey api_scan_verification.key_hex 为秘密材料，
// 版本快照脱敏（与 valkey.password/identity_salt 同一纪律），原配置不受影响。
func TestRedactGuardConfigStripsScanKey(t *testing.T) {
	cfg := &gatewayconfig.GuardConfig{
		APIScanVerification: &gatewayconfig.GuardScanVerification{KeyHex: scanTestKeyHex},
	}
	red := RedactGuardConfig(cfg)
	if red.APIScanVerification == nil || red.APIScanVerification.KeyHex != "***" {
		t.Fatalf("scan key not redacted: %+v", red.APIScanVerification)
	}
	if cfg.APIScanVerification.KeyHex != scanTestKeyHex {
		t.Fatal("original config mutated")
	}
	data, err := json.Marshal(red)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), scanTestKeyHex) {
		t.Fatalf("marshaled redacted config still contains scan key: %s", data)
	}
}
