// file_signature_test.go 文件签名 v1 密钥下发（W13-GW / P2-02）单测：
// 加载器解密路径正反（未配置/缺 kid/kid 口径/解密失败/密钥格式非法如实报错，
// 错误信息不含密钥值）、发布侧 fail-hard（未注入/未配置不下发、失败中止发布）、
// 快照脱敏断言（key_hex → "***"，kid 保留，原配置不受影响）。
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

// sigTestKeyHex 测试用签名密钥（32 字节 hex，与加载器产物同形态）。
var sigTestKeyHex = hex.EncodeToString([]byte("fedcba9876543210fedcba9876543210"))

// errFileSignatureTest 文件签名加载器测试用错误（避免与包内其他 fake 错误重名）。
var errFileSignatureTest = errors.New("file signature loader failed")

// TestNewFileSignatureLoader 加载器：未配置 → 空不下发；密文解密 + kid → 明文 hex；
// 缺 kid/kid 非法/解密失败/密钥格式非法 → 如实报错（发布侧中止发布）。
func TestNewFileSignatureLoader(t *testing.T) {
	kv := &fakeSettingsGet{kv: map[string]string{}}
	l := NewFileSignatureLoader(kv.get, fakeDecrypt)
	// 未配置签名密钥
	kid, keyHex, err := l(context.Background())
	if err != nil || kid != "" || keyHex != "" {
		t.Fatalf("unset key must yield empty: %q %q, %v", kid, keyHex, err)
	}
	// 配置了密钥但缺 kid → 错误
	kv.kv["gateway_runtime/api_file_signature_key"] = "enc:" + sigTestKeyHex
	if _, _, err = l(context.Background()); err == nil {
		t.Fatal("key without kid must error")
	}
	// kid 含 '.'（破坏 token 分段）→ 错误
	kv.kv["gateway_runtime/api_file_signature_kid"] = "k.1"
	if _, _, err = l(context.Background()); err == nil {
		t.Fatal("kid with dot must error")
	}
	// kid 含 '|'（破坏 HMAC 字段边界）→ 错误
	kv.kv["gateway_runtime/api_file_signature_kid"] = "k|1"
	if _, _, err = l(context.Background()); err == nil {
		t.Fatal("kid with pipe must error")
	}
	// kid 超长 → 错误
	kv.kv["gateway_runtime/api_file_signature_kid"] = strings.Repeat("k", 65)
	if _, _, err = l(context.Background()); err == nil {
		t.Fatal("long kid must error")
	}
	// 正常：密文解密 → kid + 明文 hex（规范化为标准 hex 编码）
	kv.kv["gateway_runtime/api_file_signature_kid"] = " k2026 "
	kid, keyHex, err = l(context.Background())
	if err != nil || kid != "k2026" || keyHex != sigTestKeyHex {
		t.Fatalf("decrypt failed: %q %q, %v", kid, keyHex, err)
	}
	// 解密失败 → 错误
	kv.kv["gateway_runtime/api_file_signature_key"] = "not-a-ciphertext"
	if _, _, err = l(context.Background()); err == nil {
		t.Fatal("decrypt failure must error")
	}
	// 明文 hex 长度非法（非 32 字节）→ 错误
	kv.kv["gateway_runtime/api_file_signature_key"] = "enc:abcd"
	if _, _, err = l(context.Background()); err == nil {
		t.Fatal("short key must error")
	}
	// 非 hex 明文 → 错误
	kv.kv["gateway_runtime/api_file_signature_key"] = "enc:" + strings.Repeat("zz", 32)
	if _, _, err = l(context.Background()); err == nil {
		t.Fatal("non-hex key must error")
	}
	// 错误信息不含密钥值
	kv.kv["gateway_runtime/api_file_signature_key"] = "enc:" + sigTestKeyHex
	kv.kv["gateway_runtime/api_file_signature_kid"] = "bad kid"
	if _, _, err = l(context.Background()); err != nil && strings.Contains(err.Error(), sigTestKeyHex) {
		t.Fatalf("error must not contain key material: %v", err)
	}
}

// TestLoadAPIFileSignatureFailHard 发布侧纪律：未注入 nil；加载失败如实报错、中止发布
// （fail-hard：静默停用签名嵌入会让管理面显示与网关行为不一致）；空值不下发；
// 正常读取透传 {enabled,kid,key_hex}。
func TestLoadAPIFileSignatureFailHard(t *testing.T) {
	// 未注入
	p := &Provider{}
	got, err := p.loadAPIFileSignature(context.Background())
	if got != nil || err != nil {
		t.Fatalf("nil loader must yield nil, nil: %v, %v", got, err)
	}
	// 加载失败 → 如实报错（中止发布，不静默降级）
	p = &Provider{fileSignature: func(ctx context.Context) (string, string, error) {
		return "", "", errFileSignatureTest
	}}
	if got, err = p.loadAPIFileSignature(context.Background()); err == nil || got != nil {
		t.Fatalf("loader failure must error: %v, %v", got, err)
	}
	// 未配置（空值）→ 不下发
	p = &Provider{fileSignature: func(ctx context.Context) (string, string, error) { return "", "", nil }}
	if got, err = p.loadAPIFileSignature(context.Background()); got != nil || err != nil {
		t.Fatalf("empty values must yield nil, nil: %v, %v", got, err)
	}
	// 正常读取
	p = &Provider{fileSignature: func(ctx context.Context) (string, string, error) { return "k2026", sigTestKeyHex, nil }}
	got, err = p.loadAPIFileSignature(context.Background())
	if err != nil || got == nil || !got.Enabled || got.KID != "k2026" || got.KeyHex != sigTestKeyHex {
		t.Fatalf("signature = %+v, %v", got, err)
	}
}

// TestRedactGuardConfigStripsFileSignatureKey api_file_signature.key_hex 为秘密材料，
// 版本快照脱敏（与 valkey.password/identity_salt/api_scan_verification 同一纪律）；
// kid 非秘密保留；原配置不受影响。
func TestRedactGuardConfigStripsFileSignatureKey(t *testing.T) {
	cfg := &gatewayconfig.GuardConfig{
		APIFileSignature: &gatewayconfig.GuardFileSignature{Enabled: true, KID: "k2026", KeyHex: sigTestKeyHex},
	}
	red := RedactGuardConfig(cfg)
	if red.APIFileSignature == nil || red.APIFileSignature.KeyHex != "***" {
		t.Fatalf("signature key not redacted: %+v", red.APIFileSignature)
	}
	if red.APIFileSignature.KID != "k2026" || !red.APIFileSignature.Enabled {
		t.Fatalf("kid/enabled must be preserved: %+v", red.APIFileSignature)
	}
	if cfg.APIFileSignature.KeyHex != sigTestKeyHex {
		t.Fatal("original config mutated")
	}
	data, err := json.Marshal(red)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), sigTestKeyHex) {
		t.Fatalf("marshaled redacted config still contains signature key: %s", data)
	}
}
