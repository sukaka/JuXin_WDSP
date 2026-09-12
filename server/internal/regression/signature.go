// signature.go Ed25519 离线验签与受信公钥登记（任务书 §6.2）。
//
// 签名侧属仓库外受控验证服务（仓库内 tools/regsign 仅作独立小工具）；
// 本文件只做服务端核验：算法白名单 ed25519、key_id 必须已登记且未撤销、
// 签名字节 = manifest 规范形原文字节。公钥由部署管理员经管理配置
// （system_settings security_regression:trusted_verify_keys）登记；私钥不进入
// 仓库、报告或被测容器。密钥撤销后历史报告保留，但不能再作为新发布的可信凭据
// （门禁 Evaluate 以 keys 快照判定，撤销即不可用）。
package regression

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// TrustedKey 已登记受信验签公钥。
type TrustedKey struct {
	KeyID     string `json:"key_id"`    // 词形：[A-Za-z0-9._-]{1,128}
	Algorithm string `json:"algorithm"` // 恒 ed25519
	PublicKey string `json:"public_key"`
	Status    string `json:"status"` // ACTIVE / REVOKED
	Comment   string `json:"comment,omitempty"`
}

// 受信密钥状态词表。
const (
	KeyStatusActive  = "ACTIVE"
	KeyStatusRevoked = "REVOKED"
)

// SettingsReader 管理配置读取（settings.Service.GetString 适配；返回空串 = 未登记任何密钥）。
type SettingsReader func(ctx context.Context, group, key, def string) string

// LoadTrustedKeys 读取并解析受信公钥登记。未配置返回空表（不视为错误——
// 无任何登记密钥时一切验签按未登记 key_id 拒绝）；配置存在但解析失败返回错误
// （登记损坏属门禁依赖不可用，调用方必须明确失败，不静默当空表放行）。
func LoadTrustedKeys(ctx context.Context, read SettingsReader) ([]TrustedKey, error) {
	raw := strings.TrimSpace(read(ctx, TrustedKeysSettingsGroup, TrustedKeysSettingsKey, ""))
	if raw == "" {
		return nil, nil
	}
	if len(raw) > 64*1024 {
		return nil, fmt.Errorf("trusted_verify_keys setting too large")
	}
	var keys []TrustedKey
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&keys); err != nil {
		return nil, fmt.Errorf("parse trusted_verify_keys: %w", err)
	}
	seen := map[string]struct{}{}
	for i := range keys {
		k := &keys[i]
		if !validKeyID(k.KeyID) {
			return nil, fmt.Errorf("trusted key %d: invalid key_id", i)
		}
		if _, dup := seen[k.KeyID]; dup {
			return nil, fmt.Errorf("trusted key %q duplicated", k.KeyID)
		}
		seen[k.KeyID] = struct{}{}
		if k.Algorithm != SignatureAlgorithmEd25519 {
			return nil, fmt.Errorf("trusted key %q: %w", k.KeyID, ErrUnknownAlgorithm)
		}
		if k.Status != KeyStatusActive && k.Status != KeyStatusRevoked {
			return nil, fmt.Errorf("trusted key %q: invalid status %q", k.KeyID, k.Status)
		}
		pub, err := base64.StdEncoding.DecodeString(k.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("trusted key %q: invalid public key", k.KeyID)
		}
	}
	return keys, nil
}

// SignatureEnvelope 签名独立封装（导入请求携带；签名与 key_id 不塞进 manifest）。
type SignatureEnvelope struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"` // base64
}

// VerifyManifestSignature 按登记密钥核验 manifest 规范形字节签名。
// 拒绝顺序固定：未知算法 → 未登记/已撤销 key_id → 签名值非法 → 验签失败；
// keys 为调用方已解析快照（解析失败在更上层即明确失败）。
func VerifyManifestSignature(keys []TrustedKey, env SignatureEnvelope, manifestBytes []byte) error {
	if env.Algorithm != SignatureAlgorithmEd25519 {
		return fmt.Errorf("%w: %q", ErrUnknownAlgorithm, env.Algorithm)
	}
	if !validKeyID(env.KeyID) {
		return fmt.Errorf("%w: %q", ErrUnknownKeyID, env.KeyID)
	}
	var key *TrustedKey
	for i := range keys {
		if keys[i].KeyID == env.KeyID {
			key = &keys[i]
			break
		}
	}
	if key == nil {
		return fmt.Errorf("%w: %q", ErrUnknownKeyID, env.KeyID)
	}
	if key.Status != KeyStatusActive {
		return fmt.Errorf("%w: %q", ErrRevokedKey, env.KeyID)
	}
	pub, err := base64.StdEncoding.DecodeString(key.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("trusted key %q: invalid public key", key.KeyID)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: malformed signature value", ErrBadSignature)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), manifestBytes, sig) {
		return ErrBadSignature
	}
	return nil
}

// validKeyID key_id 词形（避免日志注入与路径类字符；长度上限与迁移一致）。
func validKeyID(s string) bool {
	if s == "" || len(s) > maxKeyIDLen {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}
