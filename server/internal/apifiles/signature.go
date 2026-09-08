// signature.go 文件签名（P2-02 验证面）：token 解析/复算校验、密钥加载与轮换。
//
// token 形态（网关嵌入方与本验证面同一口径）：
//
//	jzsig1.{kid}.{unixts}.{hmac_hex}
//	hmac_hex = hex(HMAC-SHA256(key, kid|filename|content_sha256_hex|unixts|identity_fp))
//
// 口径说明：
//   - payload 为 "|" 拼接：filename 含 "|" 会产生拼接歧义（v1 接受该限制，
//     与嵌入方共用同一拼装函数即可保持一致）；
//   - content_sha256_hex 一律小写参与复算（输入大小写不敏感，归一后校验）；
//   - identity_fp 为签名时绑定的身份指纹（匿名/未绑定为空串）：token 不携带
//     指纹明文，验证方以请求提供的 identity_fp（缺省空串）参与复算——复算通过
//     即证明绑定关系，无独立指纹旁路检查（v1 以 HMAC 有效性为主）。
//
// 密钥管理（参照 apiscan.LoadOrCreateSigner 模式，差异如实说明）：
//   - 密文落 system_settings gateway_runtime 组 api_file_signature_key，
//     kid 落同组 api_file_signature_kid（明文序号，v1 仅保留当前密钥——
//     轮换后旧 kid 的 token 一律验证不过，属预期收紧而非故障）；
//   - 与 LoadOrCreateSigner 不同：加载路径缺密钥不自动生成（验证面要求缺失
//     如实 503），密钥只能经轮换接口显式产生。
package apifiles

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SignatureTokenPrefix token 版本前缀（v1）。
const SignatureTokenPrefix = "jzsig1"

// 签名密钥/kid 在设置表的位置（gateway_runtime 组；密钥为加密后的 hex，kid 为明文序号）。
const (
	signatureSettingsGroup = "gateway_runtime"
	signatureKeySetting    = "api_file_signature_key"
	signatureKidSetting    = "api_file_signature_kid"
)

// 签名有效期设置（api_data 组，种子见迁移 000071）。
const (
	SettingsKeySignatureMaxAgeDays = "file_signature_max_age_days"
	// DefaultSignatureMaxAgeDays 默认有效期（天；与迁移种子一致）。
	DefaultSignatureMaxAgeDays = 30
)

const (
	signatureKeyBytes    = 32              // 密钥长度（HMAC-SHA256 32 字节）
	signatureFutureSkew  = 5 * time.Minute // 未来时间戳容忍钟差
	signatureKidMaxLen   = 32
	signatureTokenMaxLen = 512
	signatureHashHexLen  = 64 // sha256 hex 长度
	// identityFPPrefixLen 验证通过后回显的身份指纹前缀长度（软提示）。
	identityFPPrefixLen = 8
)

// ErrSignatureKeyNotConfigured 签名密钥未配置（验证面如实 503；经轮换接口生成）。
var ErrSignatureKeyNotConfigured = errors.New("文件签名密钥未配置")

// ErrSignatureKeyInvalid 签名密钥材料非法（密文解密/hex/长度任一不符）。
var ErrSignatureKeyInvalid = errors.New("文件签名密钥材料非法")

// SignatureSettingsKV 设置读写接口（*settings.Service 满足；密钥密文落系统设置）。
type SignatureSettingsKV interface {
	GetString(ctx context.Context, group, key, def string) string
	GetInt(ctx context.Context, group, key string, def int) int
	UpsertString(ctx context.Context, group, key, value, description string, operatorID uuid.UUID) error
}

// SignatureEncryptor 加解密接口（*encryption.Service 满足；密钥密文不落明文）。
type SignatureEncryptor interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(encoded string) (string, error)
}

// fileSignatureHMAC 复算签名（kid|filename|content_sha256_hex|unixts|identity_fp 拼接）。
func fileSignatureHMAC(key []byte, kid, filename, contentSHA256Hex string, unixTS int64, identityFP string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(strings.Join([]string{
		kid, filename, contentSHA256Hex, strconv.FormatInt(unixTS, 10), identityFP,
	}, "|")))
	return mac.Sum(nil)
}

// SignFileToken 计算文件签名 token（参考实现：供单测构造真实签名串，
// 亦供网关嵌入方对齐口径）。key 须 32 字节；contentSHA256Hex 须小写。
func SignFileToken(key []byte, kid, filename, contentSHA256Hex string, unixTS int64, identityFP string) string {
	sum := fileSignatureHMAC(key, kid, filename, contentSHA256Hex, unixTS, identityFP)
	return strings.Join([]string{
		SignatureTokenPrefix, kid, strconv.FormatInt(unixTS, 10), hex.EncodeToString(sum),
	}, ".")
}

// signatureToken 解析后的 token 三段有效负载。
type signatureToken struct {
	Kid    string
	UnixTS int64
	Sig    []byte
}

// parseSignatureToken 解析 token（严格 "前缀.kid.unixts.hmac_hex" 四段）。
func parseSignatureToken(token string) (*signatureToken, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != SignatureTokenPrefix {
		return nil, fmt.Errorf("token 形态非法（须为 %s.{kid}.{unixts}.{hmac_hex}）", SignatureTokenPrefix)
	}
	kid := parts[1]
	if kid == "" || len(kid) > signatureKidMaxLen {
		return nil, fmt.Errorf("kid 非法")
	}
	unixTS, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || unixTS <= 0 {
		return nil, fmt.Errorf("签名时间戳非法")
	}
	if len(parts[3]) != signatureHashHexLen {
		return nil, fmt.Errorf("签名段长度非法")
	}
	sig, err := hex.DecodeString(parts[3])
	if err != nil {
		return nil, fmt.Errorf("签名段非 hex")
	}
	return &signatureToken{Kid: kid, UnixTS: unixTS, Sig: sig}, nil
}

// LoadFileSignatureKey 从设置表加载签名密钥与当前 kid（密文经 enc 解密）。
// 未配置返回 ErrSignatureKeyNotConfigured（验证面映射 503）；材料非法如实报错。
func LoadFileSignatureKey(ctx context.Context, kv SignatureSettingsKV, enc SignatureEncryptor) (key []byte, kid string, err error) {
	if kv == nil || enc == nil {
		return nil, "", errors.New("apifiles: settings/encryption 未装配，无法加载文件签名密钥")
	}
	raw := strings.TrimSpace(kv.GetString(ctx, signatureSettingsGroup, signatureKeySetting, ""))
	if raw == "" {
		return nil, "", ErrSignatureKeyNotConfigured
	}
	plain, err := enc.Decrypt(raw)
	if err != nil {
		return nil, "", fmt.Errorf("%w：解密失败: %v", ErrSignatureKeyInvalid, err)
	}
	key, err = hex.DecodeString(plain)
	if err != nil || len(key) != signatureKeyBytes {
		return nil, "", fmt.Errorf("%w：hex 或长度不符", ErrSignatureKeyInvalid)
	}
	kid = strings.TrimSpace(kv.GetString(ctx, signatureSettingsGroup, signatureKidSetting, ""))
	if kid == "" {
		return nil, "", fmt.Errorf("%w：密钥存在但 kid 缺失（状态不一致，请重新轮换）", ErrSignatureKeyInvalid)
	}
	return key, kid, nil
}

// RotateFileSignatureKey 生成新密钥并加密落库，kid 递增（首次从 "1" 开始）。
// 写序 key 后 kid：任一步失败都失败关闭（kid 与密钥错配即全部验证不过），
// 不产生半通过中间态；旧 kid 的 token 自轮换起失效（v1 仅保留当前密钥）。
func RotateFileSignatureKey(ctx context.Context, kv SignatureSettingsKV, enc SignatureEncryptor, operatorID uuid.UUID) (string, error) {
	if kv == nil || enc == nil {
		return "", errors.New("apifiles: settings/encryption 未装配，无法轮换文件签名密钥")
	}
	next := 1
	if cur := strings.TrimSpace(kv.GetString(ctx, signatureSettingsGroup, signatureKidSetting, "")); cur != "" {
		n, err := strconv.Atoi(cur)
		if err != nil || n < 1 {
			return "", fmt.Errorf("apifiles: 当前 kid %q 非法（须为正整数序号），请检查设置表", cur)
		}
		next = n + 1
	}
	key := make([]byte, signatureKeyBytes)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	cipherText, err := enc.Encrypt(hex.EncodeToString(key))
	if err != nil {
		return "", fmt.Errorf("apifiles: 加密文件签名密钥失败: %w", err)
	}
	if err := kv.UpsertString(ctx, signatureSettingsGroup, signatureKeySetting, cipherText,
		"API 文件下载签名密钥（HMAC，密文存储；经 file-signature/key/rotate 轮换）", operatorID); err != nil {
		return "", fmt.Errorf("apifiles: 落库文件签名密钥失败: %w", err)
	}
	kid := strconv.Itoa(next)
	if err := kv.UpsertString(ctx, signatureSettingsGroup, signatureKidSetting, kid,
		"API 文件下载签名密钥 ID（随轮换递增；v1 仅保留当前密钥）", operatorID); err != nil {
		return "", fmt.Errorf("apifiles: 落库文件签名 kid 失败: %w", err)
	}
	return kid, nil
}

// VerifyResult 签名验证结论（reason 为空 = 验证通过）。
type VerifyResult struct {
	Valid            bool   `json:"valid"`
	Kid              string `json:"kid,omitempty"`
	SignedAt         string `json:"signed_at,omitempty"`
	IdentityFPPrefix string `json:"identity_fp_prefix,omitempty"`
	Reason           string `json:"reason,omitempty"`
}

// VerifyFileToken 用当前密钥复算校验（纯函数，可单测）。
// valid = HMAC 一致 && kid 与当前密钥匹配 && 时间戳未过期 && 非未来时间（容忍钟差）。
// identity_fp 前缀软提示说明：复算使用的 identity_fp 由请求提供（缺省空串），
// HMAC 一致即证明 token 与该指纹绑定——这里仅在通过时回显其前缀作展示提示，
// 不做独立"比对"旁路（口径不一致的唯一后果是 HMAC 不通过，不另设误判源）。
func VerifyFileToken(key []byte, currentKid, filename, contentSHA256Hex, token, identityFP string, maxAgeDays int, now time.Time) VerifyResult {
	tok, err := parseSignatureToken(token)
	if err != nil {
		return VerifyResult{Valid: false, Reason: "token 格式非法：" + err.Error()}
	}
	signedAt := time.Unix(tok.UnixTS, 0).UTC()
	res := VerifyResult{Kid: tok.Kid, SignedAt: signedAt.Format(time.RFC3339)}
	if tok.Kid != currentKid {
		res.Reason = "kid 与当前密钥不匹配（密钥已轮换或 token 非本系统签发；v1 仅保留当前密钥）"
		return res
	}
	if !hmac.Equal(tok.Sig, fileSignatureHMAC(key, tok.Kid, filename, contentSHA256Hex, tok.UnixTS, identityFP)) {
		res.Reason = "签名不匹配（文件名/内容哈希/身份指纹与签名时不一致或 token 伪造）"
		return res
	}
	if signedAt.After(now.Add(signatureFutureSkew)) {
		res.Reason = "签名时间戳来自未来（超出钟差容忍）"
		return res
	}
	if maxAgeDays <= 0 {
		maxAgeDays = DefaultSignatureMaxAgeDays // 非法取值回退默认（不误放开）
	}
	if now.Sub(signedAt) > time.Duration(maxAgeDays)*24*time.Hour {
		res.Reason = fmt.Sprintf("签名已过期（签署于 %s，超过有效期 %d 天）",
			signedAt.Format(time.RFC3339), maxAgeDays)
		return res
	}
	res.Valid = true
	if identityFP != "" {
		prefix := identityFP
		if len(prefix) > identityFPPrefixLen {
			prefix = prefix[:identityFPPrefixLen]
		}
		res.IdentityFPPrefix = prefix
	}
	return res
}
