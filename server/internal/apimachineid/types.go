// Package apimachineid 机器身份登记管理面（NG-ID g1 批次 B1，设计
// docs/nextgen/NG-ID-g1-machine-identity.md §1.2/§1.3/§1.6/§1.12）：
// 身份（机器主体登记）+公钥（管理面静态离线导入，PEM 解析校验算法词表与密钥形态）
// +轮换/撤销状态机（rotate 原子=新 ACTIVE+旧 RETIRED+重叠窗口；revoke 与水位 seq+1
// 同一事务原子提交）+per-app 绑定（selector×mode×proof_required，绑定不引用身份——
// 登记册全局生效）。权限复用 jwt_trust.read/manage（可信密钥管理同域，
// app.go:1045-1047 实证已注册，零新增权限点）；写操作 HIGH 审计。
package apimachineid

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 词表（设计冻结）。
const (
	StatusEnabled  = "ENABLED"
	StatusDisabled = "DISABLED"

	KeyStatusActive  = "ACTIVE"
	KeyStatusRetired = "RETIRED"
	KeyStatusRevoked = "REVOKED"

	ModeObserve = "OBSERVE"
	ModeProtect = "PROTECT"

	// 算法词表（§1.2 CHECK 冻结；hmac-sha256 共享密钥形态排除（机器身份只要非对称），
	// rsa-v1_5-sha256 排除（RFC 9421 标注不推荐））。
	AlgEd25519      = "ed25519"
	AlgECDSAP256    = "ecdsa-p256-sha256"
	AlgRSAPSSSHA512 = "rsa-pss-sha512"

	// 轮换重叠窗口（§1.6：缺省 24h，上限 168h——审批面显式）。
	RotateOverlapDefaultHours = 24
	RotateOverlapMaxHours     = 168

	maxNameLen          = 128
	maxTenantLen        = 128
	maxPrincipalBindLen = 128
	maxKidLen           = 128
	maxSelectorPathLen  = 512 // jwt selector 同形（jwttrust.MaxSelectorPathLen）
	maxPEMBytes         = 8192
)

// 哨兵错误（handler 映射 400/404/409 精确区分）。
var (
	ErrNotFound         = errors.New("machine identity not found")
	ErrDuplicateName    = errors.New("machine identity name already exists")
	ErrIdentityInUse    = errors.New("machine identity is in use（存在机器身份绑定，先解绑再删除身份）")
	ErrKeyNotFound      = errors.New("machine identity key not found")
	ErrKeyDuplicate     = errors.New("machine identity key kid already exists（身份内唯一）")
	ErrKeyStateConflict = errors.New("machine identity key state conflict（仅 ACTIVE 键可轮换；已 REVOKED 键不可重复撤销）")
	ErrBindingNotFound  = errors.New("machine identity binding not found")
	ErrBindingDuplicate = errors.New("machine identity binding already exists for (application, path)")
	ErrAppNotFound      = errors.New("referenced application not found")
	ErrVersionConflict  = errors.New("machine identity version conflict（乐观锁不匹配，请刷新后重试）")
)

// ValidationError 载荷校验错误（400；与存储错误显式区分——apimcp 同形态）。
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func invalidf(format string, args ...any) error {
	return &ValidationError{Msg: fmt.Sprintf(format, args...)}
}

// ---------- 身份 ----------

// IdentityInput 身份写入载荷（POST 创建 / PUT 更新；version 仅 PUT 乐观锁）。
type IdentityInput struct {
	IdentityName       string  `json:"identity_name"`
	TenantID           *string `json:"tenant_id"`         // 可空（跨租户共享身份为 null+显式）
	PrincipalBinding   *string `json:"principal_binding"` // 可空（绑定 JWT VerifiedPrincipalID 指纹值）
	Status             string  `json:"status"`            // ENABLED（缺省）|DISABLED
	BotChallengeExempt bool    `json:"bot_challenge_exempt"`
	Version            int     `json:"version"`
}

// Identity 身份行（读模型）。
type Identity struct {
	ID                 uuid.UUID `json:"id"`
	IdentityName       string    `json:"identity_name"`
	TenantID           *string   `json:"tenant_id"`
	PrincipalBinding   *string   `json:"principal_binding"`
	Status             string    `json:"status"`
	BotChallengeExempt bool      `json:"bot_challenge_exempt"`
	Version            int       `json:"version"`
	CreatedBy          string    `json:"created_by"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// IdentitySummary 身份列表行（含键状态摘要；revocation_watermark 随列表响应带出）。
type IdentitySummary struct {
	Identity
	KeyCount    int `json:"key_count"`
	ActiveKeys  int `json:"active_keys"`
	RetiredKeys int `json:"retired_keys"`
	RevokedKeys int `json:"revoked_keys"`
}

// ValidateIdentityInput 身份载荷校验（词表/长度）。
func ValidateIdentityInput(in IdentityInput) string {
	name := strings.TrimSpace(in.IdentityName)
	if name == "" || len(name) > maxNameLen {
		return fmt.Sprintf("identity_name 必填且不超过 %d 字符", maxNameLen)
	}
	if in.TenantID != nil && len(strings.TrimSpace(*in.TenantID)) > maxTenantLen {
		return fmt.Sprintf("tenant_id 不超过 %d 字符", maxTenantLen)
	}
	if in.PrincipalBinding != nil && len(strings.TrimSpace(*in.PrincipalBinding)) > maxPrincipalBindLen {
		return fmt.Sprintf("principal_binding 不超过 %d 字符", maxPrincipalBindLen)
	}
	switch strings.ToUpper(strings.TrimSpace(in.Status)) {
	case "", StatusEnabled, StatusDisabled:
	default:
		return "status 词表外（ENABLED|DISABLED，缺省 ENABLED）"
	}
	return ""
}

// ---------- 公钥 ----------

// KeyInput 公钥导入载荷（POST keys / rotate 共用——rotate 时为本载荷替换 {keyId} 旧键）。
type KeyInput struct {
	Kid          string `json:"kid"`
	Alg          string `json:"alg"`
	PublicKeyPEM string `json:"public_key_pem"`
	NotBefore    string `json:"not_before"` // RFC3339，可空
	NotAfter     string `json:"not_after"`  // RFC3339，可空
	// OverlapHours 仅 rotate 消费：重叠窗口小时数（缺省 24，上限 168——窗口内新旧键
	// 均可验证，窗口外旧键 MID-KEY-RETIRED-EXPIRED 拒验，§1.6）。
	OverlapHours *int `json:"overlap_hours"`
}

// Key 公钥行（读模型；key_fingerprint=公钥指纹 sha256 前 16 hex 现算——管理面与事件的
// 稳定引用，不落完整公钥进事件（§1.3）；指纹不落库（四表冻结无指纹列））。
type Key struct {
	ID                 uuid.UUID  `json:"id"`
	IdentityID         uuid.UUID  `json:"identity_id"`
	Kid                string     `json:"kid"`
	Alg                string     `json:"alg"`
	PublicKeyPEM       string     `json:"public_key_pem"`
	KeyFingerprint     string     `json:"key_fingerprint"`
	Status             string     `json:"status"`
	NotBefore          *time.Time `json:"not_before"`
	NotAfter           *time.Time `json:"not_after"`
	RetireOverlapUntil *time.Time `json:"retire_overlap_until"`
	RevokedSeq         *int64     `json:"revoked_seq"`
	CreatedBy          string     `json:"created_by"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

// ValidateKeyInput 公钥载荷校验（kid/词表/PEM 形态与有效期——密码学解析在 ParsePublicKey）。
func ValidateKeyInput(in KeyInput) string {
	if strings.TrimSpace(in.Kid) == "" || len(strings.TrimSpace(in.Kid)) > maxKidLen {
		return fmt.Sprintf("kid 必填且不超过 %d 字符", maxKidLen)
	}
	switch strings.TrimSpace(in.Alg) {
	case AlgEd25519, AlgECDSAP256, AlgRSAPSSSHA512:
	default:
		return "alg 词表外（ed25519|ecdsa-p256-sha256|rsa-pss-sha512）"
	}
	pemText := strings.TrimSpace(in.PublicKeyPEM)
	if pemText == "" || len(pemText) > maxPEMBytes {
		return fmt.Sprintf("public_key_pem 必填且不超过 %d 字节", maxPEMBytes)
	}
	nb, err := parseRFC3339Ptr(in.NotBefore)
	if err != nil {
		return "not_before 须为 RFC3339 时间"
	}
	na, err := parseRFC3339Ptr(in.NotAfter)
	if err != nil {
		return "not_after 须为 RFC3339 时间"
	}
	if nb != nil && na != nil && !nb.Before(*na) {
		return "not_before 必须早于 not_after"
	}
	if in.OverlapHours != nil && (*in.OverlapHours <= 0 || *in.OverlapHours > RotateOverlapMaxHours) {
		return fmt.Sprintf("overlap_hours 须在 1..%d 小时（缺省 %d）", RotateOverlapMaxHours, RotateOverlapDefaultHours)
	}
	return ""
}

// parseRFC3339Ptr 可空 RFC3339 解析（空串=nil）。
func parseRFC3339Ptr(v string) (*time.Time, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// ParsePublicKey PEM 解析校验（§1.3 导入纪律：管理面解析校验算法词表与密钥形态——
// 声明 alg 与 PEM 实际键型一致性核对，不符拒收）。接受 PKIX（PUBLIC KEY）与
// PKCS1（RSA PUBLIC KEY）块；返回规范化 PEM（原样 trim）与指纹（sha256 前 16 hex）。
func ParsePublicKey(alg, pemText string) (normalizedPEM string, fingerprint string, err error) {
	pemText = strings.TrimSpace(pemText)
	block, rest := pem.Decode([]byte(pemText))
	if block == nil {
		return "", "", invalidf("public_key_pem 非合法 PEM 块")
	}
	if len(strings.TrimSpace(string(rest))) > 0 {
		return "", "", invalidf("public_key_pem 含 PEM 块以外内容（恰一个公钥块）")
	}
	var pub any
	switch block.Type {
	case "PUBLIC KEY":
		pub, err = x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		pub, err = x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return "", "", invalidf("public_key_pem PEM 块类型拒收（%q；须 PUBLIC KEY 或 RSA PUBLIC KEY）", block.Type)
	}
	if err != nil {
		return "", "", invalidf("public_key_pem 解析失败: %v", err)
	}
	actual := ""
	switch k := pub.(type) {
	case ed25519.PublicKey:
		actual = AlgEd25519
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() {
			actual = AlgECDSAP256
		} else {
			return "", "", invalidf("ecdsa 公钥曲线拒收（仅 P-256，词表 ecdsa-p256-sha256）")
		}
	case *rsa.PublicKey:
		actual = AlgRSAPSSSHA512
	default:
		return "", "", invalidf("public_key_pem 键型拒收（%T；仅 ed25519/ecdsa-p256/rsa）", pub)
	}
	if actual != strings.TrimSpace(alg) {
		return "", "", invalidf("alg 声明 %q 与 PEM 实际键型 %q 不一致（§1.3 一致性核对）", alg, actual)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", "", invalidf("public_key_pem 规范化失败: %v", err)
	}
	sum := sha256.Sum256(der)
	return pemText, hex.EncodeToString(sum[:])[:16], nil
}

// ---------- 绑定 ----------

// BindingInput 绑定写入载荷。
type BindingInput struct {
	ApplicationID string `json:"application_id"`
	PathExact     string `json:"path_exact"`
	PathPrefix    string `json:"path_prefix"`
	Mode          string `json:"mode"`
	ProofRequired bool   `json:"proof_required"`
	Version       int    `json:"version"`
}

// Binding 绑定行（读模型）。
type Binding struct {
	ID            uuid.UUID `json:"id"`
	ApplicationID uuid.UUID `json:"application_id"`
	PathExact     string    `json:"path_exact"`
	PathPrefix    string    `json:"path_prefix"`
	Mode          string    `json:"mode"`
	ProofRequired bool      `json:"proof_required"`
	Version       int       `json:"version"`
	CreatedBy     string    `json:"created_by"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// ValidateBindingInput 绑定载荷校验（jwt selector 同形：path_exact|path_prefix 二选一、
// / 开头、≤512、不含 query/fragment/控制字符、prefix 不以 / 结尾（根 / 除外））。
func ValidateBindingInput(in BindingInput) string {
	if _, err := uuid.Parse(strings.TrimSpace(in.ApplicationID)); err != nil {
		return "application_id 非法（UUID）"
	}
	exact := strings.TrimSpace(in.PathExact)
	prefix := strings.TrimSpace(in.PathPrefix)
	if (exact == "") == (prefix == "") {
		return "path_exact 与 path_prefix 必须且仅须提供一个（jwt selector 同形）"
	}
	path, field := exact, "path_exact"
	if prefix != "" {
		path, field = prefix, "path_prefix"
	}
	if !strings.HasPrefix(path, "/") {
		return field + " 必须以 / 开头"
	}
	if len(path) > maxSelectorPathLen {
		return fmt.Sprintf("%s 长度不能超过 %d", field, maxSelectorPathLen)
	}
	if strings.ContainsAny(path, "?#") {
		return field + " 不得包含 query 或 fragment"
	}
	for _, c := range path {
		if c < 0x20 || c == 0x7f {
			return field + " 不得包含控制字符"
		}
	}
	if prefix != "" && strings.HasSuffix(prefix, "/") && prefix != "/" {
		return "path_prefix 须按完整路径段给出，不应以 / 结尾"
	}
	switch strings.ToUpper(strings.TrimSpace(in.Mode)) {
	case "", ModeObserve, ModeProtect:
	default:
		return "mode 非法（OBSERVE|PROTECT，缺省 OBSERVE）"
	}
	return ""
}
