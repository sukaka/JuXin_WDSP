// Package license 产品侧离线授权（.lic）解析、验签、机器指纹校验、状态机与 HTTP 接口。
//
// 授权文件由授权中心（独立仓库）Ed25519 离线签发，外层结构：
//
//	{"payload": {...}, "signature": "<hex ed25519 sig>"}
//
// 签名输入 = payload map 的 Go json.Marshal 规范字节（encoding/json 对 map 键按
// 字典序紧凑序列化）。本包验签时把 payload RawMessage decode 成
// map[string]interface{} 再 json.Marshal 重构字节，与签发侧逐字节一致方可通过。
// 未配置任何验签公钥时所有授权验签失败（fail-closed，不做占位绕过）。
package license

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"
)

// 授权类型词表（license_type；缺省按正式授权处理，与签发侧口径一致）。
const (
	TypeFormal = "FORMAL"
	TypeTrial  = "TRIAL"
)

// 授权状态词表（licenses.status）。
const (
	StatusActive              = "ACTIVE"               // 生效中（全表至多一行，部分唯一索引保证）
	StatusExpired             = "EXPIRED"              // 已到期（终态）
	StatusFingerprintMismatch = "FINGERPRINT_MISMATCH" // 机器指纹不匹配（材料恢复可翻回 ACTIVE）
	StatusSuperseded          = "SUPERSEDED"           // 被新导入授权取代（终态）
	StatusInvalid             = "INVALID"              // 落库数据复核不通过（终态，理论不应发生）
)

// 授权错误类别（哨兵消息为中文，包装后可安全返回客户端；handler 按 errors.Is 映射状态码）。
var (
	// ErrMalformed 授权文件解析/字段校验失败（HTTP 400）。
	ErrMalformed = errors.New("授权文件格式错误")
	// ErrSignature 验签失败：签名不匹配、未知 key_id 或未配置验签公钥（HTTP 422，fail-closed）。
	ErrSignature = errors.New("授权文件签名校验失败")
	// ErrFingerprintMismatch 授权绑定指纹与本机不一致（含宿主机无指纹材料）（HTTP 409）。
	ErrFingerprintMismatch = errors.New("授权与本机指纹不匹配")
	// ErrDuplicate 同一 license_id 重复导入（HTTP 409）。
	ErrDuplicate = errors.New("该授权已导入")
	// ErrProductBound 授权产品形态与首次导入绑定不一致（HTTP 409）；
	// 产品形态首导永久绑定，切换必须重新安装部署（见 docs/LICENSE_DESIGN.md 增补小节）。
	ErrProductBound = errors.New("授权产品形态与本系统绑定不一致")
	// ErrNoEffective 无生效授权行（仓储查询）。
	ErrNoEffective = errors.New("无生效授权")
	// ErrEncryptionUnavailable 授权原文无法加密保存；签名原文是授权事实源，不能降级为仅数据库字段。
	ErrEncryptionUnavailable = errors.New("授权原文加密服务不可用")
)

// Quotas 授权配额（0 = 不限制；与签发侧 quotas 三键口径一致）。
type Quotas struct {
	MaxApplications int64 `json:"max_applications"`
	MaxAPIEndpoints int64 `json:"max_api_endpoints"`
	MaxQPS          int64 `json:"max_qps"`
}

// Payload 授权 payload 校验后的结构化视图。
type Payload struct {
	LicenseID          string
	LicenseType        string
	Product            string
	Customer           string
	IssuedAt           string     // RFC3339 原文（签发时间，仅展示）
	ExpiresAt          *time.Time // 到期日 00:00 UTC；到期判定含当天 23:59:59 UTC
	Perpetual          bool
	MachineFingerprint string // '' = 未绑定机器指纹
	Quotas             Quotas
	Features           []string
	Version            int64
	KeyID              string
	Raw                json.RawMessage // payload 原文（落库留存）
}

// File .lic 外层结构（payload 原文 + hex 签名）。
type File struct {
	Payload   json.RawMessage
	Signature string
}

// ParseFile 解析 .lic 外层 JSON。多余字段忽略（向前兼容），
// payload/signature 缺失或外层非合法 JSON 判 ErrMalformed。
func ParseFile(data []byte) (*File, error) {
	var f struct {
		Payload   json.RawMessage `json:"payload"`
		Signature string          `json:"signature"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("%w：外层须为合法 JSON", ErrMalformed)
	}
	if len(f.Payload) == 0 {
		return nil, fmt.Errorf("%w：缺少 payload 字段", ErrMalformed)
	}
	if strings.TrimSpace(f.Signature) == "" {
		return nil, fmt.Errorf("%w：缺少 signature 字段", ErrMalformed)
	}
	return &File{Payload: f.Payload, Signature: strings.TrimSpace(f.Signature)}, nil
}

// canonicalPayload 重构签名规范字节：RawMessage → map[string]interface{} → json.Marshal。
// 与签发侧 canonicalJSON 同一规则（map 键字典序、无空白、HTML 转义一致），
// 对 PG jsonb 规范化/键序扰动免疫；整数数值经 float64 往返保持字面不变。
func canonicalPayload(raw json.RawMessage) ([]byte, map[string]interface{}, error) {
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, nil, err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return nil, nil, err
	}
	return b, m, nil
}

// Verify 按 payload.key_id 从公钥表选 Ed25519 公钥验签，返回 decode 后的 payload map。
// 无可用公钥 / 未知 key_id / 签名不匹配一律 ErrSignature（fail-closed）；
// 文件结构问题（payload 非对象、签名非 hex、缺 key_id）判 ErrMalformed。
func Verify(raw json.RawMessage, signature string, keys map[string]ed25519.PublicKey) (map[string]interface{}, error) {
	canonical, m, err := canonicalPayload(raw)
	if err != nil {
		return nil, fmt.Errorf("%w：payload 须为 JSON 对象", ErrMalformed)
	}
	sigBytes, err := hex.DecodeString(signature)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return nil, fmt.Errorf("%w：signature 须为 Ed25519 签名 hex 编码", ErrMalformed)
	}
	keyID, _ := m["key_id"].(string)
	if keyID == "" {
		return nil, fmt.Errorf("%w：payload 缺少 key_id", ErrMalformed)
	}
	if len(keys) == 0 {
		// 未配置任何验签公钥：全部失败（严禁任何占位/测试密钥绕过）
		return nil, ErrSignature
	}
	pub, ok := keys[keyID]
	if !ok {
		return nil, fmt.Errorf("%w：未知签名密钥", ErrSignature)
	}
	if !ed25519.Verify(pub, canonical, sigBytes) {
		return nil, ErrSignature
	}
	return m, nil
}

// ParsePayload 字段校验并把 payload map 结构化。
// 口径：product ∈ {waf,wdsp,api}；license_type ∈ {FORMAL,TRIAL} 缺省 FORMAL；
// quotas 三键非负整数缺省 0；expires_at 为 YYYY-MM-DD 或 null；perpetual 为 bool。
// 非永久授权必须携带 expires_at（fail-closed：无到期日的非永久授权视同非法）。
func ParsePayload(m map[string]interface{}) (*Payload, error) {
	p := &Payload{Features: []string{}}
	var err error
	if p.LicenseID, err = requiredString(m, "license_id"); err != nil {
		return nil, err
	}
	if p.Product, err = requiredString(m, "product"); err != nil {
		return nil, err
	}
	switch p.Product {
	case "waf", "wdsp", "api":
	default:
		return nil, fmt.Errorf("%w：product 取值非法（支持 waf/wdsp/api）", ErrMalformed)
	}
	if p.KeyID, err = requiredString(m, "key_id"); err != nil {
		return nil, err
	}
	if p.Customer, err = optionalString(m, "customer"); err != nil {
		return nil, err
	}
	if p.LicenseType, err = optionalString(m, "license_type"); err != nil {
		return nil, err
	}
	if p.LicenseType == "" {
		p.LicenseType = TypeFormal
	}
	if p.LicenseType != TypeFormal && p.LicenseType != TypeTrial {
		return nil, fmt.Errorf("%w：license_type 取值非法（支持 FORMAL/TRIAL）", ErrMalformed)
	}
	if p.IssuedAt, err = optionalString(m, "issued_at"); err != nil {
		return nil, err
	}
	if p.IssuedAt != "" {
		if _, err := time.Parse(time.RFC3339, p.IssuedAt); err != nil {
			return nil, fmt.Errorf("%w：issued_at 须为 RFC3339 时间", ErrMalformed)
		}
	}
	if v, ok := m["perpetual"]; ok && v != nil {
		b, ok := v.(bool)
		if !ok {
			return nil, fmt.Errorf("%w：perpetual 须为布尔值", ErrMalformed)
		}
		p.Perpetual = b
	}
	if v, ok := m["version"]; ok && v != nil {
		n, err := nonNegInt(v, "version")
		if err != nil {
			return nil, err
		}
		p.Version = n
	}
	if err := parseExpiresAt(m, p); err != nil {
		return nil, err
	}
	if v, ok := m["machine_fingerprint"]; ok && v != nil {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%w：machine_fingerprint 须为字符串或 null", ErrMalformed)
		}
		p.MachineFingerprint = s
	}
	if err := parseQuotas(m, p); err != nil {
		return nil, err
	}
	if err := parseFeatures(m, p); err != nil {
		return nil, err
	}
	return p, nil
}

// parseExpiresAt 解析 expires_at（YYYY-MM-DD 或 null；非永久授权必填）。
func parseExpiresAt(m map[string]interface{}, p *Payload) error {
	v, ok := m["expires_at"]
	if !ok || v == nil {
		if !p.Perpetual {
			return fmt.Errorf("%w：非永久授权缺少 expires_at", ErrMalformed)
		}
		return nil
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Errorf("%w：expires_at 须为 YYYY-MM-DD 字符串或 null", ErrMalformed)
	}
	d, err := time.Parse("2006-01-02", s)
	if err != nil {
		return fmt.Errorf("%w：expires_at 格式须为 YYYY-MM-DD", ErrMalformed)
	}
	p.ExpiresAt = &d
	return nil
}

// parseQuotas 解析 quotas（对象；三键缺省 0，值须为非负整数；未知键忽略向前兼容）。
func parseQuotas(m map[string]interface{}, p *Payload) error {
	v, ok := m["quotas"]
	if !ok || v == nil {
		return nil
	}
	qm, ok := v.(map[string]interface{})
	if !ok {
		return fmt.Errorf("%w：quotas 须为对象", ErrMalformed)
	}
	keys := []struct {
		name string
		dst  *int64
	}{
		{"max_applications", &p.Quotas.MaxApplications},
		{"max_api_endpoints", &p.Quotas.MaxAPIEndpoints},
		{"max_qps", &p.Quotas.MaxQPS},
	}
	for _, k := range keys {
		vv, ok := qm[k.name]
		if !ok || vv == nil {
			continue
		}
		n, err := nonNegInt(vv, "quotas."+k.name)
		if err != nil {
			return err
		}
		*k.dst = n
	}
	return nil
}

// parseFeatures 解析 features（字符串数组；缺省空数组）。
func parseFeatures(m map[string]interface{}, p *Payload) error {
	v, ok := m["features"]
	if !ok || v == nil {
		return nil
	}
	arr, ok := v.([]interface{})
	if !ok {
		return fmt.Errorf("%w：features 须为字符串数组", ErrMalformed)
	}
	for _, item := range arr {
		s, ok := item.(string)
		if !ok {
			return fmt.Errorf("%w：features 元素须为字符串", ErrMalformed)
		}
		p.Features = append(p.Features, s)
	}
	return nil
}

// requiredString 读取必填非空字符串字段。
func requiredString(m map[string]interface{}, key string) (string, error) {
	v, ok := m[key]
	if !ok || v == nil {
		return "", fmt.Errorf("%w：缺少 %s 字段", ErrMalformed, key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%w：%s 须为字符串", ErrMalformed, key)
	}
	if strings.TrimSpace(s) == "" {
		return "", fmt.Errorf("%w：%s 不能为空", ErrMalformed, key)
	}
	return s, nil
}

// optionalString 读取可选字符串字段（缺失/null → ""；存在则须为字符串）。
func optionalString(m map[string]interface{}, key string) (string, error) {
	v, ok := m[key]
	if !ok || v == nil {
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%w：%s 须为字符串", ErrMalformed, key)
	}
	return s, nil
}

// nonNegInt 读取非负整数数值字段（JSON number 经 float64 往返，须为整值）。
func nonNegInt(v interface{}, name string) (int64, error) {
	f, ok := v.(float64)
	if !ok || f < 0 || f != math.Trunc(f) {
		return 0, fmt.Errorf("%w：%s 须为非负整数", ErrMalformed, name)
	}
	return int64(f), nil
}

// Expired 到期判定：perpetual 永不过期；expires_at 按日期含当天 23:59:59 UTC。
func (p *Payload) Expired(now time.Time) bool {
	if p.Perpetual || p.ExpiresAt == nil {
		return false
	}
	return now.UTC().After(endOfDayUTC(*p.ExpiresAt))
}

// endOfDayUTC 到期日 23:59:59 UTC（含当天口径）。
func endOfDayUTC(d time.Time) time.Time {
	y, m, day := d.UTC().Date()
	return time.Date(y, m, day, 23, 59, 59, 0, time.UTC)
}

// CheckFingerprint 机器指纹校验：未绑定（MachineFingerprint 为空）跳过；
// 绑定时须与宿主机指纹精确一致；宿主机无指纹材料（hostFP 为空）一律判不匹配
// （如实报错，不做任何绕过）。
func (p *Payload) CheckFingerprint(hostFP string) error {
	if p.MachineFingerprint == "" {
		return nil
	}
	if hostFP == "" {
		return fmt.Errorf("%w：宿主机指纹材料缺失", ErrFingerprintMismatch)
	}
	if subtle.ConstantTimeCompare([]byte(p.MachineFingerprint), []byte(hostFP)) != 1 {
		return fmt.Errorf("%w：授权绑定指纹与本机不一致", ErrFingerprintMismatch)
	}
	return nil
}
