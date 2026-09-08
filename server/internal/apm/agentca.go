// agentca.go APM Agent 控制面内置 CA 与证书签发（阶段2 上半；
// 设计 docs/BUSINESS_PERFORMANCE_APM_DESIGN.md §9.1/§12.3）。
//
// 密钥与证书纪律：
//   - CA 为 Ed25519 自签名根（与 license 包验签体系同算法族，纯标准库实现）；
//   - CA 私钥永不落明文：{private_key_hex, cert_pem} JSON 经 encryption.Service
//     （JIUZHANG_MASTER_KEY 体系）加密后存 system_settings（apm_agent.ca_material），
//     加载/生成手法与 apiscan.LoadOrCreateSigner 一致；
//   - Agent 客户端证书由 CSR 签发（CSR 自签名验证即持有证明），短有效期
//     （默认 72h，合法区间 24h~7d，见 AgentControlConfig 夹紧）；
//   - 证书身份 = SHA-256(cert.Raw) hex 指纹：控制面认证按指纹反查登记行
//     （指纹命中即证明由本 CA 签发），撤销按指纹列表（apm_agent_cert_revocations）。
//
// 说明：管理 API 在既有交付形态中经 Web 反向代理以 HTTP 暴露，TLS 客户端证书无法
// 穿透到本进程；故 Agent 面控制面接口采用「CA 签发证书 + 应用层持有证明（PoP）
// 签名头」的等价认证（VerifyPoP），TLS 层 mTLS 属数据面部署形态
// （docs/APM_DATA_PLANE_DEPLOYMENT.md 的本地/中央 Collector 通道）。
package apm

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/google/uuid"
)

// CA 材料在系统设置表的位置（密文存储，明文不出库）。
const (
	caSettingsGroup = "apm_agent"
	caSettingsKey   = "ca_material"
	// PolicySignKeyID 策略签名密钥标识（当前恒为内置 CA 公钥；信封携带供 Agent 选钥验签）。
	PolicySignKeyID = "apm-agent-ca"
)

// CA 自签名证书有效期（10 年；CA 轮换为后续工作包，届时经设置表材料替换 + 双签过渡）。
const caCertValidity = 10 * 365 * 24 * time.Hour

// Agent 客户端证书有效期夹紧区间（设计 §9.1 短期证书：24h~7d；默认 72h）。
const (
	minAgentCertTTL     = 24 * time.Hour
	maxAgentCertTTL     = 7 * 24 * time.Hour
	defaultAgentCertTTL = 72 * time.Hour
)

// PoP 签名时间戳允许的最大时钟偏差（防重放窗口；传输机密性由部署层 TLS 承担）。
const popMaxClockSkew = 5 * time.Minute

// popSigningPrefix PoP 签名域分隔前缀（与策略签名、X.509 签名输入永不重叠）。
const popSigningPrefix = "JIUZHANG-APM-POP-v1"

// 控制面错误（handler 按 errors.Is 映射状态码；消息可安全返回客户端）。
var (
	// ErrCSRInvalid CSR 解析/校验失败（HTTP 400）。
	ErrCSRInvalid = errors.New("CSR 无效")
	// ErrPoPFailed 持有证明校验失败（HTTP 401）。
	ErrPoPFailed = errors.New("客户端证书持有证明校验失败")
)

// SettingsKV 设置读写接口（*settings.Service 实现；CA 密文落系统设置）。
type SettingsKV interface {
	GetString(ctx context.Context, group, key, def string) string
	UpsertString(ctx context.Context, group, key, value, description string, operatorID uuid.UUID) error
}

// Encryptor 加解密接口（*encryption.Service 实现；JIUZHANG_MASTER_KEY 体系）。
type Encryptor interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(encoded string) (string, error)
}

// AgentCA APM Agent 控制面内置 CA。
type AgentCA struct {
	key     ed25519.PrivateKey
	cert    *x509.Certificate
	certPEM string
}

// caMaterial 加密落库的 CA 材料（私钥 hex + 自签名证书 PEM）。
type caMaterial struct {
	PrivateKeyHex string `json:"private_key_hex"`
	CertPEM       string `json:"cert_pem"`
}

// LoadOrCreateAgentCA 从设置表加载 CA 材料（密文，经 enc 解密）；不存在则生成并加密落库。
// CA 私钥/材料不出现在任何接口响应、审计正文与日志中（与凭据纪律同则）。
func LoadOrCreateAgentCA(ctx context.Context, kv SettingsKV, enc Encryptor) (*AgentCA, error) {
	if kv == nil || enc == nil {
		return nil, errors.New("apm: settings/encryption 未装配，无法加载 Agent CA")
	}
	if raw := strings.TrimSpace(kv.GetString(ctx, caSettingsGroup, caSettingsKey, "")); raw != "" {
		plain, err := enc.Decrypt(raw)
		if err != nil {
			return nil, fmt.Errorf("apm: 解密 Agent CA 材料失败: %w", err)
		}
		var m caMaterial
		if err := json.Unmarshal([]byte(plain), &m); err != nil {
			return nil, fmt.Errorf("apm: Agent CA 材料格式非法: %w", err)
		}
		return parseAgentCA(m)
	}
	key, cert, certPEM, err := generateAgentCA()
	if err != nil {
		return nil, err
	}
	material, _ := json.Marshal(caMaterial{
		PrivateKeyHex: hex.EncodeToString(key),
		CertPEM:       certPEM,
	})
	cipherText, err := enc.Encrypt(string(material))
	if err != nil {
		return nil, fmt.Errorf("apm: 加密 Agent CA 材料失败: %w", err)
	}
	if err := kv.UpsertString(ctx, caSettingsGroup, caSettingsKey, cipherText,
		"APM Agent 控制面内置 CA 材料（Ed25519，密文存储）", uuid.Nil); err != nil {
		return nil, fmt.Errorf("apm: 落库 Agent CA 材料失败: %w", err)
	}
	return &AgentCA{key: key, cert: cert, certPEM: certPEM}, nil
}

// parseAgentCA 解析落库材料并校验私钥与证书公钥一致（材料被篡改/错配时 fail-closed）。
func parseAgentCA(m caMaterial) (*AgentCA, error) {
	keyBytes, err := hex.DecodeString(strings.TrimSpace(m.PrivateKeyHex))
	if err != nil || len(keyBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("apm: Agent CA 私钥格式非法: %w", err)
	}
	key := ed25519.PrivateKey(keyBytes)
	block, _ := pem.Decode([]byte(m.CertPEM))
	if block == nil {
		return nil, errors.New("apm: Agent CA 证书 PEM 非法")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("apm: Agent CA 证书解析失败: %w", err)
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || !pub.Equal(key.Public()) {
		return nil, errors.New("apm: Agent CA 私钥与证书不匹配")
	}
	return &AgentCA{key: key, cert: cert, certPEM: m.CertPEM}, nil
}

// generateAgentCA 生成 Ed25519 自签名 CA（仅证书签名用途；MaxPathLenZero 禁止下挂二级 CA）。
func generateAgentCA() (ed25519.PrivateKey, *x509.Certificate, string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, "", err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, "", err
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "JiuZhang APM Agent CA", Organization: []string{"JiuZhang"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caCertValidity),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, nil, "", err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, "", err
	}
	return priv, cert, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

// CertPEM 返回 CA 证书 PEM（随注册响应下发，供 Agent 校验控制面签发链）。
func (ca *AgentCA) CertPEM() string { return ca.certPEM }

// PublicKeyHex 返回 CA Ed25519 公钥 hex（策略验签公钥，随注册响应下发）。
func (ca *AgentCA) PublicKeyHex() string {
	return hex.EncodeToString(ca.key.Public().(ed25519.PublicKey))
}

// CertFingerprint 计算证书 SHA-256 指纹（hex，小写 64 字符；撤销列表与登记行主键）。
func CertFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// randomSerial 生成 128 位随机证书序列号。
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

// ParseAgentCSR 解析并校验 Agent CSR：PEM 格式、自签名有效（持有证明）、
// 公钥类型白名单（Ed25519 / ECDSA P-256·P-384 / RSA≥2048——拒绝弱密钥）。
func ParseAgentCSR(csrPEM string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(csrPEM)))
	if block == nil || (block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST") {
		return nil, fmt.Errorf("%w：须为 PEM 编码的 PKCS#10 CSR", ErrCSRInvalid)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w：%v", ErrCSRInvalid, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w：自签名校验失败", ErrCSRInvalid)
	}
	if err := checkAgentPublicKey(csr.PublicKey); err != nil {
		return nil, err
	}
	return csr, nil
}

// checkAgentPublicKey Agent 密钥类型/强度白名单。
func checkAgentPublicKey(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return nil
	case *ecdsa.PublicKey:
		if k.Curve == elliptic.P256() || k.Curve == elliptic.P384() {
			return nil
		}
		return fmt.Errorf("%w：ECDSA 仅支持 P-256/P-384", ErrCSRInvalid)
	case *rsa.PublicKey:
		if k.N.BitLen() >= 2048 {
			return nil
		}
		return fmt.Errorf("%w：RSA 密钥须 ≥2048 位", ErrCSRInvalid)
	default:
		return fmt.Errorf("%w：不支持的公钥类型（支持 Ed25519/ECDSA/RSA≥2048）", ErrCSRInvalid)
	}
}

// IssueCertificate 用 CA 签发 Agent 客户端证书（ExtKeyUsage 仅 ClientAuth，禁 CA）。
// ttl 由调用侧按配置给出，此处再夹紧到 [24h, 7d]；返回证书 PEM、指纹与到期时间。
func (ca *AgentCA) IssueCertificate(csr *x509.CertificateRequest, ttl time.Duration, now time.Time) (certPEM, fingerprint string, notAfter time.Time, err error) {
	if ttl < minAgentCertTTL {
		ttl = minAgentCertTTL
	}
	if ttl > maxAgentCertTTL {
		ttl = maxAgentCertTTL
	}
	serial, err := randomSerial()
	if err != nil {
		return "", "", time.Time{}, err
	}
	cn := strings.TrimSpace(csr.Subject.CommonName)
	if len(cn) > 128 {
		cn = cn[:128]
	}
	notAfter = now.UTC().Add(ttl)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"JiuZhang APM Agent"}},
		// NotBefore 回拨 5 分钟容忍 Agent 侧轻微时钟偏差
		NotBefore:             now.UTC().Add(-5 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return "", "", time.Time{}, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", "", time.Time{}, err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), CertFingerprint(cert), notAfter, nil
}

// popSigningInput 持有证明签名输入：域分隔前缀 + 方法/路径/时间戳/正文摘要，
// 绑定到具体请求（防跨接口重放）；正文以 SHA-256 hex 入签（大正文不放大签名输入）。
func popSigningInput(method, path, timestamp, bodySHA256Hex string) []byte {
	return []byte(popSigningPrefix + "\n" + method + "\n" + path + "\n" + timestamp + "\n" + bodySHA256Hex)
}

// BodySHA256Hex 计算请求正文 SHA-256 hex（空正文同样参与签名，防剥离正文重放）。
func BodySHA256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// CheckPoPTimestamp 校验 PoP 时间戳新鲜度（RFC3339，±popMaxClockSkew）。
func CheckPoPTimestamp(ts string, now time.Time) error {
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(ts))
	if err != nil {
		return fmt.Errorf("%w：时间戳须为 RFC3339", ErrPoPFailed)
	}
	skew := now.UTC().Sub(t.UTC())
	if skew < 0 {
		skew = -skew
	}
	if skew > popMaxClockSkew {
		return fmt.Errorf("%w：时间戳超出允许时钟偏差", ErrPoPFailed)
	}
	return nil
}

// VerifyPoP 用 Agent 客户端证书公钥验证 PoP 签名（Ed25519 直接验签；
// ECDSA/RSA 对签名输入取 SHA-256 后验签）。签名覆盖 method+path+timestamp+正文摘要。
func VerifyPoP(cert *x509.Certificate, method, path, timestamp string, body []byte, sigHex string) error {
	sig, err := hex.DecodeString(strings.TrimSpace(sigHex))
	if err != nil || len(sig) == 0 {
		return fmt.Errorf("%w：签名须为 hex 编码", ErrPoPFailed)
	}
	input := popSigningInput(method, path, timestamp, BodySHA256Hex(body))
	switch pub := cert.PublicKey.(type) {
	case ed25519.PublicKey:
		if ed25519.Verify(pub, input, sig) {
			return nil
		}
	case *ecdsa.PublicKey:
		digest := sha256.Sum256(input)
		if ecdsa.VerifyASN1(pub, digest[:], sig) {
			return nil
		}
	case *rsa.PublicKey:
		digest := sha256.Sum256(input)
		if rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig) == nil {
			return nil
		}
	default:
		return fmt.Errorf("%w：证书公钥类型不支持", ErrPoPFailed)
	}
	return ErrPoPFailed
}

// ParseAgentCertHeader 解析 PoP 头中的客户端证书（base64 标准编码的 DER；
// 头值不能携带 PEM 换行，故约定 DER+base64）。
func ParseAgentCertHeader(v string) (*x509.Certificate, error) {
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v))
	if err != nil {
		return nil, fmt.Errorf("%w：证书须为 base64(DER)", ErrPoPFailed)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("%w：证书解析失败", ErrPoPFailed)
	}
	return cert, nil
}
