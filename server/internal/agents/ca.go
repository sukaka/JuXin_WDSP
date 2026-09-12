// ca.go WDSP 流量采集 Agent 内置 CA 与证书签发（Phase 2-B；
// 契约 docs/agents/WDSP_AGENT_PHASE2_CONTRACT.md §7）。
//
// 与 APM Agent CA（server/internal/apm/agentca.go）同构但完全独立（不跨包复用）：
//   - CA 为 ECDSA P-256 自签名根（仅证书签名用途；MaxPathLenZero 禁止下挂二级 CA）；
//   - CA 私钥永不落明文：{private_key_pem, cert_pem} JSON 经 encryption.Service
//     （JIUZHANG_MASTER_KEY 体系）加密后存 system_settings（traffic_agent_ca.ca_material），
//     加载/创建模式与 apm.LoadOrCreateAgentCA 一致；
//   - 客户端证书由 CSR 签发（CSR 自签名验证即持有证明），仅接受 ECDSA P-256，
//     CN = agent_id（服务端填，CSR 自报 CN 不采信），TTL 90 天；
//   - 证书身份 = SHA-256(cert.Raw) hex 指纹：PoP 认证按「当前指纹或宽限撤销行」
//     判定（契约 §10），撤销/宽限记录落 agent_cert_revocations。
package agents

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
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

// CA 材料在系统设置表的位置（密文存储，明文不出库；与 APM 的 apm_agent 命名空间相互独立）。
const (
	caSettingsGroup = "traffic_agent_ca"
	caSettingsKey   = "ca_material"
)

// CA 自签名证书有效期（10 年；CA 轮换为后续工作包）。
const caCertValidity = 10 * 365 * 24 * time.Hour

// agentCertTTL 客户端证书有效期（契约 §7：90 天；存活期过半即 45 天后 Agent 自动轮换——契约 §9/§12）。
const agentCertTTL = 90 * 24 * time.Hour

// rotateGracePeriod 证书轮换宽限期（契约 §9：旧指纹 24 小时内新旧均可认证，宽限后自动撤销）。
const rotateGracePeriod = 24 * time.Hour

// ErrCSRInvalid CSR 解析/校验失败（HTTP 400）。
var ErrCSRInvalid = errors.New("CSR 无效")

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

// AgentCA 流量采集 Agent 内置 CA。
type AgentCA struct {
	key     *ecdsa.PrivateKey
	cert    *x509.Certificate
	certPEM string
	pool    *x509.CertPool // 客户端证书链校验根池（构造时固化）
}

// caMaterial 加密落库的 CA 材料（PKCS#8 私钥 PEM + 自签名证书 PEM）。
type caMaterial struct {
	PrivateKeyPEM string `json:"private_key_pem"`
	CertPEM       string `json:"cert_pem"`
}

// LoadOrCreateAgentCA 从设置表加载 CA 材料（密文，经 enc 解密）；不存在则生成并加密落库。
// CA 私钥/材料不出现在任何接口响应、审计正文与日志中（与凭据纪律同则）。
func LoadOrCreateAgentCA(ctx context.Context, kv SettingsKV, enc Encryptor) (*AgentCA, error) {
	if kv == nil || enc == nil {
		return nil, errors.New("agents: settings/encryption 未装配，无法加载 traffic-agent CA")
	}
	if raw := strings.TrimSpace(kv.GetString(ctx, caSettingsGroup, caSettingsKey, "")); raw != "" {
		plain, err := enc.Decrypt(raw)
		if err != nil {
			return nil, fmt.Errorf("agents: 解密 traffic-agent CA 材料失败: %w", err)
		}
		var m caMaterial
		if err := json.Unmarshal([]byte(plain), &m); err != nil {
			return nil, fmt.Errorf("agents: traffic-agent CA 材料格式非法: %w", err)
		}
		return parseAgentCA(m)
	}
	key, cert, certPEM, err := generateAgentCA()
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("agents: 编码 traffic-agent CA 私钥失败: %w", err)
	}
	material, _ := json.Marshal(caMaterial{
		PrivateKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
		CertPEM:       certPEM,
	})
	cipherText, err := enc.Encrypt(string(material))
	if err != nil {
		return nil, fmt.Errorf("agents: 加密 traffic-agent CA 材料失败: %w", err)
	}
	if err := kv.UpsertString(ctx, caSettingsGroup, caSettingsKey, cipherText,
		"WDSP 流量采集 Agent 内置 CA 材料（ECDSA P-256，密文存储）", uuid.Nil); err != nil {
		return nil, fmt.Errorf("agents: 落库 traffic-agent CA 材料失败: %w", err)
	}
	return newAgentCA(key, cert, certPEM), nil
}

// newAgentCA 组装 CA 并固化链校验根池。
func newAgentCA(key *ecdsa.PrivateKey, cert *x509.Certificate, certPEM string) *AgentCA {
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &AgentCA{key: key, cert: cert, certPEM: certPEM, pool: pool}
}

// parseAgentCA 解析落库材料并校验私钥与证书公钥一致（材料被篡改/错配时 fail-closed）。
func parseAgentCA(m caMaterial) (*AgentCA, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(m.PrivateKeyPEM)))
	if block == nil {
		return nil, errors.New("agents: traffic-agent CA 私钥 PEM 非法")
	}
	anyKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("agents: traffic-agent CA 私钥解析失败: %w", err)
	}
	key, ok := anyKey.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("agents: traffic-agent CA 私钥须为 ECDSA P-256")
	}
	certBlock, _ := pem.Decode([]byte(m.CertPEM))
	if certBlock == nil {
		return nil, errors.New("agents: traffic-agent CA 证书 PEM 非法")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("agents: traffic-agent CA 证书解析失败: %w", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(key.Public()) {
		return nil, errors.New("agents: traffic-agent CA 私钥与证书不匹配")
	}
	return newAgentCA(key, cert, m.CertPEM), nil
}

// generateAgentCA 生成 ECDSA P-256 自签名 CA（仅证书签名用途；MaxPathLenZero 禁止下挂二级 CA）。
func generateAgentCA() (*ecdsa.PrivateKey, *x509.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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
		Subject:               pkix.Name{CommonName: "JiuZhang WDSP Traffic Agent CA", Organization: []string{"JiuZhang"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(caCertValidity),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, "", err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, "", err
	}
	return key, cert, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}

// CertPEM 返回 CA 证书 PEM（随注册/轮换响应下发，供 Agent 校验服务端签发链）。
func (ca *AgentCA) CertPEM() string { return ca.certPEM }

// CertFingerprint 计算证书 SHA-256 指纹（hex，小写 64 字符；当前指纹列与撤销表的主键）。
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
// 公钥仅接受 ECDSA P-256（契约 §7：Agent 本地生成 P-256 密钥对）。
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
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w：公钥须为 ECDSA P-256", ErrCSRInvalid)
	}
	return csr, nil
}

// IssueCertificate 用 CA 签发 Agent 客户端证书（CN=agent_id 由服务端填——CSR 自报 CN 不采信；
// ExtKeyUsage 仅 ClientAuth，禁 CA；TTL 固定 90 天——契约 §7）。返回证书 PEM、指纹与到期时间。
func (ca *AgentCA) IssueCertificate(csr *x509.CertificateRequest, agentID string, now time.Time) (certPEM, fingerprint string, notAfter time.Time, err error) {
	serial, err := randomSerial()
	if err != nil {
		return "", "", time.Time{}, err
	}
	notAfter = now.UTC().Add(agentCertTTL)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: agentID, Organization: []string{"JiuZhang WDSP Traffic Agent"}},
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

// VerifyClientCert 校验客户端证书链到本 CA 且在有效期内（契约 §8 校验第 1 条）。
func (ca *AgentCA) VerifyClientCert(cert *x509.Certificate, now time.Time) error {
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       ca.pool,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		CurrentTime: now.UTC(),
	}); err != nil {
		return fmt.Errorf("%w：%v", ErrPoPFailed, err)
	}
	return nil
}
