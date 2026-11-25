// Package certificates 国密 SM2 双证书（TLCP 1.1，GB/T 38636-2020）解析与校验。
package certificates

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitee.com/Trisia/gotlcp/tlcp"
	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

// 证书协议类型（与数据库 certificates.protocol_type / application_certificates.cert_slot 一致）
const (
	ProtocolInternational = "INTERNATIONAL"
	ProtocolSMTLCP        = "SM_TLCP"
)

// 国密证书解析与校验错误
var (
	ErrInvalidProtocolType = errors.New("unsupported certificate protocol_type")
	ErrNotSM2Cert          = errors.New("certificate public key is not SM2")
	ErrInvalidGMKey        = errors.New("invalid SM2 private key")
	ErrGMKeyMismatch       = errors.New("SM2 certificate and private key do not match")
	ErrGMDualCertDuplicate = errors.New("SM2 signing certificate and encryption certificate must not be identical")
	ErrInvalidGMKeyUsage   = errors.New("SM2 certificate key usage does not match its role")
)

// NormalizeProtocolType 规范化证书协议类型（空串默认 INTERNATIONAL）。
func NormalizeProtocolType(v string) (string, error) {
	s := strings.ToUpper(strings.TrimSpace(v))
	if s == "" {
		return ProtocolInternational, nil
	}
	if s != ProtocolInternational && s != ProtocolSMTLCP {
		return "", fmt.Errorf("%w: %s", ErrInvalidProtocolType, v)
	}
	return s, nil
}

// GMDualParsed 国密双证书解析结果（签名证书 + 加密证书）。
type GMDualParsed struct {
	SignCert   *smx509.Certificate
	SignParsed *ParsedCertificate
	EncCert    *smx509.Certificate
	EncParsed  *ParsedCertificate
}

// EffectiveNotAfter 返回双证中较早的到期时间（任一到期即整组不可用）。
func (g *GMDualParsed) EffectiveNotAfter() time.Time {
	if g.EncParsed != nil && g.EncParsed.NotAfter.Before(g.SignParsed.NotAfter) {
		return g.EncParsed.NotAfter
	}
	return g.SignParsed.NotAfter
}

// ParseSM2CertificatePEM 解析单张 SM2 国密 X.509 证书（PEM 编码）。
func ParseSM2CertificatePEM(certPEM string) (*smx509.Certificate, *ParsedCertificate, error) {
	certPEM = strings.TrimSpace(certPEM)
	if certPEM == "" {
		return nil, nil, ErrInvalidPEM
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, nil, ErrInvalidPEM
	}
	if block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("expect CERTIFICATE block, got %s", block.Type)
	}
	cert, err := smx509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidCert, err)
	}
	if !sm2.IsSM2PublicKey(cert.PublicKey) {
		return nil, nil, ErrNotSM2Cert
	}

	fp := sha256.Sum256(cert.Raw)
	parsed := &ParsedCertificate{
		CommonName:         cert.Subject.CommonName,
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		FingerprintSHA256:  hex.EncodeToString(fp[:]),
		PublicKeyAlgorithm: "SM2",
		PublicKeyBits:      256,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		SANDomains:         cert.DNSNames,
	}
	if parsed.CommonName == "" && len(parsed.SANDomains) > 0 {
		parsed.CommonName = parsed.SANDomains[0]
	}
	return cert, parsed, nil
}

// ParseSM2CertificateChainPEM 校验包含多张证书的国密证书链 PEM。
func ParseSM2CertificateChainPEM(chainPEM string) (*smx509.Certificate, int, error) {
	chainPEM = strings.TrimSpace(chainPEM)
	rest := []byte(chainPEM)
	count := 0
	var first *smx509.Certificate
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			if len(strings.TrimSpace(string(rest))) > 0 {
				return nil, 0, ErrInvalidPEM
			}
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, 0, fmt.Errorf("%w: expect CERTIFICATE block, got %s", ErrInvalidPEM, block.Type)
		}
		cert, err := smx509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, 0, fmt.Errorf("%w: %v", ErrInvalidCert, err)
		}
		if first == nil {
			first = cert
		}
		count++
	}
	if first == nil {
		return nil, 0, ErrInvalidPEM
	}
	return first, count, nil
}

// ValidateSM2PrivateKeyPEM 解析并校验 SM2 私钥与对应证书公钥匹配。
func ValidateSM2PrivateKeyPEM(keyPEM string, cert *smx509.Certificate) error {
	keyPEM = strings.TrimSpace(keyPEM)
	if keyPEM == "" {
		return ErrInvalidGMKey
	}
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return ErrInvalidGMKey
	}
	priv, err := parseSM2PrivateKey(block)
	if err != nil {
		return err
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !sm2.IsSM2PublicKey(pub) {
		return ErrNotSM2Cert
	}
	if !pub.Equal(&priv.PublicKey) {
		return ErrGMKeyMismatch
	}
	return nil
}

func parseSM2PrivateKey(block *pem.Block) (*sm2.PrivateKey, error) {
	switch block.Type {
	case "PRIVATE KEY":
		key, err := smx509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidGMKey, err)
		}
		return toSM2PrivateKey(key)
	case "EC PRIVATE KEY", "SM2 PRIVATE KEY":
		if key, err := smx509.ParseSM2PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		key, err := smx509.ParseTypedECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidGMKey, err)
		}
		return toSM2PrivateKey(key)
	default:
		return nil, fmt.Errorf("%w: unsupported block type %s", ErrInvalidGMKey, block.Type)
	}
}

func toSM2PrivateKey(key any) (*sm2.PrivateKey, error) {
	switch k := key.(type) {
	case *sm2.PrivateKey:
		return k, nil
	case *ecdsa.PrivateKey:
		if k.Curve != sm2.P256() {
			return nil, fmt.Errorf("%w: curve is not SM2 P-256", ErrInvalidGMKey)
		}
		out := new(sm2.PrivateKey)
		if _, err := out.FromECPrivateKey(k); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidGMKey, err)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: key is not SM2", ErrInvalidGMKey)
	}
}

// ValidateSM2CertValidity 校验 SM2 证书有效期。
func ValidateSM2CertValidity(cert *smx509.Certificate, now time.Time) error {
	if now.Before(cert.NotBefore) {
		return ErrCertNotYetValid
	}
	if now.After(cert.NotAfter) {
		return ErrCertExpired
	}
	return nil
}

// ParseAndValidateGMDualCert 校验完整的国密 TLCP 双证书（签名证书/私钥 + 加密证书/私钥 + 可选链），
// 并经 gotlcp tlcp.X509KeyPair 交叉校验以确保网关数据面 100% 可加载。
func ParseAndValidateGMDualCert(signCertPEM, signKeyPEM, encCertPEM, encKeyPEM, chainPEM string, now time.Time) (*GMDualParsed, error) {
	signCert, signParsed, err := ParseSM2CertificatePEM(signCertPEM)
	if err != nil {
		return nil, fmt.Errorf("签名证书无效: %w", err)
	}
	encCert, encParsed, err := ParseSM2CertificatePEM(encCertPEM)
	if err != nil {
		return nil, fmt.Errorf("加密证书无效: %w", err)
	}
	if signParsed.FingerprintSHA256 == encParsed.FingerprintSHA256 {
		return nil, ErrGMDualCertDuplicate
	}
	// KeyUsage 角色检查（仅当证书显式声明 KeyUsage 时校验，防签/加密证书贴反）
	if signCert.KeyUsage != 0 && (signCert.KeyUsage&smx509.KeyUsageDigitalSignature) == 0 {
		return nil, fmt.Errorf("%w: 签名证书缺少 DigitalSignature 用途", ErrInvalidGMKeyUsage)
	}
	const encUsages = smx509.KeyUsageKeyEncipherment | smx509.KeyUsageDataEncipherment | smx509.KeyUsageKeyAgreement
	if encCert.KeyUsage != 0 && (encCert.KeyUsage&encUsages) == 0 {
		return nil, fmt.Errorf("%w: 加密证书缺少 KeyEncipherment/DataEncipherment/KeyAgreement 用途", ErrInvalidGMKeyUsage)
	}

	if strings.TrimSpace(chainPEM) != "" {
		if _, _, err := ParseSM2CertificateChainPEM(chainPEM); err != nil {
			return nil, fmt.Errorf("证书链无效: %w", err)
		}
	}
	if err := ValidateSM2PrivateKeyPEM(signKeyPEM, signCert); err != nil {
		return nil, fmt.Errorf("签名私钥校验失败: %w", err)
	}
	if err := ValidateSM2PrivateKeyPEM(encKeyPEM, encCert); err != nil {
		return nil, fmt.Errorf("加密私钥校验失败: %w", err)
	}
	if err := ValidateSM2CertValidity(signCert, now); err != nil {
		return nil, fmt.Errorf("签名证书有效期校验失败: %w", err)
	}
	if err := ValidateSM2CertValidity(encCert, now); err != nil {
		return nil, fmt.Errorf("加密证书有效期校验失败: %w", err)
	}

	// 与网关数据面同源库交叉验证，杜绝“管理面通过、网关加载失败”
	if _, err := tlcp.X509KeyPair([]byte(strings.TrimSpace(signCertPEM)), []byte(strings.TrimSpace(signKeyPEM))); err != nil {
		return nil, fmt.Errorf("签名证书与私钥不被 TLCP 引擎接受: %w", err)
	}
	if _, err := tlcp.X509KeyPair([]byte(strings.TrimSpace(encCertPEM)), []byte(strings.TrimSpace(encKeyPEM))); err != nil {
		return nil, fmt.Errorf("加密证书与私钥不被 TLCP 引擎接受: %w", err)
	}

	return &GMDualParsed{
		SignCert:   signCert,
		SignParsed: signParsed,
		EncCert:    encCert,
		EncParsed:  encParsed,
	}, nil
}
