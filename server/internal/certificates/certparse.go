// Package certificates 提供HTTPS证书解析、校验与管理。
package certificates

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jiuzhang-waf/server/internal/validation"
)

// 证书状态
const (
	StatusValid       = "VALID"
	StatusExpiring    = "EXPIRING"
	StatusExpired     = "EXPIRED"
	StatusInvalid     = "INVALID"
	StatusKeyMismatch = "KEY_MISMATCH"
)

// 解析错误
var (
	ErrInvalidPEM      = errors.New("invalid PEM format")
	ErrInvalidCert     = errors.New("invalid X.509 certificate")
	ErrInvalidKey      = errors.New("invalid private key")
	ErrKeyMismatch     = errors.New("certificate and private key do not match")
	ErrCertExpired     = errors.New("certificate has expired")
	ErrCertNotYetValid = errors.New("certificate is not yet valid")
	ErrWeakKey         = errors.New("key strength too weak")
)

// ParsedCertificate 是解析后的证书信息。
type ParsedCertificate struct {
	CommonName         string    `json:"common_name"`
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SerialNumber       string    `json:"serial_number"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	FingerprintSHA256  string    `json:"fingerprint_sha256"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	PublicKeyBits      int       `json:"public_key_bits"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	SANDomains         []string  `json:"san_domains"`
}

// ParseCertificatePEM 解析 PEM 编码的 X.509 证书。
func ParseCertificatePEM(certPEM string) (*x509.Certificate, *ParsedCertificate, error) {
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
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrInvalidCert, err)
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
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		PublicKeyBits:      publicKeyBits(cert),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		SANDomains:         cert.DNSNames,
	}
	if parsed.CommonName == "" && len(parsed.SANDomains) > 0 {
		parsed.CommonName = parsed.SANDomains[0]
	}
	return cert, parsed, nil
}

// ParseCertificateChainPEM 解析可能包含多证书的 PEM（取第一张为主证书，其余为链）。
func ParseCertificateChainPEM(certPEM string) (leaf *x509.Certificate, chainCount int, err error) {
	certPEM = strings.TrimSpace(certPEM)
	rest := []byte(certPEM)
	count := 0
	var first *x509.Certificate
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
		cert, err := x509.ParseCertificate(block.Bytes)
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

// ValidatePrivateKeyPEM 解析并校验私钥，验证与证书匹配。
func ValidatePrivateKeyPEM(keyPEM string, cert *x509.Certificate) error {
	keyPEM = strings.TrimSpace(keyPEM)
	if keyPEM == "" {
		return ErrInvalidKey
	}
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return ErrInvalidKey
	}
	priv, err := parsePrivateKey(block)
	if err != nil {
		return err
	}
	return matchKey(cert, priv)
}

func parsePrivateKey(block *pem.Block) (interface{}, error) {
	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
		}
		return key, nil
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
		}
		return key, nil
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidKey, err)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("%w: unsupported block type %s", ErrInvalidKey, block.Type)
	}
}

// matchKey 校验私钥与证书公钥匹配。
func matchKey(cert *x509.Certificate, priv interface{}) error {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		privKey, ok := priv.(*rsa.PrivateKey)
		if !ok {
			return ErrKeyMismatch
		}
		if !pub.Equal(privKey.Public()) {
			return ErrKeyMismatch
		}
	case *ecdsa.PublicKey:
		privKey, ok := priv.(*ecdsa.PrivateKey)
		if !ok {
			return ErrKeyMismatch
		}
		if !pub.Equal(privKey.Public()) {
			return ErrKeyMismatch
		}
	case ed25519.PublicKey:
		privKey, ok := priv.(ed25519.PrivateKey)
		if !ok {
			return ErrKeyMismatch
		}
		if !pub.Equal(privKey.Public()) {
			return ErrKeyMismatch
		}
	default:
		return fmt.Errorf("unsupported public key type")
	}
	return nil
}

// ValidateCertValidity 校验证书有效期。
func ValidateCertValidity(cert *x509.Certificate, now time.Time) error {
	if now.Before(cert.NotBefore) {
		return ErrCertNotYetValid
	}
	if now.After(cert.NotAfter) {
		return ErrCertExpired
	}
	return nil
}

// ValidateKeyStrength 校验密钥强度。
func ValidateKeyStrength(parsed *ParsedCertificate) error {
	switch parsed.PublicKeyAlgorithm {
	case "RSA":
		if parsed.PublicKeyBits < 2048 {
			return ErrWeakKey
		}
	case "ECDSA":
		if parsed.PublicKeyBits < 256 {
			return ErrWeakKey
		}
	}
	return nil
}

// publicKeyBits 返回公钥位数。
func publicKeyBits(cert *x509.Certificate) int {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen()
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	}
	return 0
}

// CertStatus 计算证书当前状态（基于剩余有效期）。
func CertStatus(notAfter time.Time, now time.Time) string {
	if now.After(notAfter) {
		return StatusExpired
	}
	daysLeft := int(notAfter.Sub(now).Hours() / 24)
	if daysLeft <= 30 {
		return StatusExpiring
	}
	return StatusValid
}

// ExpiryLevel 返回到期级别（用于前端展示）。
func ExpiryLevel(notAfter time.Time, now time.Time) (level string, daysLeft int) {
	diff := notAfter.Sub(now)
	daysLeft = int(diff.Hours() / 24)
	switch {
	case diff < 0:
		return "expired", daysLeft
	case daysLeft <= 7:
		return "critical", daysLeft
	case daysLeft <= 15:
		return "warning", daysLeft
	case daysLeft <= 30:
		return "notice", daysLeft
	default:
		return "ok", daysLeft
	}
}

// MatchDomain 校验证书是否覆盖指定域名（CN + SAN，支持泛域名）。
func MatchDomain(parsed *ParsedCertificate, hostname string) bool {
	hostname = validation.NormalizeHostname(hostname)
	candidates := append([]string{}, parsed.SANDomains...)
	if parsed.CommonName != "" {
		candidates = append(candidates, parsed.CommonName)
	}
	for _, pattern := range candidates {
		if validation.MatchHostnamePattern(pattern, hostname) {
			return true
		}
	}
	return false
}

// MatchDomains 校验证书是否覆盖全部域名，返回不匹配的域名。
func MatchDomains(parsed *ParsedCertificate, hostnames []string) []string {
	var unmatched []string
	for _, h := range hostnames {
		if !MatchDomain(parsed, h) {
			unmatched = append(unmatched, h)
		}
	}
	return unmatched
}
