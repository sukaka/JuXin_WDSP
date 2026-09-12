package certificates

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// 生成测试用自签名证书与私钥
func makeTestCert(t *testing.T, cn string, sans []string, notBefore, notAfter time.Time) (certPEM, keyPEM string, cert *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Org"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              sans,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	cert, _ = x509.ParseCertificate(der)
	return certPEM, keyPEM, cert
}

func TestParseCertificatePEM(t *testing.T) {
	now := time.Now()
	certPEM, _, _ := makeTestCert(t, "www.example.com", []string{"www.example.com", "api.example.com"}, now.Add(-time.Hour), now.Add(365*24*time.Hour))
	_, parsed, err := ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatalf("ParseCertificatePEM: %v", err)
	}
	if parsed.CommonName != "www.example.com" {
		t.Errorf("CN = %q", parsed.CommonName)
	}
	if parsed.PublicKeyAlgorithm != "RSA" {
		t.Errorf("PublicKeyAlgorithm = %q", parsed.PublicKeyAlgorithm)
	}
	if parsed.PublicKeyBits != 2048 {
		t.Errorf("PublicKeyBits = %d", parsed.PublicKeyBits)
	}
	if len(parsed.SANDomains) != 2 {
		t.Errorf("SAN count = %d", len(parsed.SANDomains))
	}
	if len(parsed.FingerprintSHA256) != 64 {
		t.Errorf("fingerprint len = %d", len(parsed.FingerprintSHA256))
	}
}

func TestParseCertificatePEMInvalid(t *testing.T) {
	if _, _, err := ParseCertificatePEM("not a pem"); err == nil {
		t.Error("should reject invalid PEM")
	}
	if _, _, err := ParseCertificatePEM(""); err == nil {
		t.Error("should reject empty PEM")
	}
}

func TestValidatePrivateKeyMatch(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM, cert := makeTestCert(t, "www.example.com", []string{"www.example.com"}, now.Add(-time.Hour), now.Add(365*24*time.Hour))
	if err := ValidatePrivateKeyPEM(keyPEM, cert); err != nil {
		t.Errorf("valid key should match: %v", err)
	}

	// 不匹配的私钥
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	otherKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(otherKey)}))
	if err := ValidatePrivateKeyPEM(otherKeyPEM, cert); err != ErrKeyMismatch {
		t.Errorf("mismatched key err = %v, want ErrKeyMismatch", err)
	}
	_ = certPEM
}

func TestValidatePrivateKeyInvalid(t *testing.T) {
	now := time.Now()
	_, _, cert := makeTestCert(t, "a.com", nil, now.Add(-time.Hour), now.Add(time.Hour))
	if err := ValidatePrivateKeyPEM("garbage", cert); err == nil {
		t.Error("should reject invalid key PEM")
	}
}

func TestValidateCertValidity(t *testing.T) {
	now := time.Now()
	_, _, validCert := makeTestCert(t, "a.com", nil, now.Add(-time.Hour), now.Add(time.Hour))
	if err := ValidateCertValidity(validCert, now); err != nil {
		t.Errorf("valid cert err = %v", err)
	}
	_, _, expiredCert := makeTestCert(t, "a.com", nil, now.Add(-48*time.Hour), now.Add(-time.Hour))
	if err := ValidateCertValidity(expiredCert, now); err != ErrCertExpired {
		t.Errorf("expired cert err = %v, want ErrCertExpired", err)
	}
	_, _, notYetCert := makeTestCert(t, "a.com", nil, now.Add(time.Hour), now.Add(48*time.Hour))
	if err := ValidateCertValidity(notYetCert, now); err != ErrCertNotYetValid {
		t.Errorf("not-yet-valid cert err = %v, want ErrCertNotYetValid", err)
	}
}

func TestCertStatus(t *testing.T) {
	now := time.Now()
	if s := CertStatus(now.Add(60*24*time.Hour), now); s != StatusValid {
		t.Errorf("60 days left status = %q, want VALID", s)
	}
	if s := CertStatus(now.Add(20*24*time.Hour), now); s != StatusExpiring {
		t.Errorf("20 days left status = %q, want EXPIRING", s)
	}
	if s := CertStatus(now.Add(-time.Hour), now); s != StatusExpired {
		t.Errorf("past status = %q, want EXPIRED", s)
	}
}

func TestExpiryLevel(t *testing.T) {
	now := time.Now()
	level, _ := ExpiryLevel(now.Add(5*24*time.Hour), now)
	if level != "critical" {
		t.Errorf("5 days level = %q, want critical", level)
	}
	level, _ = ExpiryLevel(now.Add(45*24*time.Hour), now)
	if level != "ok" {
		t.Errorf("45 days level = %q, want ok", level)
	}
}

func TestMatchDomain(t *testing.T) {
	now := time.Now()
	certPEM, _, _ := makeTestCert(t, "www.example.com", []string{"www.example.com", "*.api.example.com"}, now.Add(-time.Hour), now.Add(365*24*time.Hour))
	_, parsed, _ := ParseCertificatePEM(certPEM)
	cases := []struct {
		host string
		want bool
	}{
		{"www.example.com", true},
		{"v1.api.example.com", true}, // 泛域名 *.api.example.com
		{"api.example.com", false},   // 泛域名不含根
		{"other.com", false},
		{"WWW.EXAMPLE.COM", true}, // 大小写不敏感
	}
	for _, c := range cases {
		if got := MatchDomain(parsed, c.host); got != c.want {
			t.Errorf("MatchDomain(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestValidateKeyStrength(t *testing.T) {
	if err := ValidateKeyStrength(&ParsedCertificate{PublicKeyAlgorithm: "RSA", PublicKeyBits: 2048}); err != nil {
		t.Errorf("RSA 2048 should pass: %v", err)
	}
	if err := ValidateKeyStrength(&ParsedCertificate{PublicKeyAlgorithm: "RSA", PublicKeyBits: 1024}); err != ErrWeakKey {
		t.Errorf("RSA 1024 err = %v, want ErrWeakKey", err)
	}
	if err := ValidateKeyStrength(&ParsedCertificate{PublicKeyAlgorithm: "ECDSA", PublicKeyBits: 256}); err != nil {
		t.Errorf("ECDSA 256 should pass: %v", err)
	}
}
