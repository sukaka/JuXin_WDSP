package certificates

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
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

func TestCertStatusAndExpiryLevelUseProvidedNow(t *testing.T) {
	// Use a historical reference time far from time.Now() to guarantee notAfter.Sub(now) is used
	refNow := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	if s := CertStatus(refNow.Add(60*24*time.Hour), refNow); s != StatusValid {
		t.Fatalf("CertStatus(+60d from refNow) = %q, want VALID", s)
	}
	if s := CertStatus(refNow.Add(10*24*time.Hour), refNow); s != StatusExpiring {
		t.Fatalf("CertStatus(+10d from refNow) = %q, want EXPIRING", s)
	}
	if lvl, days := ExpiryLevel(refNow.Add(45*24*time.Hour), refNow); lvl != "ok" || days != 45 {
		t.Fatalf("ExpiryLevel(+45d from refNow) = (%q, %d), want (ok, 45)", lvl, days)
	}
	if lvl, _ := ExpiryLevel(refNow.Add(-time.Hour), refNow); lvl != "expired" {
		t.Fatalf("ExpiryLevel(-1h from refNow) = %q, want expired", lvl)
	}
}

func TestMatchKeyUsesPublicEqual(t *testing.T) {
	now := time.Now()
	_, _, cert := makeTestCert(t, "rsa.example.com", nil, now.Add(-time.Hour), now.Add(time.Hour))
	pub := cert.PublicKey.(*rsa.PublicKey)
	// Same N, different E -> must fail matchKey via pub.Equal
	fakePriv := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: new(big.Int).Set(pub.N), E: pub.E + 2}}
	if err := matchKey(cert, fakePriv); err != ErrKeyMismatch {
		t.Fatalf("RSA different exponent should fail with ErrKeyMismatch, got %v", err)
	}

	// ECDSA match & mismatch
	ecKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecCert := &x509.Certificate{PublicKey: &ecKey1.PublicKey}
	if err := matchKey(ecCert, ecKey1); err != nil {
		t.Fatalf("matching ECDSA key failed: %v", err)
	}
	if err := matchKey(ecCert, ecKey2); err != ErrKeyMismatch {
		t.Fatalf("mismatched ECDSA key got %v, want ErrKeyMismatch", err)
	}
}

func TestUploadRejectsInvalidChainAndNilEncryptor(t *testing.T) {
	now := time.Now()
	certPEM, keyPEM, _ := makeTestCert(t, "chain.example.com", []string{"chain.example.com"}, now.Add(-time.Hour), now.Add(60*24*time.Hour))
	st := NewStore(nil, nil)

	// Invalid ChainPEM rejected before DB / enc
	if _, err := st.Upload(context.Background(), UploadInput{
		Name:      "bad-chain",
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		ChainPEM:  "not-a-valid-chain-pem",
		CreatedBy: uuid.New(),
	}); err == nil || !strings.Contains(err.Error(), "证书链") {
		t.Fatalf("invalid chain should be rejected, got %v", err)
	}

	// Private key smuggled inside ChainPEM rejected
	if _, err := st.Upload(context.Background(), UploadInput{
		Name:      "key-in-chain",
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		ChainPEM:  keyPEM,
		CreatedBy: uuid.New(),
	}); err == nil || !strings.Contains(err.Error(), "证书链") {
		t.Fatalf("private key in chain should be rejected, got %v", err)
	}

	// Valid ChainPEM with nil s.enc returns error cleanly instead of panicking
	if _, err := st.Upload(context.Background(), UploadInput{
		Name:      "nil-enc",
		CertPEM:   certPEM,
		KeyPEM:    keyPEM,
		ChainPEM:  certPEM,
		CreatedBy: uuid.New(),
	}); err == nil || !strings.Contains(err.Error(), "加密服务") {
		t.Fatalf("nil encryptor should fail cleanly, got %v", err)
	}

	if _, err := st.GetDecryptedKey(context.Background(), uuid.New()); err == nil {
		t.Fatal("GetDecryptedKey with nil encryptor should fail cleanly")
	}
}

func TestCertSummaryJSONEscapingAndShortFingerprint(t *testing.T) {
	raw := certSummary(&Certificate{
		Name:              `evil"name` + "\n",
		CommonName:        `*.example.com`,
		FingerprintSHA256: "short",
	})
	var parsed map[string]string
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatalf("certSummary produced invalid JSON %q: %v", raw, err)
	}
	if parsed["name"] != "evil\"name\n" || parsed["fingerprint"] != "short" {
		t.Fatalf("unexpected certSummary fields: %+v", parsed)
	}
}
