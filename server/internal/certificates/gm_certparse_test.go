package certificates

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

// makeTestSM2Cert 生成测试用国密 SM2 证书与私钥（支持指定 KeyUsage 和 PEM 私钥块格式）。
func makeTestSM2Cert(t *testing.T, cn string, sans []string, serial int64, usage smx509.KeyUsage, notBefore, notAfter time.Time, keyBlockType string) (certPEM, keyPEM string, cert *smx509.Certificate) {
	t.Helper()
	priv, err := sm2.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("sm2.GenerateKey: %v", err)
	}
	tmpl := &smx509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"JiuZhang GM Test"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              usage,
		ExtKeyUsage:           []smx509.ExtKeyUsage{smx509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              sans,
	}
	der, err := smx509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("smx509.CreateCertificate: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	var keyDER []byte
	switch keyBlockType {
	case "PRIVATE KEY":
		keyDER, err = smx509.MarshalPKCS8PrivateKey(priv)
	case "EC PRIVATE KEY", "SM2 PRIVATE KEY":
		keyDER, err = smx509.MarshalSM2PrivateKey(priv)
	default:
		keyBlockType = "PRIVATE KEY"
		keyDER, err = smx509.MarshalPKCS8PrivateKey(priv)
	}
	if err != nil {
		t.Fatalf("marshal sm2 private key (%s): %v", keyBlockType, err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: keyBlockType, Bytes: keyDER}))
	cert, err = smx509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("smx509.ParseCertificate: %v", err)
	}
	return certPEM, keyPEM, cert
}

func TestParseAndValidateGMDualCertSuccess(t *testing.T) {
	now := time.Now()
	for _, keyType := range []string{"PRIVATE KEY", "EC PRIVATE KEY", "SM2 PRIVATE KEY"} {
		t.Run("key_block_"+keyType, func(t *testing.T) {
			signCertPEM, signKeyPEM, _ := makeTestSM2Cert(
				t, "gm.example.com", []string{"gm.example.com", "*.gm.example.com"},
				1001, smx509.KeyUsageDigitalSignature,
				now.Add(-time.Hour), now.Add(365*24*time.Hour), keyType,
			)
			encCertPEM, encKeyPEM, _ := makeTestSM2Cert(
				t, "gm.example.com", []string{"gm.example.com", "*.gm.example.com"},
				1002, smx509.KeyUsageKeyEncipherment|smx509.KeyUsageDataEncipherment,
				now.Add(-time.Hour), now.Add(180*24*time.Hour), keyType,
			)
			dual, err := ParseAndValidateGMDualCert(signCertPEM, signKeyPEM, encCertPEM, encKeyPEM, signCertPEM, now)
			if err != nil {
				t.Fatalf("ParseAndValidateGMDualCert failed: %v", err)
			}
			if dual.SignParsed.PublicKeyAlgorithm != "SM2" || dual.SignParsed.PublicKeyBits != 256 {
				t.Errorf("unexpected sign pubkey metadata: %+v", dual.SignParsed)
			}
			if dual.EncParsed.PublicKeyAlgorithm != "SM2" || dual.EncParsed.PublicKeyBits != 256 {
				t.Errorf("unexpected enc pubkey metadata: %+v", dual.EncParsed)
			}
			if dual.SignParsed.FingerprintSHA256 == dual.EncParsed.FingerprintSHA256 {
				t.Errorf("fingerprints should differ")
			}
			// 加密证书更早到期（180天 < 365天），EffectiveNotAfter 应取较早值
			if !dual.EffectiveNotAfter().Equal(dual.EncParsed.NotAfter) {
				t.Errorf("EffectiveNotAfter = %v, want enc NotAfter %v", dual.EffectiveNotAfter(), dual.EncParsed.NotAfter)
			}
		})
	}
}

func TestGMDualCertRejectsNegativeCases(t *testing.T) {
	now := time.Now()
	validSignCert, validSignKey, _ := makeTestSM2Cert(
		t, "gm.example.com", []string{"gm.example.com"},
		2001, smx509.KeyUsageDigitalSignature,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), "PRIVATE KEY",
	)
	validEncCert, validEncKey, _ := makeTestSM2Cert(
		t, "gm.example.com", []string{"gm.example.com"},
		2002, smx509.KeyUsageKeyEncipherment|smx509.KeyUsageDataEncipherment,
		now.Add(-time.Hour), now.Add(365*24*time.Hour), "PRIVATE KEY",
	)

	t.Run("reject_rsa_cert_as_gm", func(t *testing.T) {
		rsaCert, rsaKey, _ := makeTestCert(t, "rsa.example.com", []string{"rsa.example.com"}, now.Add(-time.Hour), now.Add(24*time.Hour))
		_, err := ParseAndValidateGMDualCert(rsaCert, rsaKey, validEncCert, validEncKey, "", now)
		if !errors.Is(err, ErrNotSM2Cert) {
			t.Fatalf("want ErrNotSM2Cert, got %v", err)
		}
	})

	t.Run("reject_nist_p256_ecdsa_as_gm", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey: %v", err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(3001),
			Subject:      pkix.Name{CommonName: "p256.example.com"},
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ecKey.PublicKey, ecKey)
		if err != nil {
			t.Fatalf("x509.CreateCertificate: %v", err)
		}
		ecCertPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
		ecKeyDER, _ := x509.MarshalPKCS8PrivateKey(ecKey)
		ecKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecKeyDER}))

		_, err = ParseAndValidateGMDualCert(ecCertPEM, ecKeyPEM, validEncCert, validEncKey, "", now)
		if !errors.Is(err, ErrNotSM2Cert) {
			t.Fatalf("want ErrNotSM2Cert for NIST P-256, got %v", err)
		}
	})

	t.Run("reject_duplicate_sign_and_enc_cert", func(t *testing.T) {
		_, err := ParseAndValidateGMDualCert(validSignCert, validSignKey, validSignCert, validSignKey, "", now)
		if !errors.Is(err, ErrGMDualCertDuplicate) {
			t.Fatalf("want ErrGMDualCertDuplicate, got %v", err)
		}
	})

	t.Run("reject_swapped_key_usage", func(t *testing.T) {
		_, err := ParseAndValidateGMDualCert(validEncCert, validEncKey, validSignCert, validSignKey, "", now)
		if !errors.Is(err, ErrInvalidGMKeyUsage) {
			t.Fatalf("want ErrInvalidGMKeyUsage, got %v", err)
		}
	})

	t.Run("reject_mismatched_enc_private_key", func(t *testing.T) {
		_, err := ParseAndValidateGMDualCert(validSignCert, validSignKey, validEncCert, validSignKey, "", now)
		if !errors.Is(err, ErrGMKeyMismatch) {
			t.Fatalf("want ErrGMKeyMismatch, got %v", err)
		}
	})

	t.Run("reject_expired_enc_cert", func(t *testing.T) {
		expEncCert, expEncKey, _ := makeTestSM2Cert(
			t, "gm.example.com", []string{"gm.example.com"},
			2003, smx509.KeyUsageKeyEncipherment,
			now.Add(-48*time.Hour), now.Add(-time.Hour), "PRIVATE KEY",
		)
		_, err := ParseAndValidateGMDualCert(validSignCert, validSignKey, expEncCert, expEncKey, "", now)
		if !errors.Is(err, ErrCertExpired) {
			t.Fatalf("want ErrCertExpired, got %v", err)
		}
	})

	t.Run("reject_invalid_protocol_type", func(t *testing.T) {
		if _, err := NormalizeProtocolType("RSA_ONLY"); !errors.Is(err, ErrInvalidProtocolType) {
			t.Fatalf("want ErrInvalidProtocolType, got %v", err)
		}
		if got, err := NormalizeProtocolType(""); err != nil || got != ProtocolInternational {
			t.Fatalf("empty protocol type = %q, %v", got, err)
		}
		if got, err := NormalizeProtocolType(" sm_tlcp "); err != nil || got != ProtocolSMTLCP {
			t.Fatalf("sm_tlcp normalize = %q, %v", got, err)
		}
	})

	t.Run("reject_garbage_chain_pem", func(t *testing.T) {
		_, err := ParseAndValidateGMDualCert(validSignCert, validSignKey, validEncCert, validEncKey, "not-a-pem", now)
		if err == nil || !strings.Contains(err.Error(), "证书链无效") {
			t.Fatalf("want chain error, got %v", err)
		}
	})
}
