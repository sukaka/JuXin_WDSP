// agentca_test.go 内置 CA / CSR 签发 / 指纹 / PoP 签名单元测试（不依赖数据库）。
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
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/encryption"
)

// fakeSettingsKV 内存版设置读写（记录 Upsert 调用）。
type fakeSettingsKV struct {
	values       map[string]string
	upsertedDesc string
}

func newFakeSettingsKV() *fakeSettingsKV { return &fakeSettingsKV{values: map[string]string{}} }

func (f *fakeSettingsKV) GetString(_ context.Context, group, key, def string) string {
	if v, ok := f.values[group+":"+key]; ok {
		return v
	}
	return def
}

func (f *fakeSettingsKV) UpsertString(_ context.Context, group, key, value, description string, _ uuid.UUID) error {
	f.values[group+":"+key] = value
	f.upsertedDesc = description
	return nil
}

// testEnc 真实加密服务（固定测试密钥）。
func testEnc(t *testing.T) *encryption.Service {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	svc, err := encryption.NewWithKey(key)
	if err != nil {
		t.Fatalf("NewWithKey: %v", err)
	}
	return svc
}

// newTestCA 经 LoadOrCreateAgentCA 生成全新 CA（fake KV + 真实加密）。
func newTestCA(t *testing.T) (*AgentCA, *fakeSettingsKV) {
	t.Helper()
	kv := newFakeSettingsKV()
	ca, err := LoadOrCreateAgentCA(context.Background(), kv, testEnc(t))
	if err != nil {
		t.Fatalf("LoadOrCreateAgentCA: %v", err)
	}
	return ca, kv
}

// makeCSR 生成指定密钥类型的 CSR（PEM）。
func makeCSR(t *testing.T, key crypto.Signer, cn string) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func newEd25519CSR(t *testing.T, cn string) (ed25519.PrivateKey, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return priv, makeCSR(t, priv, cn)
}

func TestAgentCA_LoadOrCreate_Roundtrip(t *testing.T) {
	ca, kv := newTestCA(t)
	if ca.CertPEM() == "" || ca.PublicKeyHex() == "" {
		t.Fatal("CA material empty")
	}
	// 密文落库：设置表值不得含私钥/证书明文特征
	stored := kv.values[caSettingsGroup+":"+caSettingsKey]
	if strings.Contains(stored, "BEGIN CERTIFICATE") || len(stored) < 64 {
		t.Errorf("CA material stored in plaintext or too short: %q", stored[:min(32, len(stored))])
	}
	// 重复加载得到同一 CA（私钥与证书匹配校验在 parseAgentCA 内完成）
	ca2, err := LoadOrCreateAgentCA(context.Background(), kv, testEnc(t))
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if ca2.PublicKeyHex() != ca.PublicKeyHex() || ca2.CertPEM() != ca.CertPEM() {
		t.Error("reload produced different CA")
	}
	// 错误主密钥解密失败 → fail-closed
	badEnc, _ := encryption.NewWithKey(make([]byte, 32))
	if _, err := LoadOrCreateAgentCA(context.Background(), kv, badEnc); err == nil {
		t.Error("reload with wrong master key must fail")
	}
	// 未装配依赖 → 错误
	if _, err := LoadOrCreateAgentCA(context.Background(), nil, nil); err == nil {
		t.Error("nil deps must fail")
	}
}

func TestAgentCA_IssueCertificate_KeyTypes(t *testing.T) {
	ca, _ := newTestCA(t)
	now := time.Now()

	// Ed25519
	priv, csrPEM := newEd25519CSR(t, "shop-svc")
	csr, err := ParseAgentCSR(csrPEM)
	if err != nil {
		t.Fatalf("ParseAgentCSR ed25519: %v", err)
	}
	certPEM, fp, notAfter, err := ca.IssueCertificate(csr, 72*time.Hour, now)
	if err != nil {
		t.Fatalf("IssueCertificate: %v", err)
	}
	block, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued cert: %v", err)
	}
	if err := cert.CheckSignatureFrom(ca.cert); err != nil {
		t.Errorf("issued cert not signed by CA: %v", err)
	}
	if CertFingerprint(cert) != fp {
		t.Error("fingerprint mismatch")
	}
	if got := notAfter.Sub(now); got != 72*time.Hour {
		t.Errorf("ttl = %v, want 72h", got)
	}
	if cert.IsCA || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("issued cert must be client-auth leaf: isCA=%v eku=%v", cert.IsCA, cert.ExtKeyUsage)
	}
	if cert.Subject.CommonName != "shop-svc" {
		t.Errorf("CN = %q", cert.Subject.CommonName)
	}
	_ = priv

	// ECDSA P-256
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := ParseAgentCSR(makeCSR(t, ecKey, "svc-ec")); err != nil {
		t.Errorf("P-256 CSR rejected: %v", err)
	}
	// RSA 2048
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := ParseAgentCSR(makeCSR(t, rsaKey, "svc-rsa")); err != nil {
		t.Errorf("RSA-2048 CSR rejected: %v", err)
	}
	// RSA 1024 拒绝（弱密钥）
	weakKey, _ := rsa.GenerateKey(rand.Reader, 1024)
	if _, err := ParseAgentCSR(makeCSR(t, weakKey, "svc-weak")); !errors.Is(err, ErrCSRInvalid) {
		t.Errorf("RSA-1024 CSR must be rejected: %v", err)
	}
	// 垃圾 PEM 拒绝
	if _, err := ParseAgentCSR("not a pem"); !errors.Is(err, ErrCSRInvalid) {
		t.Errorf("garbage CSR must be rejected: %v", err)
	}
	// 篡改 CSR 字节 → 自签名失效
	tampered := makeCSR(t, ecKey, "svc-ec2")
	blk, _ := pem.Decode([]byte(tampered))
	blk.Bytes[len(blk.Bytes)-8] ^= 0xff
	if _, err := ParseAgentCSR(string(pem.EncodeToMemory(blk))); !errors.Is(err, ErrCSRInvalid) {
		t.Errorf("tampered CSR must be rejected: %v", err)
	}
}

func TestAgentCA_IssueCertificate_TTLClamp(t *testing.T) {
	ca, _ := newTestCA(t)
	_, csrPEM := newEd25519CSR(t, "svc")
	csr, _ := ParseAgentCSR(csrPEM)
	now := time.Now()
	// 低于下限 → 夹紧到 24h
	_, _, notAfter, err := ca.IssueCertificate(csr, time.Hour, now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if got := notAfter.Sub(now); got != minAgentCertTTL {
		t.Errorf("clamped ttl = %v, want %v", got, minAgentCertTTL)
	}
	// 高于上限 → 夹紧到 7d
	_, _, notAfter, _ = ca.IssueCertificate(csr, 30*24*time.Hour, now)
	if got := notAfter.Sub(now); got != maxAgentCertTTL {
		t.Errorf("clamped ttl = %v, want %v", got, maxAgentCertTTL)
	}
}

// popSign 测试侧 PoP 签名（与 VerifyPoP 同一输入构造——包内测试可直接复用 popSigningInput）。
func popSign(t *testing.T, key crypto.Signer, method, path, ts string, body []byte) string {
	t.Helper()
	input := popSigningInput(method, path, ts, BodySHA256Hex(body))
	var sig []byte
	var err error
	switch k := key.(type) {
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, input)
	case *ecdsa.PrivateKey:
		digest := sha256.Sum256(input)
		sig, err = ecdsa.SignASN1(rand.Reader, k, digest[:])
	case *rsa.PrivateKey:
		digest := sha256.Sum256(input)
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, digest[:])
	}
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return hex.EncodeToString(sig)
}

func TestPoP_Verify(t *testing.T) {
	ca, _ := newTestCA(t)
	now := time.Now()
	ts := now.UTC().Format(time.RFC3339)
	body := []byte(`{"agent_version":"1.0.0"}`)

	for _, keyType := range []string{"ed25519", "ecdsa", "rsa"} {
		var key crypto.Signer
		switch keyType {
		case "ed25519":
			_, priv, _ := ed25519.GenerateKey(rand.Reader)
			key = priv
		case "ecdsa":
			key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case "rsa":
			key, _ = rsa.GenerateKey(rand.Reader, 2048)
		}
		csr, err := ParseAgentCSR(makeCSR(t, key, "svc-"+keyType))
		if err != nil {
			t.Fatalf("%s CSR: %v", keyType, err)
		}
		certPEM, _, _, err := ca.IssueCertificate(csr, 72*time.Hour, now)
		if err != nil {
			t.Fatalf("%s issue: %v", keyType, err)
		}
		blk, _ := pem.Decode([]byte(certPEM))
		cert, _ := x509.ParseCertificate(blk.Bytes)

		sig := popSign(t, key, "POST", "/api/v1/apm/agent/heartbeat", ts, body)
		if err := VerifyPoP(cert, "POST", "/api/v1/apm/agent/heartbeat", ts, body, sig); err != nil {
			t.Errorf("%s valid PoP rejected: %v", keyType, err)
		}
		// 正文被改 → 拒绝
		if err := VerifyPoP(cert, "POST", "/api/v1/apm/agent/heartbeat", ts, []byte(`{}`), sig); !errors.Is(err, ErrPoPFailed) {
			t.Errorf("%s tampered body must fail: %v", keyType, err)
		}
		// 路径被改 → 拒绝
		if err := VerifyPoP(cert, "POST", "/api/v1/apm/agent/policy", ts, body, sig); !errors.Is(err, ErrPoPFailed) {
			t.Errorf("%s tampered path must fail: %v", keyType, err)
		}
		// 垃圾签名 → 拒绝
		if err := VerifyPoP(cert, "POST", "/api/v1/apm/agent/heartbeat", ts, body, "zz"); !errors.Is(err, ErrPoPFailed) {
			t.Errorf("%s garbage sig must fail: %v", keyType, err)
		}
	}
}

func TestPoP_TimestampSkew(t *testing.T) {
	now := time.Now()
	if err := CheckPoPTimestamp(now.UTC().Format(time.RFC3339), now); err != nil {
		t.Errorf("fresh timestamp rejected: %v", err)
	}
	if err := CheckPoPTimestamp(now.Add(-4*time.Minute).UTC().Format(time.RFC3339), now); err != nil {
		t.Errorf("4min-old timestamp within window rejected: %v", err)
	}
	if err := CheckPoPTimestamp(now.Add(-6*time.Minute).UTC().Format(time.RFC3339), now); !errors.Is(err, ErrPoPFailed) {
		t.Errorf("stale timestamp must fail: %v", err)
	}
	if err := CheckPoPTimestamp("not-a-time", now); !errors.Is(err, ErrPoPFailed) {
		t.Errorf("garbage timestamp must fail: %v", err)
	}
}

func TestParseAgentCertHeader(t *testing.T) {
	ca, _ := newTestCA(t)
	_, csrPEM := newEd25519CSR(t, "svc")
	csr, _ := ParseAgentCSR(csrPEM)
	certPEM, _, _, _ := ca.IssueCertificate(csr, 72*time.Hour, time.Now())
	blk, _ := pem.Decode([]byte(certPEM))
	cert, err := ParseAgentCertHeader(base64.StdEncoding.EncodeToString(blk.Bytes))
	if err != nil {
		t.Fatalf("ParseAgentCertHeader: %v", err)
	}
	if CertFingerprint(cert) != CertFingerprint(mustParseCert(t, certPEM)) {
		t.Error("cert roundtrip mismatch")
	}
	if _, err := ParseAgentCertHeader("!!!"); err == nil {
		t.Error("garbage header must fail")
	}
}

func mustParseCert(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()
	blk, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
