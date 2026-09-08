package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// selfSignedCert 测试用自签证书（指定有效期）。
func selfSignedCert(t *testing.T, key *ecdsa.PrivateKey, notBefore, notAfter time.Time) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "agent-1"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// pemDecode 解码单块 PEM，返回 DER 与块类型。
func pemDecode(s string) (der []byte, typ string) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, ""
	}
	return block.Bytes, block.Type
}

// signWithCA 模拟服务端：以 CSR 公钥签发证书（测试 CA 自签链）。
func signWithCA(t *testing.T, csr *x509.CertificateRequest, caKey *ecdsa.PrivateKey, notBefore, notAfter time.Time) []byte {
	t.Helper()
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR 签名: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "agent-1"}, // 服务端填 agent_id
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, csr.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestGenerateSaveLoadKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.key")

	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if key.Curve != elliptic.P256() {
		t.Fatal("曲线应为 P-256")
	}
	if err := SaveKey(path, key); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("私钥权限=%o，应 0600", perm)
	}
	loaded, err := LoadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.D.Cmp(key.D) != 0 {
		t.Fatal("加载密钥与保存密钥不一致")
	}
}

func TestLoadOrGenerateKeyReuse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "agent.key") // 父目录不存在 → 自动创建

	k1, err := LoadOrGenerateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := LoadOrGenerateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if k1.D.Cmp(k2.D) != 0 {
		t.Fatal("已存在且可用的密钥应复用")
	}

	// 已存在但损坏 → 报错且不覆盖
	bad := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(bad, []byte("not-a-pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrGenerateKey(bad); err == nil {
		t.Fatal("损坏密钥应报错")
	}
	data, _ := os.ReadFile(bad)
	if string(data) != "not-a-pem" {
		t.Fatal("损坏密钥不应被覆盖")
	}
}

func TestParseKeyRejectsNonP256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemData, err := MarshalKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseKeyPEM(pemData); err == nil {
		t.Fatal("非 P-256 私钥应拒绝")
	}
}

func TestCSRCNEmpty(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, err := NewCSR(key)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		t.Fatalf("CSR PEM 类型=%q", block)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "" {
		t.Fatalf("CSR CN 应留空（由服务端填 agent_id），got %q", csr.Subject.CommonName)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR 自签名校验: %v", err)
	}
	if _, ok := csr.PublicKey.(*ecdsa.PublicKey); !ok {
		t.Fatal("CSR 公钥应为 ECDSA")
	}
}

func TestCertificatePEMRoundTripAndValidity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.crt")
	key, _ := GenerateKey()
	nb := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	na := nb.Add(90 * 24 * time.Hour)
	pemData := selfSignedCert(t, key, nb, na)

	if err := SaveCertificatePEM(path, pemData); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	if perm := fi.Mode().Perm(); perm != 0o644 {
		t.Fatalf("证书权限=%o，应 0644", perm)
	}
	c, raw, err := LoadCertificatePEM(path)
	if err != nil {
		t.Fatal(err)
	}
	if !c.NotBefore.Equal(nb) || !c.NotAfter.Equal(na) {
		t.Fatalf("有效期解析错误: %s ~ %s", c.NotBefore, c.NotAfter)
	}
	if string(raw) != string(pemData) {
		t.Fatal("证书 PEM 原文应保持一致")
	}
	if c.Subject.CommonName != "agent-1" {
		t.Fatalf("CN=%q", c.Subject.CommonName)
	}

	// 非法 PEM 拒存
	if err := SaveCertificatePEM(filepath.Join(dir, "x.crt"), []byte("garbage")); err == nil {
		t.Fatal("非法证书 PEM 应拒存")
	}
}

func TestNeedsRotationTiming(t *testing.T) {
	nb := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	na := nb.Add(90 * 24 * time.Hour) // TTL 90 天
	cases := []struct {
		name string
		now  time.Time
		want bool
	}{
		{"刚签发", nb, false},
		{"存活 44 天", nb.Add(44 * 24 * time.Hour), false},
		{"存活期过半（45 天）", nb.Add(45 * 24 * time.Hour), true},
		{"距到期 <1/3 TTL", na.Add(-29 * 24 * time.Hour), true},
		{"已过期", na.Add(time.Second), false},
		{"恰到期", na, false},
	}
	for _, tc := range cases {
		if got := NeedsRotation(tc.now, nb, na); got != tc.want {
			t.Errorf("%s: NeedsRotation=%v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestLoadIdentity(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, KeyFileName)
	certPath := filepath.Join(dir, CertFileName)

	// 两文件均缺失 → (nil, nil)，Bearer 模式
	id, err := LoadIdentity(keyPath, certPath)
	if err != nil || id != nil {
		t.Fatalf("缺失时应 (nil,nil)，got id=%v err=%v", id, err)
	}

	key, _ := GenerateKey()
	if err := SaveKey(keyPath, key); err != nil {
		t.Fatal(err)
	}
	// 仅密钥存在 → (nil, nil)
	if id, err := LoadIdentity(keyPath, certPath); err != nil || id != nil {
		t.Fatalf("仅密钥存在应 (nil,nil)，got id=%v err=%v", id, err)
	}

	nb := time.Now().Add(-time.Hour)
	na := time.Now().Add(90 * 24 * time.Hour)
	if err := SaveCertificatePEM(certPath, selfSignedCert(t, key, nb, na)); err != nil {
		t.Fatal(err)
	}
	id, err = LoadIdentity(keyPath, certPath)
	if err != nil {
		t.Fatal(err)
	}
	if id == nil || id.Expired(time.Now()) || id.Due(time.Now()) {
		t.Fatalf("identity=%+v", id)
	}

	// 钥证不匹配 → 错误
	other, _ := GenerateKey()
	if err := SaveKey(keyPath, other); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadIdentity(keyPath, certPath); err == nil {
		t.Fatal("钥证不匹配应报错")
	}
}
