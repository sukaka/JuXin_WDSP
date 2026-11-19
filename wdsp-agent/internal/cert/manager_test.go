package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/transport"
)

// fakeRotateClient 测试用 rotate-cert 端点桩。
type fakeRotateClient struct {
	certPEM []byte // 成功时返回的新证书
	caPEM   []byte
	err     error  // 非 nil 则模拟失败
	gotCSR  string // 记录上送 CSR
	calls   int
}

func (f *fakeRotateClient) RotateCert(_ context.Context, _, csrPEM string) (*transport.RotateCertResponse, error) {
	f.calls++
	f.gotCSR = csrPEM
	if f.err != nil {
		return nil, f.err
	}
	return &transport.RotateCertResponse{
		AgentCertPEM:  string(f.certPEM),
		CACertPEM:     string(f.caPEM),
		CertExpiresAt: "2026-12-31T00:00:00Z",
	}, nil
}

// setupManager 创建带初始身份（旧密钥+旧证书）的管理器。
func setupManager(t *testing.T, now func() time.Time) (*Manager, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	dir := t.TempDir()
	oldKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	nb := time.Now().Add(-60 * 24 * time.Hour) // 已存活 60 天（TTL 90 天 → 已过半）
	na := time.Now().Add(30 * 24 * time.Hour)
	oldCertPEM := selfSignedCert(t, oldKey, nb, na)
	m := NewManager(
		filepath.Join(dir, KeyFileName),
		filepath.Join(dir, CertFileName),
		filepath.Join(dir, CAFileName),
		now,
	)
	if err := SaveKey(m.KeyPath, oldKey); err != nil {
		t.Fatal(err)
	}
	if err := SaveCertificatePEM(m.CertPath, oldCertPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Load(); err != nil {
		t.Fatal(err)
	}
	return m, oldKey, oldCertPEM
}

func TestManagerDueUsesInjectedClock(t *testing.T) {
	base := time.Now()
	var cur = base
	m, _, _ := setupManager(t, func() time.Time { return cur })

	// 初始证书已存活 60 天（TTL 90 天，过半）→ 到期轮换
	if !m.Due() {
		t.Fatal("已过半应到期轮换")
	}
	// 回拨时钟到签发初 → 不到期
	cur = base.Add(-55 * 24 * time.Hour) // 存活仅 5 天
	if m.Due() {
		t.Fatal("存活期未过半不应轮换")
	}
	// 推进到过期后 → 不再轮换（无法自举）
	cur = base.Add(31 * 24 * time.Hour)
	if m.Due() {
		t.Fatal("已过期不应再轮换")
	}
}

func TestManagerRotateSuccessAtomicReplace(t *testing.T) {
	m, oldKey, oldCertPEM := setupManager(t, nil)
	oldKeyBytes, _ := os.ReadFile(m.KeyPath)

	// 新证书由"服务端"用 CSR 公钥签发——桩里简化为新密钥自签，但管理器会校验
	// 新证书公钥必须与新私钥匹配，因此桩需要拿到 CSR。这里用二次调用模式：
	// 先让桩解析 CSR 再签发。为简单起见使用 proxy 桩：
	var issued []byte
	issuing := &csrIssuingClient{t: t, notBefore: time.Now().Add(-time.Hour), notAfter: time.Now().Add(90 * 24 * time.Hour), out: &issued}

	if err := m.Rotate(context.Background(), issuing, "agent-1"); err != nil {
		t.Fatal(err)
	}

	// 内存身份已更新
	id := m.Identity()
	if id == nil || id.Key.D.Cmp(oldKey.D) == 0 {
		t.Fatal("轮换后应为新私钥")
	}
	// 磁盘密钥/证书已原子替换且彼此匹配
	newKey, err := LoadKey(m.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if newKey.D.Cmp(oldKey.D) == 0 || newKey.D.Cmp(id.Key.D) != 0 {
		t.Fatal("磁盘私钥应为新密钥")
	}
	newCert, _, err := LoadCertificatePEM(m.CertPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(mustRead(t, m.CertPath)) == string(oldCertPEM) {
		t.Fatal("磁盘证书应已替换")
	}
	pub, ok := newCert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(newKey.Public()) {
		t.Fatal("新证书与新私钥不匹配")
	}
	// CA 文件已写
	if fi, err := os.Stat(m.CAPath); err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("CA 文件状态: %v %v", fi, err)
	}
	// 轮换后未过半 → 不再到期
	if m.Due() {
		t.Fatal("新证书刚签发不应到期轮换")
	}
	// TransportIdentity 可转换
	ti := m.TransportIdentity()
	if ti == nil || len(ti.CertDER) == 0 || !ti.NotAfter.Equal(newCert.NotAfter) {
		t.Fatalf("TransportIdentity=%+v", ti)
	}
	_ = oldKeyBytes
}

// csrIssuingClient 模拟服务端：解析 CSR 并用 CSR 公钥签发新证书（自签，测试用）。
type csrIssuingClient struct {
	t                   *testing.T
	notBefore, notAfter time.Time
	out                 *[]byte
	gotCSR              string
}

func (c *csrIssuingClient) RotateCert(_ context.Context, _, csrPEM string) (*transport.RotateCertResponse, error) {
	c.gotCSR = csrPEM
	block, _ := pemDecode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block)
	if err != nil {
		c.t.Fatalf("服务端桩解析 CSR: %v", err)
	}
	if csr.Subject.CommonName != "" {
		c.t.Fatalf("CSR CN 应留空，got %q", csr.Subject.CommonName)
	}
	caKey, _ := GenerateKey()
	certPEM := signWithCA(c.t, csr, caKey, c.notBefore, c.notAfter)
	caPEM := selfSignedCert(c.t, caKey, c.notBefore, c.notAfter)
	*c.out = certPEM
	return &transport.RotateCertResponse{
		AgentCertPEM:  string(certPEM),
		CACertPEM:     string(caPEM),
		CertExpiresAt: c.notAfter.UTC().Format(time.RFC3339),
	}, nil
}

func TestManagerRotateFailureKeepsOld(t *testing.T) {
	m, oldKey, oldCertPEM := setupManager(t, nil)
	fc := &fakeRotateClient{err: errors.New("server 503")}

	if err := m.Rotate(context.Background(), fc, "agent-1"); err == nil {
		t.Fatal("轮换应失败")
	}
	// 磁盘与内存保持旧件
	key, err := LoadKey(m.KeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if key.D.Cmp(oldKey.D) != 0 {
		t.Fatal("失败后私钥应保持旧件")
	}
	if string(mustRead(t, m.CertPath)) != string(oldCertPEM) {
		t.Fatal("失败后证书应保持旧件")
	}
	if m.Identity().Key.D.Cmp(oldKey.D) != 0 {
		t.Fatal("失败后内存身份应保持旧件")
	}
	// 上送的 CSR 是新密钥的（CN 留空）
	if fc.gotCSR == "" {
		t.Fatal("应已上送 CSR")
	}
}

func TestManagerRotateRejectsMismatchedResponse(t *testing.T) {
	m, oldKey, _ := setupManager(t, nil)
	// 服务端返回的证书与新私钥不匹配（用另一个密钥自签）→ 拒绝且保留旧件
	other, _ := GenerateKey()
	badCert := selfSignedCert(t, other, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	fc := &fakeRotateClient{certPEM: badCert}

	if err := m.Rotate(context.Background(), fc, "agent-1"); err == nil {
		t.Fatal("钥证不匹配的响应应拒绝")
	}
	key, _ := LoadKey(m.KeyPath)
	if key.D.Cmp(oldKey.D) != 0 {
		t.Fatal("拒绝后私钥应保持旧件")
	}
	if m.Identity().Key.D.Cmp(oldKey.D) != 0 {
		t.Fatal("拒绝后内存身份应保持旧件")
	}
}

func TestManagerRotateWithoutIdentity(t *testing.T) {
	m := NewManager(filepath.Join(t.TempDir(), KeyFileName), "x", "y", nil)
	fc := &fakeRotateClient{}
	if err := m.Rotate(context.Background(), fc, "agent-1"); err == nil {
		t.Fatal("无身份应拒绝轮换")
	}
	if fc.calls != 0 {
		t.Fatal("无身份不应发起请求")
	}
}

func TestManagerLoadWithPendingAndMissingKeyCertNoPanic(t *testing.T) {
	dir := t.TempDir()
	key, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := MarshalKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := NewCSR(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := selfSignedCert(t, key, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	m := NewManager(
		filepath.Join(dir, KeyFileName),
		filepath.Join(dir, CertFileName),
		filepath.Join(dir, CAFileName),
		nil,
	)
	if err := savePendingRotation(m.pendingRotationPath(), &pendingRotation{
		AgentID:        "agent-1",
		OldFingerprint: "oldfp",
		PrivateKeyPEM:  string(keyPEM),
		CSRPEM:         string(csr),
		AgentCertPEM:   string(certPEM),
	}); err != nil {
		t.Fatal(err)
	}
	// Both agent.key and agent.crt are missing -> Load must not panic on nil id, and should recover cleanly
	id, err := m.Load()
	if err != nil {
		t.Fatalf("Load returned unexpected error: %v", err)
	}
	if id == nil || id.Cert == nil {
		t.Fatal("expected recovered identity from signed pending rotation")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
