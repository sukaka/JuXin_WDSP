package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/transport"
)

// lostResponseClient issues once, drops that response, then replays the same
// server result. The second request must carry the same CSR public key.
type lostResponseClient struct {
	inner *csrIssuingClient
	first *transport.RotateCertResponse
	csrs  []string
}

func (c *lostResponseClient) RotateCert(ctx context.Context, agentID, csrPEM string) (*transport.RotateCertResponse, error) {
	c.csrs = append(c.csrs, csrPEM)
	if len(c.csrs) == 1 {
		resp, err := c.inner.RotateCert(ctx, agentID, csrPEM)
		if err != nil {
			return nil, err
		}
		c.first = resp
		return nil, errors.New("response lost after server commit")
	}
	return c.first, nil
}

func TestManagerRotatePendingSurvivesRestartAndReplaysCSR(t *testing.T) {
	m, _, _ := setupManager(t, nil)
	var issued []byte
	client := &lostResponseClient{inner: &csrIssuingClient{
		t: t, notBefore: time.Now().Add(-time.Hour), notAfter: time.Now().Add(90 * 24 * time.Hour),
		out: &issued,
	}}
	if err := m.Rotate(context.Background(), client, "agent-1"); err == nil {
		t.Fatal("响应丢失后首次轮换应返回错误")
	}
	if _, err := os.Stat(m.pendingRotationPath()); err != nil {
		t.Fatalf("响应丢失后应保留 pending: %v", err)
	}

	// A fresh process must recover the pending key and exact CSR from disk.
	m2 := NewManager(m.KeyPath, m.CertPath, m.CAPath, nil)
	if _, err := m2.Load(); err != nil {
		t.Fatal(err)
	}
	if err := m2.Rotate(context.Background(), client, "agent-1"); err != nil {
		t.Fatalf("重启后重试应成功: %v", err)
	}
	if len(client.csrs) != 2 || client.csrs[0] != client.csrs[1] {
		t.Fatal("重试必须复用同一 CSR")
	}
	if _, err := os.Stat(m.pendingRotationPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("成功提交后应清理 pending，err=%v", err)
	}
}

func TestManagerRotatePendingSurvivesLocalPersistFailure(t *testing.T) {
	m, _, _ := setupManager(t, nil)
	var issued []byte
	client := &csrIssuingClient{t: t, notBefore: time.Now().Add(-time.Hour), notAfter: time.Now().Add(90 * 24 * time.Hour), out: &issued}
	m.persistBundleFn = func(string, string, string, *ecdsa.PrivateKey, []byte, []byte) error {
		return errors.New("local persist failed")
	}
	if err := m.Rotate(context.Background(), client, "agent-1"); err == nil {
		t.Fatal("本地持久化失败应返回错误")
	}
	firstCSR := client.gotCSR
	if _, err := os.Stat(m.pendingRotationPath()); err != nil {
		t.Fatalf("本地持久化失败后应保留 pending: %v", err)
	}

	m.persistBundleFn = persistBundle
	if err := m.Rotate(context.Background(), client, "agent-1"); err != nil {
		t.Fatalf("复用 pending 重试应成功: %v", err)
	}
	if client.gotCSR != firstCSR {
		t.Fatal("本地持久化失败后的重试必须复用同一 CSR")
	}
	if _, err := os.Stat(m.pendingRotationPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("成功提交后应清理 pending，err=%v", err)
	}
}

func TestManagerLoadRecoversSignedPendingAfterPartialBundleCommit(t *testing.T) {
	m, oldKey, oldCertPEM := setupManager(t, nil)
	newKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := NewCSR(newKey)
	if err != nil {
		t.Fatal(err)
	}
	csrBlock, _ := pemDecode(string(csr))
	parsedCSR, err := x509.ParseCertificateRequest(csrBlock)
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	newCertPEM := signWithCA(t, parsedCSR, caKey, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	caPEM := selfSignedCert(t, caKey, time.Now().Add(-time.Hour), time.Now().Add(90*24*time.Hour))
	oldCert, err := ParseCertificatePEM(oldCertPEM)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := MarshalKeyPEM(newKey)
	if err != nil {
		t.Fatal(err)
	}
	pending := &pendingRotation{
		AgentID:        "agent-1",
		OldFingerprint: certFingerprint(oldCert),
		PrivateKeyPEM:  string(keyPEM),
		CSRPEM:         string(csr),
		AgentCertPEM:   string(newCertPEM),
		CACertPEM:      string(caPEM),
	}
	if err := savePendingRotation(m.pendingRotationPath(), pending); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash after key rename but before cert/CA renames.
	if err := SaveKey(m.KeyPath, newKey); err != nil {
		t.Fatal(err)
	}
	if got, _, err := LoadCertificatePEM(m.CertPath); err != nil || string(got.Raw) != string(oldCert.Raw) {
		t.Fatalf("证书应仍为旧证书: %v", err)
	}
	if oldKey.D.Cmp(newKey.D) == 0 {
		t.Fatal("测试必须使用不同的新私钥")
	}

	m2 := NewManager(m.KeyPath, m.CertPath, m.CAPath, nil)
	id, err := m2.Load()
	if err != nil {
		t.Fatalf("Load 应从已签发 pending 恢复: %v", err)
	}
	if id == nil || id.Key.D.Cmp(newKey.D) != 0 {
		t.Fatal("恢复后应使用 pending 新私钥")
	}
	cert, _, err := LoadCertificatePEM(m.CertPath)
	if err != nil {
		t.Fatal(err)
	}
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok || !pub.Equal(newKey.Public()) {
		t.Fatal("恢复后的证书必须与新私钥匹配")
	}
	if _, err := os.Stat(m.pendingRotationPath()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("恢复完成后应清理 pending，err=%v", err)
	}
}
