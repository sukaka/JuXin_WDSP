// 代码审查回归测试（批次5-A）：
// LOW-A4 证书轮换回滚不再吞错：回滚成功恢复旧私钥；回滚失败显式上报
// ErrRollbackFailed（磁盘钥证不匹配死状态，需重新注册）。
package cert

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// certPathAsDir 让 CertPath 指向已存在目录：原子写 rename 文件覆盖目录失败，
// 触发轮换中途的证书写失败（回滚路径）。
func certPathAsDir(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cert-as-dir")
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

// 证书写失败触发回滚：旧私钥须恢复（不得留下新私钥+旧证书的不匹配状态）。
func TestManagerRotateRollbackRestoresOldKey(t *testing.T) {
	m, oldKey, oldCertPEM := setupManager(t, nil)
	m.CertPath = certPathAsDir(t)
	var issued []byte
	issuing := &csrIssuingClient{t: t, notBefore: time.Now().Add(-time.Hour),
		notAfter: time.Now().Add(90 * 24 * time.Hour), out: &issued}

	err := m.Rotate(context.Background(), issuing, "agent-1")
	if err == nil {
		t.Fatal("证书写失败应返回错误")
	}
	if errors.Is(err, ErrRollbackFailed) {
		t.Fatalf("回滚应成功，不应上报 ErrRollbackFailed: %v", err)
	}
	key, kerr := LoadKey(m.KeyPath)
	if kerr != nil {
		t.Fatal(kerr)
	}
	if key.D.Cmp(oldKey.D) != 0 {
		t.Fatal("回滚后磁盘私钥应恢复为旧件")
	}
	// 证书与内存身份未被污染
	if string(mustRead(t, filepath.Join(filepath.Dir(m.KeyPath), CertFileName))) != string(oldCertPEM) {
		t.Fatal("旧证书应保持不变")
	}
	if m.Identity().Key.D.Cmp(oldKey.D) != 0 {
		t.Fatal("内存身份应保持旧件")
	}
}

// 回滚本身失败（旧私钥备份损坏）：错误须显式携带 ErrRollbackFailed，
// 由调用方 Error 级上报（不得静默留下钥证不匹配死状态）。
func TestManagerRotateRollbackFailureReported(t *testing.T) {
	m, _, _ := setupManager(t, nil)
	// 破坏旧私钥备份 → 回滚时 ParseKeyPEM 失败
	if err := os.WriteFile(m.KeyPath, []byte("not a pem"), 0o600); err != nil {
		t.Fatal(err)
	}
	m.CertPath = certPathAsDir(t)
	var issued []byte
	issuing := &csrIssuingClient{t: t, notBefore: time.Now().Add(-time.Hour),
		notAfter: time.Now().Add(90 * 24 * time.Hour), out: &issued}

	err := m.Rotate(context.Background(), issuing, "agent-1")
	if err == nil {
		t.Fatal("证书写失败应返回错误")
	}
	if !errors.Is(err, ErrRollbackFailed) {
		t.Fatalf("回滚失败须显式上报 ErrRollbackFailed: %v", err)
	}
}
