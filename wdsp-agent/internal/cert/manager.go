// 证书轮换管理器（契约 §9/§12）：新密钥对+CSR → rotate-cert → 原子替换本地三件套。
package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/transport"
)

// RotateClient 轮换端点抽象（*transport.Client 实现；契约 §9，仅 PoP 认证可用）。
type RotateClient interface {
	RotateCert(ctx context.Context, agentID, csrPEM string) (*transport.RotateCertResponse, error)
}

// ErrRollbackFailed 证书轮换失败后无法恢复完整旧 bundle。
var ErrRollbackFailed = errors.New("证书轮换回滚失败")

// Manager 管理 agent.key/agent.crt/ca.crt 三件套的加载与原子轮换。
// 轮换流程：生成新密钥对+CSR（CN 留空）→ 用当前证书 PoP 调 rotate-cert →
// 成功后原子替换密钥与证书并更新内存身份；任何一步失败保留旧件（旧证书到期前持续可用）。
type Manager struct {
	KeyPath  string
	CertPath string
	CAPath   string
	Now      func() time.Time // 可注入（测试）

	mu sync.Mutex
	id *Identity // 当前身份（nil=Bearer 模式）

	// persistBundleFn is injectable only for failure-path tests; production uses
	// the complete bundle implementation below.
	persistBundleFn func(string, string, string, *ecdsa.PrivateKey, []byte, []byte) error
}

// NewManager 创建管理器；now 为 nil 时用 time.Now。
func NewManager(keyPath, certPath, caPath string, now func() time.Time) *Manager {
	if now == nil {
		now = time.Now
	}
	return &Manager{KeyPath: keyPath, CertPath: certPath, CAPath: caPath, Now: now, persistBundleFn: persistBundle}
}

// Load 从磁盘加载现有身份；两文件均缺失返回 (nil, nil)。
func (m *Manager) Load() (*Identity, error) {
	pending, pendingErr := loadPendingRotation(m.pendingRotationPath())
	if pendingErr != nil {
		return nil, pendingErr
	}
	id, err := LoadIdentity(m.KeyPath, m.CertPath)
	if err != nil {
		if pending == nil || pending.AgentCertPEM == "" {
			return nil, err
		}
		// A process may have exited between the individual compatibility-path
		// renames. The signed pending bundle is the recovery source of truth.
		if err := persistCompleteBundle(m.KeyPath, m.CertPath, m.CAPath, pending.PrivateKeyPEM, []byte(pending.AgentCertPEM), []byte(pending.CACertPEM)); err != nil {
			return nil, fmt.Errorf("恢复待轮换 bundle: %w", err)
		}
		id, err = LoadIdentity(m.KeyPath, m.CertPath)
		if err != nil {
			return nil, fmt.Errorf("校验恢复后的身份: %w", err)
		}
	}
	if pending != nil && pending.AgentCertPEM != "" {
		pendingCert, parseErr := ParseCertificatePEM([]byte(pending.AgentCertPEM))
		if parseErr != nil {
			return nil, fmt.Errorf("待轮换新证书: %w", parseErr)
		}
		if certFingerprint(id.Cert) == certFingerprint(pendingCert) {
			if err := clearPendingRotation(m.pendingRotationPath()); err != nil {
				return nil, err
			}
		}
	}
	m.mu.Lock()
	m.id = id
	m.mu.Unlock()
	return id, nil
}

// Identity 当前身份（nil=无证书）。
func (m *Manager) Identity() *Identity {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.id
}

// TransportIdentity 转换为 transport 层 PoP 身份（无证书返回 nil）。
func (m *Manager) TransportIdentity() *transport.Identity {
	m.mu.Lock()
	defer m.mu.Unlock()
	return toTransportIdentity(m.id)
}

// Due 是否到达轮换时机（无身份或已过期返回 false）。
func (m *Manager) Due() bool {
	m.mu.Lock()
	id := m.id
	m.mu.Unlock()
	return id.Due(m.Now())
}

// Rotate 执行一次轮换。失败返回错误且本地三件套与内存身份保持不变。
func (m *Manager) Rotate(ctx context.Context, c RotateClient, agentID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.id == nil {
		return errors.New("无当前证书，无法轮换（rotate-cert 仅接受 PoP 认证）")
	}
	if m.id.Expired(m.Now()) {
		return errors.New("当前证书已过期，无法自举轮换（需管理员重新注册）")
	}

	oldFingerprint := certFingerprint(m.id.Cert)
	pending, err := loadPendingRotation(m.pendingRotationPath())
	if err != nil {
		return err
	}
	if pending != nil && pending.AgentID != agentID {
		return errors.New("待轮换身份属于其他 Agent")
	}
	if pending != nil && pending.OldFingerprint != oldFingerprint {
		// A completed rotation whose cleanup was interrupted leaves a stale
		// marker. The current certificate proves it is safe to discard it.
		if err := clearPendingRotation(m.pendingRotationPath()); err != nil {
			return err
		}
		pending = nil
	}

	var newKey *ecdsa.PrivateKey
	var csr []byte
	if pending != nil {
		newKey, err = ParseKeyPEM([]byte(pending.PrivateKeyPEM))
		if err != nil {
			return fmt.Errorf("待轮换私钥: %w", err)
		}
		csr = []byte(pending.CSRPEM)
	} else {
		newKey, err = GenerateKey()
		if err != nil {
			return err
		}
		csr, err = NewCSR(newKey)
		if err != nil {
			return err
		}
		keyPEM, err := MarshalKeyPEM(newKey)
		if err != nil {
			return err
		}
		pending = &pendingRotation{AgentID: agentID, OldFingerprint: oldFingerprint, PrivateKeyPEM: string(keyPEM), CSRPEM: string(csr)}
		if err := savePendingRotation(m.pendingRotationPath(), pending); err != nil {
			return err
		}
	}
	resp, err := c.RotateCert(ctx, agentID, string(csr))
	if err != nil {
		return fmt.Errorf("rotate-cert: %w", err)
	}
	newCert, err := ParseCertificatePEM([]byte(resp.AgentCertPEM))
	if err != nil {
		return fmt.Errorf("新证书: %w", err)
	}
	pub, ok := newCert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(newKey.Public()) {
		return errors.New("新证书公钥与新私钥不匹配（服务端响应异常）")
	}
	// Durably record the signed response before replacing any compatibility
	// path, allowing Load to finish a commit interrupted by process death.
	pending.AgentCertPEM = resp.AgentCertPEM
	pending.CACertPEM = resp.CACertPEM
	if err := savePendingRotation(m.pendingRotationPath(), pending); err != nil {
		return err
	}

	// 先校验并备份三件套，再按完整 bundle 提交；任一步失败都恢复已替换的全部文件。
	if err := m.persistBundleFn(m.KeyPath, m.CertPath, m.CAPath, newKey, []byte(resp.AgentCertPEM), []byte(resp.CACertPEM)); err != nil {
		return err
	}

	m.id = &Identity{Key: newKey, Cert: newCert, CertPEM: []byte(resp.AgentCertPEM)}
	if err := clearPendingRotation(m.pendingRotationPath()); err != nil {
		return fmt.Errorf("轮换已提交但清理待轮换状态失败: %w", err)
	}
	return nil
}

func (m *Manager) pendingRotationPath() string {
	return filepath.Join(filepath.Dir(m.KeyPath), PendingRotationFileName)
}

func certFingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

func savePendingRotation(path string, pending *pendingRotation) error {
	data, err := json.Marshal(pending)
	if err != nil {
		return fmt.Errorf("编码待轮换状态: %w", err)
	}
	if err := writeFileAtomic(path, data, 0o600); err != nil {
		return fmt.Errorf("保存待轮换状态: %w", err)
	}
	return nil
}

func loadPendingRotation(path string) (*pendingRotation, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("读取待轮换状态: %w", err)
	}
	var pending pendingRotation
	if err := json.Unmarshal(data, &pending); err != nil {
		return nil, fmt.Errorf("解析待轮换状态: %w", err)
	}
	if pending.AgentID == "" || pending.OldFingerprint == "" || pending.PrivateKeyPEM == "" || pending.CSRPEM == "" {
		return nil, errors.New("待轮换状态不完整")
	}
	key, err := ParseKeyPEM([]byte(pending.PrivateKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("待轮换私钥无效: %w", err)
	}
	block, _ := pem.Decode([]byte(pending.CSRPEM))
	if block == nil || (block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST") {
		return nil, errors.New("待轮换 CSR 无效")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析待轮换 CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("待轮换 CSR 签名无效: %w", err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(key.Public()) {
		return nil, errors.New("待轮换 CSR 公钥与私钥不匹配")
	}
	if pending.AgentCertPEM != "" {
		cert, err := ParseCertificatePEM([]byte(pending.AgentCertPEM))
		if err != nil {
			return nil, fmt.Errorf("待轮换新证书无效: %w", err)
		}
		certPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok || !certPub.Equal(key.Public()) {
			return nil, errors.New("待轮换新证书公钥与私钥不匹配")
		}
		if pending.CACertPEM != "" {
			if _, err := ParseCertificatePEM([]byte(pending.CACertPEM)); err != nil {
				return nil, fmt.Errorf("待轮换 CA 无效: %w", err)
			}
		}
	}
	return &pending, nil
}

type pendingRotation struct {
	AgentID        string `json:"agent_id"`
	OldFingerprint string `json:"old_fingerprint"`
	PrivateKeyPEM  string `json:"private_key_pem"`
	CSRPEM         string `json:"csr_pem"`
	AgentCertPEM   string `json:"agent_cert_pem,omitempty"`
	CACertPEM      string `json:"ca_cert_pem,omitempty"`
}

func clearPendingRotation(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("删除待轮换状态: %w", err)
	}
	return nil
}

type bundleFile struct {
	path   string
	data   []byte
	exists bool
	perm   os.FileMode
}

// persistCompleteBundle finishes a signed pending rotation without relying on
// the old on-disk pair. It is deliberately idempotent: after a crash, Load can
// repeat these atomic compatibility-path writes until the pair is complete.
func persistCompleteBundle(keyPath, certPath, caPath, keyPEM string, certPEM, caPEM []byte) error {
	key, err := ParseKeyPEM([]byte(keyPEM))
	if err != nil {
		return fmt.Errorf("待轮换私钥无效: %w", err)
	}
	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		return fmt.Errorf("待轮换证书无效: %w", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(key.Public()) {
		return errors.New("待轮换证书公钥与私钥不匹配")
	}
	if len(caPEM) > 0 {
		if _, err := ParseCertificatePEM(caPEM); err != nil {
			return fmt.Errorf("待轮换 CA 无效: %w", err)
		}
	}
	keyData, err := MarshalKeyPEM(key)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(keyPath, keyData, 0o600); err != nil {
		return fmt.Errorf("恢复私钥: %w", err)
	}
	if err := writeFileAtomic(certPath, certPEM, 0o644); err != nil {
		return fmt.Errorf("恢复证书: %w", err)
	}
	if len(caPEM) > 0 {
		if err := writeFileAtomic(caPath, caPEM, 0o644); err != nil {
			return fmt.Errorf("恢复 CA: %w", err)
		}
	}
	return nil
}

// persistBundle stages and commits key/cert/CA as one logical identity. The files
// retain their compatibility paths; rollback covers every file already replaced.
func persistBundle(keyPath, certPath, caPath string, key *ecdsa.PrivateKey, certPEM, caPEM []byte) error {
	oldKey, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("读取旧私钥: %w", err)
	}
	oldCert, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("读取旧证书: %w", err)
	}
	// Validate the old pair before touching any path. This prevents a damaged
	// on-disk identity from being used as a rollback source.
	if _, err := ParseKeyPEM(oldKey); err != nil {
		return fmt.Errorf("旧私钥无效: %w", err)
	}
	oldCertParsed, err := ParseCertificatePEM(oldCert)
	if err != nil {
		return fmt.Errorf("旧证书无效: %w", err)
	}
	oldKeyParsed, _ := ParseKeyPEM(oldKey)
	oldPub, ok := oldCertParsed.PublicKey.(*ecdsa.PublicKey)
	if !ok || !oldPub.Equal(oldKeyParsed.Public()) {
		return errors.New("旧证书公钥与私钥不匹配")
	}
	if _, err := ParseCertificatePEM(certPEM); err != nil {
		return fmt.Errorf("新证书无效: %w", err)
	}
	if caPEM != nil && len(caPEM) > 0 {
		if _, err := ParseCertificatePEM(caPEM); err != nil {
			return fmt.Errorf("新 CA 无效: %w", err)
		}
	}
	oldCA, caErr := os.ReadFile(caPath)
	if caErr != nil && !errors.Is(caErr, os.ErrNotExist) {
		return fmt.Errorf("读取旧 CA: %w", caErr)
	}
	files := []bundleFile{
		{path: keyPath, data: oldKey, exists: true, perm: 0o600},
		{path: certPath, data: oldCert, exists: true, perm: 0o644},
		{path: caPath, data: oldCA, exists: caErr == nil, perm: 0o644},
	}
	newData := [][]byte{nil, certPEM, caPEM}
	keyData, err := MarshalKeyPEM(key)
	if err != nil {
		return err
	}
	newData[0] = keyData
	changed := 0
	for i, file := range files {
		if i == 2 && len(caPEM) == 0 {
			continue
		}
		if err := writeFileAtomic(file.path, newData[i], file.perm); err != nil {
			for j := changed - 1; j >= 0; j-- {
				if rerr := restoreBundleFile(files[j]); rerr != nil {
					return fmt.Errorf("保存证书 bundle: %w；恢复旧 bundle 失败（%w: %v）", err, ErrRollbackFailed, rerr)
				}
			}
			return fmt.Errorf("保存证书 bundle: %w", err)
		}
		changed++
	}
	return nil
}

func restoreBundleFile(file bundleFile) error {
	if file.exists {
		if err := writeFileAtomic(file.path, file.data, file.perm); err != nil {
			return err
		}
		return nil
	}
	if err := os.Remove(file.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func toTransportIdentity(id *Identity) *transport.Identity {
	if id == nil {
		return nil
	}
	return &transport.Identity{
		CertDER:  id.Cert.Raw,
		Key:      id.Key,
		NotAfter: id.Cert.NotAfter,
	}
}
