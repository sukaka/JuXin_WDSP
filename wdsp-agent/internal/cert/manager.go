// 证书轮换管理器（契约 §9/§12）：新密钥对+CSR → rotate-cert → 原子替换本地三件套。
package cert

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/transport"
)

// RotateClient 轮换端点抽象（*transport.Client 实现；契约 §9，仅 PoP 认证可用）。
type RotateClient interface {
	RotateCert(ctx context.Context, agentID, csrPEM string) (*transport.RotateCertResponse, error)
}

// ErrRollbackFailed 证书轮换中途失败且旧私钥回滚也失败：磁盘上可能留下
// 新私钥+旧证书的不匹配死状态（需管理员触发重新注册）。调用方须 Error 级上报。
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
}

// NewManager 创建管理器；now 为 nil 时用 time.Now。
func NewManager(keyPath, certPath, caPath string, now func() time.Time) *Manager {
	if now == nil {
		now = time.Now
	}
	return &Manager{KeyPath: keyPath, CertPath: certPath, CAPath: caPath, Now: now}
}

// Load 从磁盘加载现有身份；两文件均缺失返回 (nil, nil)。
func (m *Manager) Load() (*Identity, error) {
	id, err := LoadIdentity(m.KeyPath, m.CertPath)
	if err != nil {
		return nil, err
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

// Rotate 执行一次轮换。失败返回错误且本地文件与内存身份保持不变。
func (m *Manager) Rotate(ctx context.Context, c RotateClient, agentID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.id == nil {
		return errors.New("无当前证书，无法轮换（rotate-cert 仅接受 PoP 认证）")
	}
	if m.id.Expired(m.Now()) {
		return errors.New("当前证书已过期，无法自举轮换（需管理员重新注册）")
	}

	newKey, err := GenerateKey()
	if err != nil {
		return err
	}
	csr, err := NewCSR(newKey)
	if err != nil {
		return err
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

	// 原子替换：先密钥后证书；证书/CA 写失败时回滚密钥，避免钥证不匹配的死状态。
	oldKeyPEM, _ := os.ReadFile(m.KeyPath)
	if err := SaveKey(m.KeyPath, newKey); err != nil {
		return err
	}
	if err := SaveCertificatePEM(m.CertPath, []byte(resp.AgentCertPEM)); err != nil {
		if rerr := m.rollbackKey(oldKeyPEM); rerr != nil {
			return fmt.Errorf("保存新证书: %w；回滚旧私钥亦失败（%w: %v），磁盘可能处于钥证不匹配状态，需重新注册", err, ErrRollbackFailed, rerr)
		}
		return err
	}
	if resp.CACertPEM != "" {
		if err := SaveCertificatePEM(m.CAPath, []byte(resp.CACertPEM)); err != nil {
			if rerr := m.rollbackKey(oldKeyPEM); rerr != nil {
				return fmt.Errorf("保存新 CA: %w；回滚旧私钥亦失败（%w: %v），磁盘可能处于钥证不匹配状态，需重新注册", err, ErrRollbackFailed, rerr)
			}
			return err
		}
	}

	m.id = &Identity{Key: newKey, Cert: newCert, CertPEM: []byte(resp.AgentCertPEM)}
	return nil
}

// rollbackKey 轮换中途失败时恢复旧私钥；回滚本身失败返回错误（不得静默——
// 失败意味着磁盘上钥证不匹配的死状态，调用方必须显式上报）。
func (m *Manager) rollbackKey(oldKeyPEM []byte) error {
	if len(oldKeyPEM) == 0 {
		return errors.New("旧私钥备份为空，无法回滚")
	}
	key, err := ParseKeyPEM(oldKeyPEM)
	if err != nil {
		return fmt.Errorf("解析旧私钥: %w", err)
	}
	if err := SaveKey(m.KeyPath, key); err != nil {
		return fmt.Errorf("回写旧私钥: %w", err)
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
