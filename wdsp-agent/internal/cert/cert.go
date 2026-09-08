// Package cert 机器身份证书（Phase 2-B，契约 §7-§9/§12）客户端侧工具：
//
//   - ECDSA P-256 密钥对生成与 PEM 读写（私钥 0600，证书 0644，均 tmp+rename 原子落盘）；
//   - CSR 生成（CN 留空，由服务端填 agent_id，契约 §7）；
//   - 证书 PEM 解析与有效期读取；
//   - Identity（密钥+证书匹配对）加载与轮换时机判定（存活期过半，契约 §9）。
package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// 状态目录内固定文件名（契约 §12）。
const (
	KeyFileName  = "agent.key"
	CertFileName = "agent.crt"
	CAFileName   = "ca.crt"
)

// GenerateKey 生成 ECDSA P-256 私钥。
func GenerateKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成 P-256 密钥: %w", err)
	}
	return key, nil
}

// MarshalKeyPEM 私钥编码为 SEC1 "EC PRIVATE KEY" PEM。
func MarshalKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("编码私钥: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// ParseKeyPEM 解析 PEM 私钥并校验为 P-256。
func ParseKeyPEM(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("非法私钥 PEM")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		// 兼容 PKCS#8 包装
		if k8, err8 := x509.ParsePKCS8PrivateKey(block.Bytes); err8 == nil {
			if ek, ok := k8.(*ecdsa.PrivateKey); ok {
				key = ek
			} else {
				return nil, errors.New("私钥非 ECDSA")
			}
		} else {
			return nil, fmt.Errorf("解析私钥: %w", err)
		}
	}
	if key.Curve != elliptic.P256() {
		return nil, errors.New("私钥曲线非 P-256")
	}
	return key, nil
}

// writeFileAtomic tmp+rename 原子写文件并修正权限（与 config.Save 同口径）。
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("创建目录: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return fmt.Errorf("写临时文件: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("替换文件: %w", err)
	}
	if err := os.Chmod(path, perm); err != nil {
		return fmt.Errorf("修正权限: %w", err)
	}
	return nil
}

// SaveKey 私钥原子落盘（0600，契约 §12）。
func SaveKey(path string, key *ecdsa.PrivateKey) error {
	data, err := MarshalKeyPEM(key)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(path, data, 0o600); err != nil {
		return fmt.Errorf("保存私钥 %s: %w", path, err)
	}
	return nil
}

// LoadKey 读取并解析私钥（P-256 校验）。
func LoadKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取私钥 %s: %w", path, err)
	}
	return ParseKeyPEM(data)
}

// LoadOrGenerateKey 已存在且可用则复用，不存在则生成并落盘；存在但损坏返回错误（不覆盖）。
func LoadOrGenerateKey(path string) (*ecdsa.PrivateKey, error) {
	key, err := LoadKey(path)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key, err = GenerateKey()
	if err != nil {
		return nil, err
	}
	if err := SaveKey(path, key); err != nil {
		return nil, err
	}
	return key, nil
}

// NewCSR 生成 PKCS#10 CSR（PEM）；CN 留空，由服务端填 agent_id（契约 §7）。
func NewCSR(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{}, // CN 留空（契约 §7）
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
	if err != nil {
		return nil, fmt.Errorf("生成 CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// ParseCertificatePEM 解析证书 PEM。
func ParseCertificatePEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("非法证书 PEM")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析证书: %w", err)
	}
	return c, nil
}

// SaveCertificatePEM 证书/CA 原子落盘（0644，公钥材料无需保密）。
func SaveCertificatePEM(path string, data []byte) error {
	if _, err := ParseCertificatePEM(data); err != nil {
		return fmt.Errorf("拒存非法证书 %s: %w", path, err)
	}
	if err := writeFileAtomic(path, data, 0o644); err != nil {
		return fmt.Errorf("保存证书 %s: %w", path, err)
	}
	return nil
}

// LoadCertificatePEM 读取并解析证书文件。
func LoadCertificatePEM(path string) (*x509.Certificate, []byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("读取证书 %s: %w", path, err)
	}
	c, err := ParseCertificatePEM(data)
	if err != nil {
		return nil, nil, err
	}
	return c, data, nil
}

// Identity 机器身份：私钥 + 与之匹配的客户端证书。
type Identity struct {
	Key     *ecdsa.PrivateKey
	Cert    *x509.Certificate
	CertPEM []byte
}

// LoadIdentity 加载密钥+证书并校验公钥匹配；任一文件缺失返回 (nil, nil)（无证书=Bearer 模式）。
func LoadIdentity(keyPath, certPath string) (*Identity, error) {
	if _, err := os.Stat(keyPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("检查私钥: %w", err)
	}
	if _, err := os.Stat(certPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("检查证书: %w", err)
	}
	key, err := LoadKey(keyPath)
	if err != nil {
		return nil, err
	}
	c, pemData, err := LoadCertificatePEM(certPath)
	if err != nil {
		return nil, err
	}
	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(key.Public()) {
		return nil, errors.New("证书公钥与私钥不匹配")
	}
	return &Identity{Key: key, Cert: c, CertPEM: pemData}, nil
}

// Expired 证书是否已过期。
func (id *Identity) Expired(now time.Time) bool {
	return !now.Before(id.Cert.NotAfter)
}

// NeedsRotation 轮换时机（契约 §9）：证书存活期过半（TTL/2）即轮换；
// 距到期 <1/3 TTL 的情形必然更晚到达，被该条件覆盖。已过期不再轮换
// （rotate-cert 仅接受 PoP 认证，过期证书无法自举，需管理员重新注册）。
func NeedsRotation(now, notBefore, notAfter time.Time) bool {
	if !now.Before(notAfter) {
		return false
	}
	ttl := notAfter.Sub(notBefore)
	if ttl <= 0 {
		return false
	}
	return !now.Before(notBefore.Add(ttl / 2))
}

// Due 当前身份是否到达轮换时机（无身份或已过期返回 false）。
func (id *Identity) Due(now time.Time) bool {
	if id == nil {
		return false
	}
	return NeedsRotation(now, id.Cert.NotBefore, id.Cert.NotAfter)
}
