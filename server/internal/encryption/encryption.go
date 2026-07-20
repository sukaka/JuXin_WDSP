// Package encryption 提供应用级私钥加密（AES-256-GCM）。
// 主密钥通过环境变量注入，不得写入Git仓库或数据库。
package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ErrNoMasterKey 主密钥未配置。
var ErrNoMasterKey = errors.New("JIUZHANG_MASTER_KEY not configured")

// ErrInvalidCiphertext 密文格式错误或解密失败。
var ErrInvalidCiphertext = errors.New("invalid ciphertext or wrong key")

// Service 是加密服务。
type Service struct {
	key []byte
}

// NewFromEnv 从环境变量加载主密钥。
// 支持 hex(64字符) 或 base64 编码的32字节密钥。
func NewFromEnv() (*Service, error) {
	raw := strings.TrimSpace(os.Getenv("JIUZHANG_MASTER_KEY"))
	if raw == "" {
		return nil, ErrNoMasterKey
	}
	return NewFromString(raw)
}

// NewFromString 从字符串解析主密钥（hex 或 base64）。
func NewFromString(raw string) (*Service, error) {
	var key []byte
	var err error
	// 优先尝试 hex（64字符=32字节）
	if len(raw) == 64 {
		key, err = hex.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid hex master key: %w", err)
		}
	} else {
		key, err = base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 master key: %w", err)
		}
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes, got %d", len(key))
	}
	return &Service{key: key}, nil
}

// NewWithKey 用给定密钥构造（测试用）。
func NewWithKey(key []byte) (*Service, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes")
	}
	k := make([]byte, 32)
	copy(k, key)
	return &Service{key: k}, nil
}

// GenerateKey 生成新主密钥（hex 编码，供安装时生成）。
func GenerateKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return hex.EncodeToString(key), nil
}

// Encrypt 加密明文，返回 base64(nonce|ciphertext)。
func (s *Service) Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt 解密密文。
func (s *Service) Decrypt(encoded string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", ErrInvalidCiphertext
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(data) < gcm.NonceSize() {
		return "", ErrInvalidCiphertext
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", ErrInvalidCiphertext
	}
	return string(plain), nil
}

// IsConfigured 检查主密钥是否已配置。
func IsConfigured() bool {
	return strings.TrimSpace(os.Getenv("JIUZHANG_MASTER_KEY")) != ""
}
