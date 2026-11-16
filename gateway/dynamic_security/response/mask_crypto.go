package response

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

const maskMapDomain = "domain"

// MaskCrypto 保存 ENCRYPT/MAP 的密钥标识与 AES-256 密钥材料。
// 密钥与 AEAD 均不导出，配置、计划和事件只携带 KeyID/MapID。
type MaskCrypto struct {
	KeyID string
	key   [32]byte
	aead  cipher.AEAD
}

func NewMaskCrypto(keyID string, key []byte) (*MaskCrypto, error) {
	if _, err := paramMaskIdentifier("key_id", keyID); err != nil {
		return nil, fmt.Errorf("mask crypto kid: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("mask crypto key must be 32 bytes")
	}
	c := &MaskCrypto{KeyID: keyID}
	copy(c.key[:], key)
	block, err := aes.NewCipher(c.key[:])
	if err != nil {
		return nil, fmt.Errorf("mask crypto AES: %w", err)
	}
	c.aead, err = cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("mask crypto GCM: %w", err)
	}
	return c, nil
}

func (c *MaskCrypto) encrypt(keyID, value string) (string, error) {
	if c == nil || c.aead == nil {
		return "", fmt.Errorf("ENCRYPT requires mask crypto")
	}
	if keyID == "" || keyID != c.KeyID {
		return "", fmt.Errorf("ENCRYPT key_id does not match configured kid")
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("ENCRYPT nonce: %w", err)
	}
	payload := c.aead.Seal(nonce, nonce, []byte(value), nil)
	return "enc_" + keyID + "_" + base64.StdEncoding.EncodeToString(payload), nil
}

func (c *MaskCrypto) mapValue(mapID, value string) (string, error) {
	if c == nil {
		return "", fmt.Errorf("MAP requires mask crypto")
	}
	if mapID == "" {
		return "", fmt.Errorf("MAP requires map_id")
	}
	mac := hmac.New(sha256.New, c.key[:])
	_, _ = mac.Write([]byte(maskMapDomain))
	_, _ = mac.Write([]byte(mapID))
	_, _ = mac.Write([]byte(value))
	return "map_" + mapID + "_" + hex.EncodeToString(mac.Sum(nil)[:8]), nil
}
