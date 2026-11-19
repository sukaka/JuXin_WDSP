package response

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
)

const (
	maskEncHKDFInfo  = "jiuzhang-wdsp-mask-aes-gcm-v1"
	maskMapHKDFInfo  = "jiuzhang-wdsp-mask-hmac-map-v1"
	maskEncAADPrefix = "jiuzhang-wdsp-mask-enc-v1\x00"
	maskMapDomain    = "jiuzhang-wdsp-mask-map-v1"
)

// MaskCrypto 保存 ENCRYPT/MAP 的密钥标识与经 HKDF-SHA256 域分离派生的独立子密钥。
// 密钥与 AEAD 均不导出，配置、计划和事件只携带 KeyID/MapID（M-G5）。
type MaskCrypto struct {
	KeyID  string
	encKey [32]byte
	mapKey [32]byte
	aead   cipher.AEAD
}

func NewMaskCrypto(keyID string, key []byte) (*MaskCrypto, error) {
	if _, err := paramMaskIdentifier("key_id", keyID); err != nil {
		return nil, fmt.Errorf("mask crypto kid: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("mask crypto key must be 32 bytes")
	}
	encDerived, err := hkdf.Key(sha256.New, key, nil, maskEncHKDFInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("mask crypto HKDF enc: %w", err)
	}
	mapDerived, err := hkdf.Key(sha256.New, key, nil, maskMapHKDFInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("mask crypto HKDF map: %w", err)
	}
	c := &MaskCrypto{KeyID: keyID}
	copy(c.encKey[:], encDerived)
	copy(c.mapKey[:], mapDerived)
	block, err := aes.NewCipher(c.encKey[:])
	if err != nil {
		return nil, fmt.Errorf("mask crypto AES: %w", err)
	}
	c.aead, err = cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("mask crypto GCM: %w", err)
	}
	return c, nil
}

func maskEncAAD(keyID string) []byte {
	return []byte(maskEncAADPrefix + keyID)
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
	payload := c.aead.Seal(nonce, nonce, []byte(value), maskEncAAD(keyID))
	return "enc_" + keyID + "_" + base64.StdEncoding.EncodeToString(payload), nil
}

func writeLengthFramed(mac io.Writer, part string) {
	var lb [4]byte
	binary.BigEndian.PutUint32(lb[:], uint32(len(part)))
	_, _ = mac.Write(lb[:])
	_, _ = mac.Write([]byte(part))
}

func (c *MaskCrypto) mapValue(mapID, value string) (string, error) {
	if c == nil {
		return "", fmt.Errorf("MAP requires mask crypto")
	}
	if mapID == "" {
		return "", fmt.Errorf("MAP requires map_id")
	}
	mac := hmac.New(sha256.New, c.mapKey[:])
	writeLengthFramed(mac, maskMapDomain)
	writeLengthFramed(mac, mapID)
	writeLengthFramed(mac, value)
	return "map_" + mapID + "_" + hex.EncodeToString(mac.Sum(nil)[:8]), nil
}
