// Package evidencekey 使用标准密码学原语封装请求PCAP的分片DEK。
// 抓包节点只需公钥；私钥由管理面独立保管，不进入抓包配置、清单或日志。
package evidencekey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const (
	envelopeVersion = 1
	envelopeSize    = 126 // version 1 + P256公开点65 + nonce12 + DEK32+GCM tag16
	keyScope        = "WDSP-PCAP-DEK-V1\x00"
)

type KeyPair struct {
	PublicKey  []byte `json:"public_key"`
	PrivateKey []byte `json:"-"`
}

// GenerateKeyPair 仅供安装/密钥轮换及测试使用；私钥落盘须使用现有主密钥加密并限制0600。
func GenerateKeyPair() (KeyPair, error) {
	privateKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, err
	}
	return KeyPair{
		PublicKey:  append([]byte(nil), privateKey.PublicKey().Bytes()...),
		PrivateKey: append([]byte(nil), privateKey.Bytes()...),
	}, nil
}

func PublicKeyID(publicKey []byte) (string, error) {
	if _, err := ecdh.P256().NewPublicKey(publicKey); err != nil {
		return "", fmt.Errorf("invalid evidence public key: %w", err)
	}
	digest := sha256.Sum256(publicKey)
	return "p256:" + hex.EncodeToString(digest[:]), nil
}

func PublicKeyFromPrivate(privateKey []byte) ([]byte, error) {
	private, err := ecdh.P256().NewPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid evidence private key: %w", err)
	}
	return append([]byte(nil), private.PublicKey().Bytes()...), nil
}

func WrapDEK(publicKey, dek []byte) ([]byte, string, error) {
	if len(dek) != 32 {
		return nil, "", fmt.Errorf("evidence DEK must be 32 bytes")
	}
	keyID, err := PublicKeyID(publicKey)
	if err != nil {
		return nil, "", err
	}
	serverPublic, err := ecdh.P256().NewPublicKey(publicKey)
	if err != nil {
		return nil, "", err
	}
	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	shared, err := ephemeral.ECDH(serverPublic)
	if err != nil {
		return nil, "", fmt.Errorf("derive evidence wrapping secret: %w", err)
	}
	defer clear(shared)
	wrapKey := deriveWrapKey(shared, ephemeral.PublicKey().Bytes(), publicKey)
	defer clear(wrapKey)
	block, err := aes.NewCipher(wrapKey)
	if err != nil {
		return nil, "", err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", err
	}
	envelope := make([]byte, 0, envelopeSize)
	envelope = append(envelope, envelopeVersion)
	envelope = append(envelope, ephemeral.PublicKey().Bytes()...)
	envelope = append(envelope, nonce...)
	envelope = aead.Seal(envelope, nonce, dek, envelopeAAD(keyID))
	return envelope, keyID, nil
}

func UnwrapDEK(privateKey []byte, keyID string, envelope []byte) ([]byte, error) {
	if len(envelope) != envelopeSize || envelope[0] != envelopeVersion {
		return nil, fmt.Errorf("invalid evidence DEK envelope")
	}
	private, err := ecdh.P256().NewPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid evidence private key: %w", err)
	}
	expectedKeyID, err := PublicKeyID(private.PublicKey().Bytes())
	if err != nil || keyID != expectedKeyID {
		return nil, fmt.Errorf("evidence key id does not match private key")
	}
	ephemeralPublic, err := ecdh.P256().NewPublicKey(envelope[1:66])
	if err != nil {
		return nil, fmt.Errorf("invalid evidence ephemeral public key: %w", err)
	}
	shared, err := private.ECDH(ephemeralPublic)
	if err != nil {
		return nil, fmt.Errorf("derive evidence wrapping secret: %w", err)
	}
	defer clear(shared)
	wrapKey := deriveWrapKey(shared, ephemeralPublic.Bytes(), private.PublicKey().Bytes())
	defer clear(wrapKey)
	block, err := aes.NewCipher(wrapKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	dek, err := aead.Open(nil, envelope[66:78], envelope[78:], envelopeAAD(keyID))
	if err != nil {
		return nil, fmt.Errorf("evidence DEK authentication failed: %w", err)
	}
	if len(dek) != 32 {
		clear(dek)
		return nil, fmt.Errorf("unexpected evidence DEK length")
	}
	return dek, nil
}

func deriveWrapKey(shared, ephemeralPublic, serverPublic []byte) []byte {
	saltInput := append(append([]byte(nil), ephemeralPublic...), serverPublic...)
	salt := sha256.Sum256(saltInput)
	extract := hmac.New(sha256.New, salt[:])
	_, _ = extract.Write(shared)
	prk := extract.Sum(nil)
	defer clear(prk)
	expand := hmac.New(sha256.New, prk)
	_, _ = expand.Write([]byte("WDSP-PCAP-KEY-HKDF-V1"))
	_, _ = expand.Write([]byte{1})
	return expand.Sum(nil)
}

func envelopeAAD(keyID string) []byte {
	return []byte(keyScope + keyID)
}
