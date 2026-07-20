package encryption

import (
	"strings"
	"testing"
)

func testService(t *testing.T) *Service {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	svc, err := NewWithKey(key)
	if err != nil {
		t.Fatalf("NewWithKey: %v", err)
	}
	return svc
}

func TestEncryptDecryptRoundtrip(t *testing.T) {
	svc := testService(t)
	secret := "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"
	enc, err := svc.Encrypt(secret)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if enc == secret || strings.Contains(enc, "PRIVATE KEY") {
		t.Error("ciphertext contains plaintext")
	}
	dec, err := svc.Decrypt(enc)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if dec != secret {
		t.Errorf("roundtrip mismatch: got %q", dec)
	}
}

func TestEncryptUniqueNonce(t *testing.T) {
	svc := testService(t)
	e1, _ := svc.Encrypt("same-plaintext")
	e2, _ := svc.Encrypt("same-plaintext")
	if e1 == e2 {
		t.Error("same plaintext produced identical ciphertext (nonce not random)")
	}
}

func TestDecryptWrongKey(t *testing.T) {
	svc1 := testService(t)
	other := make([]byte, 32)
	for i := range other {
		other[i] = byte(i + 100)
	}
	svc2, _ := NewWithKey(other)
	enc, _ := svc1.Encrypt("secret")
	if _, err := svc2.Decrypt(enc); err == nil {
		t.Error("decrypt with wrong key should fail")
	}
}

func TestDecryptInvalidCiphertext(t *testing.T) {
	svc := testService(t)
	if _, err := svc.Decrypt("!!!not-base64!!!"); err == nil {
		t.Error("decrypt invalid base64 should fail")
	}
	if _, err := svc.Decrypt("c2hvcnQ="); err == nil {
		t.Error("decrypt too-short ciphertext should fail")
	}
}

func TestNewFromStringHex(t *testing.T) {
	hexKey := strings.Repeat("ab", 32)
	svc, err := NewFromString(hexKey)
	if err != nil {
		t.Fatalf("NewFromString(hex): %v", err)
	}
	enc, _ := svc.Encrypt("test")
	if _, err := svc.Decrypt(enc); err != nil {
		t.Errorf("roundtrip with hex key: %v", err)
	}
}

func TestNewFromStringInvalidLength(t *testing.T) {
	if _, err := NewFromString("c2hvcnQ="); err == nil {
		t.Error("short key should be rejected")
	}
}

func TestGenerateKey(t *testing.T) {
	k1, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	k2, _ := GenerateKey()
	if k1 == k2 {
		t.Error("keys not random")
	}
	if len(k1) != 64 {
		t.Errorf("hex key length = %d, want 64", len(k1))
	}
}
