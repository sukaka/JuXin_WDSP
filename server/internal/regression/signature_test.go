// signature_test.go Ed25519 验签与受信密钥登记测试
// （伪造签名/未知算法/未知 key_id/已撤销/登记损坏）。
package regression

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
)

func testKey(t *testing.T, keyID, status string) (TrustedKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return TrustedKey{
		KeyID:     keyID,
		Algorithm: SignatureAlgorithmEd25519,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Status:    status,
	}, priv
}

func signWith(t *testing.T, priv ed25519.PrivateKey, keyID string, msg []byte) SignatureEnvelope {
	t.Helper()
	return SignatureEnvelope{
		Algorithm: SignatureAlgorithmEd25519,
		KeyID:     keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg)),
	}
}

func TestVerifyValidSignature(t *testing.T) {
	key, priv := testKey(t, "verifier-1", KeyStatusActive)
	msg := []byte(`{"a":1}`)
	if err := VerifyManifestSignature([]TrustedKey{key}, signWith(t, priv, "verifier-1", msg), msg); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
}

func TestVerifyForgedSignatureRejected(t *testing.T) {
	key, _ := testKey(t, "verifier-1", KeyStatusActive)
	_, evilPriv := testKey(t, "attacker", KeyStatusActive)
	msg := []byte(`{"a":1}`)
	// 攻击者私钥签名、冒用已登记 key_id
	if err := VerifyManifestSignature([]TrustedKey{key}, signWith(t, evilPriv, "verifier-1", msg), msg); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("forged signature accepted: %v", err)
	}
	// 有效签名、manifest 被改一字节
	env := signWith(t, func() ed25519.PrivateKey { _, p := testKey(t, "x", KeyStatusActive); return p }(), "x", msg)
	k2, _ := testKey(t, "x", KeyStatusActive)
	if err := VerifyManifestSignature([]TrustedKey{k2}, env, []byte(`{"a":2}`)); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered manifest accepted: %v", err)
	}
}

func TestVerifyUnknownAlgorithmRejected(t *testing.T) {
	key, priv := testKey(t, "verifier-1", KeyStatusActive)
	msg := []byte(`{"a":1}`)
	env := signWith(t, priv, "verifier-1", msg)
	env.Algorithm = "rsa-sha256"
	if err := VerifyManifestSignature([]TrustedKey{key}, env, msg); !errors.Is(err, ErrUnknownAlgorithm) {
		t.Fatalf("unknown algorithm accepted: %v", err)
	}
}

func TestVerifyUnknownKeyIDRejected(t *testing.T) {
	key, priv := testKey(t, "verifier-1", KeyStatusActive)
	msg := []byte(`{"a":1}`)
	env := signWith(t, priv, "ghost-key", msg)
	if err := VerifyManifestSignature([]TrustedKey{key}, env, msg); !errors.Is(err, ErrUnknownKeyID) {
		t.Fatalf("unknown key_id accepted: %v", err)
	}
	// 无任何登记密钥时一切验签拒绝
	env2 := signWith(t, priv, "verifier-1", msg)
	if err := VerifyManifestSignature(nil, env2, msg); !errors.Is(err, ErrUnknownKeyID) {
		t.Fatalf("empty registry accepted: %v", err)
	}
}

func TestVerifyRevokedKeyRejected(t *testing.T) {
	key, priv := testKey(t, "verifier-1", KeyStatusRevoked)
	msg := []byte(`{"a":1}`)
	if err := VerifyManifestSignature([]TrustedKey{key}, signWith(t, priv, "verifier-1", msg), msg); !errors.Is(err, ErrRevokedKey) {
		t.Fatalf("revoked key accepted: %v", err)
	}
}

func TestLoadTrustedKeysParsing(t *testing.T) {
	key, _ := testKey(t, "k1", KeyStatusActive)
	good := fmt.Sprintf(`[{"key_id":"k1","algorithm":"ed25519","public_key":%q,"status":"ACTIVE"}]`, key.PublicKey)
	reader := func(val string) SettingsReader {
		return func(context.Context, string, string, string) string { return val }
	}
	keys, err := LoadTrustedKeys(context.Background(), reader(good))
	if err != nil || len(keys) != 1 {
		t.Fatalf("good registry: keys=%v err=%v", keys, err)
	}
	for name, val := range map[string]string{
		"bad json":       `[{`,
		"unknown field":  `[{"key_id":"k1","algorithm":"ed25519","public_key":"` + key.PublicKey + `","status":"ACTIVE","x":1}]`,
		"dup key_id":     `[{"key_id":"k1","algorithm":"ed25519","public_key":"` + key.PublicKey + `","status":"ACTIVE"},{"key_id":"k1","algorithm":"ed25519","public_key":"` + key.PublicKey + `","status":"REVOKED"}]`,
		"bad algorithm":  `[{"key_id":"k1","algorithm":"rsa","public_key":"` + key.PublicKey + `","status":"ACTIVE"}]`,
		"bad status":     `[{"key_id":"k1","algorithm":"ed25519","public_key":"` + key.PublicKey + `","status":"PENDING"}]`,
		"bad public key": `[{"key_id":"k1","algorithm":"ed25519","public_key":"AAAA","status":"ACTIVE"}]`,
		"bad key_id":     `[{"key_id":"a/b","algorithm":"ed25519","public_key":"` + key.PublicKey + `","status":"ACTIVE"}]`,
	} {
		if _, err := LoadTrustedKeys(context.Background(), reader(val)); err == nil {
			t.Fatalf("%s: corrupt registry accepted", name)
		}
	}
	// 未配置 = 空表（不算损坏）
	keys, err = LoadTrustedKeys(context.Background(), reader(""))
	if err != nil || keys != nil {
		t.Fatalf("empty registry: keys=%v err=%v", keys, err)
	}
}

// ed25519Generate 测试密钥生成助手（gate_test 共用）。
func ed25519Generate() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}
