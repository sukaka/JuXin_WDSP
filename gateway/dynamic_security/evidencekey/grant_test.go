package evidencekey

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestPublicKeyGrantBindsNodeExpiryAndSignature(t *testing.T) {
	releasePublic, releasePrivate, err := generateReleaseKey()
	if err != nil {
		t.Fatal(err)
	}
	pair, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	encoded, err := SignPublicKeyGrant(pair.PublicKey, releasePrivate, "gw-a", now.Add(-time.Second), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, keyID, err := VerifyPublicKeyGrant(encoded, releasePublic, "gw-a", now)
	if err != nil || keyID == "" || string(publicKey) != string(pair.PublicKey) {
		t.Fatalf("valid public key grant rejected: %v", err)
	}
	if _, _, err := VerifyPublicKeyGrant(encoded, releasePublic, "gw-b", now); err == nil {
		t.Fatal("grant was accepted for another node")
	}
	if _, _, err := VerifyPublicKeyGrant(encoded, releasePublic, "gw-a", now.Add(2*time.Hour)); err == nil {
		t.Fatal("expired grant was accepted")
	}
	tampered := append([]byte(nil), encoded...)
	for i := range tampered {
		if tampered[i] == 'g' && tampered[i+1] == 'w' && tampered[i+2] == '-' && tampered[i+3] == 'a' {
			tampered[i+3] = 'c'
			break
		}
	}
	if _, _, err := VerifyPublicKeyGrant(tampered, releasePublic, "gw-a", now); err == nil {
		t.Fatal("tampered grant signature was accepted")
	}
}

func generateReleaseKey() ([]byte, []byte, error) {
	return ed25519.GenerateKey(rand.Reader)
}
