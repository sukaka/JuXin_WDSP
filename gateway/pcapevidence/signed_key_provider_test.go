package pcapevidence

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/evidencekey"
)

func TestSignedPublicKeyProviderRequiresCurrentTrustedGrant(t *testing.T) {
	trust, releasePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := evidencekey.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	grant, err := evidencekey.SignPublicKeyGrant(pair.PublicKey, releasePrivate, "gw-provider", now.Add(-time.Second), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	trustPath, grantPath := filepath.Join(directory, "release.pub"), filepath.Join(directory, "public.json")
	if err := os.WriteFile(trustPath, trust, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(grantPath, grant, 0o644); err != nil {
		t.Fatal(err)
	}
	provider, err := NewSignedPublicKeyProvider(trustPath, grantPath, "gw-provider")
	if err != nil {
		t.Fatal(err)
	}
	dek, err := provider.NewDEK(context.Background())
	if err != nil || len(dek.Key) != 32 {
		t.Fatalf("signed provider failed: %v", err)
	}
	unwrapped, err := evidencekey.UnwrapDEK(pair.PrivateKey, dek.KeyID, dek.WrappedKey)
	if err != nil || string(unwrapped) != string(dek.Key) {
		t.Fatalf("signed provider did not use granted key: %v", err)
	}
	clear(dek.Key)
	clear(unwrapped)
	if err := os.WriteFile(grantPath, []byte("forged"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.NewDEK(context.Background()); err == nil {
		t.Fatal("forged public key grant was accepted")
	}
	if err := os.Chmod(grantPath, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.NewDEK(context.Background()); err == nil {
		t.Fatal("world-writable public grant was accepted")
	}
}
