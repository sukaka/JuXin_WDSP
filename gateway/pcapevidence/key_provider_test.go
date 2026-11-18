package pcapevidence

import (
	"bytes"
	"context"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/evidencekey"
)

func TestPublicKeyDEKProviderUsesRealKeyEnvelope(t *testing.T) {
	pair, err := evidencekey.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	provider, err := NewPublicKeyDEKProvider(pair.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	dek, err := provider.NewDEK(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(dek.Key)
	unwrapped, err := evidencekey.UnwrapDEK(pair.PrivateKey, dek.KeyID, dek.WrappedKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(unwrapped)
	if !bytes.Equal(unwrapped, dek.Key) {
		t.Fatal("provider envelope does not unwrap to the segment DEK")
	}
	if _, err := NewPublicKeyDEKProvider([]byte("invalid")); err == nil {
		t.Fatal("invalid public key was accepted")
	}
}
