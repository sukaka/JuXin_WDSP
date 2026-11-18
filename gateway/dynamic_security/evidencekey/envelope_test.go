package evidencekey

import (
	"bytes"
	"testing"
)

func TestDEKEnvelopeRoundTrip(t *testing.T) {
	pair, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	dek := bytes.Repeat([]byte{7}, 32)
	envelope, keyID, err := WrapDEK(pair.PublicKey, dek)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(envelope, dek) {
		t.Fatal("DEK envelope contains plaintext key")
	}
	unwrapped, err := UnwrapDEK(pair.PrivateKey, keyID, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unwrapped, dek) {
		t.Fatal("unwrapped DEK differs from original")
	}
}

func TestDEKEnvelopeRejectsWrongKeyTamperingAndScope(t *testing.T) {
	pair, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	other, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	envelope, keyID, err := WrapDEK(pair.PublicKey, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapDEK(other.PrivateKey, keyID, envelope); err == nil {
		t.Fatal("wrong private key unexpectedly unwrapped DEK")
	}
	if _, err := UnwrapDEK(pair.PrivateKey, "p256:wrong", envelope); err == nil {
		t.Fatal("wrong key scope unexpectedly accepted")
	}
	tampered := append([]byte(nil), envelope...)
	tampered[len(tampered)-1] ^= 1
	if _, err := UnwrapDEK(pair.PrivateKey, keyID, tampered); err == nil {
		t.Fatal("tampered envelope unexpectedly accepted")
	}
	for _, invalid := range [][]byte{nil, make([]byte, 20)} {
		if _, err := UnwrapDEK(pair.PrivateKey, keyID, invalid); err == nil {
			t.Fatal("invalid envelope length was accepted")
		}
	}
	if _, _, err := WrapDEK(pair.PublicKey, []byte{1}); err == nil {
		t.Fatal("invalid DEK length was accepted")
	}
}
