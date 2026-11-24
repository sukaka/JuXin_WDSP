package nodesync

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"
)

const testSharedSecretHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestSharedHMACVectorMatchesHasyncd(t *testing.T) {
	secret, err := ParseSecretHex(testSharedSecretHex)
	if err != nil {
		t.Fatalf("ParseSecretHex: %v", err)
	}
	bodySum := sha256.Sum256([]byte(`{"ports":[80,443]}`))
	bodyHex := hex.EncodeToString(bodySum[:])

	// Exact same vector verified in gateway/hasyncd/auth_test.go and Python reference.
	const (
		wantBodyHex = "edd0c61bb02a963e0c2a2f8a50f01ce02b0df29a5d7b47a186e50fd3a958a387"
		wantSigHex  = "04a0f27a95a8c16d4a1819c55585caffd5a880f5ef45a85df31c98e80e49907d"
	)
	if bodyHex != wantBodyHex {
		t.Fatalf("body sha256 mismatch: got %s want %s", bodyHex, wantBodyHex)
	}

	req, err := http.NewRequest(http.MethodPost, "https://10.0.0.2:18443/v1/firewall/ensure", nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1764000000, 0).UTC()
	nonce := "00112233445566778899aabbccddeeff"
	if err := SignRequest(req, secret, "gw-a", bodyHex, now, nonce); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	if got := req.Header.Get(HeaderSignature); got != wantSigHex {
		t.Fatalf("signature mismatch:\n got: %s\nwant: %s", got, wantSigHex)
	}
	if req.Header.Get(HeaderNode) != "gw-a" ||
		req.Header.Get(HeaderTimestamp) != "1764000000" ||
		req.Header.Get(HeaderNonce) != nonce ||
		req.Header.Get(HeaderBodySHA256) != wantBodyHex {
		t.Fatalf("unexpected headers: %+v", req.Header)
	}
}

func TestParseSecretHexValidation(t *testing.T) {
	if _, err := ParseSecretHex(""); err == nil {
		t.Fatal("expected empty secret to fail")
	}
	if _, err := ParseSecretHex(strings.Repeat("a", 62)); err == nil {
		t.Fatal("expected <32 byte secret to fail")
	}
	if _, err := ParseSecretHex(strings.Repeat("g", 64)); err == nil {
		t.Fatal("expected non-hex secret to fail")
	}
	got, err := ParseSecretHex(strings.ToUpper(testSharedSecretHex))
	if err != nil || len(got) != 32 {
		t.Fatalf("expected valid 32-byte secret, got len=%d err=%v", len(got), err)
	}
}
