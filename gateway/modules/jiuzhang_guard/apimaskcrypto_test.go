package jiuzhang_guard

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

const testMaskCryptoKeyHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

func testMaskCryptoConfig() *maskCryptoJSON {
	return &maskCryptoJSON{Kid: "kid-1", KeyHex: testMaskCryptoKeyHex}
}

func testCryptoMaskRules() []maskRuleJSON {
	return []maskRuleJSON{
		{EndpointKey: "POST /v1/users", FieldPath: "token", Algorithm: "ENCRYPT", Params: map[string]any{"key_id": "kid-1"}},
		{EndpointKey: "POST /v1/users", FieldPath: "customer", Algorithm: "MAP", Params: map[string]any{"map_id": "customer-v1"}},
		{EndpointKey: "POST /v1/users", FieldPath: "users[].phone", Algorithm: "ENCRYPT", Params: map[string]any{"key_id": "kid-1"}},
	}
}

func TestCompileAPIMaskCryptoValidation(t *testing.T) {
	rules, err := compileAPIMaskRules(testCryptoMaskRules())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		config *maskCryptoJSON
	}{
		{name: "missing config"},
		{name: "bad hex", config: &maskCryptoJSON{Kid: "kid-1", KeyHex: "not-hex"}},
		{name: "short key", config: &maskCryptoJSON{Kid: "kid-1", KeyHex: "0011"}},
		{name: "bad kid", config: &maskCryptoJSON{Kid: "bad kid", KeyHex: testMaskCryptoKeyHex}},
		{name: "kid mismatch", config: &maskCryptoJSON{Kid: "other", KeyHex: testMaskCryptoKeyHex}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := compileAPIMaskCrypto(tc.config, rules)
			if err == nil {
				t.Fatal("expected mask crypto validation error")
			}
			if strings.Contains(err.Error(), testMaskCryptoKeyHex) {
				t.Fatalf("key material leaked into error: %v", err)
			}
		})
	}
	crypto, err := compileAPIMaskCrypto(testMaskCryptoConfig(), rules)
	if err != nil || crypto == nil || crypto.KeyID != "kid-1" {
		t.Fatalf("valid mask crypto rejected: crypto=%+v err=%v", crypto, err)
	}
	legacy, err := compileAPIMaskRules([]maskRuleJSON{{EndpointKey: "ek", FieldPath: "a", Algorithm: "MASK"}})
	if err != nil {
		t.Fatal(err)
	}
	if crypto, err := compileAPIMaskCrypto(nil, legacy); err != nil || crypto != nil {
		t.Fatalf("legacy algorithms must not require crypto: crypto=%v err=%v", crypto, err)
	}
}

func TestGuardValidateProvisionMaskCrypto(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config *maskCryptoJSON
	}{
		{name: "missing config"},
		{name: "bad hex", config: &maskCryptoJSON{Kid: "kid-1", KeyHex: "xyz"}},
		{name: "kid mismatch", config: &maskCryptoJSON{Kid: "other", KeyHex: testMaskCryptoKeyHex}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := &Guard{
				EventsLog:            filepath.Join(t.TempDir(), "events.log"),
				APIEventsLog:         filepath.Join(t.TempDir(), "api-events.log"),
				APIDynamicProtection: true,
				APIMaskRules:         testCryptoMaskRules(),
				APIMaskCrypto:        tc.config,
			}
			if err := g.Validate(); err == nil || !strings.Contains(err.Error(), "api_mask_crypto") {
				t.Fatalf("Validate must reject invalid mask crypto: %v", err)
			}
			if err := g.Provision(caddy.Context{Context: context.Background()}); err == nil || !strings.Contains(err.Error(), "api_mask_crypto") {
				t.Fatalf("Provision must reject invalid mask crypto: %v", err)
			}
			_ = g.Cleanup()
		})
	}
	g := &Guard{
		EventsLog:            filepath.Join(t.TempDir(), "events.log"),
		APIEventsLog:         filepath.Join(t.TempDir(), "api-events.log"),
		APIDynamicProtection: true,
		APIMaskRules:         testCryptoMaskRules(),
		APIMaskCrypto:        testMaskCryptoConfig(),
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("valid mask crypto must pass Validate: %v", err)
	}
	if err := g.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("valid mask crypto must pass Provision: %v", err)
	}
	if g.apiMaskCrypto == nil {
		t.Fatal("Provision must install compiled mask crypto")
	}
	if err := g.Cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestServeNextMaskCryptoEndToEnd(t *testing.T) {
	g, logPath := newAPIResponseTestGuard(t, "PROTECT", testCryptoMaskRules())
	crypto, err := compileAPIMaskCrypto(testMaskCryptoConfig(), g.apiMaskRules)
	if err != nil {
		t.Fatal(err)
	}
	g.apiMaskCrypto = crypto
	upstreamBody := `{"token":"plain-secret","customer":"customer-123","users":[{"phone":"13800138000"},{"phone":"13900139000"}],"ok":true}`
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, upstreamBody)
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/users", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-mask-crypto")
	req.RemoteAddr = "203.0.113.95:1001"
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	body, err := io.ReadAll(rec.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, "enc_kid-1_") || !strings.Contains(text, "map_customer-v1_") {
		t.Fatalf("crypto outputs missing: %s", text)
	}
	for _, leaked := range []string{"plain-secret", "customer-123", "13800138000", "13900139000", testMaskCryptoKeyHex, "key_hex"} {
		if strings.Contains(text, leaked) {
			t.Fatalf("plaintext or key material leaked into response: %s", text)
		}
	}

	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	encrypted := decoded["token"].(string)
	payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(encrypted, "enc_kid-1_"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := hex.DecodeString(testMaskCryptoKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonceSize := gcm.NonceSize()
	plaintext, err := gcm.Open(nil, payload[:nonceSize], payload[nonceSize:], nil)
	if err != nil || string(plaintext) != "plain-secret" {
		t.Fatalf("Guard ciphertext cannot be decrypted: %q err=%v", plaintext, err)
	}
	eventBody, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{"plain-secret", "customer-123", "13800138000", "13900139000", testMaskCryptoKeyHex, "key_hex"} {
		if strings.Contains(string(eventBody), leaked) {
			t.Fatalf("plaintext or key material leaked into event: %s", eventBody)
		}
	}
	records := readAPIRecords(t, logPath)
	if len(records) != 1 || records[0].FinalAction != "MASK_RESPONSE" {
		t.Fatalf("unexpected Guard mask event: %+v", records)
	}
}
