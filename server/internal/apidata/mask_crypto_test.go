package apidata

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/encryption"
)

func TestDecryptMaskingRule(t *testing.T) {
	keyBytes := []byte("0123456789abcdef0123456789abcdef")
	keyHex := hex.EncodeToString(keyBytes)
	crypto, err := encryption.NewWithKey(keyBytes)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := "sensitive-value"
	encoded, err := crypto.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewHandler(NewMemStore(), nil).SetMaskCryptoLoader(func(context.Context) (string, string, error) {
		return "mask_k1", keyHex, nil
	})
	mux := newTestMux(handler)
	ciphertext := "enc_mask_k1_" + encoded
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/masking-rules/decrypt", map[string]string{"ciphertext": ciphertext})
	if rr.Code != http.StatusOK {
		t.Fatalf("decrypt status=%d body=%s", rr.Code, rr.Body.String())
	}
	var result struct {
		Plaintext string `json:"plaintext"`
	}
	decodeData(t, rr, &result)
	if result.Plaintext != plaintext {
		t.Fatalf("plaintext = %q, want %q", result.Plaintext, plaintext)
	}

	for _, tc := range []struct {
		name string
		body any
	}{
		{name: "kid 不符", body: map[string]string{"ciphertext": "enc_other_" + encoded}},
		{name: "非法格式", body: map[string]string{"ciphertext": "not-encrypted"}},
		{name: "非法 base64", body: map[string]string{"ciphertext": "enc_mask_k1_%%%"}},
		{name: "解密失败", body: map[string]string{"ciphertext": "enc_mask_k1_" + encoded[:len(encoded)-2] + "AA"}},
		{name: "空值", body: map[string]string{"ciphertext": ""}},
		{name: "未知字段", body: map[string]string{"ciphertext": ciphertext, "plaintext": "forbidden"}},
		{name: "超长", body: map[string]string{"ciphertext": strings.Repeat("A", maxMaskCiphertextLen+1)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/masking-rules/decrypt", tc.body)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
			if strings.Contains(rr.Body.String(), plaintext) || strings.Contains(rr.Body.String(), keyHex) {
				t.Fatalf("error leaked plaintext or key: %s", rr.Body.String())
			}
		})
	}
}

func TestDecryptMaskingRuleUnavailable(t *testing.T) {
	mux := newTestMux(NewHandler(NewMemStore(), nil))
	rr := doJSON(t, mux, http.MethodPost, "/api/v1/api-security/masking-rules/decrypt", map[string]string{"ciphertext": "enc_k1_x"})
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
}
