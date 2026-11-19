package response

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func testMaskCrypto(t *testing.T) *MaskCrypto {
	t.Helper()
	crypto, err := NewMaskCrypto("kid-1", bytes.Repeat([]byte{0x11}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return crypto
}

func decodeJSONObject(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("invalid transformed JSON: %v", err)
	}
	return got
}

func TestApplyJSONWithKeyAllAlgorithmsAndDecrypt(t *testing.T) {
	crypto := testMaskCrypto(t)
	body := []byte(`{"secret":"plain-secret","alias":"customer-123","masked":"1234567890","hashed":"abc","removed":"delete-me","keep":true}`)
	plan := []dsctx.FieldTransform{
		{FieldPath: "secret", Algorithm: "ENCRYPT", KeyID: "kid-1"},
		{FieldPath: "alias", Algorithm: "MAP", MapID: "map-1"},
		{FieldPath: "masked", Algorithm: "MASK", KeepHead: 1, KeepTail: 2},
		{FieldPath: "hashed", Algorithm: "HASH"},
		{FieldPath: "removed", Algorithm: "REMOVE"},
	}
	res, err := ApplyJSONWithKey(body, plan, crypto)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	got := decodeJSONObject(t, res.Body)
	encrypted := got["secret"].(string)
	if !strings.HasPrefix(encrypted, "enc_kid-1_") {
		t.Fatalf("encrypted output prefix: %q", encrypted)
	}
	payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(encrypted, "enc_kid-1_"))
	if err != nil {
		t.Fatalf("ciphertext base64: %v", err)
	}
	nonceSize := crypto.aead.NonceSize()
	if len(payload) <= nonceSize {
		t.Fatal("ciphertext payload must contain nonce and sealed value")
	}
	if _, err := crypto.aead.Open(nil, payload[:nonceSize], payload[nonceSize:], nil); err == nil {
		t.Fatal("AES-GCM decrypt without AAD must fail (M-G5 AAD binding)")
	}
	if _, err := crypto.aead.Open(nil, payload[:nonceSize], payload[nonceSize:], maskEncAAD("wrong-kid")); err == nil {
		t.Fatal("AES-GCM decrypt with mismatched keyID AAD must fail")
	}
	plaintext, err := crypto.aead.Open(nil, payload[:nonceSize], payload[nonceSize:], maskEncAAD("kid-1"))
	if err != nil {
		t.Fatalf("AES-GCM decrypt: %v", err)
	}
	if string(plaintext) != "plain-secret" {
		t.Fatalf("decrypted=%q", plaintext)
	}
	if bytes.Equal(crypto.encKey[:], crypto.mapKey[:]) {
		t.Fatal("M-G5: HKDF must derive distinct AES-GCM and HMAC-MAP subkeys")
	}
	mapped := got["alias"].(string)
	mac := hmac.New(sha256.New, crypto.mapKey[:])
	writeLengthFramed(mac, maskMapDomain)
	writeLengthFramed(mac, "map-1")
	writeLengthFramed(mac, "customer-123")
	wantMap := "map_map-1_" + hex.EncodeToString(mac.Sum(nil)[:8])
	if mapped != wantMap {
		t.Fatalf("mapped=%q want=%q", mapped, wantMap)
	}
	// M-G5: length framing prevents mapID/value boundary collisions ("a"+"bc" != "ab"+"c")
	m1, err := crypto.mapValue("a", "bc")
	if err != nil {
		t.Fatal(err)
	}
	m2, err := crypto.mapValue("ab", "c")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimPrefix(m1, "map_a_") == strings.TrimPrefix(m2, "map_ab_") {
		t.Fatalf("M-G5: length-framed HMAC-MAP must not collide across mapID/value boundary: %q vs %q", m1, m2)
	}
	if got["masked"] != "1*******90" || got["hashed"] != hashValue("abc") || got["keep"] != true {
		t.Fatalf("legacy algorithms changed: %+v", got)
	}
	if _, ok := got["removed"]; ok {
		t.Fatal("REMOVE field survived")
	}
	if res.AppliedFields != 5 {
		t.Fatalf("applied=%d want 5", res.AppliedFields)
	}
	for _, leaked := range []string{"plain-secret", "customer-123", "delete-me"} {
		if strings.Contains(string(res.Body), leaked) {
			t.Fatalf("plaintext %q leaked: %s", leaked, res.Body)
		}
	}
}

func TestApplyJSONWithKeyArraysAndDeterminism(t *testing.T) {
	crypto := testMaskCrypto(t)
	body := []byte(`{"items":[{"secret":"a"},{"secret":"b"}],"aliases":["x","x"]}`)
	plan := []dsctx.FieldTransform{
		{FieldPath: "items[].secret", Algorithm: "ENCRYPT", KeyID: "kid-1"},
		{FieldPath: "aliases[]", Algorithm: "MAP", MapID: "map-1"},
	}
	first, err := ApplyJSONWithKey(body, plan, crypto)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ApplyJSONWithKey(body, plan, crypto)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON := decodeJSONObject(t, first.Body)
	secondJSON := decodeJSONObject(t, second.Body)
	firstItems := firstJSON["items"].([]any)
	secondItems := secondJSON["items"].([]any)
	firstCipher := firstItems[0].(map[string]any)["secret"].(string)
	secondCipher := secondItems[0].(map[string]any)["secret"].(string)
	if firstCipher == secondCipher {
		t.Fatal("AES-GCM must use a fresh nonce per transformation")
	}
	if res := first.AppliedFields; res != 4 {
		t.Fatalf("applied=%d want 4", res)
	}
	firstAliases := firstJSON["aliases"].([]any)
	secondAliases := secondJSON["aliases"].([]any)
	if firstAliases[0] != firstAliases[1] || firstAliases[0] != secondAliases[0] {
		t.Fatalf("MAP must be deterministic for equal values: first=%v second=%v", firstAliases, secondAliases)
	}
}

func TestApplyJSONWithKeyErrors(t *testing.T) {
	crypto := testMaskCrypto(t)
	for _, tc := range []struct {
		name   string
		plan   []dsctx.FieldTransform
		crypto *MaskCrypto
	}{
		{name: "encrypt missing crypto", plan: []dsctx.FieldTransform{{FieldPath: "a", Algorithm: "ENCRYPT", KeyID: "kid-1"}}},
		{name: "map missing crypto", plan: []dsctx.FieldTransform{{FieldPath: "a", Algorithm: "MAP", MapID: "map-1"}}},
		{name: "key mismatch", plan: []dsctx.FieldTransform{{FieldPath: "a", Algorithm: "ENCRYPT", KeyID: "other"}}, crypto: crypto},
		{name: "missing map id", plan: []dsctx.FieldTransform{{FieldPath: "a", Algorithm: "MAP"}}, crypto: crypto},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ApplyJSONWithKey([]byte(`{"a":"secret"}`), tc.plan, tc.crypto); err == nil {
				t.Fatal("expected explicit crypto error")
			}
		})
	}
	if _, err := ApplyJSON([]byte(`{"a":"secret"}`), []dsctx.FieldTransform{{FieldPath: "a", Algorithm: "ENCRYPT", KeyID: "kid-1"}}); err == nil {
		t.Fatal("legacy ApplyJSON must reject ENCRYPT without a key")
	}
	if _, err := NewMaskCrypto("bad kid", bytes.Repeat([]byte{1}, 32)); err == nil {
		t.Fatal("invalid kid must fail")
	}
	if _, err := NewMaskCrypto("kid-1", []byte{1, 2, 3}); err == nil {
		t.Fatal("short AES key must fail")
	}
}

func TestParseMaskRuleCryptoParamsAndPlan(t *testing.T) {
	encrypted, err := ParseMaskRule("ek", "a", "", "ENCRYPT", map[string]any{"key_id": "kid-1"})
	if err != nil {
		t.Fatal(err)
	}
	mapped, err := ParseMaskRule("ek", "b", "", "MAP", map[string]any{"map_id": "map-1"})
	if err != nil {
		t.Fatal(err)
	}
	plan := BuildTransformPlan([]MaskRule{encrypted, mapped}, map[string]string{"a": "string", "b": "string"})
	if len(plan) != 2 || plan[0].KeyID != "kid-1" || plan[1].MapID != "map-1" {
		t.Fatalf("crypto identifiers not carried into plan: %+v", plan)
	}
	for _, tc := range []struct {
		algorithm string
		params    map[string]any
	}{
		{algorithm: "ENCRYPT"},
		{algorithm: "MAP"},
		{algorithm: "ENCRYPT", params: map[string]any{"key_id": ""}},
		{algorithm: "ENCRYPT", params: map[string]any{"key_id": "bad kid"}},
		{algorithm: "MAP", params: map[string]any{"map_id": strings.Repeat("a", 65)}},
		{algorithm: "MAP", params: map[string]any{"map_id": 1}},
	} {
		if _, err := ParseMaskRule("ek", "a", "", tc.algorithm, tc.params); err == nil {
			t.Fatalf("invalid crypto params must fail: %s %+v", tc.algorithm, tc.params)
		}
	}
}
