package guardconfig

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

func TestNewMaskCryptoLoader(t *testing.T) {
	kv := &fakeSettingsGet{kv: map[string]string{}}
	loader := NewMaskCryptoLoader(kv.get, fakeDecrypt)
	kid, keyHex, err := loader(context.Background())
	if err != nil || kid != "" || keyHex != "" {
		t.Fatalf("unset loader = %q, %q, %v", kid, keyHex, err)
	}

	kv.kv["gateway_runtime/api_mask_encryption_kid"] = "mask_k1"
	kv.kv["gateway_runtime/api_mask_encryption_key"] = "enc:" + scanTestKeyHex
	kid, keyHex, err = loader(context.Background())
	if err != nil || kid != "mask_k1" || keyHex != scanTestKeyHex {
		t.Fatalf("loader = %q, %q, %v", kid, keyHex, err)
	}

	for _, tc := range []struct {
		name string
		kid  string
		raw  string
	}{
		{name: "缺 kid", kid: "", raw: "enc:" + scanTestKeyHex},
		{name: "缺 key", kid: "mask_k1", raw: ""},
		{name: "非法 kid", kid: "bad kid", raw: "enc:" + scanTestKeyHex},
		{name: "解密失败", kid: "mask_k1", raw: "bad"},
		{name: "短密钥", kid: "mask_k1", raw: "enc:abcd"},
		{name: "非 hex", kid: "mask_k1", raw: "enc:" + strings.Repeat("zz", 32)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			kv.kv["gateway_runtime/api_mask_encryption_kid"] = tc.kid
			kv.kv["gateway_runtime/api_mask_encryption_key"] = tc.raw
			if _, _, err := loader(context.Background()); err == nil || strings.Contains(err.Error(), scanTestKeyHex) {
				t.Fatalf("invalid config must fail without key disclosure, error=%v", err)
			}
		})
	}
}

func TestLoadAPIMaskCryptoOnlyForCryptoRules(t *testing.T) {
	calls := 0
	provider := &Provider{maskCrypto: func(context.Context) (string, string, error) {
		calls++
		return "mask_k1", scanTestKeyHex, nil
	}}
	crypto, err := provider.loadAPIMaskCrypto(context.Background(), []gatewayconfig.GuardMaskRule{{Algorithm: "MASK"}, {Algorithm: "HASH"}, {Algorithm: "REMOVE"}})
	if err != nil || crypto != nil || calls != 0 {
		t.Fatalf("non-crypto rules loaded key: crypto=%+v calls=%d err=%v", crypto, calls, err)
	}
	for _, algorithm := range []string{"ENCRYPT", "MAP"} {
		crypto, err = provider.loadAPIMaskCrypto(context.Background(), []gatewayconfig.GuardMaskRule{{Algorithm: algorithm}})
		if err != nil || crypto == nil || crypto.KID != "mask_k1" || crypto.KeyHex != scanTestKeyHex {
			t.Fatalf("%s crypto = %+v, err=%v", algorithm, crypto, err)
		}
	}
	if calls != 2 {
		t.Fatalf("loader calls = %d, want 2", calls)
	}

	provider.maskCrypto = nil
	if _, err := provider.loadAPIMaskCrypto(context.Background(), []gatewayconfig.GuardMaskRule{{Algorithm: "ENCRYPT"}}); err == nil {
		t.Fatal("missing loader must fail for ENCRYPT rule")
	}
	provider.maskCrypto = func(context.Context) (string, string, error) { return "", "", errors.New("decrypt failed") }
	if _, err := provider.loadAPIMaskCrypto(context.Background(), []gatewayconfig.GuardMaskRule{{Algorithm: "MAP"}}); err == nil {
		t.Fatal("loader error must fail for MAP rule")
	}
}

func TestRedactAndReplayMaskCrypto(t *testing.T) {
	cfg := &gatewayconfig.GuardConfig{
		APIMaskRules:  []gatewayconfig.GuardMaskRule{{Algorithm: "ENCRYPT"}},
		APIMaskCrypto: &gatewayconfig.GuardMaskCrypto{KID: "old_kid", KeyHex: scanTestKeyHex},
	}
	redacted, err := json.Marshal(RedactGuardConfig(cfg))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(redacted), scanTestKeyHex) || !strings.Contains(string(redacted), `"key_hex":"***"`) {
		t.Fatalf("redaction leaked key: %s", redacted)
	}
	if cfg.APIMaskCrypto.KeyHex != scanTestKeyHex {
		t.Fatal("redaction mutated source config")
	}

	provider := &Provider{maskCrypto: func(context.Context) (string, string, error) {
		return "new_kid", sigTestKeyHex, nil
	}}
	cfg.APIMaskCrypto.KeyHex = redactPlaceholder
	if err := provider.replayRuntimeSecrets(context.Background(), cfg); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if cfg.APIMaskCrypto == nil || cfg.APIMaskCrypto.KID != "new_kid" || cfg.APIMaskCrypto.KeyHex != sigTestKeyHex {
		t.Fatalf("replayed crypto = %+v", cfg.APIMaskCrypto)
	}
	if got := computeAPIPolicyVersion(cfg); got != computeAPIPolicyVersion(&gatewayconfig.GuardConfig{APIMaskRules: cfg.APIMaskRules}) {
		t.Fatal("mask crypto secret must not affect api_policy_version")
	}
}
