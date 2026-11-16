package tests

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/encryption"
	"github.com/jiuzhang-waf/server/internal/guardconfig"
	"github.com/jiuzhang-waf/server/internal/settings"
)

const (
	maskCryptoKIDSettingKey = "api_mask_encryption_kid"
	maskCryptoKeySettingKey = "api_mask_encryption_key"
)

func TestAPIMaskCryptoMigration000213Static(t *testing.T) {
	up := readMigration(t, "000213_api_mask_crypto.up.sql")
	for _, fragment := range []string{
		"api_masking_rules_algorithm_check", "'ENCRYPT','MAP'",
		maskCryptoKIDSettingKey, maskCryptoKeySettingKey, "'string', TRUE",
		"ON CONFLICT (setting_group, setting_key) DO NOTHING",
	} {
		if !strings.Contains(up, fragment) {
			t.Errorf("000213 up missing %q: %s", fragment, up)
		}
	}
	down := readMigration(t, "000213_api_mask_crypto.down.sql")
	for _, fragment := range []string{
		"DELETE FROM system_settings", "DELETE FROM api_masking_rules WHERE algorithm IN ('ENCRYPT', 'MAP')",
		"CHECK (algorithm IN ('MASK','HASH','REMOVE'))",
	} {
		if !strings.Contains(down, fragment) {
			t.Errorf("000213 down missing %q: %s", fragment, down)
		}
	}
}

func TestAPIMaskCryptoMigration000213Integration(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	up := readMigration(t, "000213_api_mask_crypto.up.sql")
	down := readMigration(t, "000213_api_mask_crypto.down.sql")
	for i := 0; i < 2; i++ {
		if _, err := env.db.Exec(ctx, up); err != nil {
			t.Fatalf("replay up #%d: %v", i+1, err)
		}
	}
	assertMaskCryptoSetting000213(t, env, maskCryptoKIDSettingKey, false)
	assertMaskCryptoSetting000213(t, env, maskCryptoKeySettingKey, true)
	for _, algorithm := range []string{"ENCRYPT", "MAP"} {
		params := `{"key_id":"mask_k1"}`
		if algorithm == "MAP" {
			params = `{"map_id":"map_1"}`
		}
		if _, err := env.db.Exec(ctx, `INSERT INTO api_masking_rules(name,algorithm,params_json)
			VALUES ($1,$2,$3::jsonb)`, "crypto-"+algorithm, algorithm, params); err != nil {
			t.Fatalf("insert %s rule: %v", algorithm, err)
		}
	}
	if _, err := env.db.Exec(ctx, up); err != nil {
		t.Fatalf("replay up with crypto rules: %v", err)
	}
	if _, err := env.db.Exec(ctx, down); err != nil {
		t.Fatalf("down: %v", err)
	}
	if got := s8Count(t, env, `SELECT count(*) FROM api_masking_rules WHERE algorithm IN ('ENCRYPT','MAP')`); got != 0 {
		t.Fatalf("crypto rules remain after down: %d", got)
	}
	if got := s8Count(t, env, `SELECT count(*) FROM system_settings WHERE setting_group='gateway_runtime'
		AND setting_key IN ($1,$2)`, maskCryptoKIDSettingKey, maskCryptoKeySettingKey); got != 0 {
		t.Fatalf("crypto settings remain after down: %d", got)
	}
	if _, err := env.db.Exec(ctx, `INSERT INTO api_masking_rules(name,algorithm) VALUES ('legacy-mask','MASK')`); err != nil {
		t.Fatalf("legacy algorithm must survive down: %v", err)
	}
	if _, err := env.db.Exec(ctx, up); err != nil {
		t.Fatalf("re-up: %v", err)
	}
	assertMaskCryptoSetting000213(t, env, maskCryptoKeySettingKey, true)
	if _, err := env.db.Exec(ctx, `INSERT INTO api_masking_rules(name,algorithm,params_json)
		VALUES ('reup-map','MAP','{"map_id":"map_1"}'::jsonb)`); err != nil {
		t.Fatalf("re-up must allow MAP: %v", err)
	}
}

func assertMaskCryptoSetting000213(t *testing.T, env *testEnv, key string, wantSensitive bool) {
	t.Helper()
	var value, valueType string
	var sensitive bool
	if err := env.db.QueryRow(context.Background(), `SELECT setting_value::text,value_type,is_sensitive
		FROM system_settings WHERE setting_group='gateway_runtime' AND setting_key=$1`, key).
		Scan(&value, &valueType, &sensitive); err != nil {
		t.Fatalf("read %s: %v", key, err)
	}
	if value != `""` || valueType != "string" || sensitive != wantSensitive {
		t.Fatalf("%s = value %s type %s sensitive %v; want empty string, string, %v", key, value, valueType, sensitive, wantSensitive)
	}
}

func TestAPIMaskCryptoPublishAndDecryptIntegration(t *testing.T) {
	masterBytes := []byte("0123456789abcdef0123456789abcdef")
	t.Setenv("JIUZHANG_MASTER_KEY", hex.EncodeToString(masterBytes))
	env := setupStage8Env(t)
	ctx := context.Background()
	cookies, csrf := env.s5Login(t, "mcrypto", "SECURITY_ADMIN")
	encSvc, err := encryption.NewWithKey(masterBytes)
	if err != nil {
		t.Fatal(err)
	}
	settingsSvc := settings.NewService(env.db)
	provider := s8MaskProvider(env)
	provider.SetMaskCryptoLoader(guardconfig.NewMaskCryptoLoader(settingsSvc.GetString, encSvc.Decrypt))

	createRule := func(name, algorithm, params string) {
		t.Helper()
		body := `{"name":` + strconvQuote000213(name) + `,"scope":"GLOBAL","field_path":"json.secret","algorithm":` +
			strconvQuote000213(algorithm) + `,"params_json":` + params + `}`
		s5OK(t, env.post(t, "/api/v1/api-security/masking-rules", body, cookies, csrf), "create "+algorithm)
	}
	createRule("legacy-mask", "MASK", `{"keep_head":1}`)
	baseline, err := provider.BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("non-crypto rules must not require key: %v", err)
	}
	if baseline.APIMaskCrypto != nil {
		t.Fatalf("non-crypto rules received key: %+v", baseline.APIMaskCrypto)
	}

	createRule("encrypt-rule", "ENCRYPT", `{"key_id":"mask_k1"}`)
	createRule("map-rule", "MAP", `{"map_id":"map_1"}`)
	if _, err := provider.BuildGuardConfig(ctx); err == nil {
		t.Fatal("ENCRYPT/MAP without key must abort publish")
	}

	keyHex := hex.EncodeToString([]byte("abcdef0123456789abcdef0123456789"))
	ciphertext, err := encSvc.Encrypt(keyHex)
	if err != nil {
		t.Fatal(err)
	}
	if err := settingsSvc.UpsertString(ctx, "gateway_runtime", maskCryptoKIDSettingKey, "mask_k1", "", uuid.Nil); err != nil {
		t.Fatal(err)
	}
	if err := settingsSvc.UpsertSensitiveString(ctx, "gateway_runtime", maskCryptoKeySettingKey, ciphertext, "", uuid.Nil); err != nil {
		t.Fatal(err)
	}
	published, err := provider.BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build crypto publish: %v", err)
	}
	if published.APIMaskCrypto == nil || published.APIMaskCrypto.KID != "mask_k1" || published.APIMaskCrypto.KeyHex != keyHex {
		t.Fatalf("published crypto = %+v", published.APIMaskCrypto)
	}
	generated := s8GenerateGuardJSON(t, published)
	for _, want := range []string{`"algorithm":"ENCRYPT"`, `"algorithm":"MAP"`, `"params":{"key_id":"mask_k1"}`, `"params":{"map_id":"map_1"}`, `"api_mask_crypto"`, `"kid":"mask_k1"`, `"key_hex":"` + keyHex + `"`} {
		if !strings.Contains(generated, want) {
			t.Errorf("generated config missing %s", want)
		}
	}
	if strings.Contains(generated, ciphertext) {
		t.Fatal("encrypted setting leaked into generated config")
	}

	versionID, err := provider.SaveVersionSnapshot(ctx, published, uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("save snapshot: %v", err)
	}
	var snapshot string
	if err := env.db.QueryRow(ctx, `SELECT config::text FROM access_control_versions WHERE id=$1`, versionID).Scan(&snapshot); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(snapshot, keyHex) || strings.Contains(snapshot, ciphertext) || !strings.Contains(snapshot, `"key_hex":"***"`) {
		t.Fatalf("snapshot did not redact crypto key: %s", snapshot)
	}

	newKeyHex := hex.EncodeToString([]byte("fedcba9876543210fedcba9876543210"))
	newCiphertext, err := encSvc.Encrypt(newKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	if err := settingsSvc.UpsertString(ctx, "gateway_runtime", maskCryptoKIDSettingKey, "mask_k2", "", uuid.Nil); err != nil {
		t.Fatal(err)
	}
	if err := settingsSvc.UpsertSensitiveString(ctx, "gateway_runtime", maskCryptoKeySettingKey, newCiphertext, "", uuid.Nil); err != nil {
		t.Fatal(err)
	}
	rolledBack, err := provider.GetVersionConfig(ctx, versionID)
	if err != nil {
		t.Fatalf("rollback crypto snapshot: %v", err)
	}
	if rolledBack.APIMaskCrypto == nil || rolledBack.APIMaskCrypto.KID != "mask_k2" || rolledBack.APIMaskCrypto.KeyHex != newKeyHex {
		t.Fatalf("rollback did not use current crypto key: %+v", rolledBack.APIMaskCrypto)
	}

	plaintext := "sensitive-value"
	encoded, err := encSvc.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	resp := env.post(t, "/api/v1/api-security/masking-rules/decrypt",
		`{"ciphertext":"enc_mask_k2_`+encoded+`"}`, cookies, csrf)
	var result apiResp
	readJSON(t, resp, &result)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || result.Data["plaintext"] != plaintext {
		t.Fatalf("decrypt status=%d data=%+v", resp.StatusCode, result.Data)
	}
	var risk, beforeSummary, afterSummary string
	if err := env.db.QueryRow(ctx, `SELECT risk_level,before_summary,after_summary FROM operation_audits
		WHERE module='api_data' AND action='decrypt' ORDER BY created_at DESC LIMIT 1`).Scan(&risk, &beforeSummary, &afterSummary); err != nil {
		t.Fatalf("read decrypt audit: %v", err)
	}
	if risk != "HIGH" || strings.Contains(beforeSummary+afterSummary, plaintext) ||
		strings.Contains(beforeSummary+afterSummary, newKeyHex) || strings.Contains(beforeSummary+afterSummary, newCiphertext) {
		t.Fatalf("unsafe decrypt audit: risk=%s before=%s after=%s", risk, beforeSummary, afterSummary)
	}

	for _, tc := range []struct {
		name       string
		ciphertext string
		want       int
	}{
		{name: "kid 不符", ciphertext: "enc_other_" + encoded, want: http.StatusBadRequest},
		{name: "格式错误", ciphertext: "not-encrypted", want: http.StatusBadRequest},
		{name: "解密失败", ciphertext: "enc_mask_k2_" + encoded[:len(encoded)-2] + "AA", want: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := env.post(t, "/api/v1/api-security/masking-rules/decrypt",
				`{"ciphertext":`+strconvQuote000213(tc.ciphertext)+`}`, cookies, csrf)
			body := readBodyString(t, resp)
			resp.Body.Close()
			if resp.StatusCode != tc.want || strings.Contains(body, plaintext) || strings.Contains(body, newKeyHex) {
				t.Fatalf("status=%d unsafe body=%s", resp.StatusCode, body)
			}
		})
	}

	if _, err := env.db.Exec(ctx, `DELETE FROM system_settings WHERE setting_group='gateway_runtime'
		AND setting_key IN ($1,$2)`, maskCryptoKIDSettingKey, maskCryptoKeySettingKey); err != nil {
		t.Fatal(err)
	}
	resp = env.post(t, "/api/v1/api-security/masking-rules/decrypt",
		`{"ciphertext":"enc_mask_k2_`+encoded+`"}`, cookies, csrf)
	s5Expect(t, resp, http.StatusServiceUnavailable, "decrypt without configured key")
	if _, err := env.db.Exec(ctx, `UPDATE api_masking_rules SET enabled=false WHERE algorithm IN ('ENCRYPT','MAP')`); err != nil {
		t.Fatal(err)
	}
	withoutCrypto, err := provider.BuildGuardConfig(ctx)
	if err != nil || withoutCrypto.APIMaskCrypto != nil {
		t.Fatalf("non-crypto rules after key removal must not load key: cfg=%+v err=%v", withoutCrypto.APIMaskCrypto, err)
	}
}

func strconvQuote000213(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}
