// stage8_file_compliance_publish_test.go 文件合规规则 + 文件签名 v1 发布侧端到端贯通测试
// （W13-FSIG-COMP-GW / P2-03 / P2-02 下发侧）。
//
// 链路：api_file_compliance_rules 表（迁移 000071/000081 种子/手工行）
//
//	→ 发布通道组装（guardconfig.Provider.BuildGuardConfig：
//	  SetFileComplianceRuleLister(NewFileComplianceStore(db))，与 app.go 装配同一模式）
//	→ GuardConfig.APIFileComplianceRules（表列 match_type/match_value → 下发键 match/value）
//	→ 生成器产出 Caddy JSON：jiuzhang_guard 处理器内 api_file_compliance_rules 段
//	→ 规则启停驱动 api_policy_version 确定性变化（生效校验锚点，P0-21）；
//
//	system_settings gateway_runtime 组 api_file_signature_key（密文）+ api_file_signature_kid
//	→ NewFileSignatureLoader(settings.GetString, encryption.Decrypt) 解密
//	→ GuardConfig.APIFileSignature {enabled,kid,key_hex}
//	→ Caddy JSON api_file_signature 段；RedactGuardConfig 快照脱敏（key_hex → "***"）。
//
// 容错：表缺失（DROP 后）BuildGuardConfig 仍成功且不下发规则段（Warn 跳过，与脱敏规则同一纪律）。
//
// 运行方式（与 make stage8-test-api 一致）：
//
//	POSTGRES_PASSWORD=... VALKEY_PASSWORD=... go test ./tests -run TestStage8FileCompliancePublish -count=1
package tests

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/accesscontrolversions"
	"github.com/jiuzhang-waf/server/internal/accessrules"
	"github.com/jiuzhang-waf/server/internal/apiassets"
	"github.com/jiuzhang-waf/server/internal/apimodels"
	"github.com/jiuzhang-waf/server/internal/encryption"
	"github.com/jiuzhang-waf/server/internal/guardconfig"
	"github.com/jiuzhang-waf/server/internal/protectedaddresses"
	"github.com/jiuzhang-waf/server/internal/ratelimitpolicies"
	"github.com/jiuzhang-waf/server/internal/settings"
	"github.com/jiuzhang-waf/server/internal/trustedproxies"
)

// s8FileCompProvider 按 app.go 同一接线模式构造发布组装器（WDSP 形态 + 文件合规/签名读取）。
func s8FileCompProvider(env *testEnv, encSvc *encryption.Service) *guardconfig.Provider {
	p := guardconfig.NewProvider(
		trustedproxies.NewStore(env.db), protectedaddresses.NewStore(env.db),
		accessrules.NewStore(env.db), ratelimitpolicies.NewStore(env.db),
		accesscontrolversions.NewStore(env.db),
		guardconfig.Config{
			APIDynamicProtection: true, APIProtectionMode: "PROTECT",
			APIEventsLog: "/var/log/caddy/api-runtime-events.log",
			GatewayNode:  "gw-test",
		})
	p.SetAPIModels(apimodels.NewStore(env.db))
	p.SetAPIAssets(apiassets.NewStore(env.db))
	p.SetFileComplianceRuleLister(guardconfig.NewFileComplianceRuleStore(env.db))
	if encSvc != nil {
		p.SetFileSignatureLoader(guardconfig.NewFileSignatureLoader(settings.NewService(env.db).GetString, encSvc.Decrypt))
	}
	return p
}

// TestStage8FileCompliancePublishE2E 文件合规规则：迁移 000071/000081 种子行下发
// （表列→下发键映射）、手工行进入下发与版本戳联动、表缺失 Warn 跳过容忍。
func TestStage8FileCompliancePublishE2E(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()

	// ---------- 1. 迁移 000071/000081 种子行随发布下发（表列 match_type/match_value → 下发键 match/value） ----------
	cfg1, err := s8FileCompProvider(env, nil).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build guard config: %v", err)
	}
	if len(cfg1.APIFileComplianceRules) != 18 {
		t.Fatalf("seed rules = %+v, want 18", cfg1.APIFileComplianceRules)
	}
	r0 := cfg1.APIFileComplianceRules[0]
	if r0.Direction != "DOWNLOAD" || r0.Match != "EXT" || r0.Value != "bak" || r0.Action != "OBSERVE" {
		t.Fatalf("first rule (sorted) mismatch: %+v", r0)
	}
	var foundExe bool
	for _, r := range cfg1.APIFileComplianceRules {
		if r.Direction == "UPLOAD" && r.Match == "EXT" && r.Value == "exe" && r.Action == "BLOCK" && r.Reason != "" {
			foundExe = true
		}
	}
	if !foundExe {
		t.Fatalf("seed upload exe BLOCK rule missing: %+v", cfg1.APIFileComplianceRules)
	}
	v1 := cfg1.APIPolicyVersion
	if v1 == "" {
		t.Fatal("api_policy_version must always be computed")
	}
	// 生成器：处理器 JSON 含 api_file_compliance_rules 段（json tag 跨分片契约）
	j := s8GenerateGuardJSON(t, cfg1)
	for _, want := range []string{`"api_file_compliance_rules"`, `"match":"EXT"`, `"value":"exe"`, `"action":"BLOCK"`} {
		if !strings.Contains(j, want) {
			t.Fatalf("caddy json missing %s", want)
		}
	}
	// 未配置签名密钥：api_file_signature 不下发
	if cfg1.APIFileSignature != nil || strings.Contains(j, "api_file_signature") {
		t.Fatal("api_file_signature must be omitted when unconfigured")
	}

	// ---------- 2. 手工行进入下发 + 版本戳联动 ----------
	_, err = env.db.Exec(ctx, `
INSERT INTO api_file_compliance_rules (direction, match_type, match_value, action, reason)
VALUES ('DOWNLOAD', 'FILENAME_REGEX', '(?i)\.scr$', 'BLOCK', '屏保程序下载阻断')`)
	if err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	cfg2, err := s8FileCompProvider(env, nil).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build guard config: %v", err)
	}
	if len(cfg2.APIFileComplianceRules) != 19 {
		t.Fatalf("rules = %+v, want 19", cfg2.APIFileComplianceRules)
	}
	var foundRegex bool
	for _, r := range cfg2.APIFileComplianceRules {
		if r.Direction == "DOWNLOAD" && r.Match == "FILENAME_REGEX" && r.Action == "BLOCK" {
			foundRegex = true
		}
	}
	if !foundRegex {
		t.Fatalf("manual regex rule missing: %+v", cfg2.APIFileComplianceRules)
	}
	if cfg2.APIPolicyVersion == v1 {
		t.Fatal("rule insert must change api_policy_version (W13 合规规则纳入版本戳)")
	}

	// ---------- 3. 停用全部规则 → 不下发 + 版本戳回落 ----------
	if _, err := env.db.Exec(ctx, `UPDATE api_file_compliance_rules SET enabled = false`); err != nil {
		t.Fatalf("disable rules: %v", err)
	}
	cfg3, err := s8FileCompProvider(env, nil).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build guard config: %v", err)
	}
	if len(cfg3.APIFileComplianceRules) != 0 {
		t.Fatalf("disabled rules must not be delivered: %+v", cfg3.APIFileComplianceRules)
	}
	if cfg3.APIPolicyVersion == cfg2.APIPolicyVersion {
		t.Fatal("rule disable must change api_policy_version")
	}

	// ---------- 4. 表缺失容忍：DROP 后发布主流程仍成功且不下发规则段（Warn 跳过） ----------
	if _, err := env.db.Exec(ctx, `DROP TABLE api_file_compliance_rules`); err != nil {
		t.Fatalf("drop table: %v", err)
	}
	cfg4, err := s8FileCompProvider(env, nil).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("missing table must be tolerated (warn-skip): %v", err)
	}
	if cfg4.APIFileComplianceRules != nil {
		t.Fatalf("missing table must yield nil rules: %+v", cfg4.APIFileComplianceRules)
	}
	if strings.Contains(s8GenerateGuardJSON(t, cfg4), "api_file_compliance_rules") {
		t.Fatal("missing table must not produce api_file_compliance_rules in caddy json")
	}
}

// TestStage8FileSignaturePublishE2E 文件签名密钥：system_settings 密文 → 解密下发
// （enabled/kid/key_hex）→ Caddy JSON 段；快照脱敏（key_hex → "***"，kid 保留）。
func TestStage8FileSignaturePublishE2E(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()

	encSvc, err := encryption.NewWithKey([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatalf("new encryption: %v", err)
	}
	settingsSvc := settings.NewService(env.db)
	sigKeyHex := hex.EncodeToString([]byte("fedcba9876543210fedcba9876543210"))

	// 写入密文密钥与 kid（UpsertString 与运行期功能开关同一通路）
	ciphertext, err := encSvc.Encrypt(sigKeyHex)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := settingsSvc.UpsertString(ctx, "gateway_runtime", "api_file_signature_key", ciphertext, "文件签名密钥（密文）", uuid.Nil); err != nil {
		t.Fatalf("upsert key: %v", err)
	}
	if err := settingsSvc.UpsertString(ctx, "gateway_runtime", "api_file_signature_kid", "k2026", "文件签名密钥标识", uuid.Nil); err != nil {
		t.Fatalf("upsert kid: %v", err)
	}

	// ---------- 1. 发布通道组装：密文解密下发 {enabled,kid,key_hex} ----------
	cfg, err := s8FileCompProvider(env, encSvc).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build guard config: %v", err)
	}
	sig := cfg.APIFileSignature
	if sig == nil || !sig.Enabled || sig.KID != "k2026" || sig.KeyHex != sigKeyHex {
		t.Fatalf("api_file_signature = %+v", sig)
	}
	// 生成器：处理器 JSON 含 api_file_signature 段（json tag 跨分片契约）
	j := s8GenerateGuardJSON(t, cfg)
	for _, want := range []string{`"api_file_signature"`, `"kid":"k2026"`, `"key_hex":"` + sigKeyHex + `"`} {
		if !strings.Contains(j, want) {
			t.Fatalf("caddy json missing %s", want)
		}
	}
	// 密文本身不得出现在下发面任何位置（下发的是解密后明文 hex）
	if strings.Contains(j, ciphertext) {
		t.Fatal("ciphertext must not leak into caddy json")
	}

	// ---------- 2. 快照脱敏：key_hex → "***"（kid 保留），原配置不受影响 ----------
	red, err := json.Marshal(guardconfig.RedactGuardConfig(cfg))
	if err != nil {
		t.Fatalf("marshal redacted: %v", err)
	}
	if strings.Contains(string(red), sigKeyHex) {
		t.Fatalf("redacted snapshot still contains signature key: %s", red)
	}
	if !strings.Contains(string(red), `"kid":"k2026"`) || cfg.APIFileSignature.KeyHex != sigKeyHex {
		t.Fatal("kid must survive redaction and original config must stay intact")
	}

	// ---------- 3. kid 缺失不再静默降级：已配置密钥却缺 kid → 组装报错中止发布 ----------
	// （fail-hard 口径，见 guardconfig/file_signature.go：Warn-skip 会静默停用签名嵌入，
	// 造成管理面显示与网关行为不一致，不允许带病发布）
	if _, err := env.db.Exec(ctx, `DELETE FROM system_settings WHERE setting_group = 'gateway_runtime' AND setting_key = 'api_file_signature_kid'`); err != nil {
		t.Fatalf("delete kid: %v", err)
	}
	if _, err := s8FileCompProvider(env, encSvc).BuildGuardConfig(ctx); err == nil ||
		!strings.Contains(err.Error(), "api_file_signature_kid") {
		t.Fatalf("missing kid must fail-hard with kid error, got: %v", err)
	}

	// ---------- 4. 密钥与 kid 均未配置 → 不下发签名段（未配置=网关零行为变化） ----------
	if _, err := env.db.Exec(ctx, `DELETE FROM system_settings WHERE setting_group = 'gateway_runtime' AND setting_key = 'api_file_signature_key'`); err != nil {
		t.Fatalf("delete key: %v", err)
	}
	cfg2, err := s8FileCompProvider(env, encSvc).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("unconfigured signature must be tolerated: %v", err)
	}
	if cfg2.APIFileSignature != nil {
		t.Fatalf("unconfigured signature must yield nil: %+v", cfg2.APIFileSignature)
	}
}
