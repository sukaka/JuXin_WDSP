// config_secrets_test.go 配置版本密钥语义与 GuardOverride 门控测试：
// RedactConfigSecrets 脱敏存储、Rollback 重注入当前密钥（含存量明文 JSON 统一路径）、
// 回滚覆盖快照按当前产品开关剥除 API 段（防跨重启泄漏）。
package gatewayconfig

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// fakeGuardProvider 测试用 GuardProvider（仅 BuildGuardConfig 有语义，其余接口空实现）。
type fakeGuardProvider struct {
	buildCfg   *GuardConfig
	buildErr   error
	buildCalls int
}

func (f *fakeGuardProvider) BuildGuardConfig(context.Context) (*GuardConfig, error) {
	f.buildCalls++
	return f.buildCfg, f.buildErr
}

func (f *fakeGuardProvider) SaveVersionSnapshot(context.Context, *GuardConfig, uuid.UUID, uuid.UUID) (uuid.UUID, error) {
	return uuid.New(), nil
}

func (f *fakeGuardProvider) MarkVersionResult(context.Context, uuid.UUID, string) error { return nil }

func (f *fakeGuardProvider) GetVersionConfig(context.Context, uuid.UUID) (*GuardConfig, error) {
	return nil, errors.New("not implemented")
}

// secretTestGuardConfig 含全部密钥类字段的 guard 配置（WDSP 开启形态）；
// 密钥值带 tag 前缀（old/new），便于断言「重注入的是当前值而非快照值」。
func secretTestGuardConfig(tag string) *GuardConfig {
	g := testGuardConfig()
	g.Valkey = &GuardValkey{Address: "valkey:6379", Username: "waf", Password: tag + "-valkey-secret", DB: 0}
	g.APIDynamicProtection = true
	g.APIProtectionMode = "OBSERVE"
	g.IdentitySalt = tag + "-identity-salt"
	g.TLSSessionTicketKey = tag + "-tls-ticket-key"
	g.APIScanVerification = &GuardScanVerification{KeyHex: tag + "-scan-key-hex"}
	g.APIFileSignature = &GuardFileSignature{Enabled: true, KID: tag + "-kid", KeyHex: tag + "-file-sig-key-hex"}
	g.APIMaskCrypto = &GuardMaskCrypto{KID: tag + "-mask-kid", KeyHex: tag + "-mask-crypto-key-hex"}
	g.BotPolicy = map[string]*GuardBotPolicy{
		"shop": {
			SchemaVersion: 1,
			ApplicationID: "app-shop",
			Mode:          "OBSERVE",
			Version:       1,
			Challenge:     GuardBotChallenge{Type: "JS", KeyRef: "k1"},
		},
	}
	g.BotSigningKeys = map[string]string{
		"k1": tag + "-bot-signing-secret-1",
		"k2": tag + "-bot-signing-secret-2",
	}
	return g
}

// secretValues 该 tag 配置携带的全部密钥明文。
func secretValues(tag string) []string {
	return []string{
		tag + "-valkey-secret", tag + "-identity-salt", tag + "-scan-key-hex",
		tag + "-file-sig-key-hex", tag + "-mask-crypto-key-hex", tag + "-tls-ticket-key",
		tag + "-bot-signing-secret-1", tag + "-bot-signing-secret-2",
	}
}

// generateGuardJSON 用 licenseTestApps（shop 应用）生成整站配置 JSON。
func generateGuardJSON(t *testing.T, g *GuardConfig) string {
	t.Helper()
	gen, err := Generate(GenerateInput{
		Apps:        licenseTestApps(),
		AdminSocket: "/var/run/caddy/admin.sock",
		Guard:       g,
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return gen.JSON
}

// 脱敏存储：密钥明文全部替换为 "***" 占位，非密钥字段（地址、kid 等）保留，幂等。
func TestRedactConfigSecrets(t *testing.T) {
	plain := generateGuardJSON(t, secretTestGuardConfig("old"))
	redacted, err := RedactConfigSecrets(plain)
	if err != nil {
		t.Fatalf("RedactConfigSecrets: %v", err)
	}
	var v interface{}
	if err := json.Unmarshal([]byte(redacted), &v); err != nil {
		t.Fatalf("脱敏产物不是合法 JSON: %v", err)
	}
	for _, s := range secretValues("old") {
		if strings.Contains(redacted, s) {
			t.Errorf("脱敏产物仍含密钥明文 %q", s)
		}
	}
	for _, want := range []string{`"password":"***"`, `"identity_salt":"***"`, `"key_hex":"***"`, `"keys_hex":["***"]`} {
		if !strings.Contains(redacted, want) {
			t.Errorf("脱敏产物缺少占位 %q", want)
		}
	}
	// 非密钥字段保留（valkey 地址、文件签名 kid、guard 处理器本体）
	for _, want := range []string{"valkey:6379", "old-kid", "jiuzhang_guard", "guard-events.log"} {
		if !strings.Contains(redacted, want) {
			t.Errorf("脱敏产物应保留非密钥字段 %q", want)
		}
	}
	// 幂等：对已脱敏产物再次脱敏逐字节一致
	again, err := RedactConfigSecrets(redacted)
	if err != nil {
		t.Fatalf("再次脱敏: %v", err)
	}
	if again != redacted {
		t.Error("脱敏应幂等")
	}
}

// 无 guard 的配置（纯 WAF/透传形态）：脱敏不产生占位、不报错。
func TestRedactConfigSecretsWithoutGuard(t *testing.T) {
	gen, err := Generate(GenerateInput{
		Apps:        licenseTestApps(),
		AdminSocket: "/var/run/caddy/admin.sock",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	out, err := RedactConfigSecrets(gen.JSON)
	if err != nil {
		t.Fatalf("RedactConfigSecrets: %v", err)
	}
	if strings.Contains(out, redactedSecretPlaceholder) {
		t.Error("无密钥配置不应产生脱敏占位")
	}
	if !strings.Contains(out, "reverse_proxy") {
		t.Error("脱敏不应破坏配置内容")
	}
}

// 回滚重注入：脱敏快照中的占位统一替换为当前设置值（两条回滚路径同口径的核心）。
func TestReinjectConfigSecretsRedactedSnapshot(t *testing.T) {
	oldCfg := secretTestGuardConfig("old")
	oldCfg.APIAuthzObjectHMACKeyHex = strings.Repeat("a", 64)
	oldCfg.APIAuthzModels = []GuardAuthzObjectModel{{ApplicationID: "app-1", EndpointKey: "GET /v1/orders/{id}", ObjectType: "ORDER"}}
	oldCfg.APIAuthzPreviousValid = &GuardAuthzSnapshot{
		Models:           oldCfg.APIAuthzModels,
		ObjectHMACKeyHex: oldCfg.APIAuthzObjectHMACKeyHex,
		PolicyVersion:    "previous-v1",
	}
	stored, err := RedactConfigSecrets(generateGuardJSON(t, oldCfg))
	if err != nil {
		t.Fatalf("RedactConfigSecrets: %v", err)
	}
	newCfg := secretTestGuardConfig("new")
	newCfg.APIAuthzObjectHMACKeyHex = strings.Repeat("b", 64)
	newCfg.APIAuthzModels = oldCfg.APIAuthzModels
	fake := &fakeGuardProvider{buildCfg: newCfg}
	p := &Publisher{guard: fake}
	out, err := p.reinjectConfigSecrets(context.Background(), stored)
	if err != nil {
		t.Fatalf("reinjectConfigSecrets: %v", err)
	}
	for _, s := range secretValues("new") {
		if !strings.Contains(out, s) {
			t.Errorf("重注入产物缺少当前密钥值 %q", s)
		}
	}
	for _, s := range secretValues("old") {
		if strings.Contains(out, s) {
			t.Errorf("重注入产物不得含快照旧值 %q", s)
		}
	}
	if strings.Contains(out, `"***"`) {
		t.Error("重注入产物不得残留脱敏占位")
	}
	if strings.Contains(out, oldCfg.APIAuthzObjectHMACKeyHex) ||
		!strings.Contains(out, newCfg.APIAuthzObjectHMACKeyHex) {
		t.Error("AUTHZ 当前与上一快照均必须使用当前对象引用 HMAC 密钥")
	}
	if !strings.Contains(out, "new-kid") {
		t.Error("文件签名 kid 应随当前设置重注入")
	}
	if fake.buildCalls != 1 {
		t.Fatalf("当前配置应读取一次，got %d", fake.buildCalls)
	}
	if _, err := CanonicalConfigHash(out); err != nil {
		t.Errorf("重注入产物结构无效: %v", err)
	}
}

// 存量历史版本（含旧明文）回滚同样走重注入：旧值被当前值覆盖，不静默恢复旧密钥。
func TestReinjectConfigSecretsLegacyPlaintext(t *testing.T) {
	legacy := generateGuardJSON(t, secretTestGuardConfig("old"))
	p := &Publisher{guard: &fakeGuardProvider{buildCfg: secretTestGuardConfig("new")}}
	out, err := p.reinjectConfigSecrets(context.Background(), legacy)
	if err != nil {
		t.Fatalf("reinjectConfigSecrets: %v", err)
	}
	for _, s := range secretValues("new") {
		if !strings.Contains(out, s) {
			t.Errorf("重注入产物缺少当前密钥值 %q", s)
		}
	}
	for _, s := range secretValues("old") {
		if strings.Contains(out, s) {
			t.Errorf("存量明文旧密钥 %q 不得被回放", s)
		}
	}
}

// 当前设置取不到值：按字段逐一失败并明确报错，不回放占位符或旧明文。
func TestReinjectConfigSecretsMissingCurrentValues(t *testing.T) {
	stored, err := RedactConfigSecrets(generateGuardJSON(t, secretTestGuardConfig("old")))
	if err != nil {
		t.Fatalf("RedactConfigSecrets: %v", err)
	}
	without := func(mutate func(*GuardConfig)) *GuardConfig {
		g := secretTestGuardConfig("new")
		mutate(g)
		return g
	}
	cases := []struct {
		name    string
		cur     *GuardConfig
		wantErr string
	}{
		{"缺 Valkey 连接", without(func(g *GuardConfig) { g.Valkey = nil }), "valkey"},
		{"缺 identity_salt", without(func(g *GuardConfig) { g.IdentitySalt = "" }), "identity_salt"},
		{"缺扫描签名密钥", without(func(g *GuardConfig) { g.APIScanVerification = nil }), "api_scan_verification"},
		{"扫描签名密钥为空", without(func(g *GuardConfig) { g.APIScanVerification = &GuardScanVerification{} }), "api_scan_verification"},
		{"缺文件签名密钥", without(func(g *GuardConfig) { g.APIFileSignature = nil }), "api_file_signature"},
		{"缺脱敏加密密钥", without(func(g *GuardConfig) { g.APIMaskCrypto = nil }), "api_mask_crypto"},
		{"缺 TLS 票据键", without(func(g *GuardConfig) { g.TLSSessionTicketKey = "" }), "tls_session_ticket_key"},
		{"缺 Bot 签名密钥", without(func(g *GuardConfig) { g.BotSigningKeys = nil }), "bot_policy.signing_keys"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Publisher{guard: &fakeGuardProvider{buildCfg: tc.cur}}
			_, err := p.reinjectConfigSecrets(context.Background(), stored)
			if err == nil {
				t.Fatal("取不到当前密钥值应失败")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("错误应指明字段 %q: %v", tc.wantErr, err)
			}
		})
	}
}

// 配置不含密钥字段：原样返回（字节不变），不读取当前配置、不要求装配 guard provider。
func TestReinjectConfigSecretsNoSecretFields(t *testing.T) {
	gen, err := Generate(GenerateInput{
		Apps:        licenseTestApps(),
		AdminSocket: "/var/run/caddy/admin.sock",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	fake := &fakeGuardProvider{buildCfg: secretTestGuardConfig("new")}
	p := &Publisher{guard: fake}
	out, err := p.reinjectConfigSecrets(context.Background(), gen.JSON)
	if err != nil {
		t.Fatalf("reinjectConfigSecrets: %v", err)
	}
	if out != gen.JSON {
		t.Error("无密钥字段的配置应原样返回")
	}
	if fake.buildCalls != 0 {
		t.Fatal("无密钥字段不应读取当前配置")
	}
	// 未装配 guard provider 同样放行
	p = &Publisher{}
	if _, err := p.reinjectConfigSecrets(context.Background(), gen.JSON); err != nil {
		t.Fatalf("无密钥字段且未装配 guard 不应报错: %v", err)
	}
}

// 含密钥字段但未装配 guard provider：无法重注入，明确失败（不回放占位/旧明文）。
func TestReinjectConfigSecretsNilGuardProvider(t *testing.T) {
	stored, err := RedactConfigSecrets(generateGuardJSON(t, secretTestGuardConfig("old")))
	if err != nil {
		t.Fatalf("RedactConfigSecrets: %v", err)
	}
	p := &Publisher{}
	if _, err := p.reinjectConfigSecrets(context.Background(), stored); err == nil ||
		!strings.Contains(err.Error(), "无法重注入当前密钥") {
		t.Fatalf("未装配 guard provider 应明确失败: %v", err)
	}
}

// 当前配置读取失败：如实报错（回滚失败），不静默回放。
func TestReinjectConfigSecretsBuildError(t *testing.T) {
	stored, err := RedactConfigSecrets(generateGuardJSON(t, secretTestGuardConfig("old")))
	if err != nil {
		t.Fatalf("RedactConfigSecrets: %v", err)
	}
	p := &Publisher{guard: &fakeGuardProvider{buildErr: errors.New("db down")}}
	if _, err := p.reinjectConfigSecrets(context.Background(), stored); err == nil ||
		!strings.Contains(err.Error(), "读取当前访问控制配置失败") {
		t.Fatalf("读取当前配置失败应如实返回: %v", err)
	}
}

// GuardOverride 门控：当前产品开关关闭（API_DYNAMIC_PROTECTION_ENABLED=false 或
// edition=waf）时剥除快照 API 段，口径与 buildGuardHandler 一致；非 API 字段保留。
func TestGateGuardOverrideStripsAPISectionsWhenProductOff(t *testing.T) {
	override := secretTestGuardConfig("old")
	override.APIFormalSchemas = map[string]map[string]string{"GET /api": {"id": "number"}}
	override.APIPolicyVersion = "v123"
	override.L7Rules = &GuardL7Rules{Rules: []GuardL7Rule{{ID: "l7-1", Name: "封禁", Priority: 1, Enabled: true, Action: "BLOCK"}}}
	override.AccessLog = &GuardAccessLog{Enabled: true, LogPath: "/var/log/caddy/access-full.jsonl"}
	// 当前为纯 WAF 形态（APIDynamicProtection=false）
	p := &Publisher{guard: &fakeGuardProvider{buildCfg: testGuardConfig()}}
	gated, err := p.gateGuardOverride(context.Background(), override)
	if err != nil {
		t.Fatalf("gateGuardOverride: %v", err)
	}
	// API 段剥除
	if gated.APIDynamicProtection {
		t.Error("产品开关关闭时应剥除 APIDynamicProtection")
	}
	if gated.IdentitySalt != "" || gated.APIScanVerification != nil || gated.APIFileSignature != nil ||
		gated.APIFormalSchemas != nil || gated.APIPolicyVersion != "" || gated.APIProtectionMode != "" {
		t.Errorf("API 段字段应清空: %+v", gated)
	}
	// 非 API 字段保留（valkey 段、TLS 票据键、L7、访问日志、全局黑名单）
	if gated.Valkey == nil || gated.Valkey.Password != "old-valkey-secret" {
		t.Error("valkey 段非 API 段，应保留")
	}
	if gated.TLSSessionTicketKey != "old-tls-ticket-key" {
		t.Error("TLS 票据键非 API 段，应保留")
	}
	if gated.L7Rules == nil || len(gated.L7Rules.Rules) != 1 {
		t.Error("L7 规则应保留")
	}
	if gated.AccessLog == nil || len(gated.GlobalDeny) != 1 {
		t.Error("访问日志与全局规则应保留")
	}
	// 入参不被修改（拷贝语义）
	if !override.APIDynamicProtection || override.IdentitySalt != "old-identity-salt" {
		t.Error("不得修改调用方快照")
	}
	// 口径与 buildGuardHandler 一致：剥除后生成 JSON 无 API 段，TLS 票据键仍下发
	j := generateGuardJSON(t, gated)
	for _, banned := range []string{
		"api_dynamic_protection", "identity_salt", "api_scan_verification",
		"api_file_signature", "api_formal_schemas", "api_policy_version",
	} {
		if strings.Contains(j, banned) {
			t.Errorf("剥除后配置不得含 API 段 %q", banned)
		}
	}
	if !strings.Contains(j, "old-tls-ticket-key") {
		t.Error("TLS 票据键应随配置下发")
	}
}

// GuardOverride 门控：当前产品开关开启时快照原样放行。
func TestGateGuardOverrideKeepsAPIWhenProductOn(t *testing.T) {
	override := secretTestGuardConfig("old")
	p := &Publisher{guard: &fakeGuardProvider{buildCfg: secretTestGuardConfig("new")}}
	gated, err := p.gateGuardOverride(context.Background(), override)
	if err != nil {
		t.Fatalf("gateGuardOverride: %v", err)
	}
	if gated != override {
		t.Error("开关开启时应原样返回快照")
	}
	if !gated.APIDynamicProtection || gated.IdentitySalt != "old-identity-salt" {
		t.Error("开关开启时不得改动 API 段")
	}
}

// GuardOverride 门控：快照本身未开启 API 段时直接放行（不读取当前配置）。
func TestGateGuardOverridePassthroughWhenSnapshotAPIDisabled(t *testing.T) {
	override := testGuardConfig() // APIDynamicProtection=false
	fake := &fakeGuardProvider{buildCfg: secretTestGuardConfig("new")}
	p := &Publisher{guard: fake}
	gated, err := p.gateGuardOverride(context.Background(), override)
	if err != nil {
		t.Fatalf("gateGuardOverride: %v", err)
	}
	if gated != override {
		t.Error("快照无 API 段时应原样放行")
	}
	if fake.buildCalls != 0 {
		t.Fatal("快照无 API 段时不应读取当前配置")
	}
}

// GuardOverride 门控：当前开关读取失败如实返回（不静默放行快照 API 段）。
func TestGateGuardOverrideBuildError(t *testing.T) {
	p := &Publisher{guard: &fakeGuardProvider{buildErr: errors.New("db down")}}
	gated, err := p.gateGuardOverride(context.Background(), secretTestGuardConfig("old"))
	if err == nil || gated != nil {
		t.Fatalf("读取当前配置失败应返回错误, gated=%v err=%v", gated, err)
	}
}

// TestH16DiskWritesRedactSecretsAndUse0600 回归：failed-*.json 与 active/current.json
// 落盘前必须脱敏（不含任何明文密钥含 bot_policy.signing_keys），且权限必须为 0600。
func TestH16DiskWritesRedactSecretsAndUse0600(t *testing.T) {
	dir := t.TempDir()
	plain := generateGuardJSON(t, secretTestGuardConfig("disk"))

	activeFile, err := WriteActiveConfig(dir, "current", plain)
	if err != nil {
		t.Fatalf("WriteActiveConfig: %v", err)
	}
	info, err := os.Stat(activeFile)
	if err != nil {
		t.Fatalf("stat active: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("current.json perm = %o, want 0600", perm)
	}
	activeRaw, err := os.ReadFile(activeFile)
	if err != nil {
		t.Fatalf("read active: %v", err)
	}
	for _, s := range secretValues("disk") {
		if strings.Contains(string(activeRaw), s) {
			t.Errorf("current.json leaked plaintext secret %q", s)
		}
	}

	p := &Publisher{dataDir: dir}
	p.saveFailedCandidate(&Generated{JSON: plain}, nil, errors.New("validation failed"))
	matches, err := filepath.Glob(filepath.Join(dir, "configs", "failed", "failed-*.json"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("expected 1 failed candidate file, got %v err=%v", matches, err)
	}
	failedInfo, err := os.Stat(matches[0])
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if perm := failedInfo.Mode().Perm(); perm != 0o600 {
		t.Fatalf("failed-*.json perm = %o, want 0600", perm)
	}
	failedRaw, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	for _, s := range secretValues("disk") {
		if strings.Contains(string(failedRaw), s) {
			t.Errorf("failed-*.json leaked plaintext secret %q", s)
		}
	}

	// 畸形 JSON 失败候选也不能原样将含密钥原文写盘
	dir2 := t.TempDir()
	if err := WriteFailedCandidate(dir2, `{"bad_json": "disk-bot-signing-secret-1"`, "invalid json"); err != nil {
		t.Fatalf("WriteFailedCandidate malformed: %v", err)
	}
	m2, _ := filepath.Glob(filepath.Join(dir2, "configs", "failed", "failed-*.json"))
	raw2, _ := os.ReadFile(m2[0])
	if strings.Contains(string(raw2), "disk-bot-signing-secret-1") {
		t.Error("malformed failed candidate leaked raw content")
	}
}

// TestRedactAndReinjectLoadPEMAndMultiKeySTEK 验证 Caddy load_pem 私钥脱敏、重注入（含纯 WAF 形态
// 无需 guard provider）与多键 STEK 脱敏/重注入全链路。
func TestRedactAndReinjectLoadPEMAndMultiKeySTEK(t *testing.T) {
	certID1 := uuid.New()
	certID2 := uuid.New()
	const (
		certPEM1   = "-----BEGIN CERTIFICATE-----\nCERT-1\n-----END CERTIFICATE-----\n"
		chainPEM1  = "-----BEGIN CERTIFICATE-----\nCHAIN-1\n-----END CERTIFICATE-----\n"
		oldKeyPEM1 = "-----BEGIN PRIVATE KEY-----\nOLD-SECRET-KEY-1\n-----END PRIVATE KEY-----\n"
		newKeyPEM1 = "-----BEGIN PRIVATE KEY-----\nLIVE-SECRET-KEY-1\n-----END PRIVATE KEY-----\n"
		certPEM2   = "-----BEGIN CERTIFICATE-----\nCERT-2\n-----END CERTIFICATE-----\n"
		oldKeyPEM2 = "-----BEGIN PRIVATE KEY-----\nOLD-SECRET-KEY-2\n-----END PRIVATE KEY-----\n"
		newKeyPEM2 = "-----BEGIN PRIVATE KEY-----\nLIVE-SECRET-KEY-2\n-----END PRIVATE KEY-----\n"
		oldSTEK1   = "1111111111111111111111111111111111111111111111111111111111111111"
		oldSTEK2   = "2222222222222222222222222222222222222222222222222222222222222222"
		newSTEK1   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		newSTEK2   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	)

	app1 := httpsOnlyApp("tls-a", certID1.String(), "", "a.tls.local")
	app1.CertPEM, app1.ChainPEM, app1.KeyPEM = certPEM1, chainPEM1, oldKeyPEM1
	app2 := httpsOnlyApp("tls-b", certID2.String(), "", "b.tls.local")
	app2.CertPEM, app2.KeyPEM = certPEM2, oldKeyPEM2

	oldGuard := secretTestGuardConfig("old")
	oldGuard.TLSSessionTicketKey = oldSTEK1
	oldGuard.TLSSessionTicketKeys = []string{oldSTEK1, oldSTEK2}

	gen, err := Generate(GenerateInput{
		Apps:        []AppData{app1, app2},
		AdminSocket: "unix//var/run/caddy/admin.sock",
		Guard:       oldGuard,
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	redacted, err := RedactConfigSecrets(gen.JSON)
	if err != nil {
		t.Fatalf("RedactConfigSecrets: %v", err)
	}
	// 私钥与双 STEK 均不得以明文留在脱敏产物中
	for _, secret := range []string{oldKeyPEM1, oldKeyPEM2, "OLD-SECRET-KEY-1", "OLD-SECRET-KEY-2", oldSTEK1, oldSTEK2} {
		if strings.Contains(redacted, secret) {
			t.Errorf("redacted config leaked secret %q", secret)
		}
	}
	// 证书公钥与 tags 必须保留供审计和重注入定位
	for _, keep := range []string{"CERT-1", "CHAIN-1", "CERT-2", certID1.String(), certID2.String(), `"keys_hex":["***","***"]`} {
		if !strings.Contains(redacted, keep) {
			t.Errorf("redacted config missing %q", keep)
		}
	}
	// 幂等
	if again, err := RedactConfigSecrets(redacted); err != nil || again != redacted {
		t.Fatalf("RedactConfigSecrets not idempotent: err=%v", err)
	}

	// 重注入：同时恢复 guard 密钥、双 STEK 密钥及两个证书私钥
	newGuard := secretTestGuardConfig("new")
	newGuard.TLSSessionTicketKey = newSTEK1
	newGuard.TLSSessionTicketKeys = []string{newSTEK1, newSTEK2}
	keyMap := map[uuid.UUID]string{
		certID1: newKeyPEM1,
		certID2: newKeyPEM2,
	}
	p := &Publisher{
		guard: &fakeGuardProvider{buildCfg: newGuard},
		certKeyLoader: func(_ context.Context, id uuid.UUID) (string, error) {
			k, ok := keyMap[id]
			if !ok {
				return "", errors.New("certificate not found")
			}
			return k, nil
		},
	}
	reinjected, err := p.reinjectConfigSecrets(context.Background(), redacted)
	if err != nil {
		t.Fatalf("reinjectConfigSecrets: %v", err)
	}
	for _, want := range []string{"LIVE-SECRET-KEY-1", "LIVE-SECRET-KEY-2", newSTEK1, newSTEK2, "CERT-1", "CHAIN-1"} {
		if !strings.Contains(reinjected, want) {
			t.Errorf("reinjected config missing %q", want)
		}
	}
	if strings.Contains(reinjected, `"***"`) {
		t.Errorf("reinjected config still contains placeholder: %s", reinjected)
	}

	// 纯 WAF 形态（仅有 load_pem，无 guard 处理器）：不要求装配 guard provider，仍能重注入私钥
	wafOnly, err := Generate(GenerateInput{
		Apps:        []AppData{app1},
		AdminSocket: "unix//var/run/caddy/admin.sock",
	})
	if err != nil {
		t.Fatalf("Generate waf-only: %v", err)
	}
	wafRedacted, err := RedactConfigSecrets(wafOnly.JSON)
	if err != nil {
		t.Fatalf("RedactConfigSecrets waf-only: %v", err)
	}
	pWaf := &Publisher{
		certKeyLoader: func(_ context.Context, id uuid.UUID) (string, error) {
			if id == certID1 {
				return newKeyPEM1, nil
			}
			return "", errors.New("not found")
		},
	}
	wafReinjected, err := pWaf.reinjectConfigSecrets(context.Background(), wafRedacted)
	if err != nil {
		t.Fatalf("waf-only load_pem reinject failed: %v", err)
	}
	if !strings.Contains(wafReinjected, "LIVE-SECRET-KEY-1") || strings.Contains(wafReinjected, `"***"`) {
		t.Fatalf("waf-only reinjected invalid: %s", wafReinjected)
	}
}

// TestReinjectLoadPEMFailClosed 验证 load_pem 证书缺失、未配证书仓储、非法 tags、解密失败均 fail-closed。
func TestReinjectLoadPEMFailClosed(t *testing.T) {
	certID := uuid.New()
	app := httpsOnlyApp("tls-a", certID.String(), "", "a.tls.local")
	app.CertPEM = "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n"
	app.KeyPEM = "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n"
	gen, err := Generate(GenerateInput{
		Apps:        []AppData{app},
		AdminSocket: "unix//var/run/caddy/admin.sock",
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	redacted, err := RedactConfigSecrets(gen.JSON)
	if err != nil {
		t.Fatalf("RedactConfigSecrets: %v", err)
	}

	t.Run("未装配证书仓储", func(t *testing.T) {
		p := &Publisher{}
		if _, err := p.reinjectConfigSecrets(context.Background(), redacted); err == nil || !strings.Contains(err.Error(), "未装配证书仓储") {
			t.Fatalf("err = %v, want clear Chinese missing cert store error", err)
		}
	})
	t.Run("证书已删除或解密失败", func(t *testing.T) {
		p := &Publisher{
			certKeyLoader: func(context.Context, uuid.UUID) (string, error) {
				return "", errors.New("certificate not found")
			},
		}
		if _, err := p.reinjectConfigSecrets(context.Background(), redacted); err == nil || !strings.Contains(err.Error(), certID.String()) {
			t.Fatalf("err = %v, want clear error naming certID", err)
		}
	})
	t.Run("证书私钥为空或脱敏占位", func(t *testing.T) {
		p := &Publisher{
			certKeyLoader: func(context.Context, uuid.UUID) (string, error) { return "***", nil },
		}
		if _, err := p.reinjectConfigSecrets(context.Background(), redacted); err == nil || !strings.Contains(err.Error(), "为空或仍为脱敏占位") {
			t.Fatalf("err = %v, want empty/redacted key rejection", err)
		}
	})
	t.Run("缺少 tags", func(t *testing.T) {
		bad := `{"apps":{"tls":{"certificates":{"load_pem":[{"certificate":"PEM","key":"***"}]}}}}`
		p := &Publisher{
			certKeyLoader: func(context.Context, uuid.UUID) (string, error) { return "LIVE-KEY", nil },
		}
		if _, err := p.reinjectConfigSecrets(context.Background(), bad); err == nil || !strings.Contains(err.Error(), "缺少证书标识") {
			t.Fatalf("err = %v, want missing tags error", err)
		}
	})
	t.Run("非 UUID tag", func(t *testing.T) {
		bad := `{"apps":{"tls":{"certificates":{"load_pem":[{"certificate":"PEM","key":"***","tags":["not-a-uuid"]}]}}}}`
		p := &Publisher{
			certKeyLoader: func(context.Context, uuid.UUID) (string, error) { return "LIVE-KEY", nil },
		}
		if _, err := p.reinjectConfigSecrets(context.Background(), bad); err == nil || !strings.Contains(err.Error(), "不是合法 UUID") {
			t.Fatalf("err = %v, want invalid UUID tag error", err)
		}
	})
}
