// bot_keys_test.go Bot 挑战签名密钥下发与 PROTECT 就绪门禁单元测试（WDSP P1-02 B3 预备）。
package guardconfig

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// 测试密钥材料（32 字节 hex；仅测试用途，非真实密钥）。
const (
	botTestKeyRef     = "bot-hmac-2026"
	botTestKeyHex     = "ab01cd23ef456789ab01cd23ef456789ab01cd23ef456789ab01cd23ef456789"
	botTestKeyPrevRef = "bot-hmac-2025"
	botTestKeyPrevHex = "0011223344556677001122334455667700112233445566770011223344556677"
)

// fakeBotSigningKeysLoader 测试密钥加载器（current + previous 轮换窗口形态）。
func fakeBotSigningKeysLoader(context.Context) (map[string]string, error) {
	return map[string]string{botTestKeyRef: botTestKeyHex, botTestKeyPrevRef: botTestKeyPrevHex}, nil
}

// TestNewBotSigningKeysLoader 加载器：未配置 → nil 不下发；密文解密 → 校验后映射；
// 解密失败/JSON 非法/key_ref 非法/密钥过短/条数超限 → fail-hard 报错；
// 错误信息不含密钥材料（复用 scan_verify_test.go 的 fakeSettingsGet/fakeDecrypt，
// 密文约定 "enc:" 前缀模拟）。
func TestNewBotSigningKeysLoader(t *testing.T) {
	settingsKey := botSigningKeysSettingsGroup + "/" + botSigningKeysSettingsKey

	// 未配置 → (nil, nil)
	kv := &fakeSettingsGet{kv: map[string]string{}}
	l := NewBotSigningKeysLoader(kv.get, fakeDecrypt)
	keys, err := l(context.Background())
	if err != nil || keys != nil {
		t.Fatalf("unset must be (nil,nil): keys=%v err=%v", keys, err)
	}

	// 正常：JSON 对象解密 → key_ref → 规范化 hex
	kv.kv[settingsKey] = `enc:{"` + botTestKeyRef + `":"` + strings.ToUpper(botTestKeyHex) + `"}`
	keys, err = l(context.Background())
	if err != nil {
		t.Fatalf("valid keys: %v", err)
	}
	if keys[botTestKeyRef] != botTestKeyHex {
		t.Fatalf("key not normalized to lowercase hex: %q", keys[botTestKeyRef])
	}

	// 空对象视同未配置
	kv.kv[settingsKey] = "enc:{}"
	if keys, err = l(context.Background()); err != nil || keys != nil {
		t.Fatalf("empty object must be (nil,nil): keys=%v err=%v", keys, err)
	}

	// 解密失败 → fail-hard
	kv.kv[settingsKey] = "not-a-ciphertext"
	if _, err = l(context.Background()); err == nil {
		t.Fatal("decrypt failure must error")
	}

	// 非法内容逐项拒绝；错误信息不得含密钥材料
	for name, plain := range map[string]string{
		"非 JSON":     `not-json`,
		"非对象":        `["x"]`,
		"非法 key_ref": `{"../etc/passwd":"` + botTestKeyHex + `"}`,
		"非 hex 密钥":   `{"` + botTestKeyRef + `":"zzzz"}`,
		"密钥过短":       `{"` + botTestKeyRef + `":"abcd"}`,
	} {
		kv.kv[settingsKey] = "enc:" + plain
		if _, err = l(context.Background()); err == nil {
			t.Errorf("%s must error", name)
		} else if strings.Contains(err.Error(), botTestKeyHex) {
			t.Errorf("%s error must not contain key material: %v", name, err)
		}
	}

	// 条数超限
	var b strings.Builder
	b.WriteString("{")
	for i := 0; i < botSigningKeysMaxKeys+1; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"ka` + string(rune('0'+i)) + `":"` + botTestKeyHex + `"`)
	}
	b.WriteString("}")
	kv.kv[settingsKey] = "enc:" + b.String()
	if _, err = l(context.Background()); err == nil {
		t.Error("exceeding max keys must error")
	}

	// nil 装配 → 报错（不静默）
	l = NewBotSigningKeysLoader(nil, nil)
	if _, err = l(context.Background()); err == nil {
		t.Fatal("nil get/decrypt must error")
	}
}

// TestLoadBotPolicyProtectKeyGate PROTECT 密钥就绪门禁（B1 遗留 TODO(B2) 做实）：
// Valkey 就绪但签名密钥未配置/引用未就绪 → 拒绝发布并给出可读原因（含应用与 key_ref）；
// OBSERVE 无密钥不阻断（不签名）；密钥加载器失败 → 中止发布（fail-hard，含 OBSERVE）。
func TestLoadBotPolicyProtectKeyGate(t *testing.T) {
	valkeyCfg := func() *gatewayconfig.GuardConfig {
		return &gatewayconfig.GuardConfig{Valkey: &gatewayconfig.GuardValkey{Address: "127.0.0.1:6379"}}
	}
	protect := map[string]*gatewayconfig.GuardBotPolicy{"shop": botProtectPolicy()}

	// 密钥加载器未注入 → PROTECT 拒绝发布
	p := &Provider{botPolicy: fakeBotPolicyLister{policies: protect}}
	if err := p.loadBotPolicy(context.Background(), valkeyCfg()); err == nil {
		t.Fatal("PROTECT without key loader must refuse publish")
	} else if !strings.Contains(err.Error(), "shop") || !strings.Contains(err.Error(), botTestKeyRef) {
		t.Errorf("error must name app and key_ref: %v", err)
	}

	// 密钥集合不含 key_ref → 拒绝
	p = &Provider{
		botPolicy: fakeBotPolicyLister{policies: protect},
		botSigningKeys: func(context.Context) (map[string]string, error) {
			return map[string]string{"other": botTestKeyHex}, nil
		},
	}
	if err := p.loadBotPolicy(context.Background(), valkeyCfg()); err == nil {
		t.Fatal("PROTECT with unresolvable key_ref must refuse publish")
	}

	// 密钥就绪 → 放行且密钥段注入
	p = &Provider{botPolicy: fakeBotPolicyLister{policies: protect}, botSigningKeys: fakeBotSigningKeysLoader}
	cfg := valkeyCfg()
	if err := p.loadBotPolicy(context.Background(), cfg); err != nil {
		t.Fatalf("PROTECT with ready key should pass: %v", err)
	}
	if cfg.BotSigningKeys[botTestKeyRef] != botTestKeyHex {
		t.Fatalf("bot_signing_keys not injected: %+v", cfg.BotSigningKeys)
	}

	// OBSERVE 无密钥不阻断（观测不签名），且未配置密钥时不下发密钥段
	p = &Provider{botPolicy: fakeBotPolicyLister{policies: map[string]*gatewayconfig.GuardBotPolicy{
		"shop": {SchemaVersion: 1, Mode: "OBSERVE", Version: 1},
	}}}
	cfg = valkeyCfg()
	if err := p.loadBotPolicy(context.Background(), cfg); err != nil {
		t.Errorf("OBSERVE without keys should pass: %v", err)
	}
	if cfg.BotSigningKeys != nil {
		t.Errorf("no keys configured must not set section: %+v", cfg.BotSigningKeys)
	}

	// 密钥读取/解密失败 → 中止发布（含 OBSERVE：已配置密钥不得被静默丢弃）
	p = &Provider{
		botPolicy: fakeBotPolicyLister{policies: map[string]*gatewayconfig.GuardBotPolicy{
			"shop": {SchemaVersion: 1, Mode: "OBSERVE", Version: 1},
		}},
		botSigningKeys: func(context.Context) (map[string]string, error) { return nil, errors.New("decrypt failed") },
	}
	if err := p.loadBotPolicy(context.Background(), valkeyCfg()); err == nil {
		t.Fatal("key loader failure must abort publish (fail-hard)")
	}
}

// TestRedactBotSigningKeys 快照脱敏：密钥材料 → "***"，key_ref 引用名保留（审计可溯源），
// 原配置不被修改。
func TestRedactBotSigningKeys(t *testing.T) {
	cfg := &gatewayconfig.GuardConfig{
		BotSigningKeys: map[string]string{botTestKeyRef: botTestKeyHex, "empty": ""},
	}
	cp := RedactGuardConfig(cfg)
	if cp.BotSigningKeys[botTestKeyRef] != redactPlaceholder {
		t.Errorf("key material must be redacted: %+v", cp.BotSigningKeys)
	}
	if cfg.BotSigningKeys[botTestKeyRef] != botTestKeyHex {
		t.Error("original config must not be mutated")
	}
	if _, ok := cp.BotSigningKeys["empty"]; !ok {
		t.Error("key refs must be preserved for snapshot audit")
	}
}

// TestReplayBotSigningKeys 回滚重放：快照脱敏占位清零后按当前设置重取；
// 含 PROTECT 快照：密钥仍在 → 门禁放行；密钥已删 → 可读原因拒绝回滚发布；
// 读取失败如实返回。
func TestReplayBotSigningKeys(t *testing.T) {
	snapshot := func() *gatewayconfig.GuardConfig {
		return &gatewayconfig.GuardConfig{
			Valkey:         &gatewayconfig.GuardValkey{Address: "127.0.0.1:6379"},
			BotPolicy:      map[string]*gatewayconfig.GuardBotPolicy{"shop": botProtectPolicy()},
			BotSigningKeys: map[string]string{botTestKeyRef: redactPlaceholder},
		}
	}

	// 密钥仍在 → 重放后门禁放行，占位替换为当前密钥
	p := &Provider{botSigningKeys: fakeBotSigningKeysLoader}
	cfg := snapshot()
	if err := p.replayRuntimeSecrets(context.Background(), cfg); err != nil {
		t.Fatalf("replay with keys configured: %v", err)
	}
	if cfg.BotSigningKeys[botTestKeyRef] != botTestKeyHex {
		t.Fatalf("placeholder must be replaced by current key: %+v", cfg.BotSigningKeys)
	}

	// 密钥已删（loader 返回空）→ PROTECT 门禁拒绝回滚发布
	p = &Provider{botSigningKeys: func(context.Context) (map[string]string, error) { return nil, nil }}
	if err := p.replayRuntimeSecrets(context.Background(), snapshot()); err == nil {
		t.Fatal("PROTECT snapshot with deleted key must refuse rollback publish")
	} else if !strings.Contains(err.Error(), botTestKeyRef) {
		t.Errorf("error must name key_ref: %v", err)
	}

	// 读取/解密失败 → 如实返回
	p = &Provider{botSigningKeys: func(context.Context) (map[string]string, error) {
		return nil, errors.New("decrypt failed")
	}}
	if err := p.replayRuntimeSecrets(context.Background(), snapshot()); err == nil {
		t.Fatal("loader failure must error")
	}

	// 未注入 loader → 快照原样保留（含脱敏占位），门禁按占位未就绪拒绝 PROTECT
	p = &Provider{}
	cfg = snapshot()
	if err := p.replayRuntimeSecrets(context.Background(), cfg); err == nil {
		t.Fatal("PROTECT snapshot without loader must refuse (placeholder not ready)")
	}
	if cfg.BotSigningKeys[botTestKeyRef] != redactPlaceholder {
		t.Fatalf("snapshot must be untouched without loader: %+v", cfg.BotSigningKeys)
	}
}
