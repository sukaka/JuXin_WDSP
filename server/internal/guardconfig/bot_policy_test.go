// bot_policy_test.go bot_policy 段组装与发布门禁单元测试（WDSP P1-02 B1）。
package guardconfig

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

type fakeBotPolicyLister struct {
	policies map[string]*gatewayconfig.GuardBotPolicy
	err      error
}

func (f fakeBotPolicyLister) ListForGuard(context.Context) (map[string]*gatewayconfig.GuardBotPolicy, error) {
	return f.policies, f.err
}

func botProtectPolicy() *gatewayconfig.GuardBotPolicy {
	return &gatewayconfig.GuardBotPolicy{SchemaVersion: 1, Mode: "PROTECT", Version: 2,
		Challenge: gatewayconfig.GuardBotChallenge{KeyRef: botTestKeyRef}}
}

// TestLoadBotPolicyInject 策略段注入 GuardConfig（key=应用编码；OFF 同样下发以覆盖旧配置残留）。
func TestLoadBotPolicyInject(t *testing.T) {
	p := &Provider{botPolicy: fakeBotPolicyLister{policies: map[string]*gatewayconfig.GuardBotPolicy{
		"shop": {SchemaVersion: 1, Mode: "OFF", Version: 1},
	}}}
	cfg := &gatewayconfig.GuardConfig{}
	if err := p.loadBotPolicy(context.Background(), cfg); err != nil {
		t.Fatalf("loadBotPolicy: %v", err)
	}
	if cfg.BotPolicy["shop"] == nil || cfg.BotPolicy["shop"].Mode != "OFF" {
		t.Fatalf("bot_policy not injected: %+v", cfg.BotPolicy)
	}
}

// TestLoadBotPolicyReadErrorFailsHard 读取失败中止发布
// （防已 PROTECT 应用在新配置中丢失 bot_policy 段 = 静默关闭挑战强制）。
func TestLoadBotPolicyReadErrorFailsHard(t *testing.T) {
	p := &Provider{botPolicy: fakeBotPolicyLister{err: errors.New("db down")}}
	if err := p.loadBotPolicy(context.Background(), &gatewayconfig.GuardConfig{}); err == nil {
		t.Fatal("read error must abort publish")
	}
}

// TestLoadBotPolicyProtectValkeyGate PROTECT 策略 + 共享状态存储（Valkey）未配置 →
// 拒绝发布（无共享状态时网关只能 fail-closed 503，不发布必然全站 503 的配置）；
// OBSERVE/OFF 不受该门禁阻断；Valkey 与签名密钥均已配置时放行。
func TestLoadBotPolicyProtectValkeyGate(t *testing.T) {
	p := &Provider{
		botPolicy: fakeBotPolicyLister{policies: map[string]*gatewayconfig.GuardBotPolicy{
			"shop": botProtectPolicy(),
		}},
		botSigningKeys: fakeBotSigningKeysLoader,
	}
	if err := p.loadBotPolicy(context.Background(), &gatewayconfig.GuardConfig{}); err == nil {
		t.Fatal("PROTECT without Valkey must refuse publish")
	} else if !strings.Contains(err.Error(), "shop") || !strings.Contains(err.Error(), "Valkey") {
		t.Errorf("error must name apps and reason: %v", err)
	}
	cfg := &gatewayconfig.GuardConfig{Valkey: &gatewayconfig.GuardValkey{Address: "127.0.0.1:6379"}}
	if err := p.loadBotPolicy(context.Background(), cfg); err != nil {
		t.Errorf("PROTECT with Valkey and signing key configured should pass: %v", err)
	}
	if cfg.BotPolicy["shop"] == nil {
		t.Error("bot_policy section must be set after successful gate")
	}
	if !botSigningKeysReady(cfg.BotSigningKeys, botTestKeyRef) {
		t.Error("bot_signing_keys must be injected after successful load")
	}

	// OBSERVE 无 Valkey 不阻断（观测降级不实断）
	p2 := &Provider{botPolicy: fakeBotPolicyLister{policies: map[string]*gatewayconfig.GuardBotPolicy{
		"shop": {SchemaVersion: 1, Mode: "OBSERVE", Version: 1},
	}}}
	if err := p2.loadBotPolicy(context.Background(), &gatewayconfig.GuardConfig{}); err != nil {
		t.Errorf("OBSERVE without Valkey should pass: %v", err)
	}
}

// TestLoadBotPolicyEmptyAndNil 无策略/未注入 lister → 不下发 bot_policy 段。
func TestLoadBotPolicyEmptyAndNil(t *testing.T) {
	p := &Provider{}
	cfg := &gatewayconfig.GuardConfig{}
	if err := p.loadBotPolicy(context.Background(), cfg); err != nil || cfg.BotPolicy != nil {
		t.Errorf("nil lister must be no-op: err=%v cfg=%+v", err, cfg.BotPolicy)
	}
	p2 := &Provider{botPolicy: fakeBotPolicyLister{policies: map[string]*gatewayconfig.GuardBotPolicy{}}}
	if err := p2.loadBotPolicy(context.Background(), cfg); err != nil || cfg.BotPolicy != nil {
		t.Errorf("empty policies must not set section: err=%v cfg=%+v", err, cfg.BotPolicy)
	}
}

// TestCheckBotPolicyDeps 回滚重放共用门禁：快照含 PROTECT 而 Valkey 缺失 → 拒绝；
// Valkey 就绪但 key_ref 未注入/为空引用/脱敏占位 → 拒绝；双就绪 → 放行。
func TestCheckBotPolicyDeps(t *testing.T) {
	policies := map[string]*gatewayconfig.GuardBotPolicy{"shop": botProtectPolicy()}
	if err := checkBotPolicyDeps(&gatewayconfig.GuardConfig{}, []string{"shop"}, policies); err == nil {
		t.Error("nil Valkey must refuse")
	}
	valkeyCfg := func(keys map[string]string) *gatewayconfig.GuardConfig {
		return &gatewayconfig.GuardConfig{
			Valkey:         &gatewayconfig.GuardValkey{Address: "127.0.0.1:6379"},
			BotSigningKeys: keys,
		}
	}
	if err := checkBotPolicyDeps(valkeyCfg(nil), []string{"shop"}, policies); err == nil {
		t.Error("PROTECT without signing keys must refuse")
	}
	if err := checkBotPolicyDeps(valkeyCfg(map[string]string{"other-key": botTestKeyHex}), []string{"shop"}, policies); err == nil {
		t.Error("key_ref not in injected key set must refuse")
	}
	if err := checkBotPolicyDeps(valkeyCfg(map[string]string{botTestKeyRef: redactPlaceholder}), []string{"shop"}, policies); err == nil {
		t.Error("redacted placeholder key must refuse (replay must re-inject first)")
	}
	if err := checkBotPolicyDeps(valkeyCfg(map[string]string{botTestKeyRef: botTestKeyHex}), []string{"shop"}, policies); err != nil {
		t.Errorf("Valkey + signing key ready should pass: %v", err)
	}
	// 空 key_ref 的 PROTECT 视同未就绪
	noRef := map[string]*gatewayconfig.GuardBotPolicy{"shop": {SchemaVersion: 1, Mode: "PROTECT", Version: 1}}
	if err := checkBotPolicyDeps(valkeyCfg(map[string]string{botTestKeyRef: botTestKeyHex}), []string{"shop"}, noRef); err == nil {
		t.Error("PROTECT with empty key_ref must refuse")
	}
}
