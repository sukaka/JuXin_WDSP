package guardconfig

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/encryption"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

type fakeAICrawlLister struct {
	policies map[string]*gatewayconfig.GuardAICrawlPolicy
	err      error
}

func (f fakeAICrawlLister) ListForGuard(context.Context) (map[string]*gatewayconfig.GuardAICrawlPolicy, error) {
	return f.policies, f.err
}

func TestLoadAICrawlPolicyAndFailHard(t *testing.T) {
	const testKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	// 1. 读取失败中止发布（fail-hard）
	pErr := &Provider{aiCrawl: fakeAICrawlLister{err: errors.New("db down")}}
	if err := pErr.loadAICrawlPolicy(context.Background(), &gatewayconfig.GuardConfig{}); err == nil {
		t.Fatal("lister failure must fail-hard")
	}

	// 2. PROTECT + Labyrinth 缺签名密钥必须拒绝发布
	protectPol := &gatewayconfig.GuardAICrawlPolicy{
		SchemaVersion:    1,
		ApplicationID:    "app-1",
		Mode:             "PROTECT",
		Version:          2,
		DefaultAIAction:  "TARPIT",
		LabyrinthEnabled: true,
	}
	pNoKey := &Provider{
		aiCrawl: fakeAICrawlLister{policies: map[string]*gatewayconfig.GuardAICrawlPolicy{"shop": protectPol}},
	}
	if err := pNoKey.loadAICrawlPolicy(context.Background(), &gatewayconfig.GuardConfig{}); err == nil {
		t.Fatal("PROTECT + Labyrinth without key must fail-hard")
	}

	// 3. 注入签名密钥后正常加载
	pOK := &Provider{
		aiCrawl: fakeAICrawlLister{policies: map[string]*gatewayconfig.GuardAICrawlPolicy{"shop": protectPol}},
		aiCrawlLabyrinthKey: func(_ context.Context, createIfAbsent bool) (string, error) {
			if !createIfAbsent {
				t.Fatal("expected createIfAbsent=true when labyrinth is enabled")
			}
			return testKey, nil
		},
	}
	cfg := &gatewayconfig.GuardConfig{}
	if err := pOK.loadAICrawlPolicy(context.Background(), cfg); err != nil {
		t.Fatalf("loadAICrawlPolicy: %v", err)
	}
	if cfg.AICrawlPolicy["shop"] == nil || cfg.AICrawlLabyrinthKeyHex != testKey {
		t.Fatalf("unexpected cfg: pol=%+v key=%q", cfg.AICrawlPolicy, cfg.AICrawlLabyrinthKeyHex)
	}

	// 4. 回滚回归：当前无策略或 labyrinth_enabled=false 时，若密钥已存在仍须只读解密填充
	// cfg.AICrawlLabyrinthKeyHex（且 createIfAbsent=false 绝不创建新键），供历史快照重注入使用
	for _, tc := range []struct {
		name     string
		policies map[string]*gatewayconfig.GuardAICrawlPolicy
	}{
		{"空策略列表", map[string]*gatewayconfig.GuardAICrawlPolicy{}},
		{"当前全部关闭迷宫", map[string]*gatewayconfig.GuardAICrawlPolicy{
			"shop": {SchemaVersion: 1, ApplicationID: "app-1", Mode: "OBSERVE", Version: 3, DefaultAIAction: "ALLOW", LabyrinthEnabled: false},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotCreate := true
			p := &Provider{
				aiCrawl: fakeAICrawlLister{policies: tc.policies},
				aiCrawlLabyrinthKey: func(_ context.Context, createIfAbsent bool) (string, error) {
					gotCreate = createIfAbsent
					return testKey, nil
				},
			}
			c := &gatewayconfig.GuardConfig{}
			if err := p.loadAICrawlPolicy(context.Background(), c); err != nil {
				t.Fatalf("loadAICrawlPolicy: %v", err)
			}
			if gotCreate {
				t.Fatal("createIfAbsent must be false when no policy enables labyrinth")
			}
			if c.AICrawlLabyrinthKeyHex != testKey {
				t.Fatalf("existing labyrinth key must still be populated for rollback replay, got %q", c.AICrawlLabyrinthKeyHex)
			}
		})
	}
}

func TestAICrawlLabyrinthKeyLoaderAutoGenerateAndDecrypt(t *testing.T) {
	enc, err := encryption.NewWithKey([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	store := map[string]string{}
	get := func(_ context.Context, group, key, def string) string {
		if v, ok := store[group+":"+key]; ok {
			return v
		}
		return def
	}
	createIfAbsent := func(_ context.Context, group, key, value, _ string, _ uuid.UUID) (bool, error) {
		k := group + ":" + key
		if _, exists := store[k]; exists {
			return false, nil
		}
		store[k] = value
		return true, nil
	}

	loader := NewAICrawlLabyrinthKeyLoader(get, createIfAbsent, enc.Encrypt, enc.Decrypt)
	// 只读模式下密钥不存在不得自动落库
	k0, err := loader(context.Background(), false)
	if err != nil || k0 != "" || len(store) != 0 {
		t.Fatalf("read-only load without key should return empty without writing, got k=%q err=%v store=%d", k0, err, len(store))
	}
	// createIfAbsent=true 自动生成并加密落库
	k1, err := loader(context.Background(), true)
	if err != nil {
		t.Fatalf("first load (auto-gen): %v", err)
	}
	if len(k1) != 64 {
		t.Fatalf("expected 64-char hex key, got len=%d (%q)", len(k1), k1)
	}
	if raw := store["gateway_runtime:ai_crawl_labyrinth_key"]; raw == "" || strings.Contains(raw, k1) {
		t.Fatalf("stored value must be encrypted, got %q", raw)
	}
	// 第二次只读加载应返回同一解密密钥
	k2, err := loader(context.Background(), false)
	if err != nil || k2 != k1 {
		t.Fatalf("second read-only load = %q (err=%v), want %q", k2, err, k1)
	}
}

func TestAPIPolicyVersionIncludesAICrawlExcludesLabyrinthKey(t *testing.T) {
	base := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{})

	cfg1 := &gatewayconfig.GuardConfig{
		AICrawlPolicy: map[string]*gatewayconfig.GuardAICrawlPolicy{
			"shop": {
				SchemaVersion:    1,
				ApplicationID:    "app-1",
				Mode:             "OBSERVE",
				Version:          1,
				DefaultAIAction:  "ALLOW",
				LabyrinthEnabled: true,
				LabyrinthKeyHex:  strings.Repeat("a", 64),
			},
		},
		AICrawlLabyrinthKeyHex: strings.Repeat("a", 64),
	}
	v1 := computeAPIPolicyVersion(cfg1)
	if v1 == base {
		t.Fatal("adding ai_crawl_policy must change api_policy_version")
	}

	// 轮换 labyrinth_key_hex 密钥不得改变 api_policy_version
	cfg2 := &gatewayconfig.GuardConfig{
		AICrawlPolicy: map[string]*gatewayconfig.GuardAICrawlPolicy{
			"shop": {
				SchemaVersion:    1,
				ApplicationID:    "app-1",
				Mode:             "OBSERVE",
				Version:          1,
				DefaultAIAction:  "ALLOW",
				LabyrinthEnabled: true,
				LabyrinthKeyHex:  strings.Repeat("b", 64),
			},
		},
		AICrawlLabyrinthKeyHex: strings.Repeat("b", 64),
	}
	v2 := computeAPIPolicyVersion(cfg2)
	if v2 != v1 {
		t.Fatalf("rotating labyrinth_key_hex must not change api_policy_version: %s vs %s", v1, v2)
	}
}

func TestRedactAndReplayAICrawlLabyrinthKey(t *testing.T) {
	oldKey := strings.Repeat("1", 64)
	newKey := strings.Repeat("2", 64)

	cfg := &gatewayconfig.GuardConfig{
		AICrawlPolicy: map[string]*gatewayconfig.GuardAICrawlPolicy{
			"shop": {
				SchemaVersion:    1,
				ApplicationID:    "app-1",
				Mode:             "PROTECT",
				Version:          1,
				DefaultAIAction:  "TARPIT",
				LabyrinthEnabled: true,
				LabyrinthKeyHex:  oldKey,
			},
		},
		AICrawlLabyrinthKeyHex: oldKey,
	}
	red := RedactGuardConfig(cfg)
	raw, err := json.Marshal(red)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), oldKey) {
		t.Fatalf("redacted snapshot leaked labyrinth key: %s", raw)
	}
	if red.AICrawlLabyrinthKeyHex != "***" || red.AICrawlPolicy["shop"].LabyrinthKeyHex != "***" {
		t.Fatalf("expected *** placeholders, got key=%q pol.key=%q", red.AICrawlLabyrinthKeyHex, red.AICrawlPolicy["shop"].LabyrinthKeyHex)
	}
	// 原配置不受影响
	if cfg.AICrawlLabyrinthKeyHex != oldKey || cfg.AICrawlPolicy["shop"].LabyrinthKeyHex != oldKey {
		t.Fatal("RedactGuardConfig mutated original config")
	}

	// 回滚重放：替换为当前解密密钥
	p := &Provider{
		aiCrawlLabyrinthKey: func(_ context.Context, _ bool) (string, error) { return newKey, nil },
	}
	if err := p.replayRuntimeSecrets(context.Background(), red); err != nil {
		t.Fatalf("replayRuntimeSecrets: %v", err)
	}
	if red.AICrawlLabyrinthKeyHex != newKey || red.AICrawlPolicy["shop"].LabyrinthKeyHex != "" {
		t.Fatalf("replayed key mismatch: key=%q pol.key=%q", red.AICrawlLabyrinthKeyHex, red.AICrawlPolicy["shop"].LabyrinthKeyHex)
	}
}
