// bot_policy_test.go bot_policy 段解析/校验/装配单元测试（WDSP P1-02 B1）。
// 覆盖：严格解码 fail-closed（未知字段/未知 schema_version/未知 mode 拒绝加载）、
// B0 冻结校验边界（选择器/信号规则/挑战参数/路由保留）、默认值兜底、
// Provision/Validate 拒绝与装配；B1 不接入请求链（无 ServeHTTP 挂点可测，
// 装配产物仅为解析结果与日志）。
package jiuzhang_guard

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

// botValidSection 合法 OBSERVE 段基线（各用例在其上做最小变异）。
//
// 测试密钥材料（32 字节 hex；仅测试用途，非真实密钥）。
const (
	botTestKeyID      = "bot-hmac-2026"
	botTestKeyHex     = "ab01cd23ef456789ab01cd23ef456789ab01cd23ef456789ab01cd23ef456789"
	botTestPrevKeyID  = "bot-hmac-2025"
	botTestPrevKeyHex = "0011223344556677001122334455667700112233445566770011223344556677"
)

func botValidSection() *botPolicyJSON {
	return &botPolicyJSON{
		SchemaVersion: botPolicySchemaVersion,
		ApplicationID: "app-1",
		Mode:          botModeObserve,
		Version:       1,
		Selectors:     []botSelectorJSON{{PathPrefix: "/docs"}},
		SignalRules: botSignalRulesJSON{
			MinIndependentGroups: 2,
			RequireBehaviorGroup: true,
			Rules: []botSignalRuleJSON{
				{ID: "rb_4xx", Group: "request_behavior", Metric: "status_family_ratio",
					Params: map[string]string{"family": "4xx"}, WindowSeconds: 300, Weight: 1, Threshold: 0.6},
				{ID: "as_known", Group: "access_sequence", Metric: "known_uri_ratio",
					WindowSeconds: 300, Weight: 1, Threshold: 0.3},
			},
		},
		Challenge:        botChallengeJSON{Type: "JS"},
		RouteReservation: botRouteReservationJSON{State: botReservationEnabled, Namespace: botReservedNamespace},
	}
}

// TestBotPolicyStrictDecode 严格解码 fail-closed：未知字段/多余内容/未知
// schema_version/未知 mode 一律拒绝（不静默忽略强制语义）。
func TestBotPolicyStrictDecode(t *testing.T) {
	good := botValidSection()

	// 未知字段
	raw := mustJSON(t, good)
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	m["unknown_field"] = true
	if _, err := parseBotPolicySection(mustJSON(t, m)); err == nil {
		t.Fatal("unknown field must be rejected")
	}
	// 多余 JSON 内容
	if _, err := parseBotPolicySection(json.RawMessage(`{"schema_version":1,"mode":"OFF"} {}`)); err == nil {
		t.Fatal("trailing content must be rejected")
	}
	// 未知 schema_version
	bad := *good
	bad.SchemaVersion = 2
	if _, err := parseBotPolicySection(mustJSON(t, &bad)); err == nil {
		t.Fatal("unknown schema_version must be rejected")
	}
	// 未知 mode
	badMode := *good
	badMode.Mode = "BLOCK"
	if _, err := parseBotPolicySection(mustJSON(t, &badMode)); err == nil {
		t.Fatal("unknown mode must be rejected")
	}
	// 基线通过
	if _, err := parseBotPolicySection(raw); err != nil {
		t.Fatalf("valid section must parse: %v", err)
	}
}

// TestBotPolicyChallengeDefaults 挑战参数 0 值兜底默认后复检边界。
func TestBotPolicyChallengeDefaults(t *testing.T) {
	sec, err := parseAndValidateBotPolicy(mustJSON(t, botValidSection()))
	if err != nil {
		t.Fatalf("valid section: %v", err)
	}
	c := sec.Challenge
	if c.NonceTTLSeconds != 90 || c.ClearanceTTLSeconds != 900 || c.Difficulty != 14 || c.MaxAttempts != 3 || c.Type != "JS" {
		t.Errorf("defaults not applied: %+v", c)
	}
	// 显式越界拒绝
	bad := botValidSection()
	bad.Challenge.Difficulty = 19
	if _, err := parseAndValidateBotPolicy(mustJSON(t, bad)); err == nil {
		t.Fatal("difficulty 19 must be rejected")
	}
	bad = botValidSection()
	bad.Challenge.NonceTTLSeconds = 29
	if _, err := parseAndValidateBotPolicy(mustJSON(t, bad)); err == nil {
		t.Fatal("nonce_ttl 29 must be rejected")
	}
	bad = botValidSection()
	bad.Challenge.KeyRef = "../key.pem"
	if _, err := parseAndValidateBotPolicy(mustJSON(t, bad)); err == nil {
		t.Fatal("path-like key_ref must be rejected")
	}
}

// TestBotPolicySelectors 选择器校验矩阵（与管理面 B0 口径逐条对应）。
func TestBotPolicySelectors(t *testing.T) {
	cases := []struct {
		name string
		sel  botSelectorJSON
		bad  bool
	}{
		{"exact ok", botSelectorJSON{PathExact: "/account/login"}, false},
		{"prefix ok", botSelectorJSON{PathPrefix: "/docs"}, false},
		{"both", botSelectorJSON{PathExact: "/a", PathPrefix: "/b"}, true},
		{"neither", botSelectorJSON{}, true},
		{"percent", botSelectorJSON{PathExact: "/%64ocs"}, true},
		{"dotdot", botSelectorJSON{PathPrefix: "/a/../b"}, true},
		{"wildcard", botSelectorJSON{PathPrefix: "/"}, true},
		{"trailing slash", botSelectorJSON{PathPrefix: "/docs/"}, true},
		{"covers reserved", botSelectorJSON{PathPrefix: "/_wdsp"}, true},
		{"adjacent ok", botSelectorJSON{PathPrefix: "/_wdspx"}, false},
		{"exact in namespace", botSelectorJSON{PathExact: "/_wdsp/bot/v1/verify"}, true},
	}
	for _, tc := range cases {
		sec := botValidSection()
		sec.Selectors = []botSelectorJSON{tc.sel}
		_, err := parseAndValidateBotPolicy(mustJSON(t, sec))
		if tc.bad && err == nil {
			t.Errorf("%s: must be rejected", tc.name)
		}
		if !tc.bad && err != nil {
			t.Errorf("%s: must pass, got %v", tc.name, err)
		}
	}
	// 非 OFF 无选择器
	sec := botValidSection()
	sec.Selectors = nil
	if _, err := parseAndValidateBotPolicy(mustJSON(t, sec)); err == nil {
		t.Error("OBSERVE without selectors must be rejected")
	}
}

// TestBotPolicySignalRules 信号规则校验（白名单/阈值语义/同源去重/PROTECT 覆盖充分性）。
func TestBotPolicySignalRules(t *testing.T) {
	// 未知指标
	sec := botValidSection()
	sec.SignalRules.Rules[0].Metric = "ai_risk_score"
	if _, err := parseAndValidateBotPolicy(mustJSON(t, sec)); err == nil {
		t.Error("unknown metric must be rejected")
	}
	// 声明组阈值必须 0
	sec = botValidSection()
	sec.SignalRules.Rules = append(sec.SignalRules.Rules, botSignalRuleJSON{
		ID: "cc_ua", Group: "client_claim", Metric: "ua_class_match",
		Params: map[string]string{"class": "BOT"}, WindowSeconds: 300, Weight: 1, Threshold: 0.5})
	if _, err := parseAndValidateBotPolicy(mustJSON(t, sec)); err == nil {
		t.Error("claim metric with threshold!=0 must be rejected")
	}
	// 同源计数派生不重复计权
	sec = botValidSection()
	dup := sec.SignalRules.Rules[0]
	dup.ID = "rb_4xx_dup"
	sec.SignalRules.Rules = append(sec.SignalRules.Rules, dup)
	if _, err := parseAndValidateBotPolicy(mustJSON(t, sec)); err == nil {
		t.Error("same-source derived metric must be rejected")
	}
	// require_behavior_group=false 拒绝
	sec = botValidSection()
	sec.SignalRules.RequireBehaviorGroup = false
	if _, err := parseAndValidateBotPolicy(mustJSON(t, sec)); err == nil {
		t.Error("require_behavior_group=false must be rejected")
	}
	// PROTECT 组覆盖不足（仅 1 组）
	sec = botValidSection()
	sec.Mode = botModeProtect
	sec.SignalRules.Rules = sec.SignalRules.Rules[:1]
	if _, err := parseAndValidateBotPolicy(mustJSON(t, sec)); err == nil {
		t.Error("PROTECT with 1 group must be rejected")
	}
	// 合法 PROTECT 通过（含签名密钥就绪——B3 预备：PROTECT 缺密钥 fail-closed）
	sec = botValidSection()
	sec.Mode = botModeProtect
	sec.Challenge.KeyRef = botTestKeyID
	sec.SigningKeys = map[string]string{botTestKeyID: botTestKeyHex}
	if _, err := parseAndValidateBotPolicy(mustJSON(t, sec)); err != nil {
		t.Errorf("valid PROTECT section must pass: %v", err)
	}
}

// TestBotPolicySigningKeys 签名密钥校验与密钥环装配（B3 预备）：
// 结构非法（非 hex/过短/非法 key_id）拒绝；PROTECT 缺密钥/空 key_ref/引用未就绪
// fail-closed 拒绝加载；OBSERVE 缺密钥不阻断；密钥环 current=key_ref、其余为
// previous；错误信息不含密钥材料。
func TestBotPolicySigningKeys(t *testing.T) {
	protectWithKeys := func() *botPolicyJSON {
		sec := botValidSection()
		sec.Mode = botModeProtect
		sec.Challenge.KeyRef = botTestKeyID
		sec.SigningKeys = map[string]string{botTestKeyID: botTestKeyHex, botTestPrevKeyID: botTestPrevKeyHex}
		return sec
	}

	// PROTECT 密钥环装配：current=key_ref，其余升序 previous
	sec, err := parseAndValidateBotPolicy(mustJSON(t, protectWithKeys()))
	if err != nil {
		t.Fatalf("PROTECT with ready keys: %v", err)
	}
	if sec.keyring == nil || sec.keyring.Current().ID != botTestKeyID {
		t.Fatalf("keyring current must be key_ref: %+v", sec.keyring)
	}
	if ids := sec.keyring.KeyIDs(); len(ids) != 2 {
		t.Fatalf("keyring must contain rotation window: %v", ids)
	}
	if _, ok := sec.keyring.Lookup(botTestPrevKeyID); !ok {
		t.Error("previous key must be verifiable in rotation window")
	}

	// PROTECT 缺 signing_keys → 拒绝
	bad := protectWithKeys()
	bad.SigningKeys = nil
	if _, err := parseAndValidateBotPolicy(mustJSON(t, bad)); err == nil {
		t.Error("PROTECT without signing_keys must be rejected")
	} else if strings.Contains(err.Error(), botTestKeyHex) {
		t.Errorf("error must not contain key material: %v", err)
	}
	// PROTECT 空 key_ref → 拒绝
	bad = protectWithKeys()
	bad.Challenge.KeyRef = ""
	if _, err := parseAndValidateBotPolicy(mustJSON(t, bad)); err == nil {
		t.Error("PROTECT with empty key_ref must be rejected")
	}
	// PROTECT key_ref 未就绪 → 拒绝
	bad = protectWithKeys()
	bad.Challenge.KeyRef = "bot-hmac-2099"
	if _, err := parseAndValidateBotPolicy(mustJSON(t, bad)); err == nil {
		t.Error("PROTECT with unresolvable key_ref must be rejected")
	}
	// 密钥材料非法逐项拒绝（错误信息不含材料）
	for name, keys := range map[string]map[string]string{
		"非 hex":     {botTestKeyID: "zzzz"},
		"过短":        {botTestKeyID: "abcd"},
		"非法 key_id": {"../key.pem": botTestKeyHex},
	} {
		bad = protectWithKeys()
		bad.SigningKeys = keys
		if _, err := parseAndValidateBotPolicy(mustJSON(t, bad)); err == nil {
			t.Errorf("signing_keys %s must be rejected", name)
		} else if strings.Contains(err.Error(), botTestKeyHex) {
			t.Errorf("signing_keys %s error must not contain key material: %v", name, err)
		}
	}

	// OBSERVE 无密钥 → 通过且 keyring 为 nil（观测不签名）
	sec, err = parseAndValidateBotPolicy(mustJSON(t, botValidSection()))
	if err != nil {
		t.Fatalf("OBSERVE without keys must pass: %v", err)
	}
	if sec.keyring != nil {
		t.Error("OBSERVE without keys must not build keyring")
	}
	// OBSERVE 带密钥与 key_ref → 装配密钥环（为 B3 verify 记录/降级路径预留）
	obs := botValidSection()
	obs.Challenge.KeyRef = botTestKeyID
	obs.SigningKeys = map[string]string{botTestKeyID: botTestKeyHex}
	sec, err = parseAndValidateBotPolicy(mustJSON(t, obs))
	if err != nil || sec.keyring == nil {
		t.Errorf("OBSERVE with keys must assemble keyring: %v", err)
	}
	// OBSERVE key_ref 未就绪 → 不构建密钥环但不拒载（观测不强制）
	obs = botValidSection()
	obs.Challenge.KeyRef = "bot-hmac-2099"
	obs.SigningKeys = map[string]string{botTestKeyID: botTestKeyHex}
	sec, err = parseAndValidateBotPolicy(mustJSON(t, obs))
	if err != nil {
		t.Errorf("OBSERVE with unresolvable key_ref must not fail load: %v", err)
	}
	if sec.keyring != nil {
		t.Error("OBSERVE with unresolvable key_ref must not build keyring")
	}
}

// TestBotPolicyRouteReservation 路由保留状态机与 PROTECT 一致性。
func TestBotPolicyRouteReservation(t *testing.T) {
	sec := botValidSection()
	sec.RouteReservation.State = "DISABLED"
	if _, err := parseAndValidateBotPolicy(mustJSON(t, sec)); err == nil {
		t.Error("unknown reservation state must be rejected")
	}
	sec = botValidSection()
	sec.RouteReservation.Namespace = "/_bot/"
	if _, err := parseAndValidateBotPolicy(mustJSON(t, sec)); err == nil {
		t.Error("non-frozen namespace must be rejected")
	}
	sec = botValidSection()
	sec.Mode = botModeProtect
	sec.RouteReservation.State = botReservationTombstone
	if _, err := parseAndValidateBotPolicy(mustJSON(t, sec)); err == nil {
		t.Error("PROTECT without ENABLED reservation must be rejected")
	}
}

// TestBotPolicyAssemble 装配语义：段缺失/OFF 零行为（不持有策略）；非 OFF 合法段
// 装配持有解析结果；非法段拒绝（fail-closed）。
func TestBotPolicyAssemble(t *testing.T) {
	g := &Guard{}
	if err := g.assembleBotPolicy(); err != nil || g.botPolicy != nil {
		t.Errorf("absent section must be no-op: err=%v policy=%+v", err, g.botPolicy)
	}
	off := botValidSection()
	off.Mode = botModeOff
	off.Selectors = nil
	off.SignalRules.Rules = nil
	off.RouteReservation.State = botReservationReleased
	g = &Guard{BotPolicy: mustJSON(t, off)}
	if err := g.assembleBotPolicy(); err != nil || g.botPolicy != nil {
		t.Errorf("OFF must not assemble: err=%v policy=%+v", err, g.botPolicy)
	}
	g = &Guard{BotPolicy: mustJSON(t, botValidSection())}
	if err := g.assembleBotPolicy(); err != nil {
		t.Fatalf("valid OBSERVE assemble: %v", err)
	}
	if g.botPolicy == nil || g.botPolicy.Mode != botModeObserve || g.botPolicy.Version != 1 {
		t.Errorf("assembled policy = %+v", g.botPolicy)
	}
	bad := botValidSection()
	bad.Mode = "BLOCK"
	g = &Guard{BotPolicy: mustJSON(t, bad)}
	if err := g.assembleBotPolicy(); err == nil {
		t.Fatal("invalid section must refuse load")
	}
}

// TestBotPolicyValidate Validate 同步 fail-closed（Caddy 配置校验期；OFF 也全量校验）。
func TestBotPolicyValidate(t *testing.T) {
	v := &Guard{EventsLog: "x", BotPolicy: mustJSON(t, botValidSection())}
	if err := v.Validate(); err != nil {
		t.Errorf("valid section must pass Validate: %v", err)
	}
	bad := botValidSection()
	bad.SchemaVersion = 99
	v = &Guard{EventsLog: "x", BotPolicy: mustJSON(t, bad)}
	if err := v.Validate(); err == nil {
		t.Fatal("Validate must reject unknown schema_version")
	}
	// OFF + 非法结构同样拒绝（配置面与管理面同口径）
	offBad := botValidSection()
	offBad.Mode = botModeOff
	offBad.RouteReservation.State = "DISABLED"
	v = &Guard{EventsLog: "x", BotPolicy: mustJSON(t, offBad)}
	if err := v.Validate(); err == nil {
		t.Fatal("Validate must reject invalid structure even when OFF")
	}
}

// TestBotPolicyProvisionRejectsInvalid 真实 Provision 路径：非法 bot_policy 段
// 拒绝整体配置加载（不静默删除/降级既有 PROTECT 策略）。
func TestBotPolicyProvisionRejectsInvalid(t *testing.T) {
	bad := botValidSection()
	bad.Mode = botModeProtect
	bad.RouteReservation.State = botReservationReleased // PROTECT 未注册保留路由
	resetSharedEngineForTest()
	t.Cleanup(resetSharedEngineForTest)
	g := &Guard{
		AppID: "app-1", AppCode: "shop",
		EventsLog: filepath.Join(t.TempDir(), "events.log"),
		BotPolicy: mustJSON(t, bad),
	}
	if err := g.Provision(caddy.Context{Context: context.Background()}); err == nil {
		t.Fatal("Provision must reject invalid bot_policy section")
	} else if !strings.Contains(err.Error(), "bot_policy") {
		t.Errorf("error must name bot_policy section: %v", err)
	}
}

// TestBotPolicyProvisionAssemblesValid 真实 Provision 路径：合法段装配成功且
// 请求链零行为变化（B1 无 ServeHTTP 挂点——装配产物仅解析结果）。
func TestBotPolicyProvisionAssemblesValid(t *testing.T) {
	resetSharedEngineForTest()
	t.Cleanup(resetSharedEngineForTest)
	g := &Guard{
		AppID: "app-1", AppCode: "shop",
		EventsLog: filepath.Join(t.TempDir(), "events.log"),
		BotPolicy: mustJSON(t, botValidSection()),
	}
	if err := g.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("Provision with valid bot_policy: %v", err)
	}
	if g.botPolicy == nil || g.botPolicy.Mode != botModeObserve {
		t.Errorf("assembled policy = %+v", g.botPolicy)
	}
	if g.botPolicy.Challenge.NonceTTLSeconds != 90 {
		t.Errorf("defaults not applied at assemble: %+v", g.botPolicy.Challenge)
	}
	t.Cleanup(func() { _ = g.Cleanup() })
}
