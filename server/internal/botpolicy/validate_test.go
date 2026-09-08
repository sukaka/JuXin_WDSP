// validate_test.go Bot 策略校验单元测试（B0 冻结口径的字段级矩阵；
// HTTP 层与真实 DB 覆盖见 server/tests/stage_bot_policy_test.go）。
package botpolicy

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// validObservePolicy 合法 OBSERVE 策略基线（各用例在其上做最小变异）。
func validObservePolicy() *Policy {
	p := DefaultPolicy(uuid.New())
	p.Mode = ModeObserve
	p.Selectors = []Selector{{PathPrefix: "/docs"}}
	p.SignalRules.Rules = []SignalRule{
		{ID: "rb_4xx", Group: GroupRequestBehavior, Metric: MetricStatusFamilyRatio,
			Params: map[string]string{"family": "4xx"}, WindowSeconds: 300, Weight: 1, Threshold: 0.6},
		{ID: "as_known", Group: GroupAccessSequence, Metric: MetricKnownURIRatio,
			WindowSeconds: 300, Weight: 1, Threshold: 0.3},
	}
	p.RouteReservation = RouteReservation{State: ReservationEnabled, Namespace: ReservedNamespace}
	return p
}

func hasFieldErr(errs []FieldError, substr string) bool {
	for _, e := range errs {
		if strings.Contains(e.Field+e.Message, substr) {
			return true
		}
	}
	return false
}

// TestValidateModeAndDefaults 模式枚举与 OFF 空策略（OFF 允许空 selectors/rules）。
func TestValidateModeAndDefaults(t *testing.T) {
	p := DefaultPolicy(uuid.New())
	if errs := ValidateStructure(p); len(errs) != 0 {
		t.Errorf("default OFF policy should pass: %+v", errs)
	}
	p.Mode = "CHALLENGE"
	if errs := ValidateStructure(p); !hasFieldErr(errs, "mode") {
		t.Errorf("unknown mode must be rejected: %+v", errs)
	}
	// 非 OFF 必须有选择器与信号规则
	p = DefaultPolicy(uuid.New())
	p.Mode = ModeObserve
	errs := ValidateStructure(p)
	if !hasFieldErr(errs, "非 OFF 模式必须配置至少一条选择器") || !hasFieldErr(errs, "至少一条信号规则") {
		t.Errorf("OBSERVE without selectors/rules must fail: %+v", errs)
	}
	// 基线合法 OBSERVE 通过
	if errs := ValidateStructure(validObservePolicy()); len(errs) != 0 {
		t.Errorf("valid OBSERVE policy should pass: %+v", errs)
	}
}

// TestValidateSelectors 选择器矩阵（精确/前缀二选一、编码、规范化、全站通配、保留命名空间、
// 前缀相邻目录边界——/_wdspx 不覆盖保留命名空间，/_wdsp 覆盖）。
func TestValidateSelectors(t *testing.T) {
	cases := []struct {
		name    string
		sel     Selector
		wantErr string // 空 = 通过
	}{
		{"exact ok", Selector{PathExact: "/account/login"}, ""},
		{"prefix ok", Selector{PathPrefix: "/docs"}, ""},
		{"both", Selector{PathExact: "/a", PathPrefix: "/b"}, "必须且仅须提供一个"},
		{"neither", Selector{}, "必须且仅须提供一个"},
		{"no leading slash", Selector{PathExact: "docs"}, "必须以 / 开头"},
		{"query", Selector{PathExact: "/a?x=1"}, "query"},
		{"percent encoding", Selector{PathExact: "/%64ocs"}, "百分号编码"},
		{"dotdot segment", Selector{PathPrefix: "/a/../b"}, "规范化歧义"},
		{"wildcard prefix", Selector{PathPrefix: "/"}, "全站通配"},
		{"prefix trailing slash", Selector{PathPrefix: "/docs/"}, "不应以 / 结尾"},
		{"prefix covers reserved", Selector{PathPrefix: "/_wdsp"}, "不得覆盖 Bot 保留命名空间"},
		{"prefix equals verify", Selector{PathPrefix: "/_wdsp/bot/v1/verify"}, "不得覆盖 Bot 保留命名空间"},
		{"prefix adjacent dir ok", Selector{PathPrefix: "/_wdspx"}, ""},
		{"exact in namespace", Selector{PathExact: "/_wdsp/bot/v1/verify"}, "不得落入 Bot 保留命名空间"},
		{"exact under namespace", Selector{PathExact: "/_wdsp/bot/v1/verify2"}, "不得落入 Bot 保留命名空间"},
		{"exact adjacent ok", Selector{PathExact: "/_wdsp/bot/v2/verify"}, ""},
	}
	for _, tc := range cases {
		p := validObservePolicy()
		p.Selectors = []Selector{tc.sel}
		errs := ValidateStructure(p)
		if tc.wantErr == "" {
			if len(errs) != 0 {
				t.Errorf("%s: want pass, got %+v", tc.name, errs)
			}
			continue
		}
		if !hasFieldErr(errs, tc.wantErr) {
			t.Errorf("%s: want error containing %q, got %+v", tc.name, tc.wantErr, errs)
		}
	}
}

// TestValidateSignalRules 信号规则矩阵（组/指标白名单、参数键白名单、阈值语义、
// 窗口/权重上下界、ID 词形与唯一性、同源计数派生不重复计权）。
func TestValidateSignalRules(t *testing.T) {
	t.Run("min groups bounds", func(t *testing.T) {
		p := validObservePolicy()
		p.SignalRules.MinIndependentGroups = 1
		if errs := ValidateStructure(p); !hasFieldErr(errs, "min_independent_groups") {
			t.Errorf("min_independent_groups=1 must fail: %+v", errs)
		}
		p.SignalRules.MinIndependentGroups = 4
		if errs := ValidateStructure(p); !hasFieldErr(errs, "min_independent_groups") {
			t.Errorf("min_independent_groups=4 must fail: %+v", errs)
		}
	})
	t.Run("require behavior group", func(t *testing.T) {
		p := validObservePolicy()
		p.SignalRules.RequireBehaviorGroup = false
		if errs := ValidateStructure(p); !hasFieldErr(errs, "require_behavior_group") {
			t.Errorf("require_behavior_group=false must fail: %+v", errs)
		}
	})
	t.Run("unknown metric", func(t *testing.T) {
		p := validObservePolicy()
		p.SignalRules.Rules[0].Metric = "ai_risk_score"
		if errs := ValidateStructure(p); !hasFieldErr(errs, "未知信号指标") {
			t.Errorf("unknown metric must fail: %+v", errs)
		}
	})
	t.Run("group mismatch", func(t *testing.T) {
		p := validObservePolicy()
		p.SignalRules.Rules[0].Group = GroupClientClaim
		if errs := ValidateStructure(p); !hasFieldErr(errs, "属于信号组") {
			t.Errorf("group mismatch must fail: %+v", errs)
		}
	})
	t.Run("param keys", func(t *testing.T) {
		p := validObservePolicy()
		delete(p.SignalRules.Rules[0].Params, "family")
		if errs := ValidateStructure(p); !hasFieldErr(errs, "缺少必需参数") {
			t.Errorf("missing param must fail: %+v", errs)
		}
		p = validObservePolicy()
		p.SignalRules.Rules[0].Params["extra"] = "x"
		if errs := ValidateStructure(p); !hasFieldErr(errs, "未知参数键") {
			t.Errorf("unknown param key must fail: %+v", errs)
		}
		p = validObservePolicy()
		p.SignalRules.Rules[1].Params = map[string]string{"x": "y"}
		if errs := ValidateStructure(p); !hasFieldErr(errs, "不接受参数") {
			t.Errorf("params on no-param metric must fail: %+v", errs)
		}
	})
	t.Run("threshold semantics", func(t *testing.T) {
		p := validObservePolicy()
		p.SignalRules.Rules[0].Threshold = 1.5 // ratio_gte > 1
		if errs := ValidateStructure(p); !hasFieldErr(errs, "threshold") {
			t.Errorf("ratio threshold >1 must fail: %+v", errs)
		}
		p = validObservePolicy()
		p.SignalRules.Rules[1].Threshold = 1 // ratio_lte >= 1
		if errs := ValidateStructure(p); !hasFieldErr(errs, "threshold") {
			t.Errorf("known_uri_ratio threshold >=1 must fail: %+v", errs)
		}
		p = validObservePolicy()
		p.SignalRules.Rules = append(p.SignalRules.Rules, SignalRule{
			ID: "cc_ua", Group: GroupClientClaim, Metric: MetricUAClassMatch,
			Params: map[string]string{"class": "BOT"}, WindowSeconds: 300, Weight: 1, Threshold: 0.5})
		if errs := ValidateStructure(p); !hasFieldErr(errs, "命中即触发") {
			t.Errorf("claim metric with threshold!=0 must fail: %+v", errs)
		}
	})
	t.Run("window and weight bounds", func(t *testing.T) {
		p := validObservePolicy()
		p.SignalRules.Rules[0].WindowSeconds = 10
		if errs := ValidateStructure(p); !hasFieldErr(errs, "window_seconds") {
			t.Errorf("window below min must fail: %+v", errs)
		}
		p = validObservePolicy()
		p.SignalRules.Rules[0].Weight = 0
		if errs := ValidateStructure(p); !hasFieldErr(errs, "weight") {
			t.Errorf("weight 0 must fail: %+v", errs)
		}
	})
	t.Run("rule id and duplicate", func(t *testing.T) {
		p := validObservePolicy()
		p.SignalRules.Rules[0].ID = "Bad-ID"
		if errs := ValidateStructure(p); !hasFieldErr(errs, "规则 ID") {
			t.Errorf("bad rule id must fail: %+v", errs)
		}
		p = validObservePolicy()
		p.SignalRules.Rules[1].ID = p.SignalRules.Rules[0].ID
		if errs := ValidateStructure(p); !hasFieldErr(errs, "必须唯一") {
			t.Errorf("duplicate rule id must fail: %+v", errs)
		}
	})
	t.Run("same source no double weight", func(t *testing.T) {
		p := validObservePolicy()
		dup := p.SignalRules.Rules[0]
		dup.ID = "rb_4xx_dup"
		p.SignalRules.Rules = append(p.SignalRules.Rules, dup)
		if errs := ValidateStructure(p); !hasFieldErr(errs, "不重复计权") {
			t.Errorf("same-source derived metric must fail: %+v", errs)
		}
		// 同指标不同参数 = 不同计数源，允许
		p = validObservePolicy()
		other := p.SignalRules.Rules[0]
		other.ID = "rb_5xx"
		other.Params = map[string]string{"family": "5xx"}
		p.SignalRules.Rules = append(p.SignalRules.Rules, other)
		if errs := ValidateStructure(p); len(errs) != 0 {
			t.Errorf("different params = different source, should pass: %+v", errs)
		}
	})
}

// TestValidateProtectCoverage PROTECT 组覆盖充分性（组数不足/缺行为组无法提出挑战，
// 属配置错误）与路由保留一致性（PROTECT 必须 ENABLED）。
func TestValidateProtectCoverage(t *testing.T) {
	p := validObservePolicy()
	p.Mode = ModeProtect
	if errs := ValidateStructure(p); len(errs) != 0 {
		t.Fatalf("valid PROTECT baseline should pass: %+v", errs)
	}
	// 仅 1 个信号组 → 达不到 min_independent_groups=2
	p = validObservePolicy()
	p.Mode = ModeProtect
	p.SignalRules.Rules = p.SignalRules.Rules[:1]
	if errs := ValidateStructure(p); !hasFieldErr(errs, "独立信号组") {
		t.Errorf("PROTECT with 1 group must fail: %+v", errs)
	}
	// PROTECT + 非 ENABLED 保留 → 拒绝
	p = validObservePolicy()
	p.Mode = ModeProtect
	p.RouteReservation.State = ReservationTombstone
	if errs := ValidateStructure(p); !hasFieldErr(errs, "PROTECT 要求 ENABLED") {
		t.Errorf("PROTECT without ENABLED reservation must fail: %+v", errs)
	}
}

// TestValidateChallenge 挑战参数上下界与 key_ref 词形。
func TestValidateChallenge(t *testing.T) {
	ok := func(mut func(c *Challenge)) []FieldError {
		p := validObservePolicy()
		mut(&p.Challenge)
		return ValidateStructure(p)
	}
	if errs := ok(func(c *Challenge) { c.Type = "CAPTCHA" }); !hasFieldErr(errs, "仅支持 JS") {
		t.Errorf("non-JS type must fail: %+v", errs)
	}
	if errs := ok(func(c *Challenge) { c.NonceTTLSeconds = 29 }); !hasFieldErr(errs, "nonce_ttl_seconds") {
		t.Errorf("nonce ttl below min must fail: %+v", errs)
	}
	if errs := ok(func(c *Challenge) { c.NonceTTLSeconds = 301 }); !hasFieldErr(errs, "nonce_ttl_seconds") {
		t.Errorf("nonce ttl above max must fail: %+v", errs)
	}
	if errs := ok(func(c *Challenge) { c.ClearanceTTLSeconds = 59 }); !hasFieldErr(errs, "clearance_ttl_seconds") {
		t.Errorf("clearance ttl below min must fail: %+v", errs)
	}
	if errs := ok(func(c *Challenge) { c.Difficulty = 19 }); !hasFieldErr(errs, "difficulty") {
		t.Errorf("difficulty above max must fail: %+v", errs)
	}
	if errs := ok(func(c *Challenge) { c.MaxAttempts = 6 }); !hasFieldErr(errs, "max_attempts") {
		t.Errorf("max attempts above max must fail: %+v", errs)
	}
	if errs := ok(func(c *Challenge) { c.KeyRef = "../secret" }); !hasFieldErr(errs, "key_ref") {
		t.Errorf("path-like key_ref must fail: %+v", errs)
	}
	if errs := ok(func(c *Challenge) { c.KeyRef = "bot-hmac-2026.09" }); len(errs) != 0 {
		t.Errorf("valid key_ref should pass: %+v", errs)
	}
}

// TestValidateRouteReservation 保留状态机与命名空间冻结。
func TestValidateRouteReservation(t *testing.T) {
	p := validObservePolicy()
	p.RouteReservation.State = "DISABLED"
	if errs := ValidateStructure(p); !hasFieldErr(errs, "route_reservation.state") {
		t.Errorf("unknown reservation state must fail: %+v", errs)
	}
	p = validObservePolicy()
	p.RouteReservation.Namespace = "/_bot/"
	if errs := ValidateStructure(p); !hasFieldErr(errs, "namespace") {
		t.Errorf("non-frozen namespace must fail: %+v", errs)
	}
	// OBSERVE + RELEASED 合法（观测不需要路由）；ENABLED/TOMBSTONE 也合法
	for _, st := range []string{ReservationReleased, ReservationEnabled, ReservationTombstone} {
		p = validObservePolicy()
		p.RouteReservation.State = st
		if errs := ValidateStructure(p); len(errs) != 0 {
			t.Errorf("OBSERVE with reservation %s should pass: %+v", st, errs)
		}
	}
}

// TestNormalize 输入归一化（参数大小写/空白规整）。
func TestNormalize(t *testing.T) {
	p := validObservePolicy()
	p.SignalRules.Rules[0].ID = " rb_4xx "
	p.SignalRules.Rules[0].Params["family"] = " 4XX "
	p.Challenge.KeyRef = " key1 "
	Normalize(p)
	if p.SignalRules.Rules[0].ID != "rb_4xx" || p.SignalRules.Rules[0].Params["family"] != "4xx" ||
		p.Challenge.KeyRef != "key1" {
		t.Errorf("normalize failed: %+v", p.SignalRules.Rules[0])
	}
}

// TestDefaultPolicyShape 默认策略形状冻结（GET 对无记录应用返回；OFF/version=0/保留释放）。
func TestDefaultPolicyShape(t *testing.T) {
	id := uuid.New()
	p := DefaultPolicy(id)
	if p.Mode != ModeOff || p.Version != 0 || len(p.Selectors) != 0 || len(p.SignalRules.Rules) != 0 {
		t.Errorf("default policy = %+v", p)
	}
	if p.ApplicationID != id {
		t.Errorf("application id mismatch")
	}
	if p.RouteReservation.State != ReservationReleased || p.RouteReservation.Namespace != ReservedNamespace {
		t.Errorf("default reservation = %+v", p.RouteReservation)
	}
	c := p.Challenge
	if c.Type != "JS" || c.NonceTTLSeconds != DefaultNonceTTL || c.ClearanceTTLSeconds != DefaultClearanceTTL ||
		c.Difficulty != DefaultDifficulty || c.MaxAttempts != DefaultMaxAttempts {
		t.Errorf("default challenge = %+v", c)
	}
}
