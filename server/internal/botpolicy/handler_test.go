// handler_test.go 处理器纯逻辑单元测试（路由保留冲突静态判定、请求默认值应用；
// HTTP 层 409/400/404/403 矩阵与真实 DB 见 server/tests/stage_bot_policy_test.go）。
package botpolicy

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/l7rules"
	"github.com/jiuzhang-waf/server/internal/protectedaddresses"
)

// fakeL7Lister 可编程 L7 规则读取。
type fakeL7Lister struct {
	rules []l7rules.Rule
	err   error
}

func (f fakeL7Lister) ListAllOrdered(context.Context) ([]l7rules.Rule, error) {
	return f.rules, f.err
}

// fakePathRouteLister 可编程路径转发读取。
type fakePathRouteLister struct {
	routes []gatewayconfig.AppPathRoute
	err    error
}

func (f fakePathRouteLister) ListEnabledPathRoutes(context.Context, uuid.UUID) ([]gatewayconfig.AppPathRoute, error) {
	return f.routes, f.err
}

// fakeProtectedLister 可编程保护地址读取。
type fakeProtectedLister struct {
	addrs []protectedaddresses.ProtectedAddress
	err   error
}

func (f fakeProtectedLister) List(context.Context, string) ([]protectedaddresses.ProtectedAddress, error) {
	return f.addrs, f.err
}

func denyRule(name string, conds ...l7rules.Condition) l7rules.Rule {
	return l7rules.Rule{Name: name, Enabled: true, Action: l7rules.ActionBlock, Conditions: conds}
}

// TestRuleCoversVerify L7 规则对保留 verify 端点（POST + 固定路径）的静态判定矩阵
// （多条件 AND：任一条件确定性不中即整体不中）。
func TestRuleCoversVerify(t *testing.T) {
	uri := func(op, v string) l7rules.Condition {
		return l7rules.Condition{Type: l7rules.CondTypeURI, Op: op, Value: v}
	}
	method := func(values ...string) l7rules.Condition {
		return l7rules.Condition{Type: l7rules.CondTypeMethod, Values: values}
	}
	cases := []struct {
		name string
		rule l7rules.Rule
		want condVerdict
	}{
		{"uri eq verify", denyRule("r1", uri(l7rules.OpEq, "/_wdsp/bot/v1/verify")), verdictMatch},
		{"uri eq other", denyRule("r2", uri(l7rules.OpEq, "/api/x")), verdictNoMatch},
		{"uri ne verify", denyRule("r3", uri(l7rules.OpNe, "/_wdsp/bot/v1/verify")), verdictNoMatch},
		{"uri prefix covers", denyRule("r4", uri(l7rules.OpPrefix, "/_wdsp")), verdictMatch},
		{"uri prefix root covers", denyRule("r5", uri(l7rules.OpPrefix, "/")), verdictMatch},
		{"uri prefix other", denyRule("r6", uri(l7rules.OpPrefix, "/api")), verdictNoMatch},
		{"uri prefix adjacent segment", denyRule("r7", uri(l7rules.OpPrefix, "/_wdspx")), verdictNoMatch},
		{"uri contains hit", denyRule("r8", uri(l7rules.OpContains, "/bot/")), verdictMatch},
		{"uri contains miss", denyRule("r9", uri(l7rules.OpContains, "/admin")), verdictNoMatch},
		{"uri regex unknown", denyRule("r10", uri(l7rules.OpRegex, "^/_wdsp")), verdictUnknown},
		{"method post only", denyRule("r11", method("GET", "POST")), verdictMatch},
		{"method get only", denyRule("r12", method("GET")), verdictNoMatch},
		{"uri and method both match", denyRule("r13", uri(l7rules.OpPrefix, "/"), method("POST")), verdictMatch},
		{"uri match but method miss", denyRule("r14", uri(l7rules.OpPrefix, "/"), method("GET")), verdictNoMatch},
		{"client ip unknown", denyRule("r15", l7rules.Condition{Type: l7rules.CondTypeClientIP, Values: []string{"10.0.0.0/8"}}), verdictUnknown},
		{"no conditions", denyRule("r16"), verdictMatch},
	}
	for _, tc := range cases {
		if got := ruleCoversVerify(tc.rule); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestL7Conflicts 拒绝规则冲突 → FAIL（阻断）；正则/客户端依赖 → WARN；
// 放行规则覆盖 → WARN；禁用规则跳过；读取失败降级 FAIL（不静默放行）。
func TestL7Conflicts(t *testing.T) {
	disabled := denyRule("deny-disabled", l7rules.Condition{Type: l7rules.CondTypeURI, Op: l7rules.OpEq, Value: ReservedVerifyPath})
	disabled.Enabled = false
	h := &Handler{l7: fakeL7Lister{rules: []l7rules.Rule{
		denyRule("deny-wdsp", l7rules.Condition{Type: l7rules.CondTypeURI, Op: l7rules.OpPrefix, Value: "/_wdsp"}),
		denyRule("deny-regex", l7rules.Condition{Type: l7rules.CondTypeURI, Op: l7rules.OpRegex, Value: "^/"}),
		{Name: "allow-all", Enabled: true, Action: l7rules.ActionAllow,
			Conditions: []l7rules.Condition{{Type: l7rules.CondTypeURI, Op: l7rules.OpPrefix, Value: "/"}}},
		disabled,
		denyRule("deny-api", l7rules.Condition{Type: l7rules.CondTypeURI, Op: l7rules.OpPrefix, Value: "/api"}),
	}}}

	conflicts := h.l7Conflicts(context.Background())
	byRef := map[string]RouteConflict{}
	for _, c := range conflicts {
		byRef[c.Ref] = c
	}
	if c := byRef["deny-wdsp"]; c.Status != CheckFail || c.Type != "l7_deny_rule" {
		t.Errorf("deny-wdsp should be FAIL l7_deny_rule: %+v", c)
	}
	if c := byRef["deny-regex"]; c.Status != CheckWarn {
		t.Errorf("deny-regex should be WARN: %+v", c)
	}
	if c := byRef["allow-all"]; c.Status != CheckWarn || c.Type != "l7_allow_rule" {
		t.Errorf("allow-all should be WARN l7_allow_rule: %+v", c)
	}
	if _, ok := byRef["deny-disabled"]; ok {
		t.Error("disabled rule must be skipped")
	}
	if _, ok := byRef["deny-api"]; ok {
		t.Error("rule not covering verify must not conflict")
	}
	// 读取失败降级 FAIL
	h2 := &Handler{l7: fakeL7Lister{err: errFake}}
	cs := h2.l7Conflicts(context.Background())
	if len(cs) != 1 || cs[0].Status != CheckFail {
		t.Errorf("l7 read error must degrade to FAIL: %+v", cs)
	}
	// 未装配降级 FAIL
	h3 := &Handler{}
	if cs := h3.l7Conflicts(context.Background()); len(cs) != 1 || cs[0].Status != CheckFail {
		t.Errorf("unassembled l7 lister must degrade to FAIL: %+v", cs)
	}
}

var errFake = errors.New("fake error")

// TestPathRouteConflicts 路径转发冲突：前缀覆盖 verify 或落入保留命名空间 → FAIL。
func TestPathRouteConflicts(t *testing.T) {
	h := &Handler{pathRoutes: fakePathRouteLister{routes: []gatewayconfig.AppPathRoute{
		{PathPrefix: "/", UpstreamHost: "10.0.0.1", UpstreamPort: 80},
		{PathPrefix: "/_wdsp/bot/v1/verify/extra", UpstreamHost: "10.0.0.1", UpstreamPort: 80},
		{PathPrefix: "/app", UpstreamHost: "10.0.0.1", UpstreamPort: 80},
	}}}
	conflicts := h.pathRouteConflicts(context.Background(), uuid.New())
	if len(conflicts) != 2 {
		t.Fatalf("want 2 path route conflicts, got %+v", conflicts)
	}
	for _, c := range conflicts {
		if c.Status != CheckFail || c.Type != "path_route" {
			t.Errorf("path route conflict should be FAIL: %+v", c)
		}
	}
	// 读取失败降级 FAIL
	h2 := &Handler{pathRoutes: fakePathRouteLister{err: errFake}}
	if cs := h2.pathRouteConflicts(context.Background(), uuid.New()); len(cs) != 1 || cs[0].Status != CheckFail {
		t.Errorf("path route read error must degrade to FAIL: %+v", cs)
	}
}

// TestProtectedScopeConflicts 全量保护地址段 → WARN；普通段不提示；未装配跳过。
func TestProtectedScopeConflicts(t *testing.T) {
	h := &Handler{protected: fakeProtectedLister{addrs: []protectedaddresses.ProtectedAddress{
		{Name: "all-v4", CIDR: "0.0.0.0/0"},
		{Name: "office", CIDR: "10.0.0.0/8"},
		{Name: "all-v6", CIDR: "::/0"},
	}}}
	conflicts := h.protectedScopeConflicts(context.Background())
	if len(conflicts) != 2 {
		t.Fatalf("want 2 full-range warnings, got %+v", conflicts)
	}
	for _, c := range conflicts {
		if c.Status != CheckWarn || c.Type != "protected_address_scope" {
			t.Errorf("protected address conflict should be WARN: %+v", c)
		}
	}
	if cs := (&Handler{}).protectedScopeConflicts(context.Background()); cs != nil {
		t.Errorf("nil protected lister must skip: %+v", cs)
	}
}

// TestPutRequestDefaults PUT 请求 → 领域策略的默认值应用（challenge 指针区分
// 「未提供=默认」与显式 0；route_reservation 未携带时默认 RELEASED 由 PUT 层沿用上版）。
func TestPutRequestDefaults(t *testing.T) {
	appID := uuid.New()
	// 全缺省 → B0 默认值
	req := &putRequest{Mode: "observe"}
	p := req.toPolicy(appID)
	if p.Mode != ModeObserve {
		t.Errorf("mode not upper-cased: %q", p.Mode)
	}
	if p.Challenge.Type != "JS" || p.Challenge.NonceTTLSeconds != DefaultNonceTTL ||
		p.Challenge.ClearanceTTLSeconds != DefaultClearanceTTL || p.Challenge.Difficulty != DefaultDifficulty ||
		p.Challenge.MaxAttempts != DefaultMaxAttempts {
		t.Errorf("challenge defaults not applied: %+v", p.Challenge)
	}
	if p.SignalRules.MinIndependentGroups != MinGroups || !p.SignalRules.RequireBehaviorGroup ||
		p.SignalRules.Rules == nil {
		t.Errorf("signal rules defaults not applied: %+v", p.SignalRules)
	}
	if p.RouteReservation.State != ReservationReleased || p.RouteReservation.Namespace != ReservedNamespace {
		t.Errorf("reservation default = %+v", p.RouteReservation)
	}
	// 显式 0 保留（进入校验按越界拒绝）；部分提供时其余按默认
	zero := 0
	req = &putRequest{Mode: "OBSERVE", Challenge: &challengeRequest{NonceTTLSeconds: &zero}}
	p = req.toPolicy(appID)
	if p.Challenge.NonceTTLSeconds != 0 {
		t.Errorf("explicit 0 must be preserved for validation: %+v", p.Challenge)
	}
	if p.Challenge.ClearanceTTLSeconds != DefaultClearanceTTL || p.Challenge.Difficulty != DefaultDifficulty {
		t.Errorf("omitted fields must keep defaults: %+v", p.Challenge)
	}
	// 显式 require_behavior_group=false 保留（校验层拒绝）
	no := false
	req = &putRequest{Mode: "OBSERVE", SignalRules: &signalRulesRequest{RequireBehaviorGroup: &no}}
	p = req.toPolicy(appID)
	if p.SignalRules.RequireBehaviorGroup {
		t.Error("explicit require_behavior_group=false must be preserved for validation")
	}
	// route_reservation 提供空 namespace → 归一到冻结命名空间
	req = &putRequest{Mode: "OBSERVE", RouteReservation: &RouteReservation{State: ReservationEnabled}}
	p = req.toPolicy(appID)
	if p.RouteReservation.Namespace != ReservedNamespace {
		t.Errorf("empty namespace must default to frozen namespace: %+v", p.RouteReservation)
	}
}

// TestSummarizePolicyNoSecrets 审计摘要形状（策略无秘密材料——key_ref 仅引用名入审计）。
func TestSummarizePolicyNoSecrets(t *testing.T) {
	p := validObservePolicy()
	p.Version = 3
	p.Challenge.KeyRef = "bot-hmac-2026"
	s := summarizePolicy(p, "开启观测")
	if s.Mode != ModeObserve || s.Version != 3 || s.Reason != "开启观测" {
		t.Errorf("summary = %+v", s)
	}
	if s.Challenge.KeyRef != "bot-hmac-2026" {
		t.Errorf("key_ref (reference name only) should appear: %+v", s.Challenge)
	}
	if s.RouteReservation.State != ReservationEnabled {
		t.Errorf("reservation = %+v", s.RouteReservation)
	}
}
