// evaluate_test.go 强流程检测器决策组矩阵：ALLOW/VIOLATION/UNKNOWN ×
// 定义 mode × 引擎模式（双闸），事件条目形状，UNKNOWN 恒不阻断红线。
package flowguard

import (
	"errors"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	dsevents "github.com/jiuzhang-waf/gateway/dynamic_security/events"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// evalFixture 检测器测试夹具。
type evalFixture struct {
	ctx    *dsctx.RequestContext
	bound  []BoundStep
	rt     *Runtime
	fe     *fakeEval
	parsed *parser.Parsed
}

func newEvalFixture(t *testing.T, mode string) *evalFixture {
	t.Helper()
	def := validDefinition() // query:order_id；steps create(1)/pay(2)
	def.Mode = mode
	fe := &fakeEval{reply: []interface{}{int64(0), "", int64(1), "reserved", int64(1), int64(0)}}
	rt := &Runtime{
		Store:   NewStore(fe, nil),
		HMACKey: []byte("0123456789abcdef0123456789abcdef"),
		Now:     func() time.Time { return time.Date(2026, 10, 5, 8, 0, 0, 0, time.UTC) },
	}
	var bound []BoundStep
	for _, s := range def.Steps {
		bound = append(bound, BoundStep{Definition: def, Step: s})
	}
	return &evalFixture{
		ctx:    dsctx.New("req-sf-1", dsctx.DefaultParseLimits()),
		bound:  bound,
		rt:     rt,
		fe:     fe,
		parsed: &parser.Parsed{Method: "POST", RawPath: "/v1/orders", Query: map[string]string{"order_id": "o-42"}},
	}
}

// only 取 pay 步骤绑定（默认夹具含两步，逐步骤判定）。
func (f *evalFixture) only(stepKey string) []BoundStep {
	for _, b := range f.bound {
		if b.Step.StepKey == stepKey {
			return []BoundStep{b}
		}
	}
	panic("step not in fixture: " + stepKey)
}

func findMatch(ctx *dsctx.RequestContext, ruleID string) *dsctx.DetectorMatch {
	for _, m := range ctx.CopyMatches() {
		if m.RuleID == ruleID {
			mm := m
			return &mm
		}
	}
	return nil
}

func TestEvaluateReserveOK(t *testing.T) {
	fx := newEvalFixture(t, ModeObserve)
	r := httptest.NewRequest("POST", "/v1/orders?order_id=o-42", nil)
	Evaluate(fx.ctx, r, fx.parsed, "POST /v1/orders", fx.only("create"), fx.rt, nil, "key:abc", true)
	// ALLOW：无定案明细；动作条目 INSTANCE_NEW + RESERVE 留存（冻结形状）
	if len(fx.ctx.CopyMatches()) != 0 {
		t.Fatalf("ALLOW 不应产明细: %+v", fx.ctx.CopyMatches())
	}
	acts := ActionsFromContext(fx.ctx)
	if len(acts) != 2 {
		t.Fatalf("动作条目 = %+v", acts)
	}
	if acts[0].Action != dsevents.SFlowActionInstanceNew || acts[1].Action != dsevents.SFlowActionReserve {
		t.Fatalf("动作序 = %v/%v", acts[0].Action, acts[1].Action)
	}
	main := acts[1]
	if main.Result != dsevents.SFlowResultOK || main.FencingToken != 1 || main.LeaseSeconds != 30 ||
		main.DefinitionVersion != 1 || main.ReasonCode != "" {
		t.Fatalf("RESERVE 条目 = %+v", main)
	}
	if !strings.HasPrefix(main.InstanceID, "sfref:") {
		t.Fatalf("instance_id 应为 sfref 形态: %q", main.InstanceID)
	}
	if main.OccurredAt != time.Date(2026, 10, 5, 8, 0, 0, 0, time.UTC) {
		t.Fatalf("occurred_at = %v", main.OccurredAt)
	}
	// 成功预留留存（FLOW-03 commit 消费点）
	res := ReservationFromContext(fx.ctx)
	if res == nil || res.FencingToken != 1 || res.StepKey != "create" || res.LeaseSeconds != 30 {
		t.Fatalf("Reservation = %+v", res)
	}
	// 实例键确定性（同输入同键）与主体敏感性
	r2 := httptest.NewRequest("POST", "/v1/orders?order_id=o-43", nil)
	fx2 := newEvalFixture(t, ModeObserve)
	fx2.parsed.Query = map[string]string{"order_id": "o-43"}
	Evaluate(fx2.ctx, r2, fx2.parsed, "POST /v1/orders", fx2.only("create"), fx2.rt, nil, "key:abc", true)
	if ActionsFromContext(fx2.ctx)[1].InstanceID == main.InstanceID {
		t.Fatal("异实例引用必须异实例键")
	}
}

func TestEvaluateViolationDoubleGate(t *testing.T) {
	// REJECTED 前置未确认（依赖步骤无有效预留）
	reply := []interface{}{int64(3), ReasonReserveDenied, int64(0), "predecessor_unconfirmed", int64(0), int64(0)}
	cases := []struct {
		name          string
		defMode       string
		engineProtect bool
		wantCategory  string
	}{
		{"OBSERVE 定义+引擎 PROTECT 仍只记录", ModeObserve, true, "OBSERVE"},
		{"PROTECT 定义+引擎 OBSERVE 不实断", ModeProtect, false, "OBSERVE"},
		{"双闸全真 BLOCK", ModeProtect, true, "BLOCK"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newEvalFixture(t, tc.defMode)
			fx.fe.reply = reply
			r := httptest.NewRequest("POST", "/v1/orders?order_id=o-42", nil)
			Evaluate(fx.ctx, r, fx.parsed, "POST /v1/orders", fx.only("pay"), fx.rt, nil, "key:abc", tc.engineProtect)
			m := findMatch(fx.ctx, "flowguard.violation")
			if m == nil {
				t.Fatal("违规应产 flowguard.violation 明细")
			}
			if m.Category != tc.wantCategory {
				t.Fatalf("category = %q，应 %q", m.Category, tc.wantCategory)
			}
			if m.Detector != "flowguard" || m.Evidence["reason_code"] != ReasonReserveDenied ||
				m.Evidence["detail"] != "predecessor_unconfirmed" || m.Evidence["definition_version"] != "1" {
				t.Fatalf("证据 = %+v", m.Evidence)
			}
			// 动作条目如实记录 REJECTED
			acts := ActionsFromContext(fx.ctx)
			if len(acts) != 1 || acts[0].Result != dsevents.SFlowResultRejected || acts[0].ReasonCode != ReasonReserveDenied {
				t.Fatalf("动作条目 = %+v", acts)
			}
		})
	}
}

func TestEvaluateUnknownNeverBlocks(t *testing.T) {
	replies := map[string][]interface{}{
		"脚本内 INDETERMINATE": {int64(4), ReasonUnknown, int64(0), "instance_indeterminate", int64(0), int64(0)},
	}
	for name, reply := range replies {
		t.Run(name, func(t *testing.T) {
			fx := newEvalFixture(t, ModeProtect)
			fx.fe.reply = reply
			r := httptest.NewRequest("POST", "/v1/orders?order_id=o-42", nil)
			Evaluate(fx.ctx, r, fx.parsed, "POST /v1/orders", fx.only("pay"), fx.rt, nil, "key:abc", true)
			m := findMatch(fx.ctx, "flowguard.unknown")
			if m == nil || m.Category != "OBSERVE" {
				t.Fatalf("UNKNOWN 明细 = %+v", m)
			}
			if findMatch(fx.ctx, "flowguard.violation") != nil {
				t.Fatal("UNKNOWN 绝不产 violation 明细（恒不阻断红线）")
			}
		})
	}
	// Valkey 断连：dependency_unavailable 披露 + 绝不 BLOCK
	fx := newEvalFixture(t, ModeProtect)
	fx.fe.err = errors.New("connection refused")
	r := httptest.NewRequest("POST", "/v1/orders?order_id=o-42", nil)
	Evaluate(fx.ctx, r, fx.parsed, "POST /v1/orders", fx.only("pay"), fx.rt, nil, "key:abc", true)
	m := findMatch(fx.ctx, "flowguard.unknown")
	if m == nil || m.Evidence["dependency_unavailable"] != "true" || m.Evidence["detail"] != "valkey_error" {
		t.Fatalf("断连披露 = %+v", m)
	}
	acts := ActionsFromContext(fx.ctx)
	if len(acts) != 1 || acts[0].Result != dsevents.SFlowResultUnknown || acts[0].ReasonCode != ReasonUnknown {
		t.Fatalf("UNKNOWN 动作条目 = %+v", acts)
	}
	// 密钥缺席：UNKNOWN + dependency_unavailable，不阻断
	fx = newEvalFixture(t, ModeProtect)
	fx.rt.HMACKey = nil
	Evaluate(fx.ctx, r, fx.parsed, "POST /v1/orders", fx.only("pay"), fx.rt, nil, "key:abc", true)
	m = findMatch(fx.ctx, "flowguard.unknown")
	if m == nil || m.Evidence["detail"] != "hmac_key_unavailable" || m.Evidence["dependency_unavailable"] != "true" {
		t.Fatalf("密钥缺席披露 = %+v", m)
	}
	// 实例引用缺失：UNKNOWN（非 infra，无 dependency_unavailable），不阻断
	fx = newEvalFixture(t, ModeProtect)
	fx.parsed.Query = map[string]string{}
	Evaluate(fx.ctx, r, fx.parsed, "POST /v1/orders", fx.only("pay"), fx.rt, nil, "key:abc", true)
	m = findMatch(fx.ctx, "flowguard.unknown")
	if m == nil || m.Evidence["detail"] != "missing_instance_ref" || m.Evidence["dependency_unavailable"] != "" {
		t.Fatalf("引用缺失披露 = %+v", m)
	}
}

func TestEvaluatePrincipalAndTenantSources(t *testing.T) {
	// JWT VERIFIED：主体/租户取可信声明（实例键与匿名追踪键不同域）
	fx := newEvalFixture(t, ModeObserve)
	r := httptest.NewRequest("POST", "/v1/orders?order_id=o-42", nil)
	jwt := &jwtverify.VerificationResult{
		Status:              jwtverify.StatusVerified,
		VerifiedPrincipalID: "user-1",
		VerifiedTenantID:    "tenant-9",
	}
	Evaluate(fx.ctx, r, fx.parsed, "POST /v1/orders", fx.only("create"), fx.rt, jwt, "ip:1.2.3.4", false)
	jwtIID := ActionsFromContext(fx.ctx)[1].InstanceID
	fx2 := newEvalFixture(t, ModeObserve)
	Evaluate(fx2.ctx, r, fx2.parsed, "POST /v1/orders", fx2.only("create"), fx2.rt, nil, "ip:1.2.3.4", false)
	anonIID := ActionsFromContext(fx2.ctx)[1].InstanceID
	if jwtIID == "" || anonIID == "" || jwtIID == anonIID {
		t.Fatalf("VERIFIED 与匿名主体实例键必须不同: %q vs %q", jwtIID, anonIID)
	}
}

func TestEvaluateMultiDefinitionIsolation(t *testing.T) {
	// 同端点两版本并存（FLOW-01 版本不可变装配产物）：实例键含版本维度，
	// 两绑定各自独立预留互不染指
	fx := newEvalFixture(t, ModeObserve)
	defV2 := validDefinition()
	defV2.Version = 2
	var both []BoundStep
	for _, b := range fx.bound {
		if b.Step.StepKey == "create" {
			both = append(both, b)
		}
	}
	for _, s := range defV2.Steps {
		if s.StepKey == "create" {
			both = append(both, BoundStep{Definition: defV2, Step: s})
		}
	}
	var iids []string
	fx.fe.hook = func(script string, keys, args []string) ([]interface{}, error) {
		// 从键形截取实例键（sflow:v1:{<iid>}:fence）
		iid := strings.Split(strings.TrimPrefix(keys[0], KeyPrefix+"{"), "}")[0]
		iids = append(iids, iid)
		return []interface{}{int64(0), "", int64(1), "reserved", int64(1), int64(0)}, nil
	}
	r := httptest.NewRequest("POST", "/v1/orders?order_id=o-42", nil)
	Evaluate(fx.ctx, r, fx.parsed, "POST /v1/orders", both, fx.rt, nil, "key:abc", false)
	if len(iids) != 2 || iids[0] == iids[1] {
		t.Fatalf("两版本实例键必须隔离: %v", iids)
	}
	acts := ActionsFromContext(fx.ctx)
	if len(acts) != 4 { // 两绑定各自 INSTANCE_NEW + RESERVE
		t.Fatalf("动作条目数 = %d", len(acts))
	}
}

func TestIndexByEndpoint(t *testing.T) {
	if IndexByEndpoint(nil) != nil {
		t.Fatal("nil Registry 应 nil（零行为）")
	}
	def := validDefinition()
	defV2 := validDefinition()
	defV2.Version = 2
	reg, err := BuildRegistry([]Definition{def, defV2})
	if err != nil {
		t.Fatal(err)
	}
	idx := IndexByEndpoint(reg)
	if len(idx) != 2 { // 两个端点键
		t.Fatalf("索引端点数 = %d", len(idx))
	}
	// 每端点含两版本绑定
	for ek, bs := range idx {
		if len(bs) != 2 {
			t.Fatalf("端点 %s 绑定数 = %d（同 id 多版本并存）", ek, len(bs))
		}
	}
}

// TestEvaluateExpiredTakeoverEventChain F05 审计：接管过期槽的事件链含两次
// fencing 值（EXPIRE 条目旧 token + RESERVE 条目新 token）。
func TestEvaluateExpiredTakeoverEventChain(t *testing.T) {
	fx := newEvalFixture(t, ModeObserve)
	fx.fe.reply = []interface{}{int64(0), "", int64(7), "reserved", int64(2), int64(3)}
	r := httptest.NewRequest("POST", "/v1/orders?order_id=o-42", nil)
	Evaluate(fx.ctx, r, fx.parsed, "POST /v1/orders", fx.only("create"), fx.rt, nil, "key:abc", false)
	acts := ActionsFromContext(fx.ctx)
	if len(acts) != 2 || acts[0].Action != dsevents.SFlowActionExpire || acts[1].Action != dsevents.SFlowActionReserve {
		t.Fatalf("条目 = %+v", acts)
	}
	if acts[0].FencingToken != 3 || acts[1].FencingToken != 7 {
		t.Fatalf("两次 fencing 值应可核对: old=%d new=%d", acts[0].FencingToken, acts[1].FencingToken)
	}
}

// 编译期引用守卫（strconv 在证据中使用）。
var _ = strconv.Itoa

// TestEvaluateRetiredDefinitionGate 育龄窗闸映射（§8.4-1 裁决）：RETIRED 定义绑定
// 的 Reserve 调用 allowNewInstance=false（ARGV[5]="0"），ACTIVE 定义 =true（"1"）。
func TestEvaluateRetiredDefinitionGate(t *testing.T) {
	mk := func(status string) (*evalFixture, []BoundStep) {
		fx := newEvalFixture(t, ModeObserve)
		def := validDefinition()
		def.Status = status
		var bound []BoundStep
		for _, s := range def.Steps {
			if s.StepKey == "pay" {
				bound = append(bound, BoundStep{Definition: def, Step: s})
			}
		}
		return fx, bound
	}
	fx, bound := mk(StatusRetired)
	Evaluate(fx.ctx, httptest.NewRequest("POST", "/v1/orders?order_id=o-42", nil), fx.parsed, "POST /v1/orders", bound, fx.rt, nil, "ip:203.0.113.9", false)
	if fx.fe.lastArgs[5] != "0" {
		t.Fatalf("RETIRED 定义 allow_new arg=%q, want \"0\"", fx.fe.lastArgs[5])
	}
	fx2, bound2 := mk(StatusActive)
	Evaluate(fx2.ctx, httptest.NewRequest("POST", "/v1/orders?order_id=o-42", nil), fx2.parsed, "POST /v1/orders", bound2, fx2.rt, nil, "ip:203.0.113.9", false)
	if fx2.fe.lastArgs[5] != "1" {
		t.Fatalf("ACTIVE 定义 allow_new arg=%q, want \"1\"", fx2.fe.lastArgs[5])
	}
}
