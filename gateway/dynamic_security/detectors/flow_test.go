// flow_test.go 业务流程偏离检测（§44）单测：基线校验/归组、会话追踪器
// （序号/重复短窗/对象状态/空闲重置/有界性）、四类规则命中与降级、存储注入。
package detectors

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// testFlowBaseline 三步流程基线：login → query → submit（submit 前置 login+query，
// 状态机 created → submitted）。
func testFlowBaseline() FlowBaseline {
	return FlowBaseline{
		FlowID: "order-flow",
		Steps: []FlowStep{
			{StepID: "login", EndpointKey: "POST /v1/login", Sequence: 1, StateTo: "created"},
			{StepID: "query", EndpointKey: "GET /v1/orders", Sequence: 2, Predecessors: []string{"login"}},
			{StepID: "submit", EndpointKey: "POST /v1/orders/submit", Sequence: 3, Predecessors: []string{"login", "query"}, StateFrom: "created", StateTo: "submitted", Terminal: true},
		},
	}
}

func TestValidateFlowBaselines(t *testing.T) {
	if err := ValidateFlowBaselines([]FlowBaseline{testFlowBaseline()}); err != nil {
		t.Fatalf("valid baseline rejected: %v", err)
	}
	cases := []struct {
		name string
		b    FlowBaseline
	}{
		{"empty flow_id", FlowBaseline{Steps: []FlowStep{{StepID: "a", EndpointKey: "GET /x"}}}},
		{"empty step_id", FlowBaseline{FlowID: "f", Steps: []FlowStep{{EndpointKey: "GET /x"}}}},
		{"empty endpoint", FlowBaseline{FlowID: "f", Steps: []FlowStep{{StepID: "a"}}}},
		{"dup step_id", FlowBaseline{FlowID: "f", Steps: []FlowStep{
			{StepID: "a", EndpointKey: "GET /x"}, {StepID: "a", EndpointKey: "GET /y"}}}},
		{"self predecessor", FlowBaseline{FlowID: "f", Steps: []FlowStep{
			{StepID: "a", EndpointKey: "GET /x", Predecessors: []string{"a"}}}}},
		{"unknown predecessor", FlowBaseline{FlowID: "f", Steps: []FlowStep{
			{StepID: "a", EndpointKey: "GET /x", Predecessors: []string{"ghost"}}}}},
	}
	for _, tc := range cases {
		err := ValidateFlowBaselines([]FlowBaseline{tc.b})
		if err == nil {
			t.Fatalf("%s: expected error", tc.name)
		}
		fe, ok := err.(*FlowConfigError)
		if !ok || fe.Reason == "" {
			t.Fatalf("%s: error type %T reason empty", tc.name, err)
		}
	}
}

func TestGroupFlowBaselines(t *testing.T) {
	if GroupFlowBaselines(nil) != nil {
		t.Fatal("nil in must be nil out")
	}
	g := GroupFlowBaselines([]FlowBaseline{testFlowBaseline()})
	for _, ek := range []string{"POST /v1/login", "GET /v1/orders", "POST /v1/orders/submit"} {
		if len(g[ek]) != 1 {
			t.Fatalf("endpoint %s not grouped: %+v", ek, g)
		}
	}
	if len(g["GET /other"]) != 0 {
		t.Fatal("unrelated endpoint must not be grouped")
	}
}

// flowSessionFor 构造隔离会话存储并绑定到请求上下文（测试间互不影响）。
func flowSessionFor(ctx *dsctx.RequestContext, now func() time.Time) {
	ctx.BindDetectorStoreOverrides(&StoreOverrides{FlowSession: NewMemoryFlowSessionStore(0, now)})
}

func TestFlowSessionTracker(t *testing.T) {
	base := time.Now()
	clock := base
	tr := newFlowSessionTracker(100, func() time.Time { return clock })

	// 首次观测：无先前序号/状态；seen 含本次
	s1 := tr.Observe("k", FlowObservation{StepID: "a", Sequence: 1, StateTo: "s1", ObjectKey: "o1"})
	if s1.HasMaxSequence || s1.ObjectStateBefore != "" || !s1.SeenSteps["a"] || s1.DuplicateCount != 0 {
		t.Fatalf("first snapshot wrong: %+v", s1)
	}
	// 二次观测：带幂等键；序号/对象状态为前次值
	s2 := tr.Observe("k", FlowObservation{StepID: "b", Sequence: 2, SubmitKey: "sub1", ObjectKey: "o1", StateTo: "s2"})
	if !s2.HasMaxSequence || s2.MaxSequenceBefore != 1 || s2.ObjectStateBefore != "s1" || s2.DuplicateCount != 1 {
		t.Fatalf("second snapshot wrong: %+v", s2)
	}
	// 同幂等键短窗内再次提交：count=2
	s3 := tr.Observe("k", FlowObservation{StepID: "b", Sequence: 2, SubmitKey: "sub1"})
	if s3.DuplicateCount != 2 {
		t.Fatalf("duplicate count=%d, want 2", s3.DuplicateCount)
	}
	// 出重复短窗后计数重置为 1
	clock = base.Add(2 * time.Minute)
	s4 := tr.Observe("k", FlowObservation{StepID: "b", Sequence: 2, SubmitKey: "sub1"})
	if s4.DuplicateCount != 1 {
		t.Fatalf("post-window count=%d, want 1", s4.DuplicateCount)
	}
	// 会话空闲超 TTL：轨迹重置（无先前序号/状态/seen）
	clock = base.Add(2*time.Minute + FlowSessionTTL + time.Minute)
	s5 := tr.Observe("k", FlowObservation{StepID: "c", Sequence: 3, ObjectKey: "o1"})
	if s5.HasMaxSequence || s5.ObjectStateBefore != "" || s5.SeenSteps["a"] {
		t.Fatalf("TTL reset failed: %+v", s5)
	}
}

func TestFlowSessionTrackerBounds(t *testing.T) {
	tr := newFlowSessionTracker(2, nil)
	// 会话键 LRU 定容：第 3 个键挤掉最旧
	tr.Observe("k1", FlowObservation{StepID: "a", Sequence: 1})
	tr.Observe("k2", FlowObservation{StepID: "a", Sequence: 1})
	tr.Observe("k3", FlowObservation{StepID: "a", Sequence: 1})
	if s := tr.Observe("k1", FlowObservation{StepID: "z", Sequence: 9}); s.SeenSteps["a"] {
		t.Fatal("LRU eviction failed: k1 state survived")
	}
	// 幂等键槽定容：超上限后最旧键被淘汰（重新计数为 1）
	big := newFlowSessionTracker(10, nil)
	for i := 0; i < flowMaxSubmitKeys+1; i++ {
		big.Observe("s", FlowObservation{StepID: "a", Sequence: 1, SubmitKey: fmt.Sprintf("k%d", i)})
	}
	if n := len(big.entries.items); n > 10 {
		t.Fatalf("entry cap broken: %d", n)
	}
	e := big.entries.items["s"].Value.(lruItem).val.(*flowSessionEntry)
	if len(e.submits) > flowMaxSubmitKeys {
		t.Fatalf("submit slot cap broken: %d", len(e.submits))
	}
	// 步骤集合与对象槽定容
	for i := 0; i < flowMaxSeenSteps+10; i++ {
		big.Observe("s2", FlowObservation{StepID: "step-" + string(rune(i)), Sequence: i, ObjectKey: "obj-" + string(rune(i)), StateTo: "s"})
	}
	e2 := big.entries.items["s2"].Value.(lruItem).val.(*flowSessionEntry)
	if len(e2.seen) > flowMaxSeenSteps {
		t.Fatalf("seen cap broken: %d", len(e2.seen))
	}
	if len(e2.objState) > flowMaxObjects {
		t.Fatalf("object slot cap broken: %d", len(e2.objState))
	}
}

// flowReq 构造带凭据（稳定 identity）与可选幂等键/对象标识的请求上下文。
func flowReq(t *testing.T, method, target, idemKey string, objIDs []dsctx.ObjectIdentifier) (*dsctx.RequestContext, *http.Request) {
	t.Helper()
	r, err := http.NewRequest(method, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer flow-test-token")
	if idemKey != "" {
		r.Header.Set("Idempotency-Key", idemKey)
	}
	ctx := dsctx.New("req-flow", dsctx.DefaultParseLimits())
	flowSessionFor(ctx, nil)
	if len(objIDs) > 0 {
		ctx.SetObjectIdentifiers(objIDs)
	}
	return ctx, r
}

func flowRules(ctx *dsctx.RequestContext) map[string]bool {
	out := map[string]bool{}
	for _, m := range ctx.CopyMatches() {
		out[m.RuleID] = true
	}
	return out
}

var testObjIDs = []dsctx.ObjectIdentifier{{Source: "path", Param: "id", ValueHash: "abc123"}}

func TestCheckFlowDeviationZeroBehavior(t *testing.T) {
	ctx, r := flowReq(t, http.MethodPost, "http://h/v1/orders/submit", "", nil)
	CheckFlowDeviation(ctx, r, "auth:xyz", "POST /v1/orders/submit", "", nil)
	if len(ctx.CopyMatches()) != 0 {
		t.Fatalf("nil baseline must be zero behavior: %+v", ctx.CopyMatches())
	}
	// 身份为空跳过
	ctx2, r2 := flowReq(t, http.MethodPost, "http://h/v1/orders/submit", "", nil)
	CheckFlowDeviation(ctx2, r2, "", "POST /v1/orders/submit", "", []FlowBaseline{testFlowBaseline()})
	if len(ctx2.CopyMatches()) != 0 {
		t.Fatal("empty identity must skip")
	}
	// 端点不属于任何基线步骤 → 零行为
	ctx3, r3 := flowReq(t, http.MethodGet, "http://h/v1/unrelated", "", nil)
	CheckFlowDeviation(ctx3, r3, "auth:xyz", "GET /v1/unrelated", "", []FlowBaseline{testFlowBaseline()})
	if len(ctx3.CopyMatches()) != 0 {
		t.Fatal("unrelated endpoint must be zero behavior")
	}
}

func TestCheckFlowDeviationOrderedFlow(t *testing.T) {
	// 同一主体（同一 identity+会话存储）按序走完三步：零 Finding
	ctx, r := flowReq(t, http.MethodPost, "http://h/v1/login", "", nil)
	id := "auth:ordered"
	CheckFlowDeviation(ctx, r, id, "POST /v1/login", "", []FlowBaseline{testFlowBaseline()})

	// 后续请求共享同一会话存储（同一 StoreOverrides 实例）
	stores := &StoreOverrides{FlowSession: NewMemoryFlowSessionStore(0, nil)}
	mk := func(method, target, ek string, objs []dsctx.ObjectIdentifier) *dsctx.RequestContext {
		c, rr := flowReq(t, method, target, "", objs)
		c.BindDetectorStoreOverrides(stores)
		CheckFlowDeviation(c, rr, id, ek, "", []FlowBaseline{testFlowBaseline()})
		return c
	}
	if rules := flowRules(mk(http.MethodPost, "http://h/v1/login", "POST /v1/login", testObjIDs)); len(rules) != 0 {
		t.Fatalf("login step must be clean: %v", rules)
	}
	if rules := flowRules(mk(http.MethodGet, "http://h/v1/orders", "GET /v1/orders", testObjIDs)); len(rules) != 0 {
		t.Fatalf("query after login must be clean: %v", rules)
	}
	if rules := flowRules(mk(http.MethodPost, "http://h/v1/orders/submit", "POST /v1/orders/submit", testObjIDs)); len(rules) != 0 {
		t.Fatalf("ordered submit must be clean: %v", rules)
	}
}

func TestCheckFlowDeviationStepSkip(t *testing.T) {
	stores := &StoreOverrides{FlowSession: NewMemoryFlowSessionStore(0, nil)}
	ctx, r := flowReq(t, http.MethodPost, "http://h/v1/orders/submit", "", nil)
	ctx.BindDetectorStoreOverrides(stores)
	// 未见 login/query 直达终点 → flow.step_skip（OBSERVE/HIGH）
	CheckFlowDeviation(ctx, r, "auth:skip", "POST /v1/orders/submit", "", []FlowBaseline{testFlowBaseline()})
	rules := flowRules(ctx)
	if !rules["flow.step_skip"] {
		t.Fatalf("expected step_skip, got %v", rules)
	}
	for _, m := range ctx.CopyMatches() {
		if m.RuleID != "flow.step_skip" {
			continue
		}
		if m.Category != "OBSERVE" || m.Severity != "HIGH" || m.Detector != "api_flow" {
			t.Fatalf("step_skip attrs wrong: %+v", m)
		}
		if m.Evidence["missing"] != "login,query" || m.Evidence["flow_id"] != "order-flow" {
			t.Fatalf("step_skip evidence wrong: %+v", m.Evidence)
		}
	}
	// 只见过 login 未见 query → 仍跳步，missing 只含 query
	ctx2, r2 := flowReq(t, http.MethodPost, "http://h/v1/login", "", nil)
	ctx2.BindDetectorStoreOverrides(stores)
	CheckFlowDeviation(ctx2, r2, "auth:skip2", "POST /v1/login", "", []FlowBaseline{testFlowBaseline()})
	ctx3, r3 := flowReq(t, http.MethodPost, "http://h/v1/orders/submit", "", nil)
	ctx3.BindDetectorStoreOverrides(stores)
	CheckFlowDeviation(ctx3, r3, "auth:skip2", "POST /v1/orders/submit", "", []FlowBaseline{testFlowBaseline()})
	for _, m := range ctx3.CopyMatches() {
		if m.RuleID == "flow.step_skip" && m.Evidence["missing"] != "query" {
			t.Fatalf("partial skip evidence wrong: %+v", m.Evidence)
		}
	}
}

func TestCheckFlowDeviationOutOfOrder(t *testing.T) {
	stores := &StoreOverrides{FlowSession: NewMemoryFlowSessionStore(0, nil)}
	id := "auth:ooo"
	mk := func(method, target, ek string) *dsctx.RequestContext {
		c, rr := flowReq(t, method, target, "", nil)
		c.BindDetectorStoreOverrides(stores)
		CheckFlowDeviation(c, rr, id, ek, "", []FlowBaseline{testFlowBaseline()})
		return c
	}
	mk(http.MethodPost, "http://h/v1/orders/submit", "POST /v1/orders/submit")   // seq3 先入窗
	got := flowRules(mk(http.MethodGet, "http://h/v1/orders", "GET /v1/orders")) // seq2 倒退
	if !got["flow.out_of_order"] {
		t.Fatalf("expected out_of_order, got %v", got)
	}
	for _, m := range mk(http.MethodGet, "http://h/v1/orders", "GET /v1/orders").CopyMatches() {
		// 同序号重复访问（seq2 == max 之前记录的 seq3？不，上一行已记录 seq2；再访 seq2 不倒退）
		if m.RuleID == "flow.out_of_order" && m.Evidence["sequence"] == "2" && m.Evidence["max_sequence_before"] == "2" {
			t.Fatalf("equal sequence must not be out_of_order: %+v", m.Evidence)
		}
	}
}

func TestCheckFlowDeviationDuplicateSubmit(t *testing.T) {
	stores := &StoreOverrides{FlowSession: NewMemoryFlowSessionStore(0, nil)}
	id := "auth:dup"
	const rawKey = "IDEMPOTENCY-SECRET-123"
	mk := func(idem string) *dsctx.RequestContext {
		c, rr := flowReq(t, http.MethodPost, "http://h/v1/orders/submit", idem, nil)
		c.BindDetectorStoreOverrides(stores)
		CheckFlowDeviation(c, rr, id, "POST /v1/orders/submit", "salt", []FlowBaseline{testFlowBaseline()})
		return c
	}
	if rules := flowRules(mk(rawKey)); rules["flow.duplicate_submit"] {
		t.Fatal("first submit must not be duplicate")
	}
	got := flowRules(mk(rawKey))
	if !got["flow.duplicate_submit"] {
		t.Fatalf("second submit within window must be duplicate: %v", got)
	}
	// 证据与判定不泄露幂等键明文（哈希也不含 raw）
	for _, m := range mk(rawKey).CopyMatches() {
		for k, v := range m.Evidence {
			if strings.Contains(v, rawKey) || strings.Contains(k, rawKey) {
				t.Fatalf("raw idempotency key leaked: %+v", m.Evidence)
			}
		}
	}
	// 不同幂等键不算重复
	if rules := flowRules(mk("OTHER-KEY")); rules["flow.duplicate_submit"] {
		t.Fatal("distinct idempotency key must not be duplicate")
	}
	// GET 不参与重复提交判定（任务书口径：重复 POST）
	c, rr := flowReq(t, http.MethodGet, "http://h/v1/orders", "", nil)
	c.BindDetectorStoreOverrides(stores)
	CheckFlowDeviation(c, rr, id, "GET /v1/orders", "salt", []FlowBaseline{testFlowBaseline()})
	CheckFlowDeviation(c, rr, id, "GET /v1/orders", "salt", []FlowBaseline{testFlowBaseline()})
	if flowRules(c)["flow.duplicate_submit"] {
		t.Fatal("GET must not trigger duplicate_submit")
	}
}

func TestCheckFlowDeviationDuplicateByObject(t *testing.T) {
	// 无幂等键头时回退对象哈希判定重复提交
	stores := &StoreOverrides{FlowSession: NewMemoryFlowSessionStore(0, nil)}
	id := "auth:dupobj"
	mk := func() *dsctx.RequestContext {
		c, rr := flowReq(t, http.MethodPost, "http://h/v1/orders/submit", "", testObjIDs)
		c.BindDetectorStoreOverrides(stores)
		CheckFlowDeviation(c, rr, id, "POST /v1/orders/submit", "salt", []FlowBaseline{testFlowBaseline()})
		return c
	}
	mk()
	got := flowRules(mk())
	if !got["flow.duplicate_submit"] {
		t.Fatalf("same object repeat POST must be duplicate: %v", got)
	}
	for _, m := range mk().CopyMatches() {
		if m.RuleID == "flow.duplicate_submit" && m.Evidence["key_source"] != "object" {
			t.Fatalf("key_source wrong: %+v", m.Evidence)
		}
	}
}

func TestCheckFlowDeviationIllegalStateTransition(t *testing.T) {
	stores := &StoreOverrides{FlowSession: NewMemoryFlowSessionStore(0, nil)}
	id := "auth:state"
	mk := func(method, target, ek string, objs []dsctx.ObjectIdentifier) *dsctx.RequestContext {
		c, rr := flowReq(t, method, target, "", objs)
		c.BindDetectorStoreOverrides(stores)
		CheckFlowDeviation(c, rr, id, ek, "", []FlowBaseline{testFlowBaseline()})
		return c
	}
	// login 声明 state_to=created：对象状态记账；再次 submit 要求 state_from=created → 合法
	mk(http.MethodPost, "http://h/v1/login", "POST /v1/login", testObjIDs)
	mk(http.MethodGet, "http://h/v1/orders", "GET /v1/orders", testObjIDs)
	if rules := flowRules(mk(http.MethodPost, "http://h/v1/orders/submit", "POST /v1/orders/submit", testObjIDs)); rules["flow.illegal_state_transition"] {
		t.Fatalf("legal transition must not flag: %v", rules)
	}
	// submit 后对象状态推进为 submitted；再 submit 要求 created → 非法迁移
	got := mk(http.MethodPost, "http://h/v1/orders/submit", "POST /v1/orders/submit", testObjIDs)
	found := false
	for _, m := range got.CopyMatches() {
		if m.RuleID == "flow.illegal_state_transition" {
			found = true
			if m.Evidence["expected_state"] != "created" || m.Evidence["observed_state"] != "submitted" {
				t.Fatalf("state evidence wrong: %+v", m.Evidence)
			}
		}
	}
	if !found {
		t.Fatalf("expected illegal_state_transition: %+v", got.CopyMatches())
	}
}

func TestCheckFlowDeviationStateDegradation(t *testing.T) {
	// 降级 1：会话内无先前观测状态（流程从中段进入视野）→ 不判
	stores := &StoreOverrides{FlowSession: NewMemoryFlowSessionStore(0, nil)}
	ctx, r := flowReq(t, http.MethodPost, "http://h/v1/orders/submit", "", testObjIDs)
	ctx.BindDetectorStoreOverrides(stores)
	CheckFlowDeviation(ctx, r, "auth:mid", "POST /v1/orders/submit", "", []FlowBaseline{testFlowBaseline()})
	if flowRules(ctx)["flow.illegal_state_transition"] {
		t.Fatal("no prior observed state must not flag")
	}
	// 降级 2：请求无对象标识 → 不判（同一会话已有状态记录也无法归属）
	ctx2, r2 := flowReq(t, http.MethodPost, "http://h/v1/orders/submit", "", nil)
	ctx2.BindDetectorStoreOverrides(stores)
	CheckFlowDeviation(ctx2, r2, "auth:mid2", "POST /v1/orders/submit", "", []FlowBaseline{testFlowBaseline()})
	if flowRules(ctx2)["flow.illegal_state_transition"] {
		t.Fatal("no object identifier must not flag")
	}
	// 降级 3：步骤未声明 state_from → 不参与状态判定
	noState := FlowBaseline{FlowID: "nostate", Steps: []FlowStep{
		{StepID: "a", EndpointKey: "POST /v1/login", Sequence: 1, StateTo: "x"},
		{StepID: "b", EndpointKey: "POST /v1/orders/submit", Sequence: 2},
	}}
	stores3 := &StoreOverrides{FlowSession: NewMemoryFlowSessionStore(0, nil)}
	c1, r1 := flowReq(t, http.MethodPost, "http://h/v1/login", "", testObjIDs)
	c1.BindDetectorStoreOverrides(stores3)
	CheckFlowDeviation(c1, r1, "auth:ns", "POST /v1/login", "", []FlowBaseline{noState})
	c2, r2b := flowReq(t, http.MethodPost, "http://h/v1/orders/submit", "", testObjIDs)
	c2.BindDetectorStoreOverrides(stores3)
	CheckFlowDeviation(c2, r2b, "auth:ns", "POST /v1/orders/submit", "", []FlowBaseline{noState})
	if flowRules(c2)["flow.illegal_state_transition"] {
		t.Fatal("step without state_from must not flag")
	}
}

// fakeFlowStore 记录注入调用（验证 Stores 注入路径生效）。
type fakeFlowStore struct{ calls int }

func (f *fakeFlowStore) Observe(key string, o FlowObservation) FlowSessionSnapshot {
	f.calls++
	return FlowSessionSnapshot{SeenSteps: map[string]bool{o.StepID: true}}
}

func TestCheckFlowDeviationStoreInjection(t *testing.T) {
	fake := &fakeFlowStore{}
	ctx, r := flowReq(t, http.MethodGet, "http://h/v1/orders", "", nil)
	ctx.BindDetectorStoreOverrides(&StoreOverrides{FlowSession: fake})
	CheckFlowDeviation(ctx, r, "auth:inj", "GET /v1/orders", "", []FlowBaseline{testFlowBaseline()})
	if fake.calls != 1 {
		t.Fatalf("injected store not used, calls=%d", fake.calls)
	}
	// fake 快照 seen 只含本步骤 → query 声明前置 login 缺失 → step_skip
	if !flowRules(ctx)["flow.step_skip"] {
		t.Fatalf("injected snapshot must drive detection: %+v", ctx.CopyMatches())
	}
}

// ---------- §44 剩余三项：批量执行 / 取消后继续操作 / 匿名直达后置 ----------

// testFlowRateBaseline 批量执行基线：query 步骤级上限 2 次/60s；流程级上限 3 次/60s。
func testFlowRateBaseline() FlowBaseline {
	return FlowBaseline{
		FlowID:            "rate-flow",
		MaxPerWindow:      3,
		RateWindowSeconds: 60,
		Steps: []FlowStep{
			{StepID: "login", EndpointKey: "POST /v1/login", Sequence: 1},
			{StepID: "query", EndpointKey: "GET /v1/orders", Sequence: 2, MaxPerWindow: 2, RateWindowSeconds: 60},
		},
	}
}

// testFlowCancelBaseline 取消语义基线：cancel 步骤声明 cancels_flow。
func testFlowCancelBaseline() FlowBaseline {
	return FlowBaseline{
		FlowID: "cancel-flow",
		Steps: []FlowStep{
			{StepID: "create", EndpointKey: "POST /v1/orders", Sequence: 1},
			{StepID: "pay", EndpointKey: "POST /v1/orders/pay", Sequence: 2},
			{StepID: "cancel", EndpointKey: "POST /v1/orders/cancel", Sequence: 3, CancelsFlow: true},
		},
	}
}

func TestValidateFlowBaselinesRateFields(t *testing.T) {
	if err := ValidateFlowBaselines([]FlowBaseline{testFlowRateBaseline()}); err != nil {
		t.Fatalf("valid rate baseline rejected: %v", err)
	}
	if err := ValidateFlowBaselines([]FlowBaseline{testFlowCancelBaseline()}); err != nil {
		t.Fatalf("valid cancel baseline rejected: %v", err)
	}
	cases := []struct {
		name string
		b    FlowBaseline
	}{
		{"negative flow max", FlowBaseline{FlowID: "f", MaxPerWindow: -1,
			Steps: []FlowStep{{StepID: "a", EndpointKey: "GET /x"}}}},
		{"negative flow window", FlowBaseline{FlowID: "f", RateWindowSeconds: -5,
			Steps: []FlowStep{{StepID: "a", EndpointKey: "GET /x"}}}},
		{"flow window beyond TTL", FlowBaseline{FlowID: "f", MaxPerWindow: 10, RateWindowSeconds: int(FlowSessionTTL/time.Second) + 60,
			Steps: []FlowStep{{StepID: "a", EndpointKey: "GET /x"}}}},
		{"negative step max", FlowBaseline{FlowID: "f",
			Steps: []FlowStep{{StepID: "a", EndpointKey: "GET /x", MaxPerWindow: -2}}}},
		{"step window beyond TTL", FlowBaseline{FlowID: "f",
			Steps: []FlowStep{{StepID: "a", EndpointKey: "GET /x", MaxPerWindow: 1, RateWindowSeconds: int(FlowSessionTTL/time.Second) + 1}}}},
	}
	for _, tc := range cases {
		err := ValidateFlowBaselines([]FlowBaseline{tc.b})
		if err == nil {
			t.Fatalf("%s: expected error", tc.name)
		}
		if fe, ok := err.(*FlowConfigError); !ok || fe.Reason == "" {
			t.Fatalf("%s: error type %T reason empty", tc.name, err)
		}
	}
	// 声明窗口但未声明上限（max=0）不启用判定，窗口长度不校验为错误
	b := FlowBaseline{FlowID: "f", RateWindowSeconds: int(FlowSessionTTL/time.Second) + 60,
		Steps: []FlowStep{{StepID: "a", EndpointKey: "GET /x"}}}
	if err := ValidateFlowBaselines([]FlowBaseline{b}); err != nil {
		t.Fatalf("window without max must not error: %v", err)
	}
}

func TestFlowSessionTrackerRateAndCancel(t *testing.T) {
	base := time.Now()
	clock := base
	tr := newFlowSessionTracker(100, func() time.Time { return clock })

	// 未声明窗口：计数恒 0（不判定）
	s0 := tr.Observe("k", FlowObservation{StepID: "a", Sequence: 1})
	if s0.StepWindowCount != 0 || s0.FlowWindowCount != 0 {
		t.Fatalf("undeclared window must not count: %+v", s0)
	}
	// 步骤级窗口：窗口内累计（含本次）
	s1 := tr.Observe("k", FlowObservation{StepID: "a", Sequence: 1, StepRateWindow: time.Minute})
	s2 := tr.Observe("k", FlowObservation{StepID: "a", Sequence: 1, StepRateWindow: time.Minute})
	if s1.StepWindowCount != 1 || s2.StepWindowCount != 2 {
		t.Fatalf("step window count wrong: %d %d", s1.StepWindowCount, s2.StepWindowCount)
	}
	// 出窗后计数重置为 1
	clock = base.Add(2 * time.Minute)
	s3 := tr.Observe("k", FlowObservation{StepID: "a", Sequence: 1, StepRateWindow: time.Minute})
	if s3.StepWindowCount != 1 {
		t.Fatalf("post-window step count=%d, want 1", s3.StepWindowCount)
	}
	// 流程级窗口跨步骤累计
	s4 := tr.Observe("k", FlowObservation{StepID: "b", Sequence: 2, FlowRateWindow: time.Minute})
	s5 := tr.Observe("k", FlowObservation{StepID: "a", Sequence: 1, FlowRateWindow: time.Minute})
	if s4.FlowWindowCount < 1 || s5.FlowWindowCount != s4.FlowWindowCount+1 {
		t.Fatalf("flow window count wrong: %d %d", s4.FlowWindowCount, s5.FlowWindowCount)
	}
	// 取消语义：记录前快照不粘，记录后粘
	s6 := tr.Observe("k", FlowObservation{StepID: "cancel", Sequence: 3, CancelsFlow: true})
	if s6.CancelledBefore || s6.CancelledBy != "" {
		t.Fatalf("cancel step itself must not be flagged: %+v", s6)
	}
	s7 := tr.Observe("k", FlowObservation{StepID: "a", Sequence: 1})
	if !s7.CancelledBefore || s7.CancelledBy != "cancel" {
		t.Fatalf("post-cancel snapshot wrong: %+v", s7)
	}
	// 会话空闲 TTL 重置：取消标记清除
	clock = clock.Add(FlowSessionTTL + time.Minute)
	s8 := tr.Observe("k", FlowObservation{StepID: "a", Sequence: 1})
	if s8.CancelledBefore {
		t.Fatalf("TTL reset must clear cancellation: %+v", s8)
	}
}

func TestFlowSessionTrackerRateBounds(t *testing.T) {
	tr := newFlowSessionTracker(10, nil)
	// 时间戳环定容：超长淘汰最旧
	for i := 0; i < flowMaxStepEvents+10; i++ {
		tr.Observe("s", FlowObservation{StepID: "a", Sequence: 1, StepRateWindow: FlowSessionTTL, FlowRateWindow: FlowSessionTTL})
	}
	e := tr.entries.items["s"].Value.(lruItem).val.(*flowSessionEntry)
	if len(e.flowEvents) > flowMaxStepEvents {
		t.Fatalf("flow ring cap broken: %d", len(e.flowEvents))
	}
	if len(e.stepEvents["a"]) > flowMaxStepEvents {
		t.Fatalf("step ring cap broken: %d", len(e.stepEvents["a"]))
	}
	// 步骤时间戳键槽定容：满后新步骤不建槽（StepWindowCount 恒 0 = 不判定）
	big := newFlowSessionTracker(10, nil)
	for i := 0; i < flowMaxSeenSteps+5; i++ {
		big.Observe("s2", FlowObservation{StepID: "step-" + string(rune(i)), Sequence: i, StepRateWindow: time.Minute})
	}
	e2 := big.entries.items["s2"].Value.(lruItem).val.(*flowSessionEntry)
	if len(e2.stepEvents) > flowMaxSeenSteps {
		t.Fatalf("step events key cap broken: %d", len(e2.stepEvents))
	}
}

// flowSeq 共享会话存储依次执行若干步骤观测，返回每次的匹配集合。
func flowSeq(t *testing.T, id string, b FlowBaseline, calls ...struct {
	method, target, ek string
}) []map[string]bool {
	t.Helper()
	stores := &StoreOverrides{FlowSession: NewMemoryFlowSessionStore(0, nil)}
	out := make([]map[string]bool, 0, len(calls))
	for _, c := range calls {
		ctx, r := flowReq(t, c.method, c.target, "", nil)
		ctx.BindDetectorStoreOverrides(stores)
		CheckFlowDeviation(ctx, r, id, c.ek, "", []FlowBaseline{b})
		out = append(out, flowRules(ctx))
	}
	return out
}

func TestCheckFlowDeviationRapidBatchStep(t *testing.T) {
	call := struct{ method, target, ek string }{http.MethodGet, "http://h/v1/orders", "GET /v1/orders"}
	rules := flowSeq(t, "auth:rate", testFlowRateBaseline(), call, call, call, call)
	// 步骤级上限 2：第 1/2 次干净，第 3 次起命中（scope=step）
	if rules[0]["flow.rapid_batch"] || rules[1]["flow.rapid_batch"] {
		t.Fatalf("first two calls within limit must be clean: %v %v", rules[0], rules[1])
	}
	if !rules[2]["flow.rapid_batch"] || !rules[3]["flow.rapid_batch"] {
		t.Fatalf("3rd/4th calls must flag rapid_batch: %v %v", rules[2], rules[3])
	}
}

func TestCheckFlowDeviationRapidBatchStepEvidence(t *testing.T) {
	stores := &StoreOverrides{FlowSession: NewMemoryFlowSessionStore(0, nil)}
	for i := 0; i < 3; i++ {
		ctx, r := flowReq(t, http.MethodGet, "http://h/v1/orders", "", nil)
		ctx.BindDetectorStoreOverrides(stores)
		CheckFlowDeviation(ctx, r, "auth:rate-ev", "GET /v1/orders", "", []FlowBaseline{testFlowRateBaseline()})
		if i < 2 {
			continue
		}
		found := false
		for _, m := range ctx.CopyMatches() {
			if m.RuleID != "flow.rapid_batch" {
				continue
			}
			found = true
			if m.Category != "OBSERVE" || m.Severity != "MEDIUM" || m.Detector != "api_flow" {
				t.Fatalf("rapid_batch attrs wrong: %+v", m)
			}
			if m.Evidence["scope"] != "step" || m.Evidence["limit"] != "2" ||
				m.Evidence["count"] != "3" || m.Evidence["window"] != "60s" {
				t.Fatalf("rapid_batch evidence wrong: %+v", m.Evidence)
			}
		}
		if !found {
			t.Fatal("expected step-scope rapid_batch on 3rd call")
		}
	}
}

func TestCheckFlowDeviationRapidBatchFlow(t *testing.T) {
	// 流程级上限 3：login/query 交替，第 4 次命中 scope=flow（单步均未超步骤级上限）
	login := struct{ method, target, ek string }{http.MethodPost, "http://h/v1/login", "POST /v1/login"}
	query := struct{ method, target, ek string }{http.MethodGet, "http://h/v1/orders", "GET /v1/orders"}
	rules := flowSeq(t, "auth:rateflow", testFlowRateBaseline(), login, query, login, query)
	if rules[3]["flow.rapid_batch"] != true {
		t.Fatalf("4th call must flag flow-scope rapid_batch: %v", rules[3])
	}
	stores := &StoreOverrides{FlowSession: NewMemoryFlowSessionStore(0, nil)}
	var last *dsctx.RequestContext
	for _, c := range []struct{ method, target, ek string }{login, query, login, query} {
		ctx, r := flowReq(t, c.method, c.target, "", nil)
		ctx.BindDetectorStoreOverrides(stores)
		CheckFlowDeviation(ctx, r, "auth:rateflow2", c.ek, "", []FlowBaseline{testFlowRateBaseline()})
		last = ctx
	}
	for _, m := range last.CopyMatches() {
		if m.RuleID == "flow.rapid_batch" && m.Evidence["scope"] != "flow" {
			t.Fatalf("expected flow scope only, got %+v", m.Evidence)
		}
	}
}

func TestCheckFlowDeviationRapidBatchDisabled(t *testing.T) {
	// 基线未声明任何 max_per_window（旧基线口径）：高频调用零行为
	call := struct{ method, target, ek string }{http.MethodGet, "http://h/v1/orders", "GET /v1/orders"}
	calls := make([]struct{ method, target, ek string }, 0, 10)
	for i := 0; i < 10; i++ {
		calls = append(calls, call)
	}
	for i, rules := range flowSeq(t, "auth:norate", testFlowBaseline(), calls...) {
		if rules["flow.rapid_batch"] {
			t.Fatalf("call %d: undeclared max_per_window must not judge", i)
		}
	}
}

func TestCheckFlowDeviationPostCancel(t *testing.T) {
	create := struct{ method, target, ek string }{http.MethodPost, "http://h/v1/orders", "POST /v1/orders"}
	pay := struct{ method, target, ek string }{http.MethodPost, "http://h/v1/orders/pay", "POST /v1/orders/pay"}
	cancel := struct{ method, target, ek string }{http.MethodPost, "http://h/v1/orders/cancel", "POST /v1/orders/cancel"}
	rules := flowSeq(t, "auth:cancel", testFlowCancelBaseline(), create, cancel, pay)
	if rules[0]["flow.post_cancel_operation"] {
		t.Fatal("pre-cancel step must not flag")
	}
	if rules[1]["flow.post_cancel_operation"] {
		t.Fatal("cancel step itself must not flag")
	}
	if !rules[2]["flow.post_cancel_operation"] {
		t.Fatalf("post-cancel step must flag: %v", rules[2])
	}
	// 证据含取消步骤标识
	stores := &StoreOverrides{FlowSession: NewMemoryFlowSessionStore(0, nil)}
	for _, c := range []struct{ method, target, ek string }{cancel, pay} {
		ctx, r := flowReq(t, c.method, c.target, "", nil)
		ctx.BindDetectorStoreOverrides(stores)
		CheckFlowDeviation(ctx, r, "auth:cancel-ev", c.ek, "", []FlowBaseline{testFlowCancelBaseline()})
		for _, m := range ctx.CopyMatches() {
			if m.RuleID == "flow.post_cancel_operation" {
				if m.Category != "OBSERVE" || m.Severity != "HIGH" {
					t.Fatalf("post_cancel attrs wrong: %+v", m)
				}
				if m.Evidence["cancelled_by"] != "cancel" || m.Evidence["flow_id"] != "cancel-flow" {
					t.Fatalf("post_cancel evidence wrong: %+v", m.Evidence)
				}
			}
		}
	}
}

func TestCheckFlowDeviationPostCancelUndeclared(t *testing.T) {
	// 基线无 cancels_flow 声明：任意步骤序列均不判定（不编造取消语义）
	create := struct{ method, target, ek string }{http.MethodPost, "http://h/v1/orders", "POST /v1/orders"}
	pay := struct{ method, target, ek string }{http.MethodPost, "http://h/v1/orders/pay", "POST /v1/orders/pay"}
	cancel := struct{ method, target, ek string }{http.MethodPost, "http://h/v1/orders/cancel", "POST /v1/orders/cancel"}
	noDecl := testFlowCancelBaseline()
	noDecl.Steps[2].CancelsFlow = false
	for i, rules := range flowSeq(t, "auth:nocancel", noDecl, create, cancel, pay) {
		if rules["flow.post_cancel_operation"] {
			t.Fatalf("call %d: undeclared cancel semantics must not judge", i)
		}
	}
}

func TestCheckFlowDeviationAnonymousLateEntry(t *testing.T) {
	stores := &StoreOverrides{FlowSession: NewMemoryFlowSessionStore(0, nil)}
	// 匿名（ip: 回退）直达后置步骤 query（seq2，前置 login 缺失）：
	// 只产出 anonymous_late_entry，抑制 step_skip（去重口径）
	ctx, r := flowReq(t, http.MethodGet, "http://h/v1/orders", "", nil)
	ctx.BindDetectorStoreOverrides(stores)
	CheckFlowDeviation(ctx, r, "ip:10.0.0.9", "GET /v1/orders", "", []FlowBaseline{testFlowBaseline()})
	rules := flowRules(ctx)
	if !rules["flow.anonymous_late_entry"] {
		t.Fatalf("expected anonymous_late_entry, got %v", rules)
	}
	if rules["flow.step_skip"] {
		t.Fatalf("step_skip must be suppressed when anonymous_late_entry fires: %v", rules)
	}
	for _, m := range ctx.CopyMatches() {
		if m.RuleID == "flow.anonymous_late_entry" {
			if m.Category != "OBSERVE" || m.Severity != "HIGH" || m.Detector != "api_flow" {
				t.Fatalf("anonymous_late_entry attrs wrong: %+v", m)
			}
			if m.Evidence["sequence"] != "2" || m.Evidence["min_sequence"] != "1" {
				t.Fatalf("anonymous_late_entry evidence wrong: %+v", m.Evidence)
			}
		}
	}
	// unknown 身份同样匿名
	ctxU, rU := flowReq(t, http.MethodGet, "http://h/v1/orders", "", nil)
	ctxU.BindDetectorStoreOverrides(stores)
	CheckFlowDeviation(ctxU, rU, "unknown", "GET /v1/orders", "", []FlowBaseline{testFlowBaseline()})
	if !flowRules(ctxU)["flow.anonymous_late_entry"] {
		t.Fatal("unknown identity must be anonymous")
	}
	// 匿名命中首步（login seq1，流程最小序号）：不判
	ctxF, rF := flowReq(t, http.MethodPost, "http://h/v1/login", "", nil)
	ctxF.BindDetectorStoreOverrides(stores)
	CheckFlowDeviation(ctxF, rF, "ip:10.0.0.9", "POST /v1/login", "", []FlowBaseline{testFlowBaseline()})
	if flowRules(ctxF)["flow.anonymous_late_entry"] {
		t.Fatal("first step must not flag anonymous_late_entry")
	}
	// 已登录主体（auth:/key:/sess:）直达后置步骤：不判匿名，step_skip 照常
	for _, id := range []string{"auth:x1", "key:k1", "sess:s1"} {
		ctxA, rA := flowReq(t, http.MethodGet, "http://h/v1/orders", "", nil)
		ctxA.BindDetectorStoreOverrides(&StoreOverrides{FlowSession: NewMemoryFlowSessionStore(0, nil)})
		CheckFlowDeviation(ctxA, rA, id, "GET /v1/orders", "", []FlowBaseline{testFlowBaseline()})
		rulesA := flowRules(ctxA)
		if rulesA["flow.anonymous_late_entry"] {
			t.Fatalf("%s: credentialed identity must not flag anonymous_late_entry", id)
		}
		if !rulesA["flow.step_skip"] {
			t.Fatalf("%s: credentialed skip must still flag step_skip", id)
		}
	}
}
