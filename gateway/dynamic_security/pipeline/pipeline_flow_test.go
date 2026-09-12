// pipeline_flow_test.go 业务流程偏离经统一管线生效（§44）：基线未到零行为；
// 四类 OBSERVE 级信号经管线产出且任何模式不定案阻断；Stores 注入会话存储生效。
package pipeline

import (
	"net/http"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

func flowTestBaseline() []detectors.FlowBaseline {
	return []detectors.FlowBaseline{{
		FlowID: "pipe-flow",
		Steps: []detectors.FlowStep{
			{StepID: "login", EndpointKey: "POST /v1/login", Sequence: 1},
			{StepID: "submit", EndpointKey: "POST /v1/submit", Sequence: 2, Predecessors: []string{"login"}},
		},
	}}
}

func flowPipeReq(t *testing.T, method, target, token string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(method, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	return r
}

func flowStores() *detectors.StoreOverrides {
	return &detectors.StoreOverrides{FlowSession: detectors.NewMemoryFlowSessionStore(0, nil)}
}

// 基线未到（nil）零行为：同样流量不产出任何 flow.* 明细。
func TestProcessFlowBaselineAbsent(t *testing.T) {
	res, err := Process(flowPipeReq(t, http.MethodPost, "http://h/v1/submit", "tok-absent"),
		Config{Enabled: true, Mode: "PROTECT"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range res.Context.CopyMatches() {
		if m.Detector == "api_flow" {
			t.Fatalf("no baseline must be zero behavior: %+v", m)
		}
	}
}

// 跳过前置步骤：未见 login 直达 submit → flow.step_skip（OBSERVE 级，PROTECT 也不阻断）。
func TestProcessFlowStepSkip(t *testing.T) {
	cfg := Config{Enabled: true, Mode: "PROTECT", FlowBaselines: flowTestBaseline(), Stores: flowStores()}
	res, err := Process(flowPipeReq(t, http.MethodPost, "http://h/v1/submit", "tok-skip"), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(res, "flow.step_skip") {
		t.Fatalf("expected flow.step_skip, got %+v", res.Context.CopyMatches())
	}
	if res.FinalAction == dsctx.ActionBlock {
		t.Fatalf("OBSERVE-level flow finding must not block, final=%s", res.FinalAction)
	}
	// 同主体按序走完两步 → 零流程 Finding
	res1, err := Process(flowPipeReq(t, http.MethodPost, "http://h/v1/login", "tok-ok"), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	res2, err := Process(flowPipeReq(t, http.MethodPost, "http://h/v1/submit", "tok-ok"), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []*Result{res1, res2} {
		for _, m := range r.Context.CopyMatches() {
			if m.Detector == "api_flow" {
				t.Fatalf("ordered flow must be clean: %+v", m)
			}
		}
	}
}

// 逆序调用：submit(seq2) 先达，login(seq1) 后到 → flow.out_of_order。
func TestProcessFlowOutOfOrder(t *testing.T) {
	cfg := Config{Enabled: true, Mode: "OBSERVE", FlowBaselines: flowTestBaseline(), Stores: flowStores()}
	if _, err := Process(flowPipeReq(t, http.MethodPost, "http://h/v1/submit", "tok-ooo"), cfg, nil); err != nil {
		t.Fatal(err)
	}
	res, err := Process(flowPipeReq(t, http.MethodPost, "http://h/v1/login", "tok-ooo"), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(res, "flow.out_of_order") {
		t.Fatalf("expected flow.out_of_order, got %+v", res.Context.CopyMatches())
	}
	if res.FinalAction == dsctx.ActionBlock {
		t.Fatalf("flow findings must not block in any mode, final=%s", res.FinalAction)
	}
}

// 重复提交：同主体同幂等键短窗内两次 POST → flow.duplicate_submit；明文键不入证据。
func TestProcessFlowDuplicateSubmit(t *testing.T) {
	cfg := Config{Enabled: true, Mode: "PROTECT", FlowBaselines: flowTestBaseline(), Stores: flowStores()}
	mk := func() *http.Request {
		r := flowPipeReq(t, http.MethodPost, "http://h/v1/submit", "tok-dup")
		r.Header.Set("Idempotency-Key", "RAW-IDEM-KEY-999")
		return r
	}
	if _, err := Process(mk(), cfg, nil); err != nil {
		t.Fatal(err)
	}
	res, err := Process(mk(), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(res, "flow.duplicate_submit") {
		t.Fatalf("expected flow.duplicate_submit, got %+v", res.Context.CopyMatches())
	}
	for _, m := range res.Context.CopyMatches() {
		for _, v := range m.Evidence {
			if v == "RAW-IDEM-KEY-999" {
				t.Fatalf("raw idempotency key leaked into evidence: %+v", m.Evidence)
			}
		}
	}
}

// 未授权状态转换经管线：对象状态由先序步骤 state_to 记账，非法迁移产出信号。
func TestProcessFlowIllegalStateTransition(t *testing.T) {
	baselines := []detectors.FlowBaseline{{
		FlowID: "pipe-state",
		Steps: []detectors.FlowStep{
			{StepID: "create", EndpointKey: "POST /v1/items/{id}", Sequence: 1, StateTo: "created"},
			{StepID: "approve", EndpointKey: "POST /v1/items/{id}/approve", Sequence: 2, StateFrom: "approved", StateTo: "done"},
		},
	}}
	cfg := Config{Enabled: true, Mode: "PROTECT", FlowBaselines: baselines, Stores: flowStores()}
	// create 记账对象状态 created；approve 要求 approved → 非法迁移
	if _, err := Process(flowPipeReq(t, http.MethodPost, "http://h/v1/items/42", "tok-state"), cfg, nil); err != nil {
		t.Fatal(err)
	}
	res, err := Process(flowPipeReq(t, http.MethodPost, "http://h/v1/items/42/approve", "tok-state"), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(res, "flow.illegal_state_transition") {
		t.Fatalf("expected flow.illegal_state_transition, got %+v", res.Context.CopyMatches())
	}
	for _, m := range res.Context.CopyMatches() {
		if m.RuleID == "flow.illegal_state_transition" {
			if m.Evidence["expected_state"] != "approved" || m.Evidence["observed_state"] != "created" {
				t.Fatalf("state evidence wrong: %+v", m.Evidence)
			}
		}
	}
	if res.FinalAction == dsctx.ActionBlock {
		t.Fatalf("state transition finding is OBSERVE-level, final=%s", res.FinalAction)
	}
}

// 默认内存兜底：不注入 Stores 时检测照常（进程内默认实现）。
func TestProcessFlowDefaultMemoryStore(t *testing.T) {
	cfg := Config{Enabled: true, Mode: "PROTECT", FlowBaselines: flowTestBaseline()}
	res, err := Process(flowPipeReq(t, http.MethodPost, "http://h/v1/submit", "tok-default-mem"), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(res, "flow.step_skip") {
		t.Fatalf("default memory store must drive detection: %+v", res.Context.CopyMatches())
	}
}

// 注入假存储验证 Stores 路由（含时钟注入一致性）。
type pipeFlowFakeStore struct{ calls int }

func (f *pipeFlowFakeStore) Observe(key string, o detectors.FlowObservation) detectors.FlowSessionSnapshot {
	f.calls++
	return detectors.FlowSessionSnapshot{SeenSteps: map[string]bool{o.StepID: true}}
}

func TestProcessFlowStoreOverrideRouting(t *testing.T) {
	fake := &pipeFlowFakeStore{}
	cfg := Config{Enabled: true, Mode: "PROTECT", FlowBaselines: flowTestBaseline(),
		Stores: &detectors.StoreOverrides{FlowSession: fake}}
	res, err := Process(flowPipeReq(t, http.MethodPost, "http://h/v1/submit", "tok-fake"), cfg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if fake.calls == 0 {
		t.Fatal("injected FlowSession store not used")
	}
	if !hasRule(res, "flow.step_skip") {
		t.Fatalf("injected snapshot must drive detection: %+v", res.Context.CopyMatches())
	}
}
