// flow_baselines_test.go 流程基线下发单测（§44，纯 fake，不依赖数据库）：
// 表缺失容忍（Warn 跳过）、未注入零行为、真实错误 fail-hard、正常读取透传、
// api_policy_version 纳入流程基线段。
package guardconfig

import (
	"context"
	"errors"
	"testing"

	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// fakeFlowBaselineLister 内存版流程基线读取（可注入错误路径）。
type fakeFlowBaselineLister struct {
	flows []gatewayconfig.GuardFlowBaseline
	err   error
}

func (f *fakeFlowBaselineLister) ListEnabledFlowBaselines(ctx context.Context) ([]gatewayconfig.GuardFlowBaseline, error) {
	_ = ctx
	return f.flows, f.err
}

func testFlowBaselines() []gatewayconfig.GuardFlowBaseline {
	return []gatewayconfig.GuardFlowBaseline{{
		FlowID: "checkout", MaxPerWindow: 5, RateWindowSeconds: 30,
		Steps: []gatewayconfig.GuardFlowStep{
			{StepID: "browse", EndpointKey: "GET /v1/items", Sequence: 1, Predecessors: []string{}},
			{StepID: "pay", EndpointKey: "POST /v1/orders/{id}/pay", Sequence: 2,
				Predecessors: []string{"browse"}, Terminal: true, StateFrom: "CREATED", StateTo: "PAID",
				MaxPerWindow: 2, RateWindowSeconds: 10, CancelsFlow: true},
		},
	}}
}

// TestLoadAPIFlowBaselinesTolerance 流程基线：未注入 nil；表缺失 Warn 跳过返回 nil；
// 真实查询错误 fail-hard；空结果不下发；正常读取透传。
func TestLoadAPIFlowBaselinesTolerance(t *testing.T) {
	// 未注入
	p := &Provider{}
	if got := p.loadAPIFlowBaselines(context.Background()); got != nil {
		t.Fatalf("nil lister must yield nil: %v", got)
	}
	// 表不存在 → 容忍跳过
	p = &Provider{flowBaselines: &fakeFlowBaselineLister{err: errors.New(`relation "api_flow_baseline_steps" does not exist`)}}
	if got := p.loadAPIFlowBaselines(context.Background()); got != nil {
		t.Fatalf("missing table must be tolerated: %v", got)
	}
	// 真实查询错误 → fail-hard（不静默发布为空策略）
	p = &Provider{flowBaselines: &fakeFlowBaselineLister{err: errors.New("connection refused")}}
	if _, err := p.loadAPIFlowBaselinesStrict(context.Background()); err == nil {
		t.Fatal("real query error must abort candidate publication")
	}
	// 空结果 → 不下发
	p = &Provider{flowBaselines: &fakeFlowBaselineLister{flows: []gatewayconfig.GuardFlowBaseline{}}}
	if got := p.loadAPIFlowBaselines(context.Background()); got != nil {
		t.Fatalf("empty baselines must yield nil: %v", got)
	}
	// 正常读取
	p = &Provider{flowBaselines: &fakeFlowBaselineLister{flows: testFlowBaselines()}}
	got := p.loadAPIFlowBaselines(context.Background())
	if len(got) != 1 || got[0].FlowID != "checkout" || len(got[0].Steps) != 2 ||
		got[0].Steps[1].Predecessors[0] != "browse" || got[0].Steps[1].StateTo != "PAID" ||
		got[0].MaxPerWindow != 5 || got[0].Steps[1].CancelsFlow != true {
		t.Fatalf("baselines = %+v", got)
	}
}

// TestComputeAPIPolicyVersionFlow 版本戳纳入流程基线段：内容变更即变；缺省（nil/空）零变化。
func TestComputeAPIPolicyVersionFlow(t *testing.T) {
	schemas := map[string]map[string]string{"POST /v1/orders": {"amount": "number"}}

	base := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{APIFormalSchemas: schemas})
	withFlows := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{
		APIFormalSchemas: schemas, APIFlowBaselines: testFlowBaselines()})
	if withFlows == base {
		t.Fatal("flow baselines must be part of policy version")
	}
	// 同内容恒同（确定性）
	if v := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{
		APIFormalSchemas: schemas, APIFlowBaselines: testFlowBaselines()}); v != withFlows {
		t.Fatalf("same content must yield same version: %s != %s", v, withFlows)
	}
	// 基线内容变更（state_to 翻转）→ 版本变化
	changed := testFlowBaselines()
	changed[0].Steps[1].StateTo = "CANCELLED"
	if v := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{
		APIFormalSchemas: schemas, APIFlowBaselines: changed}); v == withFlows {
		t.Fatal("flow baseline content change must change version")
	}
	// 批量执行/取消语义字段变更（cancels_flow / max_per_window 翻转）→ 版本变化
	cancelFlip := testFlowBaselines()
	cancelFlip[0].Steps[1].CancelsFlow = false
	if v := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{
		APIFormalSchemas: schemas, APIFlowBaselines: cancelFlip}); v == withFlows {
		t.Fatal("cancels_flow change must change version")
	}
	maxFlip := testFlowBaselines()
	maxFlip[0].MaxPerWindow = 0
	if v := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{
		APIFormalSchemas: schemas, APIFlowBaselines: maxFlip}); v == withFlows {
		t.Fatal("flow-level max_per_window change must change version")
	}
	// 空切片与 nil 等价（omitempty 缺省零变化，与既有版本逐字节一致）
	if v := computeAPIPolicyVersion(&gatewayconfig.GuardConfig{
		APIFormalSchemas: schemas, APIFlowBaselines: []gatewayconfig.GuardFlowBaseline{}}); v != base {
		t.Fatal("empty flow baselines must not change version")
	}
}
