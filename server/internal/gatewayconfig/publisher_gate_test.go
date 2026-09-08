// publisher_gate_test.go 安全回归发布门禁挂接单元测试（WDSP P1-04 R3）：
// 未装配放行；放行结论继续发布；拒绝/依赖不可用映射为不同失败码；
// 恢复通道标志透传。
package gatewayconfig

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

type fakeRegressionGate struct {
	outcome  RegressionGateOutcome
	gotInput *RegressionGateInput
}

func (f *fakeRegressionGate) EvaluatePublish(_ context.Context, in RegressionGateInput) RegressionGateOutcome {
	f.gotInput = &in
	return f.outcome
}

func TestRegressionGateNilAllows(t *testing.T) {
	p := &Publisher{}
	ok, code, msg := p.evaluateRegressionGate(context.Background(), uuid.New(), uuid.New(), "cfgfpv1:abc", false)
	if !ok || code != "" || msg != "" {
		t.Fatalf("nil gate should allow, got ok=%t code=%s", ok, code)
	}
}

func TestRegressionGateAllowedContinues(t *testing.T) {
	p := &Publisher{}
	g := &fakeRegressionGate{outcome: RegressionGateOutcome{Allowed: true}}
	p.SetRegressionGate(g)
	taskID, versionID := uuid.New(), uuid.New()
	ok, _, _ := p.evaluateRegressionGate(context.Background(), taskID, versionID, "cfgfpv1:abc", true)
	if !ok {
		t.Fatal("allowed outcome blocked")
	}
	if g.gotInput == nil || g.gotInput.TaskID != taskID || g.gotInput.VersionID != versionID ||
		g.gotInput.Fingerprint != "cfgfpv1:abc" || !g.gotInput.RestoreChannel {
		t.Fatalf("gate input not passed through: %+v", g.gotInput)
	}
}

func TestRegressionGateRejectedMapsCode(t *testing.T) {
	p := &Publisher{}
	p.SetRegressionGate(&fakeRegressionGate{outcome: RegressionGateOutcome{
		Allowed: false, Message: "缺少绑定当前候选指纹的证据"}})
	ok, code, msg := p.evaluateRegressionGate(context.Background(), uuid.New(), uuid.New(), "cfgfpv1:abc", false)
	if ok || code != "REGRESSION_GATE_REJECTED" {
		t.Fatalf("rejected outcome: ok=%t code=%s", ok, code)
	}
	if msg == "" {
		t.Fatal("rejection message empty")
	}
}

func TestRegressionGateUnavailableMapsCode(t *testing.T) {
	p := &Publisher{}
	p.SetRegressionGate(&fakeRegressionGate{outcome: RegressionGateOutcome{
		Allowed: false, Unavailable: true, Message: "db down"}})
	ok, code, msg := p.evaluateRegressionGate(context.Background(), uuid.New(), uuid.New(), "cfgfpv1:abc", false)
	if ok || code != "REGRESSION_GATE_UNAVAILABLE" {
		t.Fatalf("unavailable outcome: ok=%t code=%s", ok, code)
	}
	if msg == "" {
		t.Fatal("unavailable message empty")
	}
}
