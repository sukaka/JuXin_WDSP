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

func TestRollbackRegressionGateHashesReinjectedCandidateAndUsesRecoveryChannel(t *testing.T) {
	p := &Publisher{}
	g := &fakeRegressionGate{outcome: RegressionGateOutcome{Allowed: true}}
	p.SetRegressionGate(g)
	taskID, versionID := uuid.New(), uuid.New()
	ok, code, msg := p.evaluateRollbackRegressionGate(context.Background(), taskID, versionID, `{"servers":{}}`)
	if !ok || code != "" || msg != "" {
		t.Fatalf("rollback gate should allow: ok=%t code=%s msg=%s", ok, code, msg)
	}
	if g.gotInput == nil || !g.gotInput.RestoreChannel || g.gotInput.TaskID != taskID || g.gotInput.VersionID != versionID {
		t.Fatalf("rollback gate input missing recovery channel or ids: %+v", g.gotInput)
	}
	want, err := CanonicalConfigHash(`{"servers":{}}`)
	if err != nil {
		t.Fatalf("hash candidate: %v", err)
	}
	if g.gotInput.Fingerprint != "cfgfpv1:"+want {
		t.Fatalf("fingerprint = %q, want cfgfpv1:%s", g.gotInput.Fingerprint, want)
	}
}

func TestRollbackRegressionGateRejectsInvalidCandidateBeforeLoad(t *testing.T) {
	p := &Publisher{}
	ok, code, msg := p.evaluateRollbackRegressionGate(context.Background(), uuid.New(), uuid.New(), "not-json")
	if ok || code != "ROLLBACK_CONFIG_HASH_FAILED" || msg == "" {
		t.Fatalf("invalid rollback candidate: ok=%t code=%s msg=%s", ok, code, msg)
	}
}
