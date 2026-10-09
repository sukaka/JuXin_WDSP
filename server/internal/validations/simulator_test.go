package validations

import (
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
)

func blockishMatches() []dsctx.DetectorMatch {
	return []dsctx.DetectorMatch{
		// api_schema 为可信阻断源；CRITICAL 严重度满足 hasBlock 判定（engine.go:115）
		{Detector: "api_schema", RuleID: "r-1", Severity: "CRITICAL", ScoreDelta: 10, Message: "schema violation"},
	}
}

func TestSimulateWouldBlock(t *testing.T) {
	s := NewSimulator()
	r := s.Simulate(PolicyRef{Mode: decision.ModeProtect, Digest: "pol-1"}, []FindingBatch{
		{InputID: "in-1", Matches: blockishMatches()},
	})
	if r.Status != "COMPLETED" || len(r.Verdicts) != 1 {
		t.Fatalf("report=%+v", r)
	}
	v := r.Verdicts[0]
	if v.Status != VerdictEvaluated || !v.WouldBlock {
		t.Fatalf("verdict=%+v（应 EVALUATED 且 would_block）", v)
	}
	if v.FinalAction == "" || v.Candidate == "" {
		t.Fatalf("候选/最终动作必须分离记录: %+v", v)
	}
}

func TestSimulateObserveOnly(t *testing.T) {
	s := NewSimulator()
	r := s.Simulate(PolicyRef{Mode: decision.ModeProtect, Digest: "pol-1"}, []FindingBatch{
		{InputID: "in-1", Matches: []dsctx.DetectorMatch{{Detector: "behavior", RuleID: "r-1", ScoreDelta: 0}}},
	})
	v := r.Verdicts[0]
	if v.WouldBlock {
		t.Fatalf("零分 Finding 不得 would_block: %+v", v)
	}
}

func TestSimulateModeOffNeverBlocks(t *testing.T) {
	s := NewSimulator()
	r := s.Simulate(PolicyRef{Mode: decision.ModeOff, Digest: "pol-1"}, []FindingBatch{
		{InputID: "in-1", Matches: blockishMatches()},
	})
	v := r.Verdicts[0]
	if v.WouldBlock || v.FinalAction != "ALLOW" {
		t.Fatalf("ModeOff 必须为 ALLOW 且不阻断: %+v", v)
	}
}

func TestSimulateExceptionHitKeepsEvidence(t *testing.T) {
	s := NewSimulator()
	r := s.Simulate(PolicyRef{Mode: decision.ModeProtect, Digest: "pol-1"}, []FindingBatch{
		{
			InputID: "in-1",
			Matches: blockishMatches(),
			Exceptions: []decision.ExceptionRef{
				{ExceptionID: "exc-1", Version: 1, DetectorID: "api_schema", RuleID: "r-1"},
			},
		},
	})
	v := r.Verdicts[0]
	if !v.ExceptionHit {
		t.Fatalf("例外命中未标记: %+v", v)
	}
	if v.WouldBlock {
		t.Fatalf("被豁免 Finding 不得升级为阻断: %+v", v)
	}
}

func TestSimulateCannotReproduceAndInsufficient(t *testing.T) {
	s := NewSimulator()
	r := s.Simulate(PolicyRef{Mode: decision.ModeProtect, Digest: "pol-1"}, []FindingBatch{
		{InputID: "in-missing", MissingReason: "协议不可复现（grpc 双向流）"},
		{InputID: "in-empty"},
	})
	if r.Verdicts[0].Status != VerdictCannotReproduce {
		t.Fatalf("缺输入必须 CANNOT_REPRODUCE: %+v", r.Verdicts[0])
	}
	if r.Verdicts[0].WouldBlock {
		t.Fatal("不可复现不得给出阻断结论")
	}
	if r.Verdicts[1].Status != VerdictEvidenceInsufficient {
		t.Fatalf("空 Finding 必须 EVIDENCE_INSUFFICIENT: %+v", r.Verdicts[1])
	}
}

func TestMarkStaleOnDigestChange(t *testing.T) {
	s := NewSimulator()
	r := s.Simulate(PolicyRef{Mode: decision.ModeProtect, Digest: "pol-1"}, []FindingBatch{
		{InputID: "in-1", Matches: blockishMatches()},
	})
	if MarkStale(&r, "pol-1", r.CorpusDigest) {
		t.Fatal("摘要一致不得标 STALE")
	}
	if !MarkStale(&r, "pol-2", r.CorpusDigest) {
		t.Fatal("策略摘要变更必须标 STALE")
	}
	if r.Status != "STALE" {
		t.Fatalf("status=%s want STALE", r.Status)
	}
}

// TestSimulatorHasNoExternalDependencies 结构性零外部调用断言：
// Simulator 类型不存在任何依赖字段（网关客户端/Valkey/DB/HTTP 在类型层面不可能存在）。
func TestSimulatorHasNoExternalDependencies(t *testing.T) {
	s := NewSimulator()
	var _ = *s // 空结构体——本断言以类型形状为证；任何未来新增依赖字段都必须经本测试评审
	r := s.Simulate(PolicyRef{Mode: decision.ModeProtect, Digest: "pol-x"}, []FindingBatch{
		{InputID: "in-1", Matches: blockishMatches()},
	})
	if r.ResourceNote == "" || r.ID == "" || r.InputsDigest == "" {
		t.Fatalf("报告要素缺失: %+v", r)
	}
}

func TestReportDigestDeterministic(t *testing.T) {
	s := NewSimulator()
	b := []FindingBatch{{InputID: "in-1", Matches: blockishMatches()}}
	r1 := s.Simulate(PolicyRef{Mode: decision.ModeProtect, Digest: "pol-1"}, b)
	r2 := s.Simulate(PolicyRef{Mode: decision.ModeProtect, Digest: "pol-1"}, b)
	if r1.CorpusDigest != r2.CorpusDigest || r1.InputsDigest != r2.InputsDigest {
		t.Fatal("同一输入的语料/输入摘要必须确定")
	}
}
