package coverage

import (
	"testing"
	"time"

	gwcov "github.com/jiuzhang-waf/gateway/dynamic_security/coverage"
)

var t0 = time.Date(2026, 10, 3, 12, 0, 30, 0, time.UTC)

func obs(status gwcov.Status, detector string) gwcov.Observation {
	o := gwcov.Observation{
		RequestID:     "rid",
		ApplicationID: "app-1",
		EndpointKey:   "GET /v1/users/{id}",
		Detector:      detector,
		Phase:         gwcov.PhaseRequest,
		Scope:         gwcov.ScopeDeclared{Bytes: 100, Messages: 1, Direction: "request"},
		Status:        status,
		BytesExamined: 100,
		PolicyVersion: "pol-1",
		NodeID:        "node-1",
		OccurredAt:    t0,
	}
	switch status {
	case gwcov.StatusPartial:
		o.ReasonCode = gwcov.ReasonInputTruncated
		o.Truncated = true
		o.BytesExamined = 50
	case gwcov.StatusSkipped:
		o.ReasonCode = gwcov.ReasonRuleUnselected
	case gwcov.StatusError:
		o.ReasonCode = gwcov.ReasonParseError
	case gwcov.StatusNotApplicable:
		o.ReasonCode = gwcov.ReasonNAFrozenRule
		o.NARuleID = "na/x"
	}
	return o
}

func TestAggregatorFiveStateAndE(t *testing.T) {
	a := NewAggregator(100)
	a.Add(obs(gwcov.StatusFull, "d1"))
	a.Add(obs(gwcov.StatusFull, "d1"))
	a.Add(obs(gwcov.StatusPartial, "d1"))
	a.Add(obs(gwcov.StatusSkipped, "d1"))
	a.Add(obs(gwcov.StatusError, "d1"))
	a.Add(obs(gwcov.StatusNotApplicable, "d1"))

	k := DimKey{ApplicationID: "app-1", EndpointKey: "GET /v1/users/{id}", Detector: "d1",
		Phase: "request", PolicyVersion: "pol-1", NodeID: "node-1",
		Minute: t0.Truncate(time.Minute)}
	m := a.Metrics(k)
	if m.E != 5 {
		t.Fatalf("E=%d want 5（NA 不进 E）", m.E)
	}
	if m.Bucket.NotApplicable != 1 {
		t.Fatalf("NA=%d want 1", m.Bucket.NotApplicable)
	}
	if m.NoApplicableTraffic {
		t.Fatal("E>0 不得标无适用流量")
	}
	wantFull := 2.0 / 5.0
	if m.FullRate != wantFull {
		t.Fatalf("FullRate=%v want %v", m.FullRate, wantFull)
	}
	wantEff := 3.0 / 5.0
	if m.EffectiveRate != wantEff {
		t.Fatalf("EffectiveRate=%v want %v", m.EffectiveRate, wantEff)
	}
}

func TestAggregatorZeroENoTraffic(t *testing.T) {
	a := NewAggregator(100)
	m := a.Metrics(DimKey{ApplicationID: "nope"})
	if !m.NoApplicableTraffic {
		t.Fatal("不存在的维度键必须标无适用流量（绝不显示 100%）")
	}
	if m.FullRate != 0 || m.EffectiveRate != 0 {
		t.Fatalf("零分母比率必须为 0: %+v", m)
	}
	// 只含 NA 的桶 E=0，同样标无适用流量
	a.Add(obs(gwcov.StatusNotApplicable, "d2"))
	k := DimKey{ApplicationID: "app-1", EndpointKey: "GET /v1/users/{id}", Detector: "d2",
		Phase: "request", PolicyVersion: "pol-1", NodeID: "node-1", Minute: t0.Truncate(time.Minute)}
	m2 := a.Metrics(k)
	if m2.E != 0 || !m2.NoApplicableTraffic {
		t.Fatalf("纯 NA 桶必须 E=0 且无适用流量: %+v", m2)
	}
}

func TestAggregatorDimCapOverflow(t *testing.T) {
	a := NewAggregator(2)
	a.Add(obs(gwcov.StatusFull, "d1"))
	a.Add(obs(gwcov.StatusFull, "d2"))
	a.Add(obs(gwcov.StatusFull, "d3")) // 触发 other 归拢
	a.Add(obs(gwcov.StatusFull, "d4")) // 再次归拢
	if a.Overflow() != 2 {
		t.Fatalf("Overflow=%d want 2", a.Overflow())
	}
	keys := a.Snapshot()
	foundOther := false
	for _, k := range keys {
		if k.Detector == "other" {
			foundOther = true
			m := a.Metrics(k)
			if m.Bucket.Full != 2 {
				t.Fatalf("other 桶计数=%d want 2", m.Bucket.Full)
			}
		}
	}
	if !foundOther {
		t.Fatal("未生成 other 归拢桶")
	}
}

func TestAggregatorInvalidDropped(t *testing.T) {
	a := NewAggregator(100)
	bad := obs(gwcov.StatusFull, "d1")
	bad.Status = "BOGUS"
	a.Add(bad)
	if a.Invalid() != 1 {
		t.Fatalf("Invalid=%d want 1", a.Invalid())
	}
	if len(a.Snapshot()) != 0 {
		t.Fatal("非法记录不得入桶")
	}
}

func TestAggregatorMinuteWindowSplit(t *testing.T) {
	a := NewAggregator(100)
	o1 := obs(gwcov.StatusFull, "d1")
	o2 := obs(gwcov.StatusFull, "d1")
	o2.OccurredAt = t0.Add(61 * time.Second)
	a.Add(o1)
	a.Add(o2)
	if len(a.Snapshot()) != 2 {
		t.Fatalf("跨分钟应分桶: keys=%d", len(a.Snapshot()))
	}
}

func TestSamplerDeterministic(t *testing.T) {
	s := NewSampler(3)
	kept := 0
	for i := 0; i < 9; i++ {
		if s.Keep() {
			kept++
		}
	}
	seen, k, d := s.Stats()
	if seen != 9 || k != 3 || d != 6 {
		t.Fatalf("Stats=%d/%d/%d want 9/3/6", seen, k, d)
	}
	if kept != 3 {
		t.Fatalf("kept=%d want 3", kept)
	}
	if s.Rate() != 3.0/9.0 {
		t.Fatalf("Rate=%v want %v", s.Rate(), 3.0/9.0)
	}
	s1 := NewSampler(1)
	for i := 0; i < 5; i++ {
		if !s1.Keep() {
			t.Fatal("N=1 必须全保留")
		}
	}
}

func TestAggregatorDrain(t *testing.T) {
	a := NewAggregator(100)
	a.Add(obs(gwcov.StatusFull, "d1"))
	a.Add(obs(gwcov.StatusPartial, "d1"))
	a.Add(obs(gwcov.StatusFull, "d2"))

	drained := a.Drain()
	if len(drained) != 2 {
		t.Fatalf("Drain 键数=%d want 2", len(drained))
	}
	var d1 Bucket
	for k, b := range drained {
		if k.Detector == "d1" {
			d1 = b
		}
	}
	if d1.Full != 1 || d1.Partial != 1 {
		t.Fatalf("d1 桶=%+v want Full=1 Partial=1", d1)
	}
	// Drain 后聚合器清零（增量语义），overflow/invalid 累计不清
	if len(a.Snapshot()) != 0 {
		t.Fatal("Drain 后桶应清零")
	}
	bad := obs(gwcov.StatusFull, "d1")
	bad.Status = "BOGUS"
	a.Add(bad)
	if got := a.Drain(); len(got) != 0 {
		t.Fatalf("二次 Drain 应为空增量, got %d 键", len(got))
	}
	if a.Invalid() != 1 {
		t.Fatalf("Drain 不应清 invalid 累计: %d", a.Invalid())
	}
}
