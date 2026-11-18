package coverage

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func baseObs() Observation {
	return Observation{
		RequestID:     "rid-1",
		ApplicationID: "app-1",
		EndpointKey:   "GET /v1/users/{id}",
		Detector:      "graphql.cost_v1",
		Phase:         PhaseRequest,
		Scope:         ScopeDeclared{Bytes: 1024, Messages: 1, Direction: "request"},
		Status:        StatusFull,
		BytesExamined: 1024,
		PolicyVersion: "pol-1",
		NodeID:        "node-1",
	}
}

func TestObservationValidateStates(t *testing.T) {
	cases := []struct {
		name string
		mod  func(*Observation)
		want string // 空串 = 合法
	}{
		{"full-ok", func(o *Observation) {}, ""},
		{"full-with-truncated", func(o *Observation) { o.Truncated = true }, "截断记录不得标 FULL"},
		{"partial-ok", func(o *Observation) {
			o.Status = StatusPartial
			o.ReasonCode = ReasonInputTruncated
			o.Truncated = true
			o.BytesExamined = 512
		}, ""},
		{"skipped-need-reason", func(o *Observation) { o.Status = StatusSkipped }, "必须携带"},
		{"skipped-ok", func(o *Observation) {
			o.Status = StatusSkipped
			o.ReasonCode = ReasonRuleUnselected
		}, ""},
		{"error-ok", func(o *Observation) {
			o.Status = StatusError
			o.ReasonCode = ReasonParseError
		}, ""},
		{"na-wrong-reason", func(o *Observation) {
			o.Status = StatusNotApplicable
			o.ReasonCode = ReasonDisabled
		}, "COV_NA_FROZEN_RULE"},
		{"na-missing-ruleid", func(o *Observation) {
			o.Status = StatusNotApplicable
			o.ReasonCode = ReasonNAFrozenRule
		}, "na_rule_id"},
		{"na-ok", func(o *Observation) {
			o.Status = StatusNotApplicable
			o.ReasonCode = ReasonNAFrozenRule
			o.NARuleID = "na-classification/graphql-subscription"
		}, ""},
		{"bad-status", func(o *Observation) { o.Status = "SOMETHING" }, "status 非法"},
		{"bad-phase", func(o *Observation) { o.Phase = "sideways" }, "phase 非法"},
		{"bad-reason", func(o *Observation) {
			o.Status = StatusSkipped
			o.ReasonCode = "COV_NOT_A_THING"
		}, "未注册"},
		{"no-request-id", func(o *Observation) { o.RequestID = "" }, "request_id 必填"},
		{"no-detector", func(o *Observation) { o.Detector = "" }, "detector 必填"},
		{"negative-bytes", func(o *Observation) { o.BytesExamined = -1 }, "不得为负"},
		{"over-scope", func(o *Observation) { o.BytesExamined = 1 << 20 }, "超过声明范围"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := baseObs()
			c.mod(&o)
			got := o.Validate()
			if c.want == "" && got != "" {
				t.Fatalf("期望合法，实际违规: %s", got)
			}
			if c.want != "" {
				if got == "" {
					t.Fatalf("期望违规 %q，实际合法", c.want)
				}
				if !contains(got, c.want) {
					t.Fatalf("违规信息 %q 不含 %q", got, c.want)
				}
			}
		})
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && (s == sub || len(s) > 0 && containsRune(s, sub)))
}

func containsRune(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestReasonRegistryAllNamespaced(t *testing.T) {
	for code := range validReasons {
		s := string(code)
		if len(s) < 5 || s[:4] != "COV_" {
			t.Fatalf("reason code 未按 COV_ 命名空间: %s", s)
		}
	}
}

func TestStatusRequiresReason(t *testing.T) {
	for _, s := range []Status{StatusSkipped, StatusError, StatusNotApplicable} {
		if !s.RequiresReason() {
			t.Fatalf("%s 应要求 reason", s)
		}
	}
	for _, s := range []Status{StatusFull, StatusPartial} {
		if s.RequiresReason() {
			t.Fatalf("%s 不应强制 reason", s)
		}
	}
}

type memSink struct {
	mu   sync.Mutex
	obs  []Observation
	call int
}

func (m *memSink) Store(o []Observation) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.call++
	m.obs = append(m.obs, o...)
}

func TestEmitterNonBlockingOnFullQueue(t *testing.T) {
	// 容量 1，不启动消费：第二条应立即被丢弃而非阻塞
	e := NewEmitter(1, 1, nil)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 5; i++ {
			e.Emit(baseObs())
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Emit 在队列满时阻塞")
	}
	if e.Emitted() != 1 || e.Dropped() != 4 {
		t.Fatalf("emitted=%d dropped=%d, want 1/4", e.Emitted(), e.Dropped())
	}
}

func TestEmitterDropsInvalidRecords(t *testing.T) {
	e := NewEmitter(8, 2, nil)
	bad := baseObs()
	bad.Status = "BOGUS"
	e.Emit(bad)
	if e.Dropped() != 1 || e.Emitted() != 0 {
		t.Fatalf("非法记录未按丢弃计数: emitted=%d dropped=%d", e.Emitted(), e.Dropped())
	}
}

func TestEmitterFlushToSink(t *testing.T) {
	sink := &memSink{}
	e := NewEmitter(16, 3, sink)
	e.Start()
	defer e.Stop()
	n := 7
	for i := 0; i < n; i++ {
		o := baseObs()
		o.RequestID = fmt.Sprintf("rid-%d", i)
		e.Emit(o)
	}
	// 等一个 flush 周期以上
	time.Sleep(400 * time.Millisecond)
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.obs) != n {
		t.Fatalf("sink 收到 %d 条, want %d", len(sink.obs), n)
	}
	if sink.call < 2 { // batch=3 → 至少两次 flush（3+3+1）
		t.Fatalf("flush 次数异常: %d", sink.call)
	}
}

func TestEmitterStopDrains(t *testing.T) {
	sink := &memSink{}
	e := NewEmitter(64, 4, sink)
	e.Start()
	for i := 0; i < 10; i++ {
		e.Emit(baseObs())
	}
	e.Stop()
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.obs) != 10 {
		t.Fatalf("Stop 未排空: got %d want 10", len(sink.obs))
	}
}

func TestEmitDefaultsOccurredAt(t *testing.T) {
	e := NewEmitter(4, 1, nil)
	o := baseObs()
	o.OccurredAt = time.Time{}
	e.Emit(o)
	if e.Emitted() != 1 {
		t.Fatal("缺省时间戳的合法记录应入队")
	}
}
