package pipeline

import (
	"net/http"
	"strings"
	"sync"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/coverage"
)

type covMemSink struct {
	mu  sync.Mutex
	obs []coverage.Observation
}

func (m *covMemSink) Store(o []coverage.Observation) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.obs = append(m.obs, o...)
}

func (m *covMemSink) all() []coverage.Observation {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]coverage.Observation, len(m.obs))
	copy(out, m.obs)
	return out
}

func newCovEmitter(sink *covMemSink) *coverage.Emitter {
	e := coverage.NewEmitter(64, 1, sink)
	e.Start()
	return e
}

func TestCoverageNilEmitterZeroBehavior(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "http://h/v1/orders/9", nil)
	res, err := Process(r, Config{Enabled: true, Mode: "PROTECT"}, nil)
	if err != nil || res == nil {
		t.Fatalf("res=%v err=%v", res, err)
	}
	if res.FinalAction == "" {
		t.Fatal("nil 发射器下管线应正常定案")
	}
}

func TestCoveragePipelineDisabled(t *testing.T) {
	sink := &covMemSink{}
	e := newCovEmitter(sink)
	r, _ := http.NewRequest(http.MethodGet, "http://h/v1/x", nil)
	r.Header.Set("X-Request-Id", "rid-disabled-1")
	res, err := Process(r, Config{
		Enabled: false, Coverage: e,
		ApplicationID: "app-9", PolicyVersion: "pol-9", NodeName: "gw-9",
	}, nil)
	if err != nil || !res.Skipped {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	e.Stop()
	obs := sink.all()
	if len(obs) != 1 {
		t.Fatalf("obs=%d want 1", len(obs))
	}
	o := obs[0]
	if o.Status != coverage.StatusSkipped || o.ReasonCode != coverage.ReasonPipelineDisabled {
		t.Fatalf("obs=%+v", o)
	}
	if o.ApplicationID != "app-9" || o.PolicyVersion != "pol-9" || o.NodeID != "gw-9" {
		t.Fatalf("默认回填缺失: %+v", o)
	}
	if msg := o.Validate(); msg != "" {
		t.Fatalf("记录契约校验失败: %s", msg)
	}
}

func TestCoverageFullScopeRecord(t *testing.T) {
	sink := &covMemSink{}
	e := newCovEmitter(sink)
	r, _ := http.NewRequest(http.MethodPost, "http://h/v1/orders/9", strings.NewReader("a=1&b=2"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("X-Request-Id", "rid-full-1")
	res, err := Process(r, Config{Enabled: true, Mode: "PROTECT", Coverage: e, NodeName: "gw-1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.Stop()
	obs := sink.all()
	if len(obs) != 1 {
		t.Fatalf("obs=%d want 1（成功路径一条范围记录）", len(obs))
	}
	o := obs[0]
	if o.Status != coverage.StatusFull {
		t.Fatalf("完整处理应 FULL: %+v", o)
	}
	if o.EndpointKey != res.EndpointKey || o.EndpointKey == "" {
		t.Fatalf("endpoint_key=%q 与结果 %q 不一致", o.EndpointKey, res.EndpointKey)
	}
	if o.BytesExamined != 7 || o.Scope.Bytes != 7 {
		t.Fatalf("bytes=%d/%d want 7/7", o.BytesExamined, o.Scope.Bytes)
	}
	if msg := o.Validate(); msg != "" {
		t.Fatalf("契约校验失败: %s", msg)
	}
}

func TestCoverageTruncatedPartial(t *testing.T) {
	sink := &covMemSink{}
	e := newCovEmitter(sink)
	body := strings.Repeat("x", 64)
	r, _ := http.NewRequest(http.MethodPost, "http://h/v1/up", strings.NewReader(body))
	r.Header.Set("Content-Type", "text/plain")
	r.Header.Set("X-Request-Id", "rid-trunc-1")
	limits := dsctx.DefaultParseLimits()
	limits.MaxBodyParseBytes = 16
	res, err := Process(r, Config{Enabled: true, Mode: "PROTECT", Limits: limits, Coverage: e}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Parsed == nil || !res.Parsed.BodyTruncated {
		t.Fatalf("前置假设失败：体应被截断 parsed=%+v", res.Parsed)
	}
	e.Stop()
	obs := sink.all()
	if len(obs) != 1 {
		t.Fatalf("obs=%d want 1", len(obs))
	}
	o := obs[0]
	if o.Status != coverage.StatusPartial || o.ReasonCode != coverage.ReasonInputTruncated || !o.Truncated {
		t.Fatalf("截断应 PARTIAL+COV_INPUT_TRUNCATED: %+v", o)
	}
	if msg := o.Validate(); msg != "" {
		t.Fatalf("契约校验失败: %s", msg)
	}
}

// TestCoverageGoldenNoBehaviorChange 零行为黄金对照：同一请求接入/不接入发射器，
// 最终动作与匹配集合必须完全一致。
func TestCoverageGoldenNoBehaviorChange(t *testing.T) {
	build := func() *http.Request {
		r, _ := http.NewRequest(http.MethodPost, "http://h/v1/orders/9", strings.NewReader("a=1&b=2"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}
	resNil, err := Process(build(), Config{Enabled: true, Mode: "PROTECT"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sink := &covMemSink{}
	e := newCovEmitter(sink)
	defer e.Stop()
	resCov, err := Process(build(), Config{Enabled: true, Mode: "PROTECT", Coverage: e}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resNil.FinalAction != resCov.FinalAction {
		t.Fatalf("final action 变化: %s vs %s", resNil.FinalAction, resCov.FinalAction)
	}
	if len(resNil.Context.Matches) != len(resCov.Context.Matches) {
		t.Fatalf("Matches 数量变化: %d vs %d", len(resNil.Context.Matches), len(resCov.Context.Matches))
	}
}
