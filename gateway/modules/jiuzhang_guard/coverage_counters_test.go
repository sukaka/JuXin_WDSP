package jiuzhang_guard

import (
	"errors"
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestCovCountersIncAndSnapshot(t *testing.T) {
	c := NewCovCounters()
	c.Inc(StageTotal)
	c.Inc(StageTotal)
	c.Inc(StageCC)
	c.Inc(CovStage("bogus"))
	snap := c.Snapshot()
	if len(snap) != len(covStageOrder) {
		t.Fatalf("快照键数=%d want %d", len(snap), len(covStageOrder))
	}
	if snap[0].Stage != StageTotal || snap[0].Count != 2 {
		t.Fatalf("total=%v", snap[0])
	}
	found := false
	for _, s := range snap {
		if s.Stage == StageCC {
			found = true
			if s.Count != 1 {
				t.Fatalf("cc=%d want 1", s.Count)
			}
		}
	}
	if !found {
		t.Fatal("缺 StageCC 键")
	}
	c.Reset()
	for _, s := range c.Snapshot() {
		if s.Count != 0 {
			t.Fatalf("Reset 后仍有余量: %+v", s)
		}
	}
}

func TestCovStageLabelsFrozen(t *testing.T) {
	// 标签为聚合对账契约，增删改必须有意识地同步下游
	want := map[CovStage]bool{
		"total":               true,
		"rejected_manual_ban": true, "rejected_ip_blacklist": true, "rejected_auto_ban": true,
		"rejected_l7_acl": true, "rejected_cc": true, "rejected_license_quota": true,
		"intercepted_bot": true, "intercepted_waf": true, "reached_api_pipeline": true, "reached_upstream": true,
	}
	if len(want) != len(covStageOrder) {
		t.Fatalf("阶段集合漂移: order=%d want=%d", len(covStageOrder), len(want))
	}
	for _, s := range covStageOrder {
		if !want[s] {
			t.Fatalf("未登记阶段: %s", s)
		}
		delete(want, s)
	}
	for extra := range want {
		t.Fatalf("多余标签: %s", extra)
	}
}

// TestProxyAndCount 归因精确性：链路完成计 reached_upstream；
// Coraza/WAF 中断计 intercepted_waf 且不计 reached_upstream；其他错误两不计。
func TestProxyAndCount(t *testing.T) {
	DefaultCovCounters.Reset()
	okHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })
	wafHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return caddyhttp.HandlerError{ID: "tx-1", StatusCode: 403, Err: errors.New(corazaInterruptionMessage)}
	})
	otherHandler := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return errors.New("boom")
	})
	r, _ := http.NewRequest(http.MethodGet, "http://h/", nil)
	_ = proxyAndCount(&fakeRespWriter{}, r, okHandler)
	_ = proxyAndCount(&fakeRespWriter{}, r, wafHandler)
	_ = proxyAndCount(&fakeRespWriter{}, r, otherHandler)
	snap := map[CovStage]uint64{}
	for _, s := range DefaultCovCounters.Snapshot() {
		snap[s.Stage] = s.Count
	}
	if snap[StageProxied] != 1 {
		t.Fatalf("reached_upstream=%d want 1", snap[StageProxied])
	}
	if snap[StageWAFIntercept] != 1 {
		t.Fatalf("intercepted_waf=%d want 1", snap[StageWAFIntercept])
	}
	if snap[StageProxied]+snap[StageWAFIntercept] != 2 {
		t.Fatalf("WAF 中断不得计入源站到达: %+v", snap)
	}
}

type fakeRespWriter struct{ header http.Header }

func (f *fakeRespWriter) Header() http.Header {
	if f.header == nil {
		f.header = http.Header{}
	}
	return f.header
}
func (f *fakeRespWriter) Write(b []byte) (int, error) { return len(b), nil }
func (f *fakeRespWriter) WriteHeader(int)             {}
