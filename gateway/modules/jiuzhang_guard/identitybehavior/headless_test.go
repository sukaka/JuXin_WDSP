package identitybehavior

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/clientip"
	"go.uber.org/zap"
)

// newHeadlessTestEngine 装配内存存储 + 事件记录器的测试引擎（可选信号汇聚回调）。
func newHeadlessTestEngine(t *testing.T, scores map[string]int) (*Engine, string) {
	t.Helper()
	cfg, err := Compile(&Params{Enabled: true, Scores: scores}, zap.NewNop())
	if err != nil || cfg == nil {
		t.Fatalf("compile: %v %v", cfg, err)
	}
	ev, path := newEventTestLogger(t)
	return NewEngine(cfg, NewMemoryStore(0, zap.NewNop()), ev, Options{
		AppID: "app1", GatewayNode: "gw-test", Salt: "salt", Logger: zap.NewNop(),
	}), path
}

// serveOnce 单请求完整 Begin/End 链路（响应 200）。
func serveOnce(t *testing.T, e *Engine, ua string) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "http://waf-test.local/api", nil)
	r.RemoteAddr = "203.0.113.10:1"
	r.Header.Set("User-Agent", ua)
	res := clientip.Result{ClientIP: mustIP(t, "203.0.113.10")}
	rec := httptest.NewRecorder()
	w, obs := e.Begin(rec, r, res)
	if obs == nil {
		t.Fatal("observation expected")
	}
	w.WriteHeader(http.StatusOK)
	e.End(r, obs)
}

func mustIP(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// HEADLESS-001：HeadlessChrome UA → HEADLESS 信号（默认 10 分、OBSERVE、v1.0.0、60s 节流），
// 且经 SignalSink 汇入风险累加器。
func TestHeadlessSignalEmitted(t *testing.T) {
	e, path := newHeadlessTestEngine(t, nil)
	var sunk []Signal
	e.SetSignalSink(func(_ string, sigs []Signal) { sunk = append(sunk, sigs...) })
	serveOnce(t, e, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 HeadlessChrome/120.0 Safari/537.36")
	// 60s 内第二请求节流：不再产信号
	serveOnce(t, e, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 HeadlessChrome/120.0 Safari/537.36")
	var headless []map[string]any
	for _, m := range readEventLines(t, path) {
		if m["record_type"] == RecordReconSignal && m["signal"] == SignalHeadless {
			headless = append(headless, m)
		}
	}
	if len(headless) != 1 {
		t.Fatalf("HEADLESS signals (60s throttle): %v", headless)
	}
	m := headless[0]
	if m["rule_code"] != RuleHeadless || m["rule_version"] != RuleVersion ||
		m["risk_score_delta"].(float64) != 10 || m["mode"] != ModeObserve {
		t.Fatalf("headless signal fields: %v", m)
	}
	if len(sunk) != 1 || sunk[0].Signal != SignalHeadless || sunk[0].ScoreDelta != 10 {
		t.Fatalf("sink must receive throttled headless signal once: %+v", sunk)
	}
}

// 60s 节流窗口过后再次产信号（引擎时钟可注入）。
func TestHeadlessThrottleExpiry(t *testing.T) {
	e, _ := newHeadlessTestEngine(t, nil)
	base := time.Now().UTC()
	e.now = func() time.Time { return base }
	ua := "HeadlessChrome/120.0"
	serveOnce(t, e, ua)
	serveOnce(t, e, ua) // 节流
	if got := e.headless.len(); got != 1 {
		t.Fatalf("throttle lru: %d", got)
	}
	e.now = func() time.Time { return base.Add(headlessSignalThrottle + time.Second) }
	var n int
	e.SetSignalSink(func(_ string, sigs []Signal) { n += len(sigs) })
	serveOnce(t, e, ua) // 节流过期 → 再产
	if n != 1 {
		t.Fatalf("signal after throttle expiry: %d", n)
	}
}

// scores 显式 0 = 规则关闭；普通浏览器 UA 不产 HEADLESS 信号。
func TestHeadlessDisabledAndNegative(t *testing.T) {
	e, path := newHeadlessTestEngine(t, map[string]int{SignalHeadless: 0})
	serveOnce(t, e, "HeadlessChrome/120.0")
	serveOnce(t, e, "Mozilla/5.0 Chrome/120.0")
	for _, m := range readEventLines(t, path) {
		if m["record_type"] == RecordReconSignal && m["signal"] == SignalHeadless {
			t.Fatalf("disabled rule must not signal: %v", m)
		}
	}
	e2, path2 := newHeadlessTestEngine(t, nil)
	serveOnce(t, e2, "Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 Safari/605.1.15")
	for _, m := range readEventLines(t, path2) {
		if m["record_type"] == RecordReconSignal && m["signal"] == SignalHeadless {
			t.Fatalf("non-headless UA must not signal: %v", m)
		}
	}
}
