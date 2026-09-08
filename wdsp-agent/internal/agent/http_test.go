// HTTP 通道接线测试（Phase 3 契约 §3/§10：/http 404 → 降级 L0 且不再重试）。
package agent

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/buffer"
	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
	"github.com/jiuzhang-waf/wdsp-agent/internal/filter"
	"github.com/jiuzhang-waf/wdsp-agent/internal/flow"
	"github.com/jiuzhang-waf/wdsp-agent/internal/httpsensor"
	"github.com/jiuzhang-waf/wdsp-agent/internal/ratelimit"
	"github.com/jiuzhang-waf/wdsp-agent/internal/selfmon"
	"github.com/jiuzhang-waf/wdsp-agent/internal/transport"
)

// newTestAgent 构造最小可用 Agent（抓包后端在当前平台不可用时 Fail-Open 降级）。
func newTestAgent(t *testing.T, serverURL string) *Agent {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	client, err := transport.New(serverURL, false, "test")
	if err != nil {
		t.Fatal(err)
	}
	buf, err := buffer.Open(t.TempDir(), 0, 0, time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	a := &Agent{
		cfg: &config.Config{
			AgentID: "a1", Server: serverURL,
			Policy: &config.Policy{
				Name: "p", CaptureLevel: config.LevelL2,
				Capture: config.Capture{Interfaces: []string{"lo0"}, Direction: "both", Ports: []int{8080}},
				Output:  config.Output{Mode: "FLOW"},
			},
		},
		log:     log,
		client:  client,
		bucket:  ratelimit.New(100),
		buf:     buf,
		filt:    filter.New([]uint16{8080}, "both"),
		monitor: selfmon.NewMonitor(20, 512),
	}
	a.tracker = flow.NewTracker("a1", 0, 0, nil, nil)
	a.sensor = httpsensor.New("a1", a.filt.HasPort, nil, log)
	a.initPhase4() // Phase 4：背压帽/定向规则/生效等级/采样 接线
	return a
}

func TestSendHTTPBatch404Downgrade(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":"NOT_FOUND","message":"no route"}}`))
	}))
	defer srv.Close()

	a := newTestAgent(t, srv.URL)
	a.applyPolicy(a.cfg.EffectivePolicy())
	if !a.sensor.Enabled() {
		t.Fatal("L2 策略下传感器应启用")
	}

	recs := []events.HTTPRecord{{
		FlowID: "a1-1.1.1.1-80-2.2.2.2-8080-1", RequestTS: 1788256800.123,
		SrcIP: "1.1.1.1", SrcPort: 80, DstIP: "2.2.2.2", DstPort: 8080,
		Direction: "ingress", TLSVisibility: "PLAINTEXT",
		Request: &events.HTTPMessage{Method: "GET", Scheme: "http", Host: "h", URI: "/"},
	}}
	a.sendHTTPBatch(recs)
	if !a.httpGone.Load() {
		t.Fatal("404 后应标记 httpGone（契约 §10 降级）")
	}
	if a.sensor.Enabled() {
		t.Fatal("404 降级后传感器应按 L0 停用")
	}
	if calls != 1 {
		t.Fatalf("只应调用 /http 一次: %d", calls)
	}
	// 降级后不再重试该端点（直接丢弃计数，不污染缓存）
	a.sendHTTPBatch(recs)
	if calls != 1 {
		t.Fatalf("降级后不应再调用 /http: %d", calls)
	}
	if a.buf.Bytes() != 0 {
		t.Fatalf("404 的记录不应进磁盘缓存: %d bytes", a.buf.Bytes())
	}
}

func TestSendHTTPBatchServerErrorBuffered(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	a := newTestAgent(t, srv.URL)
	a.applyPolicy(a.cfg.EffectivePolicy())
	// 缓存禁用：500 转缓存失败 → 丢弃计数，但不得误判 404 降级
	a.sendHTTPBatch([]events.HTTPRecord{{
		FlowID: "a1-1.1.1.1-80-2.2.2.2-8080-1", RequestTS: 1.0,
		Request: &events.HTTPMessage{Method: "GET", Scheme: "http", Host: "h", URI: "/"},
	}})
	if a.httpGone.Load() {
		t.Fatal("500 不应触发 404 降级")
	}
	if a.metrics.Dropped.Load() == 0 {
		t.Fatal("缓存禁用 + 500 应丢弃计数")
	}
}
