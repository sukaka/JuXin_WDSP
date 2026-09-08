// 代码审查回归测试（批次5-A）：
//   - HIGH-12：TLS 加密流不进入 HTTP 重组器（flow 透传 visibility，agent 拦截）；
//   - MED-20：磁盘缓存补传限速等待失效——桶持续饱和时不得落入正常发送；
//   - LOW-A2：内存队列字节上限原子预留（check-then-act 合一 + 失败回滚）。
package agent

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/buffer"
	"github.com/jiuzhang-waf/wdsp-agent/internal/capture"
	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
	"github.com/jiuzhang-waf/wdsp-agent/internal/ratelimit"
)

// HIGH-12：TLS 流（首包 0x16 03 xx）不送重组器；嗅探未决期间误建的连接
// 在首个 TLS payload 到达时被 L0 终止释放，长连接不再钉住半流 goroutine。
func TestOnPacketTLSFlowSkipsSensor(t *testing.T) {
	a := newTestAgent(t, "http://127.0.0.1:1")
	a.applyPolicy(a.cfg.EffectivePolicy()) // L2：HTTP 传感器启用
	defer a.sensor.Close()
	base := time.Now()
	seq := uint32(1000)
	sseq := uint32(7000)
	pkt := func(src string, sport uint16, dst string, dport uint16, ingress bool,
		s *uint32, payload []byte, syn, fin bool) capture.Packet {
		p := capture.Packet{
			Ts: base, SrcIP: src, DstIP: dst, SrcPort: sport, DstPort: dport,
			Ingress: ingress, Seq: *s, SYN: syn, ACK: !syn, PSH: len(payload) > 0,
			FIN: fin, Payload: payload, OrigLen: len(payload) + 54,
		}
		*s += uint32(len(payload))
		if syn || fin {
			*s++
		}
		return p
	}
	cli, srv := "10.0.0.1", "10.0.0.2"
	cport, sport := uint16(51234), uint16(8080)

	// TLS 流：握手 + ClientHello + 应用数据
	a.onPacket(pkt(cli, cport, srv, sport, true, &seq, nil, true, false))
	a.onPacket(pkt(srv, sport, cli, cport, false, &sseq, nil, true, false))
	if a.sensor.Conns() != 1 {
		t.Fatalf("嗅探未决期间允许建链（未决不拦截）: conns=%d", a.sensor.Conns())
	}
	a.onPacket(pkt(cli, cport, srv, sport, true, &seq, []byte{0x16, 0x03, 0x01, 0x00, 0x2e, 0x01}, false, false))
	if got := a.sensor.Conns(); got != 0 {
		t.Fatalf("TLS 首包后连接应被终止释放: conns=%d", got)
	}
	// 后续 TLS 字节不再进重组器（长连接不再重建）
	for i := 0; i < 5; i++ {
		a.onPacket(pkt(cli, cport, srv, sport, true, &seq, []byte{0x17, 0x03, 0x03, 0x00, 0x10, 0xaa}, false, false))
		a.onPacket(pkt(srv, sport, cli, cport, false, &sseq, []byte{0x17, 0x03, 0x03, 0x00, 0x10, 0xbb}, false, false))
	}
	if got := a.sensor.Conns(); got != 0 {
		t.Fatalf("TLS 流不得重建重组连接: conns=%d", got)
	}

	// 对照：明文 HTTP 流正常进重组器
	seq2, sseq2 := uint32(1000), uint32(7000)
	a.onPacket(pkt(cli, cport+1, srv, sport, true, &seq2, nil, true, false))
	a.onPacket(pkt(srv, sport, cli, cport+1, false, &sseq2, nil, true, false))
	a.onPacket(pkt(cli, cport+1, srv, sport, true, &seq2,
		[]byte("GET /ok HTTP/1.1\r\nHost: h\r\n\r\n"), false, false))
	if got := a.sensor.Conns(); got != 1 {
		t.Fatalf("明文流应正常建链: conns=%d", got)
	}
}

// MED-20：补传批次在限速等待窗口内未获令牌 → 整批保留缓存下轮重试，
// 不得落入正常发送（不限速照发）。
func TestReplayBufferRespectsRateLimit(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"accepted":500}`))
	}))
	defer srv.Close()

	a := newTestAgent(t, srv.URL)
	buf, err := buffer.Open(t.TempDir(), 0, 0, time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	a.buf = buf
	// 缩短限速等待窗口（原 50×100ms ≈ 5s）
	oldAttempts, oldInterval := replayWaitAttempts, replayWaitInterval
	replayWaitAttempts, replayWaitInterval = 3, time.Millisecond
	t.Cleanup(func() { replayWaitAttempts, replayWaitInterval = oldAttempts, oldInterval })

	// 单批 500 条（约 200KB），超过令牌桶最小突发 64KB → Allow 恒失败
	evs := make([]events.FlowEvent, 0, 500)
	for i := 0; i < 500; i++ {
		evs = append(evs, events.FlowEvent{
			EventType: events.TypeFlowEnd, FlowID: fmt.Sprintf("a1-f-%d", i),
			Timestamp: time.Now().Unix(), SrcIP: "10.0.0.1", SrcPort: uint16(1000 + i),
			DstIP: "10.0.0.2", DstPort: 8080, Protocol: "tcp", Direction: "ingress",
			HTTPHost: strings.Repeat("h", 200), TLSVisibility: events.VisibilityPlaintext,
		})
	}
	a.bufferEvents(evs)
	if a.buf.Bytes() == 0 {
		t.Fatal("缓存应有积压")
	}

	a.bucket = ratelimit.New(0.1) // 12.5KB/s，突发上限 64KB < 批次体量
	a.replayBuffer()
	if calls != 0 {
		t.Fatalf("限速未满足不应发送（不得落入正常发送）: calls=%d", calls)
	}
	if a.buf.Bytes() == 0 {
		t.Fatal("未发送批次应保留在缓存（下轮继续）")
	}
	if a.metrics.Forwarded.Load() != 0 {
		t.Fatalf("未发送不应计入 forwarded: %d", a.metrics.Forwarded.Load())
	}

	// 下轮限速放开 → 补传成功并清缓存
	a.bucket = ratelimit.New(0)
	a.replayBuffer()
	if calls != 1 {
		t.Fatalf("限速恢复后应补传: calls=%d", calls)
	}
	if a.buf.Bytes() != 0 {
		t.Fatalf("补传成功应清缓存: %d", a.buf.Bytes())
	}
}

// LOW-A2：原子预留在并发下绝不突破上限，且账本与成功预留数一致。
func TestReserveQBytesConcurrent(t *testing.T) {
	var q atomic.Int64
	const limit = int64(1000)
	const n = int64(7)
	var success atomic.Int64
	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				if reserveQBytes(&q, n, limit) {
					success.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if got := q.Load(); got > limit {
		t.Fatalf("并发生产者突破上限: %d > %d", got, limit)
	}
	if q.Load() != success.Load()*n {
		t.Fatalf("账本不一致: q=%d success*%d=%d", q.Load(), n, success.Load()*n)
	}
	// 边界：恰好不超额
	if reserveQBytes(&q, limit-q.Load()+1, limit) {
		t.Fatal("超额预留应拒绝")
	}
}

// LOW-A2：队列满（channel 无法接收）时预留额度回滚，不泄漏账本。
func TestOnHTTPRecordRollsBackReservationWhenQueueFull(t *testing.T) {
	a := newTestAgent(t, "http://127.0.0.1:1")
	a.httpQ = make(chan httpQItem) // 无缓冲且无接收方：入队必失败
	rec := events.HTTPRecord{
		FlowID:  "a1-1.1.1.1-80-2.2.2.2-8080-1",
		Request: &events.HTTPMessage{Method: "GET", Host: "h", URI: "/"},
	}
	a.onHTTPRecord(rec)
	if got := a.httpQBytes.Load(); got != 0 {
		t.Fatalf("入队失败应回滚预留额度: %d", got)
	}
	if a.metrics.Dropped.Load() == 0 {
		t.Fatal("缓存禁用下入队失败应丢弃计数")
	}
}
