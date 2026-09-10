// P1-03 发送侧测试：400 永久失败隔离（不再死循环）、429 Retry-After 退避、
// 补传公平预算、统一指标准确性。
package agent

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/buffer"
	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
	"github.com/jiuzhang-waf/wdsp-agent/internal/ratelimit"
)

func p1Record(uri string) events.HTTPRecord {
	return events.HTTPRecord{
		FlowID: "a1-1.1.1.1-80-2.2.2.2-8080-1", RequestTS: 1788256800.123,
		SrcIP: "1.1.1.1", SrcPort: 80, DstIP: "2.2.2.2", DstPort: 8080,
		Direction: "ingress", TLSVisibility: "PLAINTEXT",
		Request: &events.HTTPMessage{Method: "GET", Scheme: "http", Host: "h", URI: uri},
	}
}

// 400 永久失败：含非法记录的批次二分隔离，合法记录照常接受，非法记录丢弃
// 计数（permanent_invalid），不转缓存、不无限重放。
func TestSendHTTPBatch400Isolation(t *testing.T) {
	var calls atomic.Int64
	var acceptedURIs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var req events.HTTPRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("请求体解析: %v", err)
		}
		for _, rec := range req.Records {
			if rec.Request != nil && strings.Contains(rec.Request.URI, "/poison") {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": "BAD_RECORD", "message": "invalid"}})
				return
			}
		}
		for _, rec := range req.Records {
			acceptedURIs = append(acceptedURIs, rec.Request.URI)
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(events.HTTPAcceptedResponse{Accepted: len(req.Records)})
	}))
	defer srv.Close()

	a := newTestAgent(t, srv.URL)
	recs := []events.HTTPRecord{p1Record("/ok1"), p1Record("/poison"), p1Record("/ok2")}
	a.sendHTTPBatch(recs)

	if a.buf.Bytes() != 0 {
		t.Fatalf("400 永久失败不应转缓存: %d bytes", a.buf.Bytes())
	}
	if a.metrics.dropReasonsSnapshot()[DropReasonPermanentInvalid] != 1 {
		t.Fatalf("permanent_invalid 应计数 1: %v", a.metrics.dropReasonsSnapshot())
	}
	if len(acceptedURIs) != 2 {
		t.Fatalf("合法记录应重建批次接受: %v", acceptedURIs)
	}
	if a.metrics.Accepted.Load() != 2 {
		t.Fatalf("accepted 指标应为 2: %d", a.metrics.Accepted.Load())
	}
	// 请求数有界：整批 1 次 + 二分至多 ~2N 次，绝不无限重放
	if n := calls.Load(); n == 0 || n > 8 {
		t.Fatalf("400 隔离请求数应有界: %d", n)
	}
}

// 整批全部 400：全部丢弃计数，缓存为零，请求数 ≤ 2N-1。
func TestSendHTTPBatch400AllInvalidBounded(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"code":"BAD_RECORD","message":"invalid"}}`))
	}))
	defer srv.Close()

	a := newTestAgent(t, srv.URL)
	const n = 8
	recs := make([]events.HTTPRecord, 0, n)
	for i := 0; i < n; i++ {
		recs = append(recs, p1Record("/x"))
	}
	a.sendHTTPBatch(recs)

	if a.buf.Bytes() != 0 {
		t.Fatalf("整批 400 不应转缓存: %d", a.buf.Bytes())
	}
	if a.metrics.Dropped.Load() != n {
		t.Fatalf("应丢弃 %d 条: %d", n, a.metrics.Dropped.Load())
	}
	if a.metrics.dropReasonsSnapshot()[DropReasonPermanentInvalid] != n {
		t.Fatalf("permanent_invalid 应为 %d: %v", n, a.metrics.dropReasonsSnapshot())
	}
	if c := calls.Load(); c > 2*n-1 {
		t.Fatalf("请求数应 ≤ 2N-1=%d: %d", 2*n-1, c)
	}
	// 再次发送同样批次仍是有限次请求（不存在"缓存重放"放大）
	a.sendHTTPBatch(recs)
	if c := calls.Load(); c > 2*(2*n-1) {
		t.Fatalf("无缓存重放放大: %d", c)
	}
}

// 429：尊重 Retry-After——设置退避窗口，批次转缓存保留；窗口内不再请求。
func TestSendHTTPBatch429RetryAfter(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"code":"RATE_LIMITED","message":"slow down"}}`))
	}))
	defer srv.Close()

	buf, err := buffer.Open(t.TempDir(), 0, 0, time.Minute, true)
	if err != nil {
		t.Fatal(err)
	}
	a := newTestAgent(t, srv.URL)
	a.buf = buf
	a.sendHTTPBatch([]events.HTTPRecord{p1Record("/a")})
	if calls.Load() != 1 {
		t.Fatalf("首次应请求一次: %d", calls.Load())
	}
	if a.httpRetryWait() < 25*time.Second {
		t.Fatalf("应记录 Retry-After 退避窗口: %v", a.httpRetryWait())
	}
	if buf.Bytes() == 0 {
		t.Fatal("429 批次应转缓存保留（at-least-once）")
	}
	// 退避窗口内：不再向服务端发请求，直接转缓存
	a.sendHTTPBatch([]events.HTTPRecord{p1Record("/b")})
	if calls.Load() != 1 {
		t.Fatalf("退避窗口内不应再请求: %d", calls.Load())
	}
	// 补传同样尊重退避窗口（本批保留）
	if err := a.replayHTTPBatch([]events.HTTPRecord{p1Record("/c")}); err == nil {
		t.Fatal("退避窗口内补传应暂停")
	}
	if calls.Load() != 1 {
		t.Fatalf("补传在退避窗口内不应请求: %d", calls.Load())
	}
	// 窗口过后恢复发送
	a.httpRetryUntil.Store(0)
	a.sendHTTPBatch([]events.HTTPRecord{p1Record("/d")})
	if calls.Load() != 2 {
		t.Fatalf("窗口过后应恢复请求: %d", calls.Load())
	}
}

// 补传公平预算：补传消耗独立份额桶——实时桶限额极低不影响补传，
// 份额桶限额极低时补传暂停（实时保底），两桶互不消耗。
func TestReplayFairnessBudget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req events.HTTPRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(events.HTTPAcceptedResponse{Accepted: len(req.Records)})
	}))
	defer srv.Close()

	// 缩短补传限速等待窗口（测试提速）
	oldAttempts, oldInterval := replayWaitAttempts, replayWaitInterval
	replayWaitAttempts, replayWaitInterval = 3, 10*time.Millisecond
	defer func() { replayWaitAttempts, replayWaitInterval = oldAttempts, oldInterval }()

	// 缓存积压 > 64KB（令牌桶突发下限），确保份额桶限速真实生效
	mkBuffered := func(t *testing.T) *Agent {
		buf, err := buffer.Open(t.TempDir(), 0, 0, time.Hour, true)
		if err != nil {
			t.Fatal(err)
		}
		a := newTestAgent(t, srv.URL)
		a.buf = buf
		rec := p1Record("/replayed" + strings.Repeat("x", 700))
		data, _ := json.Marshal(rec)
		for i := 0; i < 150; i++ { // ~110KB 积压
			if err := buf.Write(append([]byte{bufTagHTTP}, data...)); err != nil {
				t.Fatal(err)
			}
		}
		return a
	}

	// 实时桶近乎枯竭（12.5B/s），份额桶充足：补传照常完成——不抢实时预算。
	a := mkBuffered(t)
	a.bucket.SetRate(0.0001)
	a.replayBucket = ratelimit.New(100)
	a.replayBuffer()
	if a.buf.Bytes() != 0 {
		t.Fatalf("份额桶充足时补传应完成: %d", a.buf.Bytes())
	}

	// 份额桶近乎枯竭（12.5B/s，突发 64KB < 110KB 积压）：补传暂停且缓存保留，
	// 实时桶满血可用——实时采集不被离线积压饿死。
	a2 := mkBuffered(t)
	a2.bucket = ratelimit.New(100)
	a2.replayBucket = ratelimit.New(0.0001)
	a2.replayBuffer()
	if a2.buf.Bytes() == 0 {
		t.Fatal("份额桶枯竭时补传应保留缓存")
	}
	if !a2.bucket.Allow(60 << 10) {
		t.Fatal("实时预算不应被补传耗尽")
	}
}

// R15：缓存回调批次可能大于令牌桶 burst，但可拆成多个服务端批次逐个发送。
// 每个发送单元都必须先获得令牌，不能因为整段缓存一次性超过 burst 而永久停滞。
func TestReplaySplitsBatchBelowTokenBurst(t *testing.T) {
	var calls atomic.Int64
	var received atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var req events.FlowsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("flows 请求体解析: %v", err)
		}
		received.Add(int64(len(req.Events)))
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(events.FlowsResponse{Accepted: len(req.Events)})
	}))
	defer srv.Close()

	oldAttempts, oldInterval := replayWaitAttempts, replayWaitInterval
	replayWaitAttempts, replayWaitInterval = 120, 10*time.Millisecond
	t.Cleanup(func() { replayWaitAttempts, replayWaitInterval = oldAttempts, oldInterval })

	buf, err := buffer.Open(t.TempDir(), 0, 0, time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	a := newTestAgent(t, srv.URL)
	a.buf = buf
	// 0.5 Mbps 的 burst 受 64 KiB 下限约束；缓存回调批次约 80 KiB，
	// 需要拆分为多个小于 burst 的 flows 请求。
	const n = 80
	for i := 0; i < n; i++ {
		ev := events.FlowEvent{
			EventType: events.TypeFlowEnd, FlowID: "r15-" + strings.Repeat("x", 800),
			Timestamp: time.Now().Unix(), SrcIP: "10.0.0.1", SrcPort: uint16(1000 + i),
			DstIP: "10.0.0.2", DstPort: 8080, Protocol: "tcp", Direction: "ingress",
			HTTPHost: "h", TLSVisibility: events.VisibilityPlaintext,
		}
		data, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		if err := buf.Write(append([]byte{bufTagFlow}, data...)); err != nil {
			t.Fatal(err)
		}
	}
	a.replayBucket = ratelimit.New(0.5)
	a.replayBuffer()

	if calls.Load() < 2 {
		t.Fatalf("超过 burst 的缓存批次应拆成至少两个请求: calls=%d", calls.Load())
	}
	if got := received.Load(); got != n {
		t.Fatalf("拆分补传不应丢失记录: got=%d want=%d", got, n)
	}
	if a.buf.Bytes() != 0 {
		t.Fatalf("拆分补传成功后应清空缓存: %d bytes", a.buf.Bytes())
	}
}

// R15：现有 HTTP 批次上限高于低速令牌桶 burst 时，也必须进一步拆分，
// 且每个实际 HTTP 请求单元都单独获取补传预算。
func TestReplayHTTPSplitsBatchBelowTokenBurst(t *testing.T) {
	var calls atomic.Int64
	var received atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var req events.HTTPRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("http 请求体解析: %v", err)
		}
		received.Add(int64(len(req.Records)))
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(events.HTTPAcceptedResponse{Accepted: len(req.Records)})
	}))
	defer srv.Close()

	oldAttempts, oldInterval := replayWaitAttempts, replayWaitInterval
	replayWaitAttempts, replayWaitInterval = 120, 10*time.Millisecond
	t.Cleanup(func() { replayWaitAttempts, replayWaitInterval = oldAttempts, oldInterval })

	buf, err := buffer.Open(t.TempDir(), 0, 0, time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	a := newTestAgent(t, srv.URL)
	a.buf = buf
	const n = 100
	for i := 0; i < n; i++ {
		rec := p1Record("/r15-" + strings.Repeat("x", 900) + fmt.Sprint(i))
		data, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		if err := buf.Write(append([]byte{bufTagHTTP}, data...)); err != nil {
			t.Fatal(err)
		}
	}
	a.replayBucket = ratelimit.New(0.5)
	a.replayBuffer()

	if calls.Load() < 2 {
		t.Fatalf("超过 burst 的 HTTP 缓存批次应拆成至少两个请求: calls=%d", calls.Load())
	}
	if got := received.Load(); got != n {
		t.Fatalf("HTTP 拆分补传不应丢失记录: got=%d want=%d", got, n)
	}
	if a.buf.Bytes() != 0 {
		t.Fatalf("HTTP 拆分补传成功后应清空缓存: %d bytes", a.buf.Bytes())
	}
}

// 补传中的永久非法记录：隔离丢弃后段可删除（不再无限重放）。
func TestReplayHTTPBatch400Isolated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req events.HTTPRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		for _, rec := range req.Records {
			if rec.Request != nil && strings.Contains(rec.Request.URI, "/poison") {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":{"code":"BAD_RECORD","message":"invalid"}}`))
				return
			}
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(events.HTTPAcceptedResponse{Accepted: len(req.Records)})
	}))
	defer srv.Close()

	buf, err := buffer.Open(t.TempDir(), 0, 0, time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	a := newTestAgent(t, srv.URL)
	a.buf = buf
	for _, uri := range []string{"/ok", "/poison"} {
		rec := p1Record(uri)
		data, _ := json.Marshal(rec)
		if err := buf.Write(append([]byte{bufTagHTTP}, data...)); err != nil {
			t.Fatal(err)
		}
	}
	a.replayBuffer()
	if buf.Bytes() != 0 {
		t.Fatalf("含永久非法记录的段补传后应清空: %d", buf.Bytes())
	}
	if a.metrics.dropReasonsSnapshot()[DropReasonPermanentInvalid] != 1 {
		t.Fatalf("permanent_invalid 应计数 1: %v", a.metrics.dropReasonsSnapshot())
	}
	if a.metrics.Accepted.Load() != 1 {
		t.Fatalf("合法记录应被接受: %d", a.metrics.Accepted.Load())
	}
}

// 统一指标快照：normalized/masked/accepted/dropped_by_reason/spool/oldest_age/
// source_disconnect/association_pending 均出现在心跳 metrics 中。
func TestMetricsSnapshotUnifiedFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"accepted":1}`))
	}))
	defer srv.Close()
	a := newTestAgent(t, srv.URL)

	a.sendHTTPBatch([]events.HTTPRecord{p1Record("/ok")})
	a.metrics.DropReason(DropReasonQueueFull, 3)
	a.onConnection(false)
	a.onConnection(true)

	m := a.metricsSnapshot()
	if m.Accepted != 1 {
		t.Fatalf("accepted=%d", m.Accepted)
	}
	if m.DroppedByReason[DropReasonQueueFull] != 3 {
		t.Fatalf("dropped_by_reason 分账错误: %v", m.DroppedByReason)
	}
	if m.SourceDisconnects != 1 {
		t.Fatalf("source_disconnect=%d", m.SourceDisconnects)
	}
	// spool_bytes 与 buffer_bytes 同值（统一命名）
	if m.SpoolBytes != m.BufferBytes {
		t.Fatalf("spool_bytes=%d buffer_bytes=%d", m.SpoolBytes, m.BufferBytes)
	}
	if m.OldestAgeSec < 0 {
		t.Fatalf("oldest_age_sec=%v", m.OldestAgeSec)
	}
}
