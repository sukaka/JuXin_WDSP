// tapsrc 单元测试：分帧器（分片/半消息/超限/乱序字节）、规范化（配对/
// gRPC/WS/脱敏/截断）、配置校验、会话重连。
package tapsrc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
)

// ── 分帧器 ───────────────────────────────────────────────

func TestFrameScannerSingle(t *testing.T) {
	sc := newFrameScanner(1 << 20)
	frames := sc.feed([]byte("{\n \"a\": 1\n}\n"))
	if len(frames) != 1 || !strings.Contains(string(frames[0]), `"a": 1`) {
		t.Fatalf("frames=%d", len(frames))
	}
}

func TestFrameScannerSplit(t *testing.T) {
	sc := newFrameScanner(1 << 20)
	msg := `{"http_buffered_trace":{"request":{"headers":[{"key":":path","value":"/a?x=\"}nested\""}]}}}`
	// 逐字节喂入（极端分片）
	var frames [][]byte
	for i := 0; i < len(msg); i++ {
		frames = append(frames, sc.feed([]byte(msg[i:i+1]))...)
	}
	if len(frames) != 1 {
		t.Fatalf("frames=%d", len(frames))
	}
	var tw traceWrapper
	if err := json.Unmarshal(frames[0], &tw); err != nil {
		t.Fatal(err)
	}
	if tw.HTTPBufferedTrace.Request.Headers[0].Value != `/a?x="}nested"` {
		t.Fatalf("value=%q", tw.HTTPBufferedTrace.Request.Headers[0].Value)
	}
}

func TestFrameScannerMultiAndSeparator(t *testing.T) {
	sc := newFrameScanner(1 << 20)
	frames := sc.feed([]byte("{\"a\":1}\n{\"b\":2}{\"c\":3}\n"))
	if len(frames) != 3 {
		t.Fatalf("frames=%d", len(frames))
	}
}

func TestFrameScannerOversize(t *testing.T) {
	sc := newFrameScanner(64)
	// 超限帧（>64B）+ 后续正常帧：超限丢弃且状态机恢复同步
	big := `{"pad":"` + strings.Repeat("x", 200) + `"}`
	small := `{"ok":1}`
	frames := sc.feed([]byte(big + "\n" + small))
	if len(frames) != 1 || string(frames[0]) != small {
		t.Fatalf("frames=%d %q", len(frames), frames)
	}
	if sc.overflowed() == false {
		t.Fatal("应记录超限")
	}
	if n := sc.takeOverflow(); n != 1 {
		t.Fatalf("overflow=%d", n)
	}
	// 分块喂入的超限帧：后半段不得继续累积内存
	sc2 := newFrameScanner(64)
	half := len(big) / 2
	if f := sc2.feed([]byte(big[:half])); len(f) != 0 {
		t.Fatal("半帧不应产出")
	}
	frames = sc2.feed([]byte(big[half:] + small))
	if len(frames) != 1 || string(frames[0]) != small {
		t.Fatalf("断帧续传后同步失败: %d", len(frames))
	}
	if len(sc2.buf) > 64 {
		t.Fatalf("超限帧字节不应驻留: %d", len(sc2.buf))
	}
}

func TestFrameScannerReset(t *testing.T) {
	sc := newFrameScanner(1 << 20)
	sc.feed([]byte(`{"partial":`))
	sc.reset()
	frames := sc.feed([]byte(`{"ok":true}`))
	if len(frames) != 1 {
		t.Fatalf("reset 后应恢复: %d", len(frames))
	}
}

// ── 规范化 ───────────────────────────────────────────────

type collector struct {
	mu   sync.Mutex
	recs []events.HTTPRecordV2
}

func (c *collector) add(r events.HTTPRecordV2) {
	c.mu.Lock()
	c.recs = append(c.recs, r)
	c.mu.Unlock()
}

func newTestSource(t *testing.T, observed string, tlsTerminated bool, coll *collector) *Source {
	t.Helper()
	if coll == nil {
		coll = &collector{}
	}
	s, err := New("agent-t1", Config{
		AdminAddr:           "127.0.0.1:9901",
		SourceInstance:      "envoy-e2e",
		ConfigID:            "wdsp_tap",
		ObservedHTTPVersion: observed,
		TLSTerminated:       tlsTerminated,
		BodyEnabled:         true,
	}, coll.add, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.UpdatePolicy(config.LevelL2, 4096, config.DefaultMasking())
	return s
}

func tapTraceJSON(reqHeaders [][2]string, reqBody string, reqTrunc bool,
	respHeaders [][2]string, respTrailers [][2]string) []byte {
	h := func(pairs [][2]string) []map[string]string {
		out := []map[string]string{}
		for _, p := range pairs {
			out = append(out, map[string]string{"key": p[0], "value": p[1]})
		}
		return out
	}
	msg := map[string]any{"headers": h(reqHeaders)}
	if reqBody != "" || reqTrunc {
		msg["body"] = map[string]any{"as_bytes": base64.StdEncoding.EncodeToString([]byte(reqBody)), "truncated": reqTrunc}
	}
	trace := map[string]any{"request": msg}
	if respHeaders != nil {
		rm := map[string]any{"headers": h(respHeaders)}
		if respTrailers != nil {
			rm["trailers"] = h(respTrailers)
		}
		trace["response"] = rm
	}
	data, _ := json.Marshal(map[string]any{"http_buffered_trace": trace})
	return data
}

func TestNormalizeBasicH2(t *testing.T) {
	coll := &collector{}
	s := newTestSource(t, "2", true, coll)
	frame := tapTraceJSON([][2]string{
		{":authority", "api.example.com"}, {":path", "/h2/a?token=plain-t1"}, {":method", "GET"}, {":scheme", "https"},
		{"authorization", "Bearer plain-secret-t1"}, {"x-wdsp-debug", "strip-me"}, {"cookie", "c1=v1"},
		{"cookie", "c2=v2"}, // 重复值保序
	}, "", false, [][2]string{{":status", "200"}, {"content-type", "application/json"}}, nil)
	s.handleFrame(frame)
	if len(coll.recs) != 1 {
		t.Fatalf("recs=%d", len(coll.recs))
	}
	r := coll.recs[0]
	if r.SourceType != "ENVOY_TAP" || r.SourceInstance != "envoy-e2e" || r.SourceCapabilitiesVersion != "envoy-tap/1" {
		t.Fatalf("来源标识异常: %+v", r)
	}
	if r.ObservedHTTPVersion != "2" || r.OriginalHTTPVersion == nil || *r.OriginalHTTPVersion != "2" {
		t.Fatalf("协议断言: obs=%s orig=%v", r.ObservedHTTPVersion, r.OriginalHTTPVersion)
	}
	if r.TLSVisibility != "DECRYPTED" {
		t.Fatalf("tls_visibility=%s", r.TLSVisibility)
	}
	if r.AssociationState != "COMPLETE" || r.AssociationReason != "" {
		t.Fatalf("关联: %s/%s", r.AssociationState, r.AssociationReason)
	}
	if r.CaptureStreamID != nil {
		t.Fatal("tap 缓冲输出无流 ID，capture_stream_id 应为 null（不造假）")
	}
	if r.Request.Method != "GET" || r.Request.Host != "api.example.com" || r.Request.Scheme != "https" {
		t.Fatalf("请求行: %+v", r.Request)
	}
	if strings.Contains(r.Request.URI, "plain-t1") {
		t.Fatalf("query 未脱敏: %s", r.Request.URI)
	}
	if got := r.Request.Headers["authorization"]; len(got) != 1 || got[0] != "********" {
		t.Fatalf("authorization 未脱敏: %v", got)
	}
	if got := r.Request.Headers["cookie"]; len(got) != 2 || got[0] != "********" || got[1] != "********" {
		t.Fatalf("重复值应保序逐值脱敏: %v", got)
	}
	if _, ok := r.Request.Headers["x-wdsp-debug"]; ok {
		t.Fatal("x-wdsp-* 控制头未剥离")
	}
	if r.Response == nil || r.Response.Status != 200 {
		t.Fatalf("响应配对: %+v", r.Response)
	}
	if r.LatencyMS == nil || *r.LatencyMS != 0 {
		t.Fatal("tap 时戳口径：latency 恒 0（不表达业务延迟）")
	}
}

func TestNormalizeRequestOnlyDisconnect(t *testing.T) {
	coll := &collector{}
	s := newTestSource(t, "2", false, coll)
	frame := tapTraceJSON([][2]string{
		{":authority", "a.b"}, {":path", "/x"}, {":method", "POST"}, {":scheme", "http"},
	}, "partial-body", true, nil, nil) // response 缺失（流异常结束）
	s.handleFrame(frame)
	r := coll.recs[0]
	if r.Response != nil || r.ResponseTS != nil || r.LatencyMS != nil {
		t.Fatal("响应缺失应同步 null")
	}
	if r.AssociationState != "REQUEST_ONLY" || r.AssociationReason != "DISCONNECT" {
		t.Fatalf("关联: %s/%s", r.AssociationState, r.AssociationReason)
	}
	// 契约 V1.1：Envoy 截断 → truncated=true + original_total_size=null
	bq := r.Request.BodyQuality
	if !bq.Truncated || bq.OriginalTotalSize != nil {
		t.Fatalf("tap 截断口径: %+v", bq)
	}
}

func TestNormalizeGRPC(t *testing.T) {
	coll := &collector{}
	s := newTestSource(t, "2", true, coll)

	// unary 成功：grpc_status=0, CLOSED
	s.handleFrame(tapTraceJSON([][2]string{
		{":authority", "svc.local"}, {":path", "/pkg.UserService/GetUser"}, {":method", "POST"}, {":scheme", "https"},
		{"content-type", "application/grpc"}, {"grpc-timeout", "1S"},
	}, "\x00\x00\x00\x00\x05proto", false, [][2]string{{":status", "200"}, {"content-type", "application/grpc"}},
		[][2]string{{"grpc-status", "0"}, {"grpc-message", ""}}))
	r := coll.recs[0]
	if r.GRPC == nil || r.GRPC.Service != "pkg.UserService" || r.GRPC.Method != "GetUser" {
		t.Fatalf("grpc 解析: %+v", r.GRPC)
	}
	if r.GRPC.GRPCStatus == nil || *r.GRPC.GRPCStatus != 0 || r.GRPC.StreamState != "CLOSED" {
		t.Fatalf("grpc 状态: %+v", r.GRPC)
	}
	// gRPC 正文默认不采集（content_type 跳过，不解析 Protobuf）
	if r.Request.Body != "" || r.Request.BodyQuality.SkippedReason != "content_type" {
		t.Fatalf("gRPC 正文不应采集: body=%q skipped=%q", r.Request.Body, r.Request.BodyQuality.SkippedReason)
	}
	// 响应 trailers 保序保留
	if got := r.Response.Trailers["grpc-status"]; len(got) != 1 || got[0] != "0" {
		t.Fatalf("trailers: %v", r.Response.Trailers)
	}

	// 非零 grpc-status：HTTP 200 ≠ RPC 成功
	s.handleFrame(tapTraceJSON([][2]string{
		{":authority", "svc.local"}, {":path", "/pkg.UserService/Bad"}, {":method", "POST"}, {":scheme", "https"},
		{"content-type", "application/grpc"},
	}, "", false, [][2]string{{":status", "200"}}, [][2]string{{"grpc-status", "3"}}))
	r = coll.recs[1]
	if r.Response.Status != 200 {
		t.Fatal("HTTP 状态应为 200")
	}
	if r.GRPC.GRPCStatus == nil || *r.GRPC.GRPCStatus != 3 {
		t.Fatalf("grpc_status=3 应如实呈现: %+v", r.GRPC)
	}

	// trailers-only 响应（错误快捷路径）：grpc-status 并入响应 headers
	// （Envoy 实测呈现形态），仍应如实解析
	s.handleFrame(tapTraceJSON([][2]string{
		{":authority", "svc.local"}, {":path", "/pkg.UserService/Fail"}, {":method", "POST"}, {":scheme", "https"},
		{"content-type", "application/grpc"},
	}, "", false, [][2]string{{":status", "200"}, {"grpc-status", "3"}, {"grpc-message", "x"}}, nil))
	r = coll.recs[2]
	if r.GRPC.GRPCStatus == nil || *r.GRPC.GRPCStatus != 3 || r.GRPC.StreamState != "CLOSED" {
		t.Fatalf("trailers-only grpc-status 应如实解析: %+v", r.GRPC)
	}

	// 取消/未完成：响应缺失 → 不伪造 grpc-status=0
	s.handleFrame(tapTraceJSON([][2]string{
		{":authority", "svc.local"}, {":path", "/pkg.S/Stream"}, {":method", "POST"}, {":scheme", "https"},
		{"content-type", "application/grpc"},
	}, "", false, nil, nil))
	r = coll.recs[3]
	if r.GRPC == nil || r.GRPC.GRPCStatus != nil || r.GRPC.StreamState != "UNKNOWN" {
		t.Fatalf("取消/未完成应 UNKNOWN: %+v", r.GRPC)
	}
}

func TestNormalizeWebSocketHandshake(t *testing.T) {
	coll := &collector{}
	s := newTestSource(t, "1.1", false, coll)
	s.handleFrame(tapTraceJSON([][2]string{
		{":authority", "ws.local"}, {":path", "/ws"}, {":method", "GET"}, {":scheme", "http"},
		{"upgrade", "websocket"}, {"connection", "Upgrade"}, {"sec-websocket-key", "k"}, {"sec-websocket-version", "13"},
	}, "", false, [][2]string{{":status", "101"}, {"upgrade", "websocket"}, {"sec-websocket-accept", "a"}}, nil))
	r := coll.recs[0]
	if r.Response.Status != 101 || r.AssociationState != "COMPLETE" {
		t.Fatalf("握手视图: %+v", r.Response)
	}
	if r.Request.Body != "" || r.Response.Body != "" {
		t.Fatal("WS 帧内容不得驻留")
	}
	if r.GRPC != nil {
		t.Fatal("非 gRPC 流量")
	}
}

func TestNormalizeBodyTruncatedByEnvoy(t *testing.T) {
	coll := &collector{}
	s := newTestSource(t, "2", false, coll)
	s.handleFrame(tapTraceJSON([][2]string{
		{":authority", "a.b"}, {":path", "/up"}, {":method", "POST"}, {":scheme", "http"},
		{"content-type", "text/plain"},
	}, strings.Repeat("z", 3000), true, [][2]string{{":status", "200"}}, nil))
	r := coll.recs[0]
	bq := r.Request.BodyQuality
	if !bq.Truncated || bq.OriginalTotalSize != nil || bq.CapturedBytes <= 0 {
		t.Fatalf("Envoy 截断口径: %+v", bq)
	}
}

func TestNormalizeHostConflict(t *testing.T) {
	coll := &collector{}
	s := newTestSource(t, "2", false, coll)
	s.handleFrame(tapTraceJSON([][2]string{
		{":authority", "real.example"}, {":path", "/"}, {":method", "GET"}, {":scheme", "http"},
		{"host", "spoofed.example"},
	}, "", false, [][2]string{{":status", "200"}}, nil))
	r := coll.recs[0]
	if r.Request.Host != "real.example" {
		t.Fatalf("authority 为准: %s", r.Request.Host)
	}
	if _, ok := r.Request.Headers["host"]; ok {
		t.Fatal("冲突 host 头应移除（不静默覆盖）")
	}
}

func TestConfigValidation(t *testing.T) {
	if _, err := New("a", Config{SourceInstance: "x", ConfigID: "c",
		AdminAddr: "0.0.0.0:9901"}, nil, nil); err == nil {
		t.Fatal("wildcard admin 应拒绝")
	}
	if _, err := New("a", Config{SourceInstance: "x", ConfigID: "c",
		AdminAddr: "10.0.0.5:9901"}, nil, nil); err == nil {
		t.Fatal("非回环 admin 应拒绝")
	}
	if _, err := New("a", Config{AdminAddr: "127.0.0.1:9901", ConfigID: "c"}, nil, nil); err == nil {
		t.Fatal("缺 source_instance 应拒绝")
	}
	if _, err := New("a", Config{SourceInstance: "x", AdminAddr: "127.0.0.1:9901"}, nil, nil); err == nil {
		t.Fatal("缺 config_id 应拒绝")
	}
	if _, err := New("a", Config{SourceInstance: "x", AdminAddr: "127.0.0.1:9901",
		ConfigID: "c", ObservedHTTPVersion: "2.0"}, nil, nil); err == nil {
		t.Fatal("非法协议断言应拒绝")
	}
}

// TestSessionReconnect 假 Admin 流：首连下发一条 trace 后主动断开 → 适配器
// 有界退避重连并重新提交 tap 配置，后续 trace 继续产出。
func TestSessionReconnect(t *testing.T) {
	coll := &collector{}
	var posts int
	var mu sync.Mutex
	frame := tapTraceJSON([][2]string{
		{":authority", "a.b"}, {":path", "/r"}, {":method", "GET"}, {":scheme", "http"},
	}, "", false, [][2]string{{":status", "200"}}, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tap" || r.Method != http.MethodPost {
			w.WriteHeader(404)
			return
		}
		mu.Lock()
		posts++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(frame)
		w.Write([]byte("\n"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// 立即结束流（模拟 tap 中断）
	}))
	defer srv.Close()

	s, err := New("agent-t1", Config{
		AdminAddr:           strings.TrimPrefix(srv.URL, "http://"),
		SourceInstance:      "envoy-e2e",
		ConfigID:            "wdsp_tap",
		ObservedHTTPVersion: "1.1",
		ReconnectMin:        50 * time.Millisecond,
		ReconnectMax:        100 * time.Millisecond,
	}, coll.add, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		coll.mu.Lock()
		n := len(coll.recs)
		coll.mu.Unlock()
		mu.Lock()
		p := posts
		mu.Unlock()
		if n >= 2 && p >= 2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	s.Shutdown(context.Background())
	<-done

	coll.mu.Lock()
	defer coll.mu.Unlock()
	if len(coll.recs) < 2 {
		t.Fatalf("重连后应继续产出: %d", len(coll.recs))
	}
	if s.Stats.Disconnects.Load() < 1 || s.Stats.Reconnects.Load() < 1 {
		t.Fatalf("断连/重连计数: %d/%d", s.Stats.Disconnects.Load(), s.Stats.Reconnects.Load())
	}
	// 每条记录的 event_id 稳定且互异
	ids := map[string]bool{}
	for _, r := range coll.recs {
		if !strings.HasPrefix(r.EventID, "ev-") {
			t.Fatalf("event_id 形态: %s", r.EventID)
		}
		ids[r.EventID] = true
	}
	if len(ids) != len(coll.recs) {
		t.Fatal("event_id 冲突")
	}
}

// TestAdminReject 配置被拒（非 200）计数并退避重试，不 panic。
func TestAdminReject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
	}))
	defer srv.Close()
	s, err := New("agent-t1", Config{
		AdminAddr:      strings.TrimPrefix(srv.URL, "http://"),
		SourceInstance: "x",
		ConfigID:       "bad",
		ReconnectMin:   30 * time.Millisecond,
		ReconnectMax:   50 * time.Millisecond,
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	s.Run(ctx)
	if s.Stats.AdminRejects.Load() < 1 {
		t.Fatal("Admin 拒绝应计数")
	}
}

// 静态检验：回环校验
func TestLoopbackValidation(t *testing.T) {
	if err := validateLoopbackAdmin("127.0.0.1:9901"); err != nil {
		t.Fatal(err)
	}
	if err := validateLoopbackAdmin("localhost:9901"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"0.0.0.0:9901", ":9901", "192.168.1.1:9901", "127.0.0.1:0", "127.0.0.1:abc"} {
		if err := validateLoopbackAdmin(bad); err == nil {
			t.Fatalf("%s 应被拒绝", bad)
		}
	}
	_ = net.IPv4(127, 0, 0, 1) // 保留 net 引用
	_ = fmt.Sprint()
}
