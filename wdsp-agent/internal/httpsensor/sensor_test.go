// httpsensor 合成包驱动测试（macOS 可跑）：直接构造 capture.Packet 序列
// （含 SYN/Seq/FIN）喂入重组器，验证解析、关联、Body 红线与脱敏。
package httpsensor

import (
	"bytes"
	"compress/gzip"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/capture"
	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
)

const (
	testCliIP   = "10.0.0.1"
	testCliPort = 51234
	testSrvIP   = "10.0.0.2"
	testSrvPort = 8080
)

// recorder 收集产出记录。
type recorder struct {
	mu   sync.Mutex
	recs []events.HTTPRecord
}

func (r *recorder) add(rec events.HTTPRecord) {
	r.mu.Lock()
	r.recs = append(r.recs, rec)
	r.mu.Unlock()
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.recs)
}

// waitN 等待至少 n 条记录（重组消费为异步 goroutine）。
func (r *recorder) waitN(t *testing.T, n int) []events.HTTPRecord {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if r.count() >= n {
			r.mu.Lock()
			defer r.mu.Unlock()
			return append([]events.HTTPRecord(nil), r.recs...)
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("等待 %d 条记录超时，当前 %d 条", n, r.count())
	return nil
}

func newTestSensor(level string, maxBody int, masking config.Masking) (*Sensor, *recorder) {
	rec := &recorder{}
	s := New("agent1", func(p uint16) bool { return p == testSrvPort }, rec.add,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.UpdatePolicy(level, maxBody, masking)
	return s, rec
}

// pktFeed 合成单连接双向包序列。
type pktFeed struct {
	s        *Sensor
	base     time.Time
	offMs    int64
	cseq     uint32
	sseq     uint32
	cliPort  uint16
	srvPort  uint16
	finFlags bool
	level    string // 非空时经 AssembleLevel 按流等级喂入（Phase 4）
	bothHit  bool   // 两端端口均在采集集（capture.Packet.BothHit 透传）
}

func newPktFeed(s *Sensor) *pktFeed {
	return &pktFeed{
		s: s, base: time.Now(),
		cseq: 1000, sseq: 7000,
		cliPort: testCliPort, srvPort: testSrvPort,
	}
}

func (f *pktFeed) ts() time.Time { return f.base.Add(time.Duration(f.offMs) * time.Millisecond) }

func (f *pktFeed) send(srcIP, dstIP string, srcPort, dstPort uint16, ingress bool,
	seq *uint32, payload []byte, syn, fin, rst bool) {
	p := capture.Packet{
		Ts: f.ts(), SrcIP: srcIP, DstIP: dstIP, SrcPort: srcPort, DstPort: dstPort,
		Ingress: ingress, BothHit: f.bothHit, Seq: *seq, SYN: syn, ACK: !syn, PSH: len(payload) > 0,
		FIN: fin, RST: rst, Payload: payload, OrigLen: len(payload) + 54,
	}
	if f.level != "" {
		f.s.AssembleLevel(p, f.level)
	} else {
		f.s.Assemble(p)
	}
	*seq += uint32(len(payload))
	if syn || fin {
		*seq++
	}
}

func (f *pktFeed) handshake() {
	f.send(testCliIP, testSrvIP, f.cliPort, f.srvPort, true, &f.cseq, nil, true, false, false)
	f.send(testSrvIP, testCliIP, f.srvPort, f.cliPort, false, &f.sseq, nil, true, false, false)
}

func (f *pktFeed) c2s(data string) {
	f.offMs += 5
	f.send(testCliIP, testSrvIP, f.cliPort, f.srvPort, true, &f.cseq, []byte(data), false, false, false)
}

func (f *pktFeed) s2c(data string) {
	f.offMs += 5
	f.send(testSrvIP, testCliIP, f.srvPort, f.cliPort, false, &f.sseq, []byte(data), false, false, false)
}

// c2sFrags 分片发送（跨包分片 header/body）。
func (f *pktFeed) c2sFrags(frags ...string) {
	for _, d := range frags {
		f.c2s(d)
	}
}

func (f *pktFeed) s2cFrags(frags ...string) {
	for _, d := range frags {
		f.s2c(d)
	}
}

func (f *pktFeed) closeBoth() {
	f.offMs += 5
	f.send(testCliIP, testSrvIP, f.cliPort, f.srvPort, true, &f.cseq, nil, false, true, false)
	f.offMs += 5
	f.send(testSrvIP, testCliIP, f.srvPort, f.cliPort, false, &f.sseq, nil, false, true, false)
}

// ── 基础关联 ───────────────────────────────────────────────

func TestGetRequestResponseAssociation(t *testing.T) {
	s, rec := newTestSensor(config.LevelL2, config.DefaultMaxBodySize, config.DefaultMasking())
	f := newPktFeed(s)
	f.handshake()
	f.c2s("GET /api/login?token=abc&user=bob HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer xyz\r\n\r\n")
	f.s2c("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: sid=123\r\nContent-Length: 15\r\n\r\n{\"token\":\"xyz\"}")
	f.closeBoth()

	recs := rec.waitN(t, 1)
	r := recs[0]
	if r.Request.Method != "GET" || r.Request.Host != "api.example.com" {
		t.Fatalf("请求行错误: %+v", r.Request)
	}
	// query 参数 token 脱敏（缺省 MASK）
	if r.Request.URI != "/api/login?token=********&user=bob" {
		t.Fatalf("URI 脱敏错误: %q", r.Request.URI)
	}
	// Header 脱敏：authorization / set-cookie 缺省 MASK
	if r.Request.Headers["authorization"] != "********" {
		t.Fatalf("authorization 未脱敏: %q", r.Request.Headers["authorization"])
	}
	if r.Response.Headers["set-cookie"] != "********" {
		t.Fatalf("set-cookie 未脱敏: %q", r.Response.Headers["set-cookie"])
	}
	if r.Response.Status != 200 {
		t.Fatalf("状态码错误: %d", r.Response.Status)
	}
	if r.ResponseTS == nil || r.LatencyMs == nil {
		t.Fatal("response_ts/latency_ms 应非 null")
	}
	// 响应 JSON Body 一级字段 token 脱敏
	if !strings.Contains(r.Response.Body, "\"token\":\"********\"") {
		t.Fatalf("响应 Body 未脱敏: %q", r.Response.Body)
	}
	if r.Response.OriginalBodySize != 15 || r.Response.BodyTruncated {
		t.Fatalf("original_body_size 错误: %+v", r.Response)
	}
	if r.TLSVisibility != "PLAINTEXT" {
		t.Fatalf("tls_visibility 错误: %q", r.TLSVisibility)
	}
	// flow_id 格式与 flow 包一致
	wantPrefix := "agent1-10.0.0.1-51234-10.0.0.2-8080-"
	if !strings.HasPrefix(r.FlowID, wantPrefix) {
		t.Fatalf("flow_id 错误: %q", r.FlowID)
	}
}

func TestPostJSONBodyMasking(t *testing.T) {
	s, rec := newTestSensor(config.LevelL2, config.DefaultMaxBodySize, config.DefaultMasking())
	f := newPktFeed(s)
	f.handshake()
	body := `{"user":"alice","password":"secret123","nested":{"password":"inner"}}`
	f.c2s("POST /login HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nContent-Length: " +
		itoa(len(body)) + "\r\n\r\n" + body)
	f.s2c("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
	f.closeBoth()

	recs := rec.waitN(t, 1)
	b := recs[0].Request.Body
	if !strings.Contains(b, `"password":"********"`) {
		t.Fatalf("一级 password 未脱敏: %q", b)
	}
	// H-22.3：嵌套 JSON 必须递归脱敏，杜绝凭据明文泄漏
	if !strings.Contains(b, `"nested":{"password":"********"}`) || strings.Contains(b, "inner") {
		t.Fatalf("嵌套字段应递归脱敏: %q", b)
	}
	if recs[0].Request.OriginalBodySize != int64(len(body)) {
		t.Fatalf("original_body_size 错误: %d", recs[0].Request.OriginalBodySize)
	}
}

// ── keep-alive 多对顺序关联 ────────────────────────────────

func TestKeepAliveTwoPairsInOrder(t *testing.T) {
	s, rec := newTestSensor(config.LevelL2, config.DefaultMaxBodySize, config.DefaultMasking())
	f := newPktFeed(s)
	f.handshake()
	f.c2s("GET /first HTTP/1.1\r\nHost: h\r\n\r\n")
	f.s2c("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	f.c2s("GET /second HTTP/1.1\r\nHost: h\r\n\r\n")
	f.s2c("HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n")
	f.closeBoth()

	recs := rec.waitN(t, 2)
	if recs[0].Request.URI != "/first" || recs[0].Response.Status != 200 {
		t.Fatalf("第一对错误: %+v", recs[0])
	}
	if recs[1].Request.URI != "/second" || recs[1].Response.Status != 201 {
		t.Fatalf("第二对错误: %+v", recs[1])
	}
}

// ── 跨包分片 ───────────────────────────────────────────────

func TestFragmentedHeaderAndBody(t *testing.T) {
	s, rec := newTestSensor(config.LevelL2, config.DefaultMaxBodySize, config.DefaultMasking())
	f := newPktFeed(s)
	f.handshake()
	f.c2sFrags(
		"POST /up HT",
		"TP/1.1\r\nHost: h\r\nContent-Type: text/plain\r\nContent-Len",
		"gth: 11\r\n\r\nhello",
		" world",
	)
	f.s2cFrags(
		"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2",
		"\r\n\r\no",
		"k",
	)
	f.closeBoth()

	recs := rec.waitN(t, 1)
	if recs[0].Request.Body != "hello world" {
		t.Fatalf("分片请求 Body 错误: %q", recs[0].Request.Body)
	}
	if recs[0].Response.Body != "ok" {
		t.Fatalf("分片响应 Body 错误: %q", recs[0].Response.Body)
	}
}

// ── chunked 响应 ───────────────────────────────────────────

func TestChunkedResponse(t *testing.T) {
	s, rec := newTestSensor(config.LevelL2, config.DefaultMaxBodySize, config.DefaultMasking())
	f := newPktFeed(s)
	f.handshake()
	f.c2s("GET /c HTTP/1.1\r\nHost: h\r\n\r\n")
	f.s2c("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nX-Trailer: t\r\n\r\n")
	f.closeBoth()

	recs := rec.waitN(t, 1)
	if recs[0].Response.Body != "hello world" {
		t.Fatalf("chunked Body 错误: %q", recs[0].Response.Body)
	}
	if recs[0].Response.OriginalBodySize != 11 {
		t.Fatalf("chunked original_body_size 错误: %d", recs[0].Response.OriginalBodySize)
	}
}

// ── Body 截断与对齐 ────────────────────────────────────────

func TestBodyTruncationAndAlignment(t *testing.T) {
	s, rec := newTestSensor(config.LevelL2, 64, config.DefaultMasking())
	f := newPktFeed(s)
	f.handshake()
	big := strings.Repeat("a", 200)
	f.c2s("POST /big HTTP/1.1\r\nHost: h\r\nContent-Type: text/plain\r\nContent-Length: 200\r\n\r\n" + big)
	// 截断后流仍保持字节对齐：第二对请求/响应应正常解析
	f.c2s("GET /after HTTP/1.1\r\nHost: h\r\n\r\n")
	f.s2c("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	f.closeBoth()

	recs := rec.waitN(t, 2)
	r0 := recs[0].Request
	if !r0.BodyTruncated || r0.OriginalBodySize != 200 || len(r0.Body) != 64 {
		t.Fatalf("截断标记错误: truncated=%v orig=%d len=%d", r0.BodyTruncated, r0.OriginalBodySize, len(r0.Body))
	}
	if recs[1].Request.URI != "/after" {
		t.Fatalf("截断后 keep-alive 未对齐: %+v", recs[1].Request)
	}
}

// ── 内容类型白名单 ─────────────────────────────────────────

func TestContentTypeWhitelistSkip(t *testing.T) {
	s, rec := newTestSensor(config.LevelL2, config.DefaultMaxBodySize, config.DefaultMasking())
	f := newPktFeed(s)
	f.handshake()
	f.c2s("GET /img HTTP/1.1\r\nHost: h\r\n\r\n")
	f.s2c("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 8\r\n\r\n\x89PNG\r\n\x1a\n")
	f.closeBoth()

	recs := rec.waitN(t, 1)
	resp := recs[0].Response
	if resp.BodySkippedReason != "content_type" || resp.Body != "" || resp.OriginalBodySize != 8 {
		t.Fatalf("白名单跳过错误: %+v", resp)
	}
}

// ── gzip 解压 ──────────────────────────────────────────────

func TestGzipResponseDecompress(t *testing.T) {
	s, rec := newTestSensor(config.LevelL2, config.DefaultMaxBodySize, config.DefaultMasking())
	f := newPktFeed(s)
	f.handshake()
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, _ = w.Write([]byte(`{"ok":true}`))
	_ = w.Close()
	f.c2s("GET /gz HTTP/1.1\r\nHost: h\r\n\r\n")
	f.send(testSrvIP, testCliIP, f.srvPort, f.cliPort, false, &f.sseq,
		[]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: "+itoa(gz.Len())+"\r\n\r\n"), false, false, false)
	f.offMs += 5
	f.send(testSrvIP, testCliIP, f.srvPort, f.cliPort, false, &f.sseq, gz.Bytes(), false, false, false)
	f.closeBoth()

	recs := rec.waitN(t, 1)
	if recs[0].Response.Body != `{"ok":true}` {
		t.Fatalf("gzip 解压错误: %q", recs[0].Response.Body)
	}
	// original_body_size 记线上（压缩后）长度
	if recs[0].Response.OriginalBodySize != int64(gz.Len()) {
		t.Fatalf("gzip original_body_size 错误: %d", recs[0].Response.OriginalBodySize)
	}
}

func TestBrotliSkipped(t *testing.T) {
	s, rec := newTestSensor(config.LevelL2, config.DefaultMaxBodySize, config.DefaultMasking())
	f := newPktFeed(s)
	f.handshake()
	f.c2s("GET /br HTTP/1.1\r\nHost: h\r\n\r\n")
	f.s2c("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: br\r\nContent-Length: 5\r\n\r\nabcde")
	f.closeBoth()

	recs := rec.waitN(t, 1)
	if recs[0].Response.BodySkippedReason != "encoding" || recs[0].Response.BodyTruncated {
		t.Fatalf("br 应 skipped=encoding: %+v", recs[0].Response)
	}
}

// ── multipart 摘要 ─────────────────────────────────────────

func TestMultipartSummary(t *testing.T) {
	s, rec := newTestSensor(config.LevelL2, config.DefaultMaxBodySize, config.DefaultMasking())
	f := newPktFeed(s)
	f.handshake()
	body := "--BOUND\r\n" +
		"Content-Disposition: form-data; name=\"password\"\r\n\r\n" +
		"secret\r\n" +
		"--BOUND\r\n" +
		"Content-Disposition: form-data; name=\"file1\"; filename=\"a.png\"\r\n" +
		"Content-Type: image/png\r\n\r\n" +
		"\x89PNGDATA\r\n" +
		"--BOUND--\r\n"
	f.c2s("POST /upload HTTP/1.1\r\nHost: h\r\nContent-Type: multipart/form-data; boundary=BOUND\r\nContent-Length: " +
		itoa(len(body)) + "\r\n\r\n" + body)
	f.s2c("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	f.closeBoth()

	recs := rec.waitN(t, 1)
	b := recs[0].Request.Body
	if recs[0].Request.BodySkippedReason != "" {
		t.Fatalf("multipart 不应 skipped: %+v", recs[0].Request)
	}
	if !strings.Contains(b, `"password":"********"`) {
		t.Fatalf("multipart 字段未脱敏: %q", b)
	}
	if !strings.Contains(b, `"filename":"a.png"`) || !strings.Contains(b, `"content_type":"image/png"`) {
		t.Fatalf("multipart 文件元数据缺失: %q", b)
	}
}

// ── 脱敏四模式 ─────────────────────────────────────────────

func TestMaskingModes(t *testing.T) {
	mk := func(hMode, pMode string) config.Masking {
		return config.Masking{
			Headers: config.MaskRule{Mode: hMode, Names: []string{"Authorization"}},
			Params:  config.MaskRule{Mode: pMode, Names: []string{"Token"}},
		}
	}
	cases := []struct {
		name        string
		masking     config.Masking
		wantAuth    string // "" 表示头被 DROP
		wantURI     string
		bodyContain string
	}{
		{"NONE", mk(config.MaskModeNone, config.MaskModeNone), "Bearer xyz", "/?token=abc&a=1", `"token":"abc"`},
		{"MASK", mk(config.MaskModeMask, config.MaskModeMask), "********", "/?token=********&a=1", `"token":"********"`},
		{"HASH", mk(config.MaskModeHash, config.MaskModeHash), "sha256:", "/?token=sha256:", `"token":"sha256:`},
		{"DROP", mk(config.MaskModeDrop, config.MaskModeDrop), "", "/?a=1", `{}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, rec := newTestSensor(config.LevelL2, config.DefaultMaxBodySize, tc.masking)
			f := newPktFeed(s)
			f.handshake()
			body := `{"token":"abc"}`
			f.c2s("POST /?token=abc&a=1 HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer xyz\r\nContent-Type: application/json\r\nContent-Length: " +
				itoa(len(body)) + "\r\n\r\n" + body)
			f.s2c("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
			f.closeBoth()

			recs := rec.waitN(t, 1)
			r := recs[0].Request
			if tc.wantAuth == "" {
				if _, ok := r.Headers["authorization"]; ok {
					t.Fatalf("DROP 模式 authorization 应删除: %+v", r.Headers)
				}
			} else if !strings.HasPrefix(r.Headers["authorization"], tc.wantAuth) {
				t.Fatalf("authorization 脱敏错误: %q", r.Headers["authorization"])
			}
			if tc.masking.Params.Mode == config.MaskModeHash {
				if !strings.HasPrefix(r.URI, tc.wantURI) {
					t.Fatalf("URI HASH 脱敏错误: %q", r.URI)
				}
			} else if r.URI != tc.wantURI {
				t.Fatalf("URI 脱敏错误: got %q want %q", r.URI, tc.wantURI)
			}
			if !strings.Contains(r.Body, tc.bodyContain) {
				t.Fatalf("Body 脱敏错误: %q", r.Body)
			}
		})
	}
}

// ── 采集等级矩阵 ───────────────────────────────────────────

func TestCaptureLevelMatrix(t *testing.T) {
	feed := func(s *Sensor) {
		f := newPktFeed(s)
		f.handshake()
		f.c2s("GET /lv HTTP/1.1\r\nHost: h\r\nAuthorization: Bearer xyz\r\n\r\n")
		f.s2c("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3\r\n\r\nabc")
		f.closeBoth()
	}

	t.Run("L0", func(t *testing.T) {
		s, rec := newTestSensor(config.LevelL0, config.DefaultMaxBodySize, config.DefaultMasking())
		if s.Enabled() {
			t.Fatal("L0 不应启用传感器")
		}
		feed(s) // Assemble 直接返回
		time.Sleep(100 * time.Millisecond)
		if rec.count() != 0 {
			t.Fatalf("L0 不应产出记录: %d", rec.count())
		}
	})
	t.Run("L1", func(t *testing.T) {
		s, rec := newTestSensor(config.LevelL1, config.DefaultMaxBodySize, config.DefaultMasking())
		feed(s)
		recs := rec.waitN(t, 1)
		r := recs[0]
		if r.Request.Headers["authorization"] != "********" {
			t.Fatalf("L1 头部应脱敏: %+v", r.Request.Headers)
		}
		if r.Response.Body != "" || r.Response.OriginalBodySize != 3 || r.Response.BodySkippedReason != "" {
			t.Fatalf("L1 不应采 Body: %+v", r.Response)
		}
	})
	t.Run("L2", func(t *testing.T) {
		s, rec := newTestSensor(config.LevelL2, config.DefaultMaxBodySize, config.DefaultMasking())
		feed(s)
		recs := rec.waitN(t, 1)
		if recs[0].Response.Body != "abc" {
			t.Fatalf("L2 应采 Body: %+v", recs[0].Response)
		}
	})
	t.Run("L3", func(t *testing.T) {
		// L3 传感器侧 = L2（RAW 通道附加在 agent 编排层）
		s, rec := newTestSensor(config.LevelL3, config.DefaultMaxBodySize, config.DefaultMasking())
		feed(s)
		recs := rec.waitN(t, 1)
		if recs[0].Response.Body != "abc" {
			t.Fatalf("L3 应按 L2 采 Body: %+v", recs[0].Response)
		}
	})
}

// ── 响应缺失 → null ────────────────────────────────────────

func TestResponseNullOnClose(t *testing.T) {
	s, rec := newTestSensor(config.LevelL2, config.DefaultMaxBodySize, config.DefaultMasking())
	f := newPktFeed(s)
	f.handshake()
	f.c2s("GET /noresp HTTP/1.1\r\nHost: h\r\n\r\n")
	f.closeBoth()

	recs := rec.waitN(t, 1)
	r := recs[0]
	if r.Response != nil || r.ResponseTS != nil || r.LatencyMs != nil {
		t.Fatalf("响应未捕获应为 null: %+v", r)
	}
}

// ── 解析失败回退 ───────────────────────────────────────────

func TestParseFailureFallback(t *testing.T) {
	s, rec := newTestSensor(config.LevelL2, config.DefaultMaxBodySize, config.DefaultMasking())
	// TLS ClientHello 字节流：非 HTTP → 回退（无记录、不 panic、进程存活）
	f := newPktFeed(s)
	f.handshake()
	f.offMs += 5
	f.send(testCliIP, testSrvIP, f.cliPort, f.srvPort, true, &f.cseq,
		[]byte{0x16, 0x03, 0x01, 0x00, 0x2e, 0x01, 0x00, 0x00, 0x2a, 0x03, 0x03}, false, false, false)
	f.closeBoth()

	time.Sleep(200 * time.Millisecond)
	if rec.count() != 0 {
		t.Fatalf("非 HTTP 流不应产出记录: %d", rec.count())
	}
	if s.Stats.ParseFallbacks.Load() == 0 {
		t.Fatal("应记录 ParseFallbacks")
	}

	// 传感器仍可正常处理后续连接（回退不影响进程）
	s2, rec2 := newTestSensor(config.LevelL2, config.DefaultMaxBodySize, config.DefaultMasking())
	f2 := newPktFeed(s2)
	f2.handshake()
	f2.c2s("GET /ok HTTP/1.1\r\nHost: h\r\n\r\n")
	f2.s2c("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	f2.closeBoth()
	rec2.waitN(t, 1)
}

// ── Header 16KB 钳制 ───────────────────────────────────────

func TestHeaderClamped16KB(t *testing.T) {
	s, rec := newTestSensor(config.LevelL2, config.DefaultMaxBodySize, config.DefaultMasking())
	f := newPktFeed(s)
	f.handshake()
	// 构造总大小 >16KB 的头部块（单行 <32KB）
	var hb strings.Builder
	hb.WriteString("GET /h HTTP/1.1\r\nHost: h\r\n")
	for i := 0; i < 30; i++ {
		hb.WriteString("X-Pad-")
		hb.WriteString(strings.Repeat("k", 4))
		hb.WriteString(": ")
		hb.WriteString(strings.Repeat("v", 600))
		hb.WriteString("\r\n")
	}
	hb.WriteString("\r\n")
	f.c2s(hb.String())
	f.s2c("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	f.closeBoth()

	recs := rec.waitN(t, 1)
	total := 0
	for k, v := range recs[0].Request.Headers {
		total += len(k) + len(v) + 4
	}
	if total > maxHeaderStoreBytes {
		t.Fatalf("Header 存储超 16KB 钳制: %d", total)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// s2cTruncated 模拟抓包截断帧（D-06）：payload 不会进入重组流，故不推进 sseq。
func (f *pktFeed) s2cTruncated() {
	f.offMs += 5
	p := capture.Packet{
		Ts: f.ts(), SrcIP: testSrvIP, DstIP: testCliIP, SrcPort: f.srvPort, DstPort: f.cliPort,
		Ingress: false, Seq: f.sseq, ACK: true, Truncated: true, OrigLen: 9000,
	}
	f.s.Assemble(p)
}

// ── D-06 截断快速失败 ──────────────────────────────────────

// 截断帧到达时响应侧正在读 Body（inflight）：finalize 须立即接管并补发
// response=null，不得干等空闲冲刷；一对请求/响应精确上报一次。
func TestTruncatedFastFailInflight(t *testing.T) {
	s, rec := newTestSensor(config.LevelL2, config.DefaultMaxBodySize, config.DefaultMasking())
	f := newPktFeed(s)
	f.handshake()
	f.c2s("GET /big HTTP/1.1\r\nHost: h\r\n\r\n")
	f.s2c("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 5000\r\n\r\n" +
		strings.Repeat("a", 100))
	time.Sleep(50 * time.Millisecond) // 让响应侧进入 Body 读取（inflight）
	f.s2cTruncated()

	recs := rec.waitN(t, 1) // 3s 内补发，证明不等 ~90s 空闲冲刷
	r := recs[0]
	if r.Request.URI != "/big" {
		t.Fatalf("请求解析错误: %+v", r.Request)
	}
	if r.Response != nil || r.ResponseTS != nil || r.LatencyMs != nil {
		t.Fatalf("截断快速失败应补 response=null: %+v", r)
	}
	f.closeBoth()
	time.Sleep(300 * time.Millisecond)
	if n := rec.count(); n != 1 {
		t.Fatalf("一对请求只应上报一次, got %d", n)
	}
	if s.Stats.ParseFallbacks.Load() == 0 {
		t.Fatal("截断快速失败应计入 ParseFallbacks")
	}
}

// 截断帧到达时请求尚在配对队列（reqCh）：finalize 排空队列补发 null。
func TestTruncatedFastFailQueued(t *testing.T) {
	s, rec := newTestSensor(config.LevelL2, config.DefaultMaxBodySize, config.DefaultMasking())
	f := newPktFeed(s)
	f.handshake()
	f.c2s("GET /queued HTTP/1.1\r\nHost: h\r\n\r\n")
	f.s2cTruncated()

	recs := rec.waitN(t, 1)
	if recs[0].Request.URI != "/queued" || recs[0].Response != nil {
		t.Fatalf("截断快速失败应补 response=null: %+v", recs[0])
	}
	f.closeBoth()
	time.Sleep(300 * time.Millisecond)
	if n := rec.count(); n != 1 {
		t.Fatalf("一对请求只应上报一次, got %d", n)
	}
	if s.Stats.ParseFallbacks.Load() == 0 {
		t.Fatal("截断快速失败应计入 ParseFallbacks")
	}
}
