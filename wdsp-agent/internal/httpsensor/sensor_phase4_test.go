// Phase 4 按流生效等级接线测试（契约 §2.4/§3.1）：L0 不建链、
// 规则提升后从当前请求起采集（已过不补）、帽压回落终止既有连接。
package httpsensor

import (
	"testing"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
)

func TestAssembleLevelL0NoConn(t *testing.T) {
	s, rec := newTestSensor(config.LevelL0, config.DefaultMaxBodySize, config.DefaultMasking())
	f := newPktFeed(s)
	f.level = config.LevelL0
	f.handshake()
	f.c2s("GET / HTTP/1.1\r\nHost: h\r\n\r\n")
	f.s2c("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	f.closeBoth()
	// L0 不建链、不产生记录
	if n := rec.count(); n != 0 {
		t.Fatalf("L0 不应产生 HTTP 记录: %d", n)
	}
	if s.Stats.RecordsEmitted.Load() != 0 {
		t.Fatalf("L0 不应 emit: %d", s.Stats.RecordsEmitted.Load())
	}
}

func TestAssembleLevelBoostFromCurrentRequest(t *testing.T) {
	// 全局 L0：请求行命中规则后由上层以 L2 喂入（模拟"L0 流即时提升"）
	s, rec := newTestSensor(config.LevelL0, config.DefaultMaxBodySize, config.DefaultMasking())
	f := newPktFeed(s)
	// 握手与首请求前的包按 L0 流过（不建链，已过的不补）
	f.level = config.LevelL0
	f.handshake()
	// 从携带请求行的包起按 L2 喂入（提升即时生效）
	f.level = config.LevelL2
	f.c2s("POST /api/payment HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n{\"a\":1}")
	f.s2c("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")
	f.closeBoth()

	recs := rec.waitN(t, 1)
	r := recs[0]
	if r.Request.Method != "POST" || r.Request.URI != "/api/payment" {
		t.Fatalf("提升后应从当前请求起采集: %+v", r.Request)
	}
	// L2 采集 Body
	if r.Request.Body != `{"a":1}` {
		t.Fatalf("L2 应采请求 Body: %q", r.Request.Body)
	}
	if r.Response == nil || r.Response.Status != 200 {
		t.Fatalf("响应应配对: %+v", r.Response)
	}
}

func TestAssembleLevelCapPressTerminatesConn(t *testing.T) {
	s, rec := newTestSensor(config.LevelL2, config.DefaultMaxBodySize, config.DefaultMasking())
	f := newPktFeed(s)
	f.level = config.LevelL2
	f.handshake()
	f.c2s("POST /upload HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n{\"a\":1}")
	time.Sleep(150 * time.Millisecond) // 等待请求解析入配对队列（消费 goroutine 异步）
	// 降级帽压回 L0：既有连接立即终止，已解析未配对请求补发 response=null
	f.level = config.LevelL0
	f.s2c("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n") // 帽压后的包触发终止（不再喂入重组器）
	recs := rec.waitN(t, 1)
	r := recs[0]
	if r.Request.Method != "POST" {
		t.Fatalf("已采集请求不应丢: %+v", r.Request)
	}
	if r.Response != nil || r.ResponseTS != nil {
		t.Fatalf("终止应补发 response=null: %+v", r.Response)
	}
	// 后续包不再建链
	f.c2s("GET /again HTTP/1.1\r\nHost: h\r\n\r\n")
	time.Sleep(50 * time.Millisecond)
	if rec.count() != 1 {
		t.Fatalf("帽压后不应再产生记录: %d", rec.count())
	}
}

func TestConnLevelGatesBodyPerMessage(t *testing.T) {
	// 全局 L2 策略下按流等级喂入：L1 消息无 Body，升级 L2 后新消息采 Body
	s, rec := newTestSensor(config.LevelL2, config.DefaultMaxBodySize, config.DefaultMasking())
	f := newPktFeed(s)
	f.level = config.LevelL1
	f.handshake()
	f.c2s("POST /a HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n{\"a\":1}")
	f.s2c("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	// 流级提升 L2（规则命中）：从下一请求起采 Body
	f.level = config.LevelL2
	f.c2s("POST /b HTTP/1.1\r\nHost: h\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n{\"b\":2}")
	f.s2c("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	f.closeBoth()

	recs := rec.waitN(t, 2)
	if recs[0].Request.Body != "" || recs[0].Request.OriginalBodySize != 7 {
		t.Fatalf("L1 消息不采 Body 但记原始大小: %+v", recs[0].Request)
	}
	if recs[1].Request.Body != `{"b":2}` {
		t.Fatalf("提升 L2 后新请求应采 Body: %q", recs[1].Request.Body)
	}
}
