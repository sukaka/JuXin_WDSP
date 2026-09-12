// 代码审查回归测试（批次5-A）：
// LOW-A7 双采集端口连接在重组器内正确配对（canonical 五元组排序兜底）。
package httpsensor

import (
	"io"
	"log/slog"
	"testing"

	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
)

// 两端端口均命中采集集（如 8080↔8080 互访）时，逐包方向判定随包向翻转；
// canonical 以五元组排序兜底后，同一连接两向须挂到不同半流槽位并正常配对。
func TestBothHitConnectionPairs(t *testing.T) {
	rec := &recorder{}
	// client 与 server 端口均在采集集（双采集端口互访场景）
	s := New("agent1", func(p uint16) bool { return p == testSrvPort || p == testCliPort }, rec.add,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.UpdatePolicy(config.LevelL2, config.DefaultMaxBodySize, config.DefaultMasking())
	f := newPktFeed(s)
	f.bothHit = true
	f.handshake()
	f.c2s("GET /both HTTP/1.1\r\nHost: h\r\n\r\n")
	f.s2c("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	f.closeBoth()

	recs := rec.waitN(t, 1)
	r := recs[0]
	if r.Request == nil || r.Request.Method != "GET" || r.Request.URI != "/both" {
		t.Fatalf("请求未配对: %+v", r.Request)
	}
	if r.Response == nil || r.Response.Status != 200 {
		t.Fatalf("响应未配对（双采集端口连接被拆/半流槽位冲突）: %+v", r.Response)
	}
	// canonical：小端点为 client 侧（10.0.0.1:51234 < 10.0.0.2:8080）
	if r.SrcIP != testCliIP || r.SrcPort != testCliPort || r.DstIP != testSrvIP || r.DstPort != testSrvPort {
		t.Fatalf("canonical 错误: %s:%d → %s:%d", r.SrcIP, r.SrcPort, r.DstIP, r.DstPort)
	}
}
