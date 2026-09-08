//go:build ebpfsmoke

// eBPF/TC 后端冒烟测试（不进常规测试套件，需 privileged Linux 环境）：
//
//	go test -tags ebpfsmoke ./internal/ebpfcapture/ -run TestSmoke -v -count=1
//
// 覆盖：eBPF 对象加载（BTF/权限）、TCX 逐网卡 ingress+egress 挂载、
// ringbuf 事件上送与解码、端口 map 命中、内核计数（submitted）。
// 环境不满足（内核 <6.6 / 无 BTF / 无权限）时如实失败并记录现象。
package ebpfcapture

import (
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/capture"
	"github.com/jiuzhang-waf/wdsp-agent/internal/filter"
)

const smokePort = 18080

// TestSmokeTCXRingbuf lo 网卡全链路冒烟。
func TestSmokeTCXRingbuf(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:"+itoa(smokePort))
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer ln.Close() //nolint:errcheck // 测试清理
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() {
				defer c.Close() //nolint:errcheck // 测试清理
				buf := make([]byte, 4096)
				n, _ := c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
				_ = n
			}()
		}
	}()

	filt := filter.New([]uint16{smokePort}, filter.Both)
	st := &capture.Stats{}
	var mu sync.Mutex
	var got []capture.Packet
	b, err := NewBackend(capture.BackendConfig{
		Ifaces:   []string{"lo"},
		Filter:   filt,
		Consumer: func(p capture.Packet) { mu.Lock(); got = append(got, p); mu.Unlock() },
		Stats:    st,
		Log:      slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatalf("创建后端失败: %v", err)
	}
	if err := b.Start(); err != nil {
		t.Fatalf("eBPF 加载/TCX 挂载失败（需内核≥6.6+BTF+CAP_BPF/CAP_NET_ADMIN）: %v", err)
	}
	defer b.Close() //nolint:errcheck // 测试清理

	// 产生 HTTP 流量
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("拨号失败: %v", err)
	}
	if _, err := conn.Write([]byte("GET /smoke HTTP/1.1\r\nHost: smoke.local\r\n\r\n")); err != nil {
		t.Fatalf("写请求失败: %v", err)
	}
	_, _ = io.ReadAll(conn)
	conn.Close() //nolint:errcheck // 测试清理

	// 等待 ringbuf 事件（含 payload 的数据包可能晚于握手包到达）
	deadline := time.Now().Add(5 * time.Second)
	sawPayload := false
	for time.Now().Before(deadline) {
		mu.Lock()
		for _, p := range got {
			if len(p.Payload) > 0 {
				sawPayload = true
				break
			}
		}
		n := len(got)
		mu.Unlock()
		if sawPayload {
			break
		}
		if n == 0 {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		time.Sleep(50 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) == 0 {
		t.Fatalf("ringbuf 未收到任何事件（received=%d）", st.Received.Load())
	}
	t.Logf("收到 %d 个事件，received=%d filtered=%d", len(got), st.Received.Load(), st.Filtered.Load())

	var sawIngress, sawEgress bool
	for _, p := range got {
		if p.SrcPort == smokePort || p.DstPort == smokePort {
			if p.Ingress {
				sawIngress = true
			} else {
				sawEgress = true
			}
		}
	}
	if !sawIngress {
		t.Error("应捕获到 dst 端口命中的请求方向包（ingress 语义）")
	}
	if !sawEgress {
		t.Error("应捕获到 src 端口命中的响应方向包（egress 语义）")
	}
	if !sawPayload {
		t.Error("应捕获到含 payload 的包（HTTP 请求/响应字节）")
	}

	// 内核计数
	pkts, drops, kerr := b.KernelStats()
	if kerr != nil {
		t.Fatalf("KernelStats: %v", kerr)
	}
	t.Logf("内核计数 submitted=%d dropped=%d", pkts, drops)
	if pkts == 0 {
		t.Error("内核 submitted 计数应 >0")
	}

	// 端口热更：先静置排空在途事件，换到未使用端口后旧端口流量不再上送
	time.Sleep(500 * time.Millisecond)
	base := st.Received.Load()
	b.SetPorts([]uint16{smokePort + 1})
	conn2, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("二次拨号失败: %v", err)
	}
	_, _ = conn2.Write([]byte("GET /2 HTTP/1.1\r\n\r\n"))
	_, _ = io.ReadAll(conn2)
	conn2.Close() //nolint:errcheck // 测试清理
	time.Sleep(300 * time.Millisecond)
	if st.Received.Load() != base {
		t.Errorf("SetPorts 热更后旧端口仍上送: received %d → %d", base, st.Received.Load())
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
