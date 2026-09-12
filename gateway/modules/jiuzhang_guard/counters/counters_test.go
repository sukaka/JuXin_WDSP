package counters

import (
	"io"
	"net"
	"testing"
	"time"
)

// 悬挂服务端（TCP 可连但永不响应）：NewValkeyClient 必须在读写超时内报错，
// 而非无限期阻塞——验证 ConnWriteTimeout 对 Valkey 悬挂的兜底（修复前该用例会挂死）。
func TestNewValkeyClient_HungServerFailsFast(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go io.Copy(io.Discard, c) // 只读不应答，保持连接悬挂
		}
	}()
	start := time.Now()
	cli, err := NewValkeyClient(ValkeyConfig{Address: ln.Addr().String()})
	if err == nil {
		cli.Close()
		t.Fatal("hung server must fail, not hang forever")
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("must fail within read/write timeout bound (%v), took %v", valkeyCmdTimeout, d)
	}
}

// 不可路由地址（RFC 5737 TEST-NET-1）：建连必须受 Dial 超时约束报错，而非挂死。
func TestNewValkeyClient_DialTimeout(t *testing.T) {
	start := time.Now()
	_, err := NewValkeyClient(ValkeyConfig{Address: "192.0.0.1:6390"})
	if err == nil {
		t.Fatal("unreachable address must fail")
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("dial must be bounded by valkeyDialTimeout (%v), took %v", valkeyDialTimeout, d)
	}
}
