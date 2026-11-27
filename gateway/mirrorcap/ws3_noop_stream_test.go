package mirrorcap

import (
	"runtime"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
)

// TestStreamFactoryRejectAndNoConsumerZeroGoroutines 验证超并发上限或无消费者时返回零开销 noopTCPStream，
// 不为被拒绝连接额外拉起 DiscardBytesToEOF goroutine。
func TestStreamFactoryRejectAndNoConsumerZeroGoroutines(t *testing.T) {
	stats := &Stats{}
	netFlow, _ := gopacket.FlowFromEndpoints(layers.NewIPEndpoint([]byte{10, 0, 0, 1}), layers.NewIPEndpoint([]byte{10, 0, 0, 2}))
	tcpFlow, _ := gopacket.FlowFromEndpoints(layers.NewTCPPortEndpoint(12345), layers.NewTCPPortEndpoint(80))

	// 1. maxConn 已满时的拒绝路径
	fFull := &streamFactory{stats: stats, maxConn: 1}
	fFull.active.Store(1)
	before := runtime.NumGoroutine()
	for i := 0; i < 200; i++ {
		st := fFull.New(netFlow, tcpFlow)
		if _, ok := st.(noopTCPStream); !ok {
			t.Fatalf("expected noopTCPStream when maxConn exceeded, got %T", st)
		}
		st.Reassembled([]tcpassembly.Reassembly{{Bytes: []byte("GET / HTTP/1.1\r\n\r\n")}})
		st.ReassemblyComplete()
	}
	after := runtime.NumGoroutine()
	if after > before+10 {
		t.Fatalf("rejected streams spawned goroutines: before=%d after=%d", before, after)
	}
	if got := stats.StreamsRejected.Load(); got != 200 {
		t.Fatalf("StreamsRejected = %d, want 200", got)
	}

	// 2. 无消费者路径（detect=nil 且 sniff=nil）同样返回 noopTCPStream 且不泄 active
	fNone := &streamFactory{stats: stats, maxConn: 10}
	st := fNone.New(netFlow, tcpFlow)
	if _, ok := st.(noopTCPStream); !ok {
		t.Fatalf("expected noopTCPStream with no consumer, got %T", st)
	}
	if fNone.active.Load() != 0 {
		t.Fatalf("active count leaked: %d", fNone.active.Load())
	}
}
