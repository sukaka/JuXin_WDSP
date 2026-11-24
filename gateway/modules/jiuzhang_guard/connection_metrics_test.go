package jiuzhang_guard

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
)

func TestConnectionMetricsListener(t *testing.T) {
	metrics := &connectionMetrics{}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wrapped := (&ConnectionMetrics{metrics: metrics}).WrapListener(listener)
	defer wrapped.Close()

	client, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	server, err := wrapped.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if got := metrics.acceptedTotal.Load(); got != 1 {
		t.Fatalf("accepted_total = %d, want 1", got)
	}
	if got := metrics.active.Load(); got != 1 {
		t.Fatalf("active = %d, want 1", got)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	_ = server.Close()
	if got := metrics.active.Load(); got != 0 {
		t.Fatalf("active after duplicate Close = %d, want 0", got)
	}
	_ = client.Close()
}

func TestConnectionMetricsProvisionedWrappersShareOnlyNodeCounters(t *testing.T) {
	first := &ConnectionMetrics{}
	second := &ConnectionMetrics{}
	if err := first.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	if err := second.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	if first.metrics != globalConnectionMetrics || second.metrics != globalConnectionMetrics {
		t.Fatal("listener wrappers must share the stable process-wide connection counter")
	}
}

func TestConnectionMetricsConcurrentConnections(t *testing.T) {
	metrics := &connectionMetrics{}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wrapped := (&ConnectionMetrics{metrics: metrics}).WrapListener(listener)
	defer wrapped.Close()

	const connectionCount = 32
	clients := make([]net.Conn, 0, connectionCount)
	servers := make([]net.Conn, 0, connectionCount)
	for i := 0; i < connectionCount; i++ {
		client, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		server, err := wrapped.Accept()
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, client)
		servers = append(servers, server)
	}
	if got := metrics.acceptedTotal.Load(); got != connectionCount {
		t.Fatalf("accepted_total = %d, want %d", got, connectionCount)
	}
	if got := metrics.active.Load(); got != connectionCount {
		t.Fatalf("active = %d, want %d", got, connectionCount)
	}

	var wg sync.WaitGroup
	for i := range servers {
		wg.Add(2)
		go func(server net.Conn) {
			defer wg.Done()
			_ = server.Close()
			_ = server.Close()
		}(servers[i])
		go func(client net.Conn) {
			defer wg.Done()
			_ = client.Close()
		}(clients[i])
	}
	wg.Wait()
	if got := metrics.active.Load(); got != 0 {
		t.Fatalf("active after concurrent duplicate closes = %d, want 0", got)
	}
}

func TestConnectionMetricsTracksBytesInAndOut(t *testing.T) {
	metrics := &connectionMetrics{}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wrapped := (&ConnectionMetrics{metrics: metrics}).WrapListener(listener)
	defer wrapped.Close()

	client, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := wrapped.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	inPayload := []byte("hello-gateway-inbound-bytes")
	outPayload := []byte("response-outbound-payload-123456")

	errCh := make(chan error, 1)
	go func() {
		if _, err := client.Write(inPayload); err != nil {
			errCh <- err
			return
		}
		reply := make([]byte, len(outPayload))
		if _, err := io.ReadFull(client, reply); err != nil {
			errCh <- err
			return
		}
		_ = client.Close()
		errCh <- nil
	}()

	received := make([]byte, len(inPayload))
	if _, err := io.ReadFull(server, received); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Write(outPayload); err != nil {
		t.Fatal(err)
	}
	// Trigger an EOF read (n == 0, err == io.EOF) to ensure zero-byte reads do not corrupt totals.
	var eofBuf [8]byte
	_, _ = server.Read(eofBuf[:])

	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if got := metrics.bytesInTotal.Load(); got != uint64(len(inPayload)) {
		t.Fatalf("bytes_in_total = %d, want %d", got, len(inPayload))
	}
	if got := metrics.bytesOutTotal.Load(); got != uint64(len(outPayload)) {
		t.Fatalf("bytes_out_total = %d, want %d", got, len(outPayload))
	}
}

func TestConnectionMetricsCountingConnUnwrapAndNetConn(t *testing.T) {
	metrics := &connectionMetrics{}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	wrapped := (&ConnectionMetrics{metrics: metrics}).WrapListener(listener)
	defer wrapped.Close()

	client, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	server, err := wrapped.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	netConnProvider, ok := server.(interface{ NetConn() net.Conn })
	if !ok {
		t.Fatalf("accepted conn %T does not implement NetConn() net.Conn", server)
	}
	unwrapper, ok := server.(interface{ Unwrap() net.Conn })
	if !ok {
		t.Fatalf("accepted conn %T does not implement Unwrap() net.Conn", server)
	}
	rawA := netConnProvider.NetConn()
	rawB := unwrapper.Unwrap()
	if rawA == nil || rawB == nil || rawA != rawB {
		t.Fatalf("NetConn()=%v Unwrap()=%v, want same non-nil underlying conn", rawA, rawB)
	}
	if _, ok := rawA.(*net.TCPConn); !ok {
		t.Fatalf("underlying conn = %T, want *net.TCPConn", rawA)
	}
}
