package jiuzhang_guard

import (
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
