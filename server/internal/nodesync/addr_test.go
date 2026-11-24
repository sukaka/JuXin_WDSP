package nodesync

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
)

type stubResolver struct {
	fn func(ctx context.Context, network, host string) ([]net.IP, error)
}

func (r stubResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	return r.fn(ctx, network, host)
}

func TestValidateSyncAgentAddr(t *testing.T) {
	validAddrs := []string{
		"http://127.0.0.1:18443",
		"https://127.0.0.1:18443",
		"https://10.0.0.2:18443",
		"https://172.16.10.20:18443",
		"https://192.168.100.5:18443",
		"https://[::1]:18443",
		"https://[fd12:3456:789a::1]:18443",
		"https://10.0.0.2/",
	}
	for _, addr := range validAddrs {
		if err := ValidateSyncAgentAddr(addr); err != nil {
			t.Errorf("expected %q to be valid, got error: %v", addr, err)
		}
	}

	deniedAddrs := []string{
		"",
		"   ",
		"unix:///var/run/caddy/admin.sock",
		"/var/run/caddy/admin.sock",
		"ftp://10.0.0.2:18443",
		"https://user:pass@10.0.0.2:18443",
		"https://10.0.0.2:18443/v1/health",
		"https://10.0.0.2:18443?foo=bar",
		"https://10.0.0.2:18443#frag",
		"https://10.0.0.2:0",
		"https://10.0.0.2:70000",
		"https://8.8.8.8:18443",
		"https://1.1.1.1:18443",
		"http://169.254.169.254",
		"http://169.254.170.2:80",
		"http://100.100.100.200:80",
		"http://[fd00:ec2::254]:18443",
		"http://169.254.10.20:18443",
		"http://[fe80::1]:18443",
		"http://[::ffff:169.254.169.254]:18443",
		"http://[::ffff:8.8.8.8]:18443",
		"http://0.0.0.0:18443",
		"http://224.0.0.1:18443",
		"https://10.0.0.2:18443\r\n",
	}
	for _, addr := range deniedAddrs {
		err := ValidateSyncAgentAddr(addr)
		if err == nil {
			t.Errorf("expected %q to be rejected, but succeeded", addr)
			continue
		}
		if !errors.Is(err, ErrSyncAgentAddrDenied) {
			t.Errorf("expected ErrSyncAgentAddrDenied for %q, got %v", addr, err)
		}
	}
}

func TestValidateSyncAgentAddrHostnameResolution(t *testing.T) {
	ctx := context.Background()

	// All resolved IPs private -> allowed.
	resOK := stubResolver{fn: func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.0.0.2"), net.ParseIP("fd00::2")}, nil
	}}
	if err := ValidateSyncAgentAddrWithResolver(ctx, "https://gw-b.internal:18443", resOK); err != nil {
		t.Fatalf("expected private hostname to pass: %v", err)
	}

	// Mixed private + public IP -> rejected.
	resMixed := stubResolver{fn: func(context.Context, string, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.0.0.2"), net.ParseIP("8.8.8.8")}, nil
	}}
	if err := ValidateSyncAgentAddrWithResolver(ctx, "https://mixed.internal:18443", resMixed); !errors.Is(err, ErrSyncAgentAddrDenied) {
		t.Fatalf("expected mixed public/private hostname to be rejected, got %v", err)
	}
}

func TestDialTimeDNSRebindingRejected(t *testing.T) {
	var calls atomic.Int32
	rebindResolver := stubResolver{fn: func(context.Context, string, string) ([]net.IP, error) {
		if calls.Add(1) == 1 {
			// Initial NewClient validation returns loopback IP.
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		}
		// At dial time, attacker flips DNS to cloud metadata / public IP!
		return []net.IP{net.ParseIP("169.254.169.254")}, nil
	}}

	client, err := NewClient(ClientConfig{
		Addr:      "http://rebind.internal:18443",
		SecretHex: testSharedSecretHex,
		Resolver:  rebindResolver,
	})
	if err != nil {
		t.Fatalf("NewClient unexpectedly failed initial private check: %v", err)
	}

	_, err = client.Health(context.Background())
	if err == nil {
		t.Fatal("expected dial-time DNS rebinding to be blocked")
	}
	if !errors.Is(err, ErrSyncAgentAddrDenied) {
		t.Fatalf("expected ErrSyncAgentAddrDenied on DNS rebinding, got %v", err)
	}
}
