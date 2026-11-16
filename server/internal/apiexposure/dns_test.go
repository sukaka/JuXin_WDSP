// dns_test.go 公网视角 DNS 判定测试：注入假查询函数（不做真实网络调用）覆盖
// PUBLIC / PRIVATE_ONLY / NXDOMAIN / NODATA / 多服务器故障切换 / 全失败 ERROR /
// 空域名与空服务器不产证据。
package apiexposure

import (
	"context"
	"errors"
	"net"
	"testing"
)

// fakeDNS 假查询：host → IPs 或错误（errIsNX 模拟权威 NXDOMAIN）。
type fakeDNS struct {
	byHost map[string][]net.IP
	err    map[string]error
	calls  []string // 调用记录（server|host）
}

func (f *fakeDNS) lookup(_ context.Context, server, host string) ([]net.IP, error) {
	f.calls = append(f.calls, server+"|"+host)
	if err := f.err[host]; err != nil {
		return nil, err
	}
	return f.byHost[host], nil
}

func nxdomainErr() error {
	return &net.DNSError{IsNotFound: true, Name: "nx.test"}
}

func TestResolvePublicViewMatrix(t *testing.T) {
	servers := []string{"223.5.5.5", "8.8.8.8"}
	cases := []struct {
		name    string
		hosts   map[string][]net.IP
		errs    map[string]error
		host    string
		servers []string
		want    string
	}{
		{"解析到公网 IP", map[string][]net.IP{"api.pub.test": {net.ParseIP("93.184.216.34")}}, nil, "api.pub.test", servers, DNSPublic},
		{"公网与内网混合答录含公网即 PUBLIC", map[string][]net.IP{"mix.test": {net.ParseIP("10.0.0.1"), net.ParseIP("1.1.1.1")}}, nil, "mix.test", servers, DNSPublic},
		{"仅解析到内网", map[string][]net.IP{"intra.test": {net.ParseIP("10.0.0.1"), net.ParseIP("192.168.1.1")}}, nil, "intra.test", servers, DNSPrivateOnly},
		{"NXDOMAIN", nil, map[string]error{"no.test": nxdomainErr()}, "no.test", servers, DNSNXDomain},
		{"NODATA 空答录视同不可解析", map[string][]net.IP{"nodata.test": {}}, nil, "nodata.test", servers, DNSNXDomain},
		{"全部服务器失败 ERROR", nil, map[string]error{"down.test": errors.New("i/o timeout")}, "down.test", servers, DNSError},
		{"空域名不产证据", nil, nil, "", servers, ""},
		{"空服务器列表不产证据", nil, nil, "api.pub.test", nil, ""},
		{"域名末尾根点归一", map[string][]net.IP{"dot.test": {net.ParseIP("1.1.1.1")}}, nil, "dot.test.", servers, DNSPublic},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fk := &fakeDNS{byHost: c.hosts, err: c.errs}
			r := newTestResolver(fk.lookup)
			if got := r.ResolvePublicView(context.Background(), c.host, c.servers); got != c.want {
				t.Fatalf("ResolvePublicView(%q) = %s, want %s", c.host, got, c.want)
			}
		})
	}
}

// TestResolvePublicViewFailover 首台传输失败换次台并成功（次台结果为准）。
func TestResolvePublicViewFailover(t *testing.T) {
	fk := &fakeDNS{byHost: map[string][]net.IP{"ok.test": {net.ParseIP("1.1.1.1")}}}
	first := true
	r := newTestResolver(func(_ context.Context, server, host string) ([]net.IP, error) {
		if first {
			first = false
			return nil, errors.New("connection refused")
		}
		return fk.lookup(context.Background(), server, host)
	})
	if got := r.ResolvePublicView(context.Background(), "ok.test", []string{"bad.dns", "good.dns"}); got != DNSPublic {
		t.Fatalf("failover = %s, want PUBLIC", got)
	}
	if first {
		t.Fatal("expected first server to have been tried")
	}
}

// TestResolvePublicViewNilResolver nil 判定器返回空串（不产证据不 panic）。
func TestResolvePublicViewNilResolver(t *testing.T) {
	var r *PublicResolver
	if got := r.ResolvePublicView(context.Background(), "a.test", []string{"223.5.5.5"}); got != "" {
		t.Fatalf("nil resolver = %q, want empty", got)
	}
}
