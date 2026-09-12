package clientip

import (
	"net/http"
	"net/netip"
	"testing"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/cidr"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/trustedproxy"
)

func mustSet(t *testing.T, defs ...trustedproxy.Proxy) *trustedproxy.Set {
	t.Helper()
	s, err := trustedproxy.NewSet(defs)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func pfx(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := cidr.ParseAddress(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func req(remoteAddr string, headers map[string]string) *http.Request {
	r, _ := http.NewRequest("GET", "http://example.com/", nil)
	r.RemoteAddr = remoteAddr
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestDirectConnection(t *testing.T) {
	rs := NewResolver(0)
	set := mustSet(t, trustedproxy.Proxy{Name: "lb", Prefix: pfx(t, "10.0.0.0/8"), HeaderType: trustedproxy.HeaderXForwardedFor})
	// 直接访问（不可信来源）伪造 XFF 必须无效
	res := rs.Resolve(req("203.0.113.9:5555", map[string]string{"X-Forwarded-For": "1.1.1.1"}), set)
	if res.Source != SourceConnection || res.ClientIP.String() != "203.0.113.9" {
		t.Errorf("untrusted source must ignore XFF: %+v", res)
	}
}

func TestSingleTrustedProxy(t *testing.T) {
	rs := NewResolver(0)
	set := mustSet(t, trustedproxy.Proxy{Name: "lb", Prefix: pfx(t, "10.0.0.1"), HeaderType: trustedproxy.HeaderXForwardedFor})
	res := rs.Resolve(req("10.0.0.1:8080", map[string]string{"X-Forwarded-For": "198.51.100.7"}), set)
	if res.ClientIP.String() != "198.51.100.7" || res.Source != SourceXForwardedFor || res.TrustedProxyUsed != "lb" {
		t.Errorf("single trusted proxy: %+v", res)
	}
}

func TestMultiLevelChain(t *testing.T) {
	rs := NewResolver(0)
	set := mustSet(t,
		trustedproxy.Proxy{Name: "lb1", Prefix: pfx(t, "10.0.0.1"), HeaderType: trustedproxy.HeaderXForwardedFor},
		trustedproxy.Proxy{Name: "cdn", Prefix: pfx(t, "172.16.0.0/12"), HeaderType: trustedproxy.HeaderXForwardedFor},
	)
	// client, cdn(172.16.5.5) 可信, lb1 连接源可信 → 客户端为 198.51.100.7
	res := rs.Resolve(req("10.0.0.1:8080", map[string]string{"X-Forwarded-For": "198.51.100.7, 172.16.5.5"}), set)
	if res.ClientIP.String() != "198.51.100.7" {
		t.Errorf("multi-level chain: %+v", res)
	}
	// 混合可信与非可信：client(198.51.100.7), 非可信(203.0.113.1), cdn可信
	// 从右跳过可信 172.16.5.5 → 203.0.113.1 非可信 = 客户端（不可信其左侧声明）
	res = rs.Resolve(req("10.0.0.1:8080", map[string]string{"X-Forwarded-For": "198.51.100.7, 203.0.113.1, 172.16.5.5"}), set)
	if res.ClientIP.String() != "203.0.113.1" {
		t.Errorf("mixed chain should stop at first untrusted from right: %+v", res)
	}
}

func TestChainTooLong(t *testing.T) {
	rs := NewResolver(4)
	set := mustSet(t, trustedproxy.Proxy{Name: "lb", Prefix: pfx(t, "10.0.0.1"), HeaderType: trustedproxy.HeaderXForwardedFor})
	res := rs.Resolve(req("10.0.0.1:8080", map[string]string{"X-Forwarded-For": "1.1.1.1, 2.2.2.2, 3.3.3.3, 4.4.4.4, 5.5.5.5"}), set)
	if !res.ChainTooLong || res.ClientIP.String() != "10.0.0.1" {
		t.Errorf("chain too long should fallback to connection: %+v", res)
	}
}

func TestInvalidHeaderFallback(t *testing.T) {
	rs := NewResolver(0)
	set := mustSet(t, trustedproxy.Proxy{Name: "lb", Prefix: pfx(t, "10.0.0.1"), HeaderType: trustedproxy.HeaderXForwardedFor})
	res := rs.Resolve(req("10.0.0.1:8080", map[string]string{"X-Forwarded-For": "not-an-ip, 1.1.1.1"}), set)
	if !res.HeaderInvalid || res.ClientIP.String() != "10.0.0.1" {
		t.Errorf("invalid header fallback: %+v", res)
	}
}

func TestXRealIP(t *testing.T) {
	rs := NewResolver(0)
	set := mustSet(t, trustedproxy.Proxy{Name: "nginx", Prefix: pfx(t, "10.0.0.2"), HeaderType: trustedproxy.HeaderXRealIP})
	res := rs.Resolve(req("10.0.0.2:80", map[string]string{"X-Real-IP": "198.51.100.20"}), set)
	if res.ClientIP.String() != "198.51.100.20" || res.Source != SourceXRealIP {
		t.Errorf("x-real-ip: %+v", res)
	}
}

func TestForwardedHeader(t *testing.T) {
	rs := NewResolver(0)
	set := mustSet(t, trustedproxy.Proxy{Name: "cdn", Prefix: pfx(t, "10.0.0.3"), HeaderType: trustedproxy.HeaderForwarded})
	res := rs.Resolve(req("10.0.0.3:80", map[string]string{"Forwarded": `for=198.51.100.1:5678;proto=https, for="[2001:db8::1]", for=unknown`}), set)
	// 链: 198.51.100.1, 2001:db8::1（unknown 跳过）→ 右端 2001:db8::1 非可信 = 客户端
	if res.ClientIP.String() != "2001:db8::1" || res.Source != SourceForwarded {
		t.Errorf("forwarded: %+v", res)
	}
}

func TestCustomHeaderOnlyForConfiguredProxy(t *testing.T) {
	rs := NewResolver(0)
	set := mustSet(t,
		trustedproxy.Proxy{Name: "cdn", Prefix: pfx(t, "10.0.0.4"), HeaderType: trustedproxy.HeaderCustom, CustomHeaderName: "X-True-Client"},
		trustedproxy.Proxy{Name: "lb", Prefix: pfx(t, "10.0.0.5"), HeaderType: trustedproxy.HeaderXForwardedFor},
	)
	// 配置 CUSTOM 的代理：读自定义头
	res := rs.Resolve(req("10.0.0.4:80", map[string]string{"X-True-Client": "198.51.100.30"}), set)
	if res.ClientIP.String() != "198.51.100.30" || res.Source != SourceCustomHeader {
		t.Errorf("custom header: %+v", res)
	}
	// 未配置 CUSTOM 的代理：自定义头必须被忽略
	res = rs.Resolve(req("10.0.0.5:80", map[string]string{"X-True-Client": "198.51.100.30"}), set)
	if res.ClientIP.String() != "10.0.0.5" || res.Source != SourceConnection {
		t.Errorf("custom header must be ignored for non-CUSTOM proxy: %+v", res)
	}
}

func TestIPv6AndMapped(t *testing.T) {
	rs := NewResolver(0)
	set := mustSet(t, trustedproxy.Proxy{Name: "lb6", Prefix: pfx(t, "2001:db8:ffff::/48"), HeaderType: trustedproxy.HeaderXForwardedFor})
	res := rs.Resolve(req("[2001:db8:ffff::1]:80", map[string]string{"X-Forwarded-For": "::ffff:198.51.100.9"}), set)
	if res.ClientIP.String() != "198.51.100.9" {
		t.Errorf("v4-mapped normalize: %+v", res)
	}
}

func TestControlCharsRejected(t *testing.T) {
	rs := NewResolver(0)
	set := mustSet(t, trustedproxy.Proxy{Name: "lb", Prefix: pfx(t, "10.0.0.1"), HeaderType: trustedproxy.HeaderXForwardedFor})
	r := req("10.0.0.1:80", nil)
	r.Header["X-Forwarded-For"] = []string{"1.1.1.1\r\nInjected: yes"}
	res := rs.Resolve(r, set)
	if !res.HeaderInvalid {
		t.Errorf("control chars must be rejected: %+v", res)
	}
}

func TestAllTrustedChainFallback(t *testing.T) {
	rs := NewResolver(0)
	set := mustSet(t,
		trustedproxy.Proxy{Name: "lb", Prefix: pfx(t, "10.0.0.0/8"), HeaderType: trustedproxy.HeaderXForwardedFor},
		trustedproxy.Proxy{Name: "cdn", Prefix: pfx(t, "172.16.0.0/12"), HeaderType: trustedproxy.HeaderXForwardedFor},
	)
	// 全链可信（10.0.0.9 与 172.16.5.5 均可信）：最左端声明可被客户端注入，
	// 不采信，保守回落连接源并产生伪造回落标记（M-26/S11）
	res := rs.Resolve(req("10.0.0.1:8080", map[string]string{"X-Forwarded-For": "10.0.0.9, 172.16.5.5"}), set)
	if !res.ChainAllTrusted {
		t.Errorf("all-trusted chain must set ChainAllTrusted: %+v", res)
	}
	if res.ClientIP.String() != "10.0.0.1" || res.Source != SourceConnection {
		t.Errorf("all-trusted chain must fallback to connection: %+v", res)
	}
	if res.ChainSummary != "10.0.0.9, 172.16.5.5" {
		t.Errorf("chain summary must be preserved for observability: %+v", res)
	}
}

func TestPartialTrustedChainNoFallback(t *testing.T) {
	rs := NewResolver(0)
	set := mustSet(t,
		trustedproxy.Proxy{Name: "lb", Prefix: pfx(t, "10.0.0.0/8"), HeaderType: trustedproxy.HeaderXForwardedFor},
		trustedproxy.Proxy{Name: "cdn", Prefix: pfx(t, "172.16.0.0/12"), HeaderType: trustedproxy.HeaderXForwardedFor},
	)
	// 部分可信：从右跳过可信 172.16.5.5，第一个非可信 198.51.100.7 为客户端，不触发回落标记
	res := rs.Resolve(req("10.0.0.1:8080", map[string]string{"X-Forwarded-For": "198.51.100.7, 172.16.5.5"}), set)
	if res.ChainAllTrusted {
		t.Errorf("partial trusted chain must not set ChainAllTrusted: %+v", res)
	}
	if res.ClientIP.String() != "198.51.100.7" || res.Source != SourceXForwardedFor {
		t.Errorf("partial trusted chain should take first untrusted from right: %+v", res)
	}
}

func TestAllTrustedChainTooLongPrecedence(t *testing.T) {
	rs := NewResolver(2)
	set := mustSet(t, trustedproxy.Proxy{Name: "lb", Prefix: pfx(t, "10.0.0.0/8"), HeaderType: trustedproxy.HeaderXForwardedFor})
	// 链超限优先于全链可信判定：回落连接源且只标记 ChainTooLong
	res := rs.Resolve(req("10.0.0.1:8080", map[string]string{"X-Forwarded-For": "10.0.0.2, 10.0.0.3, 10.0.0.4"}), set)
	if !res.ChainTooLong || res.ChainAllTrusted {
		t.Errorf("chain too long takes precedence over all-trusted fallback: %+v", res)
	}
	if res.ClientIP.String() != "10.0.0.1" || res.Source != SourceConnection {
		t.Errorf("chain too long should fallback to connection: %+v", res)
	}
}

func TestXRealIPTrustedValueFallback(t *testing.T) {
	rs := NewResolver(0)
	set := mustSet(t, trustedproxy.Proxy{Name: "nginx", Prefix: pfx(t, "10.0.0.0/8"), HeaderType: trustedproxy.HeaderXRealIP})
	// X-Real-IP 声明值本身落在可信段：等价全链可信，回落连接源
	res := rs.Resolve(req("10.0.0.2:80", map[string]string{"X-Real-IP": "10.0.0.9"}), set)
	if !res.ChainAllTrusted || res.ClientIP.String() != "10.0.0.2" || res.Source != SourceConnection {
		t.Errorf("trusted x-real-ip value must fallback to connection: %+v", res)
	}
}
