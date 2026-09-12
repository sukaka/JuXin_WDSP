package trustedproxy

import (
	"net/netip"
	"testing"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/cidr"
)

func tp(t *testing.T, name, addr string, ht HeaderType, prio int) Proxy {
	t.Helper()
	p, err := cidr.ParseAddress(addr)
	if err != nil {
		t.Fatal(err)
	}
	return Proxy{Name: name, Prefix: p, HeaderType: ht, Priority: prio}
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	ip, err := cidr.ParseIP(s)
	if err != nil {
		t.Fatal(err)
	}
	return ip
}

func mustPfx(t *testing.T, s string) netip.Prefix {
	t.Helper()
	pf, err := cidr.ParseAddress(s)
	if err != nil {
		t.Fatal(err)
	}
	return pf
}

func TestSetMatchPriority(t *testing.T) {
	s, err := NewSet([]Proxy{
		tp(t, "broad", "10.0.0.0/8", HeaderXForwardedFor, 100),
		tp(t, "specific", "10.1.1.1", HeaderXRealIP, 10),
	})
	if err != nil {
		t.Fatal(err)
	}
	// 精确匹配优先（优先级数值小）
	p := s.Match(mustAddr(t, "10.1.1.1"))
	if p == nil || p.Name != "specific" {
		t.Errorf("expected specific proxy, got %+v", p)
	}
	p = s.Match(mustAddr(t, "10.2.2.2"))
	if p == nil || p.Name != "broad" {
		t.Errorf("expected broad proxy, got %+v", p)
	}
	if s.Trusted(mustAddr(t, "11.0.0.1")) {
		t.Error("untrusted ip should not match")
	}
}

func TestSetValidation(t *testing.T) {
	if _, err := NewSet([]Proxy{tp(t, "bad", "10.0.0.1", "NOPE", 1)}); err == nil {
		t.Error("unknown header type should fail")
	}
	if _, err := NewSet([]Proxy{{Name: "c", Prefix: mustPfx(t, "10.0.0.1"), HeaderType: HeaderCustom, CustomHeaderName: "bad header!"}}); err == nil {
		t.Error("invalid custom header name should fail")
	}
	if _, err := NewSet([]Proxy{{Name: "c", Prefix: mustPfx(t, "10.0.0.1"), HeaderType: HeaderCustom, CustomHeaderName: "X-True-IP"}}); err != nil {
		t.Errorf("valid custom header should pass: %v", err)
	}
}
