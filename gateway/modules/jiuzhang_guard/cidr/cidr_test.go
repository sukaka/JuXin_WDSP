package cidr

import (
	"net/netip"
	"testing"
)

func TestParseIP(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"192.168.1.1", "192.168.1.1", false},
		{"2001:db8::1", "2001:db8::1", false},
		{"::ffff:192.168.1.1", "192.168.1.1", false}, // v4映射v6归一
		{"", "", true},
		{"example.com", "", true},            // 域名禁止
		{"http://1.2.3.4", "", true},         // 带协议禁止
		{"1.2.3.4:8080", "", true},           // 带端口禁止
		{"[2001:db8::1]:443", "", true},      // v6带端口禁止
		{"1.2.3.4/24", "", true},             // CIDR 应走 ParseCIDR
		{"10.0.0.*", "", true},               // 通配禁止
		{"1.2.3.4\nSet-Cookie: x", "", true}, // 控制字符禁止
		{"2001:db8::1%eth0", "", true},       // zone 禁止
	}
	for _, c := range cases {
		got, err := ParseIP(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseIP(%q) expected error, got %v", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseIP(%q) unexpected error: %v", c.in, err)
			continue
		}
		if got.String() != c.want {
			t.Errorf("ParseIP(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParseCIDR(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"10.0.0.0/8", "10.0.0.0/8", false},
		{"192.168.1.77/24", "192.168.1.0/24", false}, // 掩码化
		{"2001:db8::/32", "2001:db8::/32", false},
		{"::ffff:10.0.0.0/104", "10.0.0.0/8", false}, // 映射归一：104-96=8
		{"10.0.0.0/33", "", true},
		{"2001:db8::/129", "", true},
		{"abc/8", "", true},
		{"", "", true},
	}
	for _, c := range cases {
		got, err := ParseCIDR(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseCIDR(%q) expected error, got %v", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseCIDR(%q) unexpected error: %v", c.in, err)
			continue
		}
		if got.String() != c.want {
			t.Errorf("ParseCIDR(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParseAddress(t *testing.T) {
	p, err := ParseAddress("192.168.1.5")
	if err != nil || p.String() != "192.168.1.5/32" {
		t.Errorf("ParseAddress single v4 = %v, %v", p, err)
	}
	p, err = ParseAddress("2001:db8::1")
	if err != nil || p.String() != "2001:db8::1/128" {
		t.Errorf("ParseAddress single v6 = %v, %v", p, err)
	}
	if _, err = ParseAddress("bad!!"); err == nil {
		t.Error("ParseAddress invalid should error")
	}
}

func TestMatcher(t *testing.T) {
	entries := []Entry{}
	must := func(s string) {
		p, err := ParseAddress(s)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, Entry{Prefix: p, Meta: s})
	}
	must("192.168.1.1")
	must("10.0.0.0/8")
	must("2001:db8::/32")
	must("2001:db8::5")

	m := NewMatcher(entries)
	if !m.Contains(netip.MustParseAddr("192.168.1.1")) {
		t.Error("exact v4 miss")
	}
	if !m.Contains(netip.MustParseAddr("10.9.9.9")) {
		t.Error("cidr v4 miss")
	}
	if m.Contains(netip.MustParseAddr("11.0.0.1")) {
		t.Error("v4 false positive")
	}
	if !m.Contains(netip.MustParseAddr("2001:db8::5")) {
		t.Error("exact v6 miss")
	}
	if !m.Contains(netip.MustParseAddr("2001:db8::9999")) {
		t.Error("cidr v6 miss")
	}
	if m.Contains(netip.MustParseAddr("2001:db9::1")) {
		t.Error("v6 false positive")
	}
	// v4 映射 v6 查询也应命中 v4 条目
	if !m.Contains(netip.MustParseAddr("::ffff:192.168.1.1")) {
		t.Error("mapped v4 miss")
	}
}
