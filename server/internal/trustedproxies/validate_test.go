package trustedproxies

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeCIDRValid(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    string
		wantVer string
	}{
		{"单IPv4", "192.168.1.5", "192.168.1.5", IPVersion4},
		{"IPv4 CIDR已掩码", "192.168.1.0/24", "192.168.1.0/24", IPVersion4},
		{"IPv4 CIDR需掩码", "192.168.1.77/24", "192.168.1.0/24", IPVersion4},
		{"IPv4 /32", "10.0.0.9/32", "10.0.0.9/32", IPVersion4},
		{"单IPv6", "2001:DB8::1", "2001:db8::1", IPVersion6},
		{"IPv6 CIDR需掩码", "2001:db8::dead:1/32", "2001:db8::/32", IPVersion6},
		{"IPv6回环", "::1", "::1", IPVersion6},
		{"映射IPv6单地址归一", "::ffff:1.2.3.4", "1.2.3.4", IPVersion4},
		{"映射IPv6十六进制形式", "::ffff:c000:201", "192.0.2.1", IPVersion4},
		{"映射IPv6前缀归一并掩码", "::ffff:c0a8:14d/120", "192.168.1.0/24", IPVersion4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ver, err := NormalizeCIDR(c.input)
			if err != nil {
				t.Fatalf("NormalizeCIDR(%q) error: %v", c.input, err)
			}
			if got != c.want {
				t.Errorf("NormalizeCIDR(%q) = %q, want %q", c.input, got, c.want)
			}
			if ver != c.wantVer {
				t.Errorf("NormalizeCIDR(%q) version = %q, want %q", c.input, ver, c.wantVer)
			}
		})
	}
}

func TestNormalizeCIDRInvalid(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"空串", ""},
		{"域名", "proxy.example.com"},
		{"带协议", "http://192.168.1.0/24"},
		{"带端口", "192.168.1.5:8080"},
		{"通配符", "192.168.1.*"},
		{"掩码越界v4", "192.168.1.0/33"},
		{"掩码越界v6", "2001:db8::/129"},
		{"映射前缀掩码不足96", "::ffff:1.2.3.4/80"},
		{"控制字符换行", "192.168.1.5\n"},
		{"控制字符制表", "\t192.168.1.5"},
		{"带区域", "fe80::1%eth0"},
		{"超长输入", strings.Repeat("1", 65)},
		{"非掩码CIDR带空格", " 192.168.1.0/24"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := NormalizeCIDR(c.input)
			if err == nil {
				t.Fatalf("NormalizeCIDR(%q) should be rejected", c.input)
			}
			if !errors.Is(err, ErrInvalidInput) {
				t.Errorf("NormalizeCIDR(%q) error should wrap ErrInvalidInput, got %v", c.input, err)
			}
		})
	}
}

func TestMatchCIDR(t *testing.T) {
	cases := []struct {
		name string
		cidr string
		ip   string
		want bool
	}{
		{"v4前缀命中", "192.168.1.0/24", "192.168.1.77", true},
		{"v4前缀未命中", "192.168.1.0/24", "192.168.2.1", false},
		{"v4单地址相等", "10.0.0.1", "10.0.0.1", true},
		{"v4单地址不等", "10.0.0.1", "10.0.0.2", false},
		{"v6前缀命中", "2001:db8::/32", "2001:db8::1", true},
		{"v6单地址", "::1", "::1", true},
		{"映射测试IP命中v4前缀", "192.168.1.0/24", "::ffff:192.168.1.5", true},
		{"映射CIDR命中v4测试IP", "::ffff:c0a8:100/120", "192.168.1.5", true},
		{"族不匹配", "192.168.1.0/24", "::1", false},
		{"非法IP", "192.168.1.0/24", "not-an-ip", false},
		{"非法CIDR", "garbage", "192.168.1.5", false},
		{"边界首地址", "10.0.0.0/30", "10.0.0.0", true},
		{"边界末地址", "10.0.0.0/30", "10.0.0.3", true},
		{"边界外", "10.0.0.0/30", "10.0.0.4", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := MatchCIDR(c.cidr, c.ip); got != c.want {
				t.Errorf("MatchCIDR(%q, %q) = %v, want %v", c.cidr, c.ip, got, c.want)
			}
		})
	}
}

func validProxy() *TrustedProxy {
	return &TrustedProxy{
		Name:       "办公网出口代理",
		CIDR:       "192.168.1.77/24",
		HeaderType: HeaderXForwardedFor,
		Priority:   100,
		Status:     StatusEnabled,
		Scope:      ScopeGlobal,
	}
}

func TestValidateInputNormalizes(t *testing.T) {
	p := validProxy()
	if err := ValidateInput(p); err != nil {
		t.Fatalf("valid proxy rejected: %v", err)
	}
	if p.CIDR != "192.168.1.0/24" {
		t.Errorf("cidr not masked: %q", p.CIDR)
	}
	if p.IPVersion != IPVersion4 {
		t.Errorf("ip_version = %q, want IPV4", p.IPVersion)
	}
}

func TestValidateInputName(t *testing.T) {
	p := validProxy()
	p.Name = ""
	if err := ValidateInput(p); err == nil {
		t.Error("empty name should be rejected")
	}
	p.Name = strings.Repeat("a", 101)
	if err := ValidateInput(p); err == nil {
		t.Error("name >100 should be rejected")
	}
}

func TestValidateInputHeader(t *testing.T) {
	cases := []struct {
		name       string
		headerType string
		customName string
		wantErr    bool
	}{
		{"XFF", HeaderXForwardedFor, "", false},
		{"X-Real-IP", HeaderXRealIP, "", false},
		{"Forwarded", HeaderForwarded, "", false},
		{"标准类型不允许自定义头名", HeaderXForwardedFor, "X-Real-IP", true},
		{"CUSTOM缺头名", HeaderCustom, "", true},
		{"CUSTOM合法", HeaderCustom, "X-Client-IP", false},
		{"CUSTOM点与下划线", HeaderCustom, "X_Client.IP-1", false},
		{"CUSTOM含空格", HeaderCustom, "X Client IP", true},
		{"CUSTOM含冒号", HeaderCustom, "X:Client", true},
		{"CUSTOM含中文", HeaderCustom, "客户端IP", true},
		{"CUSTOM超长", HeaderCustom, strings.Repeat("a", 65), true},
		{"非法头类型", "X_FAKE_IP", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := validProxy()
			p.HeaderType = c.headerType
			p.CustomHeaderName = c.customName
			err := ValidateInput(p)
			if c.wantErr && err == nil {
				t.Error("should be rejected")
			}
			if !c.wantErr && err != nil {
				t.Errorf("should pass: %v", err)
			}
		})
	}
}

func TestValidateInputPriority(t *testing.T) {
	for _, tc := range []struct {
		priority int
		wantErr  bool
	}{
		{0, false}, {100, false}, {10000, false}, {-1, true}, {10001, true},
	} {
		p := validProxy()
		p.Priority = tc.priority
		err := ValidateInput(p)
		if tc.wantErr && err == nil {
			t.Errorf("priority %d should be rejected", tc.priority)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("priority %d should pass: %v", tc.priority, err)
		}
	}
}

func TestValidateInputScope(t *testing.T) {
	p := validProxy()
	p.Scope = ScopeNode
	if err := ValidateInput(p); err == nil {
		t.Error("NODE scope without node_name should be rejected")
	}
	p.NodeName = "gateway-01"
	if err := ValidateInput(p); err != nil {
		t.Errorf("NODE scope with node_name should pass: %v", err)
	}
	p.Scope = ScopeGlobal
	if err := ValidateInput(p); err == nil {
		t.Error("GLOBAL scope with node_name should be rejected")
	}
	p.NodeName = ""
	p.Scope = "CLUSTER"
	if err := ValidateInput(p); err == nil {
		t.Error("invalid scope should be rejected")
	}
}

func TestValidateInputDescription(t *testing.T) {
	p := validProxy()
	p.Description = strings.Repeat("d", 501)
	if err := ValidateInput(p); err == nil {
		t.Error("description >500 should be rejected")
	}
}

func TestIsValidIPLiteral(t *testing.T) {
	if !isValidIPLiteral("192.168.1.1") {
		t.Error("v4 should be valid")
	}
	if !isValidIPLiteral("::1") {
		t.Error("v6 should be valid")
	}
	if isValidIPLiteral("192.168.1.0/24") {
		t.Error("CIDR should not be a valid single IP literal")
	}
	if isValidIPLiteral("example.com") {
		t.Error("domain should not be valid")
	}
}
