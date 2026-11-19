package validation

import (
	"net/netip"
	"testing"
)

func TestValidateAppCode(t *testing.T) {
	cases := []struct {
		code    string
		wantErr bool
	}{
		{"portal-system", false},
		{"finance-api", false},
		{"abc", false},
		{"ab", true},
		{"A-Upper", true},
		{"-leading", true},
		{"trailing-", true},
		{"double--dash", true},
		{"with_underscore", true},
		{"with space", true},
		{string(make([]byte, 65)), true},
	}
	for _, c := range cases {
		err := ValidateAppCode(c.code)
		if (err != nil) != c.wantErr {
			t.Errorf("ValidateAppCode(%q) err=%v, wantErr=%v", c.code, err, c.wantErr)
		}
	}
}

func TestValidateHostname(t *testing.T) {
	cases := []struct {
		host     string
		wantType string
		wantErr  bool
	}{
		{"www.example.com", "EXACT", false},
		{"API.Example.COM.", "EXACT", false}, // 规范化小写去尾点
		{"*.example.com", "WILDCARD", false},
		{"*.service.example.com", "WILDCARD", false},
		{"*example.com", "", true},       // 非法泛域名
		{"api.*.example.com", "", true},  // 中间泛域名
		{"example", "", true},            // 单标签
		{"example..com", "", true},       // 空标签
		{"http://example.com", "", true}, // 含协议
		{"example.com/path", "", true},   // 含路径
		{"example.com:8080", "", true},   // 含端口
		{"example.com\n", "", true},      // 控制字符
		{"-bad.com", "", true},           // 标签开头短横线
		{"*.com", "", true},              // 泛域名仅一标签
	}
	for _, c := range cases {
		_, dt, err := ValidateHostname(c.host)
		if (err != nil) != c.wantErr {
			t.Errorf("ValidateHostname(%q) err=%v, wantErr=%v", c.host, err, c.wantErr)
		}
		if !c.wantErr && dt != c.wantType {
			t.Errorf("ValidateHostname(%q) type=%q, want %q", c.host, dt, c.wantType)
		}
	}
}

func TestNormalizeHostname(t *testing.T) {
	cases := map[string]string{
		"WWW.Example.COM.":   "www.example.com",
		"  api.example.com ": "api.example.com",
		"Example.com":        "example.com",
	}
	for in, want := range cases {
		if got := NormalizeHostname(in); got != want {
			t.Errorf("NormalizeHostname(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestMatchHostnamePattern(t *testing.T) {
	cases := []struct {
		pattern string
		host    string
		want    bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "www.example.com", false},
		{"*.example.com", "www.example.com", true},
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "example.com", false},     // 泛域名不含根域名
		{"*.example.com", "a.b.example.com", false}, // 只匹配一级子域名
		{"*.example.com", "other.com", false},
	}
	for _, c := range cases {
		if got := MatchHostnamePattern(c.pattern, c.host); got != c.want {
			t.Errorf("MatchHostnamePattern(%q,%q)=%v, want %v", c.pattern, c.host, got, c.want)
		}
	}
}

func TestIsValidUpstreamHost(t *testing.T) {
	cases := []struct {
		host    string
		wantErr bool
	}{
		{"192.0.2.10", false},
		{"2001:db8::10", false},
		{"backend.example.internal", false},
		{"backend.local", false},
		{"http://backend.com", true},
		{"backend.com/path", true},
		{"user:pass@backend.com", true},
		{"backend.com:8080", true},
		{"*.example.com", true},
		{"backend..com", true},
		{"", true},
	}
	for _, c := range cases {
		err := IsValidUpstreamHost(c.host)
		if (err != nil) != c.wantErr {
			t.Errorf("IsValidUpstreamHost(%q) err=%v, wantErr=%v", c.host, err, c.wantErr)
		}
	}
}

func TestContainsControlChars(t *testing.T) {
	if !ContainsControlChars("bad\nhost") {
		t.Error("should detect newline")
	}
	if !ContainsControlChars("bad\thost") {
		t.Error("should detect tab")
	}
	if ContainsControlChars("good-host.com") {
		t.Error("false positive on normal host")
	}
}

func TestC06IPv4MappedAndMetadataSSRFProtection(t *testing.T) {
	// 绝对禁止元数据地址（含 IPv4-mapped IPv6、ECS、阿里云、AWS IPv6、带 Zone）
	blocked := []string{
		"169.254.169.254",
		"::ffff:169.254.169.254",
		"169.254.170.2",
		"::ffff:169.254.170.2",
		"100.100.100.200",
		"::ffff:100.100.100.200",
		"fd00:ec2::254",
		"fd00:ec2::254%eth0",
	}
	for _, raw := range blocked {
		addr := netip.MustParseAddr(raw)
		if !IsBlockedAddress(addr) {
			t.Errorf("IsBlockedAddress(%q) = false, want true", raw)
		}
		if _, err := ResolveAndValidate(raw, true); err == nil {
			t.Errorf("ResolveAndValidate(%q, allowPrivate=true) = nil, want error", raw)
		}
		if _, err := ResolveAndValidate(raw, false); err == nil {
			t.Errorf("ResolveAndValidate(%q, allowPrivate=false) = nil, want error", raw)
		}
	}

	// 私网/特殊/回环/组播/未指定/IPv4-mapped IPv6/带 Zone 地址
	privateOrSpecial := []string{
		"::ffff:127.0.0.1",
		"::ffff:10.0.0.1",
		"::ffff:192.168.1.1",
		"::ffff:172.16.0.1",
		"::",
		"224.0.0.1",
		"::ffff:224.0.0.1",
		"ff02::1",
		"fe80::1%eth0",
		"2001:db8::1%eth0",
	}
	for _, raw := range privateOrSpecial {
		addr := netip.MustParseAddr(raw)
		if !IsPrivateOrSpecialAddress(addr) {
			t.Errorf("IsPrivateOrSpecialAddress(%q) = false, want true", raw)
		}
		if _, err := ResolveAndValidate(raw, false); err == nil {
			t.Errorf("ResolveAndValidate(%q, allowPrivate=false) = nil, want error", raw)
		}
	}
	// 带 Zone 的地址即便 allowPrivate=true 也必须被 ResolveAndValidate 拒绝
	if _, err := ResolveAndValidate("fe80::1%eth0", true); err == nil {
		t.Error("zoned IPv6 address must be rejected even with allowPrivate=true")
	}
	// 公网 IPv4-mapped IPv6 解映射为纯 IPv4 放行
	addrs, err := ResolveAndValidate("::ffff:93.184.216.34", false)
	if err != nil || len(addrs) != 1 || addrs[0].String() != "93.184.216.34" {
		t.Fatalf("public mapped IPv6 should unmap and pass: addrs=%v err=%v", addrs, err)
	}
}
