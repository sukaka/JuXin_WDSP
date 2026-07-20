package validation

import (
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
		host      string
		wantType  string
		wantErr   bool
	}{
		{"www.example.com", "EXACT", false},
		{"API.Example.COM.", "EXACT", false}, // 规范化小写去尾点
		{"*.example.com", "WILDCARD", false},
		{"*.service.example.com", "WILDCARD", false},
		{"*example.com", "", true},           // 非法泛域名
		{"api.*.example.com", "", true},      // 中间泛域名
		{"example", "", true},                // 单标签
		{"example..com", "", true},           // 空标签
		{"http://example.com", "", true},     // 含协议
		{"example.com/path", "", true},       // 含路径
		{"example.com:8080", "", true},       // 含端口
		{"example.com\n", "", true},          // 控制字符
		{"-bad.com", "", true},               // 标签开头短横线
		{"*.com", "", true},                  // 泛域名仅一标签
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
		"WWW.Example.COM.": "www.example.com",
		"  api.example.com ": "api.example.com",
		"Example.com":      "example.com",
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
		{"*.example.com", "example.com", false},        // 泛域名不含根域名
		{"*.example.com", "a.b.example.com", false},    // 只匹配一级子域名
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
