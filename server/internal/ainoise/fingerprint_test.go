// fingerprint_test.go URI 归一化与指纹稳定性测试。
package ainoise

import "testing"

func TestNormalizeURI(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/users/42", "/users/{n}"},
		{"/users/42/orders/987", "/users/{n}/orders/{n}"},
		{"/a/550e8400-e29b-41d4-a716-446655440000", "/a/{uuid}"},
		{"/a/550E8400-E29B-41D4-A716-446655440000", "/a/{uuid}"},
		{"/files/0123456789abcdef", "/files/{h}"},
		{"/files/0123456789ABCDEF0123", "/files/{h}"},
		{"/files/abcdef", "/files/abcdef"}, // 短于16位不归一
		{"/search?q=1&page=2", "/search"},
		{"/path#frag", "/path"},
		{"", "/"},
		{"/", "/"},
		{"/api/v1/items", "/api/v1/items"},
		{"/2024/01/report", "/{n}/{n}/report"},
	}
	for _, c := range cases {
		if got := NormalizeURI(c.in); got != c.want {
			t.Errorf("NormalizeURI(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestNormalizeURIIdempotent(t *testing.T) {
	for _, in := range []string{"/users/42", "/a/550e8400-e29b-41d4-a716-446655440000", "/files/0123456789abcdef"} {
		once := NormalizeURI(in)
		if twice := NormalizeURI(once); twice != once {
			t.Errorf("NormalizeURI not idempotent: %q -> %q -> %q", in, once, twice)
		}
	}
}

func TestFingerprintDeterministic(t *testing.T) {
	rid := 942100
	a := Fingerprint("WAF", "example.com", "/users/{n}", &rid, "", "1.2.3.4")
	b := Fingerprint("WAF", "example.com", "/users/{n}", &rid, "", "1.2.3.4")
	if a != b {
		t.Fatal("fingerprint not deterministic")
	}
	if len(a) != 64 {
		t.Fatalf("fingerprint len=%d want 64", len(a))
	}
	// host 大小写不敏感
	if c := Fingerprint("WAF", "Example.COM", "/users/{n}", &rid, "", "1.2.3.4"); c != a {
		t.Fatal("host case should not affect fingerprint")
	}
}

func TestFingerprintSensitivity(t *testing.T) {
	rid := 942100
	base := Fingerprint("WAF", "example.com", "/users/{n}", &rid, "", "1.2.3.4")
	// 任一维度变化 → 指纹变化
	variants := map[string]string{
		"source": Fingerprint("API", "example.com", "/users/{n}", &rid, "", "1.2.3.4"),
		"host":   Fingerprint("WAF", "other.com", "/users/{n}", &rid, "", "1.2.3.4"),
		"uri":    Fingerprint("WAF", "example.com", "/users/{n}/x", &rid, "", "1.2.3.4"),
		"ip":     Fingerprint("WAF", "example.com", "/users/{n}", &rid, "", "5.6.7.8"),
	}
	for name, v := range variants {
		if v == base {
			t.Errorf("fingerprint insensitive to %s", name)
		}
	}
	// rule_id 与 detector_code 互斥：rule_id 优先
	rid2 := 941160
	if v := Fingerprint("WAF", "example.com", "/users/{n}", &rid2, "", "1.2.3.4"); v == base {
		t.Error("fingerprint insensitive to rule_id")
	}
	withRule := Fingerprint("API", "example.com", "/users/{n}", &rid, "api_schema", "1.2.3.4")
	ruleOnly := Fingerprint("API", "example.com", "/users/{n}", &rid, "", "1.2.3.4")
	if withRule != ruleOnly {
		t.Error("detector_code should be ignored when rule_id present")
	}
	detOnly := Fingerprint("API", "example.com", "/users/{n}", nil, "api_schema", "1.2.3.4")
	if detOnly == ruleOnly {
		t.Error("fingerprint insensitive to detector_code")
	}
}
