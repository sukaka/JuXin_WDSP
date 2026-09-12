package protectedaddresses

import "testing"

func testAddrs() []ProtectedAddress {
	return []ProtectedAddress{
		{Name: "回环地址（IPv4）", Address: "127.0.0.1", AddressType: TypeLoopback, SourceType: SourceSystem, Status: StatusEnabled},
		{Name: "链路本地（IPv4）", CIDR: "169.254.0.0/16", AddressType: TypeLinkLocal, SourceType: SourceSystem, Status: StatusEnabled},
		{Name: "链路本地（IPv6）", CIDR: "fe80::/10", AddressType: TypeLinkLocal, SourceType: SourceSystem, Status: StatusEnabled},
		{Name: "数据库", Address: "10.0.0.2", AddressType: TypeDatabase, SourceType: SourceSystem, Status: StatusEnabled},
		{Name: "源站段", CIDR: "172.16.0.0/12", AddressType: TypeUpstream, SourceType: SourceSystem, Status: StatusEnabled},
		{Name: "已停用条目", Address: "8.8.8.8", AddressType: TypeCustom, SourceType: SourceManual, Status: StatusDisabled},
	}
}

func TestMatchProtected(t *testing.T) {
	addrs := testAddrs()
	cases := []struct {
		name     string
		ip       string
		wantHit  bool
		wantName string
	}{
		{"单IP命中", "10.0.0.2", true, "数据库"},
		{"CIDR命中v4", "172.16.5.5", true, "源站段"},
		{"CIDR命中v6", "fe80::1234", true, "链路本地（IPv6）"},
		{"映射IP命中单地址", "::ffff:10.0.0.2", true, "数据库"},
		{"映射IP命中CIDR", "::ffff:172.16.5.5", true, "源站段"},
		{"未命中", "203.0.113.9", false, ""},
		{"停用条目不命中", "8.8.8.8", false, ""},
		{"非法IP", "not-an-ip", false, ""},
		{"空IP", "", false, ""},
		{"CIDR输入不命中", "10.0.0.0/24", false, ""},
		{"v6不在v4段内", "2001:db8::1", false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hit, name := MatchProtected(addrs, c.ip)
			if hit != c.wantHit {
				t.Errorf("MatchProtected(%q) hit = %v, want %v", c.ip, hit, c.wantHit)
			}
			if name != c.wantName {
				t.Errorf("MatchProtected(%q) name = %q, want %q", c.ip, name, c.wantName)
			}
		})
	}
}

func TestMatchProtectedV6NotMatchV4(t *testing.T) {
	addrs := testAddrs()
	hit, _ := MatchProtected(addrs, "::1")
	if hit {
		t.Error("::1 should not match v4-only list")
	}
}

func TestMatchProtectedEmptyList(t *testing.T) {
	hit, name := MatchProtected(nil, "10.0.0.2")
	if hit || name != "" {
		t.Error("empty list should not match")
	}
}
