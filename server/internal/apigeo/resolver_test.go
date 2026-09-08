// resolver_test.go 出境判定矩阵测试：本土/境外/内网/未知/非法输入 +
// home_regions 解析归一 + 未启用降级。
package apigeo

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"
)

// fakeLookup 假国家码查询（map 驱动；errOn 触发底层错误路径）。
type fakeLookup struct {
	byIP  map[string]string
	errOn map[string]error
}

func (f fakeLookup) LookupCountry(ip netip.Addr) (string, error) {
	if err := f.errOn[ip.String()]; err != nil {
		return "", err
	}
	return f.byIP[ip.String()], nil
}

// TestClassifyMatrix 判定矩阵：本土/境外/内网/未知/非法五档。
func TestClassifyMatrix(t *testing.T) {
	lookup := fakeLookup{byIP: map[string]string{
		"114.114.114.114": "CN",
		"8.8.8.8":         "US",
		"1.1.1.1":         "AU",
		"9.9.9.9":         "", // 库未收录
	}}
	r := NewGeoResolver(lookup, ParseHomeRegions("CN"))
	cases := []struct {
		name    string
		ip      string
		scope   Scope
		country string
	}{
		// 本土
		{"本土v4", "114.114.114.114", ScopeHome, "CN"},
		// 境外
		{"境外v4", "8.8.8.8", ScopeForeign, "US"},
		{"境外v4-2", "1.1.1.1", ScopeForeign, "AU"},
		// 内网/保留（全部 INTERNAL，不进入库查询）
		{"RFC1918-10", "10.0.0.1", ScopeInternal, ""},
		{"RFC1918-172", "172.16.5.4", ScopeInternal, ""},
		{"RFC1918-192", "192.168.1.1", ScopeInternal, ""},
		{"环回", "127.0.0.1", ScopeInternal, ""},
		{"链路本地", "169.254.1.1", ScopeInternal, ""},
		{"CGNAT", "100.64.0.1", ScopeInternal, ""},
		{"保留240段", "240.0.0.1", ScopeInternal, ""},
		{"零段", "0.1.2.3", ScopeInternal, ""},
		{"组播", "224.0.0.1", ScopeInternal, ""},
		{"v6环回", "::1", ScopeInternal, ""},
		{"v6-ULA", "fd00::1", ScopeInternal, ""},
		{"v6链路本地", "fe80::1", ScopeInternal, ""},
		{"v6未指定", "::", ScopeInternal, ""},
		// 未知（公网但库未收录）
		{"未知", "9.9.9.9", ScopeUnknown, ""},
		// 非法输入
		{"空串", "", ScopeInvalid, ""},
		{"非IP", "abc", ScopeInvalid, ""},
		{"越界段", "999.1.1.1", ScopeInvalid, ""},
		{"带空格归一", " 8.8.8.8 ", ScopeForeign, "US"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			scope, country, err := r.Classify(c.ip)
			if err != nil {
				t.Fatalf("classify %q: %v", c.ip, err)
			}
			if scope != c.scope || country != c.country {
				t.Fatalf("classify %q = (%s, %q), want (%s, %q)", c.ip, scope, country, c.scope, c.country)
			}
		})
	}
}

// TestClassifyHomeRegions 多本土地区与变更即时生效（判定器按轮重建）。
func TestClassifyHomeRegions(t *testing.T) {
	lookup := fakeLookup{byIP: map[string]string{"8.8.8.8": "US"}}
	// US 加入本土集合后，同 IP 由 FOREIGN 变 HOME
	r := NewGeoResolver(lookup, ParseHomeRegions("CN, US"))
	scope, country, err := r.Classify("8.8.8.8")
	if err != nil || scope != ScopeHome || country != "US" {
		t.Fatalf("classify = (%s, %q, %v), want (HOME, US)", scope, country, err)
	}
}

// TestClassifyDisabled 数据源未启用（nil lookup / nil resolver）一律 UNKNOWN。
func TestClassifyDisabled(t *testing.T) {
	r := NewGeoResolver(nil, []string{"CN"})
	if r.Enabled() {
		t.Fatal("nil lookup should be disabled")
	}
	scope, _, err := r.Classify("8.8.8.8")
	if err != nil || scope != ScopeUnknown {
		t.Fatalf("classify disabled = (%s, %v), want UNKNOWN", scope, err)
	}
	var nilResolver *GeoResolver
	if nilResolver.Enabled() {
		t.Fatal("nil resolver should be disabled")
	}
	scope, _, err = nilResolver.Classify("8.8.8.8")
	if err != nil || scope != ScopeUnknown {
		t.Fatalf("classify nil resolver = (%s, %v), want UNKNOWN", scope, err)
	}
}

// TestClassifyLookupError 底层数据损坏错误如实上抛（不吞错）。
func TestClassifyLookupError(t *testing.T) {
	boom := errors.New("corrupt record")
	r := NewGeoResolver(fakeLookup{errOn: map[string]error{"8.8.8.8": boom}}, []string{"CN"})
	if _, _, err := r.Classify("8.8.8.8"); !errors.Is(err, boom) {
		t.Fatalf("classify err = %v, want %v", err, boom)
	}
}

// TestParseHomeRegions 解析归一：trim/大写/去重/非法项忽略/空值与全非法回退 CN。
func TestParseHomeRegions(t *testing.T) {
	cases := []struct {
		raw  string
		want []string
	}{
		{"", []string{"CN"}},
		{"CN", []string{"CN"}},
		{" cn ,us,,HK ", []string{"CN", "HK", "US"}},
		{"CN,CN,cn", []string{"CN"}},
		{"C,CN1,??,U S", []string{"CN"}}, // 全非法回退默认
		{"US,XX", []string{"US", "XX"}},  // 两位字母即收（不在世 list 由库侧决定命中）
	}
	for _, c := range cases {
		if got := ParseHomeRegions(c.raw); !reflect.DeepEqual(got, c.want) {
			t.Fatalf("ParseHomeRegions(%q) = %v, want %v", c.raw, got, c.want)
		}
	}
}

// TestInternalAddrMatrix 内网/保留地址判定矩阵（isInternalAddr 直测）。
func TestInternalAddrMatrix(t *testing.T) {
	internal := []string{
		"10.0.0.0", "10.255.255.255", "172.16.0.1", "172.31.255.254", "192.168.0.1",
		"127.0.0.1", "169.254.0.1", "100.64.0.0", "100.127.255.255",
		"0.0.0.1", "240.0.0.1", "255.255.255.255", "224.0.0.5",
		"::1", "fc00::1", "fdff::abcd", "fe80::1", "ff02::1", "::",
		"::ffff:10.0.0.1", // 4-in-6 私网归一后仍内网
	}
	for _, ip := range internal {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			t.Fatalf("parse %s: %v", ip, err)
		}
		if !isInternalAddr(addr) {
			t.Fatalf("%s should be internal", ip)
		}
	}
	public := []string{"8.8.8.8", "1.1.1.1", "100.63.255.255", "100.128.0.1", "172.15.9.9", "172.32.0.1", "11.0.0.1", "223.255.255.1"}
	for _, ip := range public {
		addr, _ := netip.ParseAddr(ip)
		if isInternalAddr(addr) {
			t.Fatalf("%s should NOT be internal", ip)
		}
	}
}
