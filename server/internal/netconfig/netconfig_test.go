package netconfig

import (
	"context"
	"strings"
	"testing"

	"github.com/jiuzhang-waf/server/internal/nodeinterfaces"
)

// iface 造一条网口清单记录（校验数据源）。
func iface(ifname, role string, present bool) nodeinterfaces.Interface {
	return nodeinterfaces.Interface{NodeName: "gw-1", Ifname: ifname, Role: role, Present: present}
}

// testIfaces 校验测试共用清单：eth0 管理口、eth1 已消失、eth2-eth5 业务口。
func testIfaces() []nodeinterfaces.Interface {
	return []nodeinterfaces.Interface{
		iface("eth0", nodeinterfaces.RoleManagement, true),
		iface("eth1", nodeinterfaces.RoleTraffic, false),
		iface("eth2", nodeinterfaces.RoleTraffic, true),
		iface("eth3", nodeinterfaces.RoleTraffic, true),
		iface("eth4", "", true),
		iface("eth5", "", true),
	}
}

func validConfig() Config {
	return Config{
		Bridges:   []Bridge{{Name: "br0", Ports: []string{"eth2", "eth3"}}},
		IPForward: true,
		Routes:    []Route{{Dst: "10.9.0.0/24", Via: "192.168.50.1"}},
	}
}

// 合法输入：空配置、完整配置、多桥多路由、IPv6 路由、字段去空白归一化。
func TestValidateOK(t *testing.T) {
	// 空配置（bridges/routes 可为空数组）
	cfg := DefaultConfig()
	if err := Validate(&cfg, testIfaces()); err != nil {
		t.Fatalf("empty config: %v", err)
	}
	// nil 切片归一化为空数组（契约恒为数组）
	cfg = Config{}
	if err := Validate(&cfg, nil); err != nil {
		t.Fatalf("nil slices: %v", err)
	}
	if cfg.Bridges == nil || cfg.Routes == nil {
		t.Fatal("nil slices 未归一化为空数组")
	}

	cfg = validConfig()
	if err := Validate(&cfg, testIfaces()); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	// 多桥 + 多路由 + IPv6
	cfg = Config{
		Bridges: []Bridge{
			{Name: "br0", Ports: []string{"eth2", "eth3"}},
			{Name: "br99", Ports: []string{"eth4", "eth5"}},
		},
		Routes: []Route{
			{Dst: "10.9.0.0/24", Via: "192.168.50.1"},
			{Dst: "fd00::/64", Via: "fe80::1"},
		},
	}
	if err := Validate(&cfg, testIfaces()); err != nil {
		t.Fatalf("multi bridge/route: %v", err)
	}
	// 去空白归一化
	cfg = Config{Bridges: []Bridge{{Name: " br1 ", Ports: []string{" eth2 ", "eth3"}}},
		Routes: []Route{{Dst: " 10.9.0.0/24 ", Via: " 192.168.50.1 "}}}
	if err := Validate(&cfg, testIfaces()); err != nil {
		t.Fatalf("trim: %v", err)
	}
	if cfg.Bridges[0].Name != "br1" || cfg.Bridges[0].Ports[0] != "eth2" ||
		cfg.Routes[0].Dst != "10.9.0.0/24" || cfg.Routes[0].Via != "192.168.50.1" {
		t.Fatalf("归一化未生效: %+v", cfg)
	}
}

// 各类非法输入一律报错（错误信息须具体）。
func TestValidateReject(t *testing.T) {
	cases := []struct {
		name string
		mut  func(c *Config)
		want string // 错误信息子串
	}{
		{"bridge name empty", func(c *Config) { c.Bridges[0].Name = "" }, "桥名非法"},
		{"bridge name no digits", func(c *Config) { c.Bridges[0].Name = "br" }, "桥名非法"},
		{"bridge name 3 digits", func(c *Config) { c.Bridges[0].Name = "br100" }, "桥名非法"},
		{"bridge name prefix", func(c *Config) { c.Bridges[0].Name = "xbr0" }, "桥名非法"},
		{"bridge name upper", func(c *Config) { c.Bridges[0].Name = "BR0" }, "桥名非法"},
		{"bridge dup", func(c *Config) {
			c.Bridges = append(c.Bridges, Bridge{Name: "br0", Ports: []string{"eth4", "eth5"}})
		}, "桥名重复"},
		{"too few ports", func(c *Config) { c.Bridges[0].Ports = []string{"eth2"} }, "至少需要 2 个"},
		{"nil ports", func(c *Config) { c.Bridges[0].Ports = nil }, "至少需要 2 个"},
		{"blank port", func(c *Config) { c.Bridges[0].Ports = []string{"eth2", " "} }, "空成员口"},
		{"unknown port", func(c *Config) { c.Bridges[0].Ports = []string{"eth2", "eth9"} }, "不存在于该节点"},
		{"not present port", func(c *Config) { c.Bridges[0].Ports = []string{"eth1", "eth2"} }, "present=false"},
		{"management port", func(c *Config) { c.Bridges[0].Ports = []string{"eth0", "eth2"} }, "MANAGEMENT"},
		{"dup port same bridge", func(c *Config) {
			c.Bridges[0].Ports = []string{"eth2", "eth3", "eth2"}
		}, "成员口重复"},
		{"port in two bridges", func(c *Config) {
			c.Bridges = append(c.Bridges, Bridge{Name: "br1", Ports: []string{"eth3", "eth4"}})
		}, "不得同时出现"},
		{"bad dst", func(c *Config) { c.Routes[0].Dst = "10.9.0.0/33" }, "CIDR"},
		{"dst not cidr", func(c *Config) { c.Routes[0].Dst = "10.9.0.0" }, "CIDR"},
		{"dst garbage", func(c *Config) { c.Routes[0].Dst = "abc" }, "CIDR"},
		{"bad via", func(c *Config) { c.Routes[0].Via = "999.1.1.1" }, "IP"},
		{"via empty", func(c *Config) { c.Routes[0].Via = "" }, "IP"},
		{"via hostname", func(c *Config) { c.Routes[0].Via = "gw.local" }, "IP"},
		{"dup dst", func(c *Config) {
			c.Routes = append(c.Routes, Route{Dst: "10.9.0.0/24", Via: "192.168.50.2"})
		}, "重复"},
	}
	for _, tc := range cases {
		cfg := validConfig()
		tc.mut(&cfg)
		err := Validate(&cfg, testIfaces())
		if err == nil {
			t.Fatalf("%s: 应报错", tc.name)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: 错误信息 %q 不含 %q", tc.name, err.Error(), tc.want)
		}
	}
}

// 防御性上限：桥数量、单桥成员口数量、路由数量。
func TestValidateLimits(t *testing.T) {
	cfg := Config{}
	for i := 0; i <= maxBridges; i++ {
		cfg.Bridges = append(cfg.Bridges, Bridge{Name: "br" + strings.Repeat("1", 1), Ports: []string{"eth2", "eth3"}})
	}
	if err := Validate(&cfg, testIfaces()); err == nil || !strings.Contains(err.Error(), "上限") {
		t.Fatalf("bridges 上限未生效: %v", err)
	}

	cfg = Config{Bridges: []Bridge{{Name: "br0", Ports: make([]string, maxBridgePorts+1)}}}
	for i := range cfg.Bridges[0].Ports {
		cfg.Bridges[0].Ports[i] = "eth2"
	}
	if err := Validate(&cfg, testIfaces()); err == nil || !strings.Contains(err.Error(), "上限") {
		t.Fatalf("成员口上限未生效: %v", err)
	}

	cfg = Config{}
	for i := 0; i <= maxRoutes; i++ {
		cfg.Routes = append(cfg.Routes, Route{Dst: "10.9.0.0/24", Via: "192.168.50.1"})
	}
	if err := Validate(&cfg, testIfaces()); err == nil || !strings.Contains(err.Error(), "上限") {
		t.Fatalf("routes 上限未生效: %v", err)
	}
}

// DNS/NTP 服务器列表校验：合法列表（IP/主机名/IPv6）通过；>4 项、空项、
// 非法主机一律报错；归一化去空白。
func TestValidateServers(t *testing.T) {
	cfg := validConfig()
	cfg.DNSServers = []string{"223.5.5.5", "2001:4860:4860::8888"}
	cfg.NTPServers = []string{"pool.ntp.org", "ntp.aliyun.com", "time.cloudflare.com", "1.1.1.1"}
	if err := Validate(&cfg, testIfaces()); err != nil {
		t.Fatalf("valid servers: %v", err)
	}

	cases := []struct {
		name string
		mut  func(c *Config)
		want string
	}{
		{"dns 超 4 项", func(c *Config) {
			c.DNSServers = []string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5"}
		}, "上限"},
		{"ntp 超 4 项", func(c *Config) {
			c.NTPServers = []string{"a.org", "b.org", "c.org", "d.org", "e.org"}
		}, "上限"},
		{"dns 空项", func(c *Config) { c.DNSServers = []string{"1.1.1.1", " "} }, "空列表项"},
		{"dns 元字符", func(c *Config) { c.DNSServers = []string{"8.8.8.8;rm"} }, "不是合法 IP 或主机名"},
		{"ntp 非法字符", func(c *Config) { c.NTPServers = []string{"pool.ntp.org!"} }, "不是合法 IP 或主机名"},
		{"dns CIDR 不允许", func(c *Config) { c.DNSServers = []string{"8.8.8.8/24"} }, "不是合法 IP 或主机名"},
	}
	for _, tc := range cases {
		cfg := validConfig()
		tc.mut(&cfg)
		err := Validate(&cfg, testIfaces())
		if err == nil {
			t.Fatalf("%s: 应报错", tc.name)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: 错误信息 %q 不含 %q", tc.name, err.Error(), tc.want)
		}
	}

	// 归一化去空白
	cfg = validConfig()
	cfg.DNSServers = []string{" 223.5.5.5 "}
	if err := Validate(&cfg, testIfaces()); err != nil {
		t.Fatalf("trim: %v", err)
	}
	if cfg.DNSServers[0] != "223.5.5.5" {
		t.Fatalf("dns 归一化未生效: %+v", cfg.DNSServers)
	}
}

// MemStore 与校验联动：保存后可原样读回（切片恒为数组）。
func TestMemStoreRoundTrip(t *testing.T) {
	m := NewMemStore()
	if _, _, found, err := m.Get(context.Background(), "gw-1"); err != nil || found {
		t.Fatalf("empty Get found=%v err=%v", found, err)
	}
	cfg := validConfig()
	if err := m.Save(context.Background(), "gw-1", cfg); err != nil {
		t.Fatal(err)
	}
	got, _, found, err := m.Get(context.Background(), "gw-1")
	if err != nil || !found {
		t.Fatalf("Get found=%v err=%v", found, err)
	}
	if len(got.Bridges) != 1 || got.Bridges[0].Name != "br0" || !got.IPForward || len(got.Routes) != 1 {
		t.Fatalf("roundtrip = %+v", got)
	}
}
