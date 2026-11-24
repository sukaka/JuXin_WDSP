package netif

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func stubInterfaceAddrs(t *testing.T, fn func() (map[string][]string, map[string]error, error)) {
	t.Helper()
	prev := interfaceAddrsLookup
	interfaceAddrsLookup = fn
	t.Cleanup(func() { interfaceAddrsLookup = prev })
}

// buildSysfsFixture 构造 sysfs 风格目录树：
//
//	root/devices/0000:03:00.0/{driver -> ../../drivers/ixgbe}
//	root/devices/0000:04:00.0/                     （无驱动符号链接）
//	root/devices/usb1/1-2.3/                       （USB 设备，非 PCI 拓扑）
//	root/drivers/ixgbe/
//	root/net/                                      ← sysfsDir
//	  eth0/    device→0000:03:00.0, up, 10000
//	  enp4s0/  device→0000:04:00.0, down, 无 speed 文件
//	  usb0/    device→usb1/1-2.3
//	  veth99/  device 存在但名称命中虚拟前缀（验证名称过滤优先）
//	  lo/ docker0/ br-abc/                         （无 device）
func buildSysfsFixture(t *testing.T) (sysfsDir string) {
	t.Helper()
	root := t.TempDir()
	mk := func(parts ...string) string {
		p := filepath.Join(parts...)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write := func(dir, name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	link := func(oldname, newname string) {
		if err := os.Symlink(oldname, newname); err != nil {
			t.Fatal(err)
		}
	}

	dev1 := mk(root, "devices", "0000:03:00.0")
	mk(root, "devices", "0000:04:00.0")
	mk(root, "devices", "usb1", "1-2.3")
	mk(root, "drivers", "ixgbe")
	link(filepath.Join("..", "..", "drivers", "ixgbe"), filepath.Join(dev1, "driver"))

	sysfsDir = mk(root, "net")

	eth0 := mk(sysfsDir, "eth0")
	link(filepath.Join("..", "..", "devices", "0000:03:00.0"), filepath.Join(eth0, "device"))
	write(eth0, "address", "00:11:22:33:44:55\n")
	write(eth0, "operstate", "up\n")
	write(eth0, "speed", "10000\n")

	enp := mk(sysfsDir, "enp4s0")
	link(filepath.Join("..", "..", "devices", "0000:04:00.0"), filepath.Join(enp, "device"))
	write(enp, "address", "aa:bb:cc:dd:ee:ff\n")
	write(enp, "operstate", "down\n")
	// 无 speed 文件（DOWN 口内核返回 EINVAL，等效缺失）→ LinkSpeed 应为 0

	usb0 := mk(sysfsDir, "usb0")
	link(filepath.Join("..", "..", "devices", "usb1", "1-2.3"), filepath.Join(usb0, "device"))
	write(usb0, "address", "02:00:00:00:00:01\n")
	write(usb0, "operstate", "up\n")
	write(usb0, "speed", "480\n")

	// 虚拟口：名称命中前缀（即使 device 符号链接存在也必须排除）
	veth := mk(sysfsDir, "veth99")
	link(filepath.Join("..", "..", "devices", "0000:04:00.0"), filepath.Join(veth, "device"))
	for _, name := range []string{"lo", "docker0", "br-abc"} {
		mk(sysfsDir, name)
	}
	return sysfsDir
}

func findIface(t *testing.T, ifs []Interface, name string) Interface {
	t.Helper()
	for _, ifi := range ifs {
		if ifi.IfName == name {
			return ifi
		}
	}
	t.Fatalf("interface %s not found in %+v", name, ifs)
	return Interface{}
}

func TestCollectFiltersAndSysfsFallback(t *testing.T) {
	stubInterfaceAddrs(t, func() (map[string][]string, map[string]error, error) {
		return map[string][]string{
			"eth0": {"192.168.1.10/24", "2408:8207::10/64"},
		}, nil, nil
	})
	sysfsDir := buildSysfsFixture(t)
	inv, err := Collect(sysfsDir, nil) // 无 ethtool：兜底路径
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.ProbeErrors) != 0 {
		t.Errorf("probe errors: %v", inv.ProbeErrors)
	}
	// 仅物理口：eth0/enp4s0/usb0；lo/docker0/br-abc/veth99 被过滤；按名称排序
	if len(inv.Interfaces) != 3 {
		t.Fatalf("interfaces: %+v", inv.Interfaces)
	}
	if inv.Interfaces[0].IfName != "enp4s0" || inv.Interfaces[1].IfName != "eth0" || inv.Interfaces[2].IfName != "usb0" {
		t.Errorf("order: %+v", inv.Interfaces)
	}

	eth0 := findIface(t, inv.Interfaces, "eth0")
	if eth0.MAC != "00:11:22:33:44:55" || eth0.OperState != "up" || eth0.LinkSpeed != 10000 {
		t.Errorf("eth0 fields: %+v", eth0)
	}
	if !reflect.DeepEqual(eth0.IPAddresses, []string{"192.168.1.10/24", "2408:8207::10/64"}) {
		t.Errorf("eth0 ip_addresses: %+v", eth0.IPAddresses)
	}
	if eth0.PCIPath != "0000:03:00.0" {
		t.Errorf("eth0 pci: %q", eth0.PCIPath)
	}
	if eth0.Driver != "ixgbe" { // sysfs device/driver 符号链接兜底
		t.Errorf("eth0 driver: %q", eth0.Driver)
	}
	if eth0.MediaType != MediaUnknown { // 无 ethtool → UNKNOWN
		t.Errorf("eth0 media: %q", eth0.MediaType)
	}

	enp := findIface(t, inv.Interfaces, "enp4s0")
	if enp.LinkSpeed != 0 || enp.OperState != "down" {
		t.Errorf("enp4s0 fields: %+v", enp)
	}
	if enp.IPAddresses == nil || len(enp.IPAddresses) != 0 {
		t.Errorf("enp4s0 ip_addresses should be empty non-nil slice, got %#v", enp.IPAddresses)
	}
	if enp.Driver != "" || enp.PCIPath != "0000:04:00.0" {
		t.Errorf("enp4s0 driver/pci: %+v", enp)
	}

	usb0 := findIface(t, inv.Interfaces, "usb0")
	if usb0.PCIPath != "" { // USB 拓扑不是 PCI BDF
		t.Errorf("usb0 pci should be empty: %q", usb0.PCIPath)
	}
}

type fakeProbe struct {
	driver, bus, media string
	infoErr            error // DriverAndBus 失败
	mediaErr           error // Media 失败
}

type fakeProber struct{ m map[string]fakeProbe }

func (f fakeProber) DriverAndBus(ifname string) (string, string, error) {
	r, ok := f.m[ifname]
	if !ok {
		return "", "", errors.New("probe unsupported")
	}
	if r.infoErr != nil {
		return "", "", r.infoErr
	}
	return r.driver, r.bus, nil
}

func (f fakeProber) Media(ifname string) (string, error) {
	r, ok := f.m[ifname]
	if !ok {
		return "", errors.New("probe unsupported")
	}
	if r.mediaErr != nil {
		return "", r.mediaErr
	}
	return r.media, nil
}

func TestCollectWithProber(t *testing.T) {
	stubInterfaceAddrs(t, func() (map[string][]string, map[string]error, error) {
		return map[string][]string{"eth0": {"10.0.0.5/24"}}, nil, nil
	})
	sysfsDir := buildSysfsFixture(t)
	prober := fakeProber{m: map[string]fakeProbe{
		"eth0":   {driver: "igb", bus: "0000:03:00.0", media: MediaTP},
		"enp4s0": {media: MediaFibre, infoErr: errors.New("ethtool -i failed")},
	}}
	inv, err := Collect(sysfsDir, prober)
	if err != nil {
		t.Fatal(err)
	}

	eth0 := findIface(t, inv.Interfaces, "eth0")
	if eth0.Driver != "igb" || eth0.MediaType != MediaTP || eth0.PCIPath != "0000:03:00.0" {
		t.Errorf("eth0 ethtool override: %+v", eth0)
	}

	enp := findIface(t, inv.Interfaces, "enp4s0")
	if enp.MediaType != MediaFibre {
		t.Errorf("enp4s0 media: %q", enp.MediaType)
	}
	if enp.Driver != "" { // DriverAndBus 失败：保持 sysfs 兜底（本例为空）
		t.Errorf("enp4s0 driver: %q", enp.Driver)
	}

	// 探测失败不吞错：enp4s0 DriverAndBus + usb0 两项 = 3 条
	if len(inv.ProbeErrors) != 3 {
		t.Errorf("probe errors: %v", inv.ProbeErrors)
	}
}

func TestCollectMissingDir(t *testing.T) {
	if _, err := Collect(filepath.Join(t.TempDir(), "nonexistent"), nil); err == nil {
		t.Fatal("expect error for missing sysfs dir")
	}
}

func TestParseEthtoolInfo(t *testing.T) {
	out := `driver: ixgbe
version: 6.1.0
firmware-version: 0x800008df
expansion-rom-version:
bus-info: 0000:03:00.0
supports-statistics: yes
`
	d, b := parseEthtoolInfo(out)
	if d != "ixgbe" || b != "0000:03:00.0" {
		t.Errorf("parse: driver=%q bus=%q", d, b)
	}
	if d, b := parseEthtoolInfo("garbage\n\n"); d != "" || b != "" {
		t.Errorf("garbage: driver=%q bus=%q", d, b)
	}
}

func TestParseSupportedPorts(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want string
	}{
		{"tp", "Settings for eth0:\n\tSupported ports: [ TP ]\n\tSpeed: 1000Mb/s\n", MediaTP},
		{"fibre", "Settings for eth0:\n\tSupported ports: [ FIBRE ]\n", MediaFibre},
		{"combo first wins", "\tSupported ports: [ TP FIBRE ]\n", MediaTP},
		{"combo fibre first", "\tSupported ports: [ FIBRE TP ]\n", MediaFibre},
		{"unrecognized", "\tSupported ports: [ MII ]\n", ""},
		{"empty", "\tSupported ports: [ ]\n", ""},
		{"absent", "Settings for eth0:\n\tSpeed: Unknown!\n", ""},
	}
	for _, c := range cases {
		if got := parseSupportedPorts(c.out); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

type rawAddr string

func (r rawAddr) Network() string { return "ip+net" }
func (r rawAddr) String() string  { return string(r) }

func TestNormalizeNetAddrs(t *testing.T) {
	mustIPNet := func(cidr string) *net.IPNet {
		t.Helper()
		ip, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatal(err)
		}
		ipNet.IP = ip
		return ipNet
	}
	addrs := []net.Addr{
		nil,
		mustIPNet("2408:8207::20/64"),
		mustIPNet("fe80::216:3eff:fe6c:fd83/64"), // IPv6 link-local：应过滤
		mustIPNet("127.0.0.1/8"),                 // loopback：应过滤
		mustIPNet("::1/128"),                     // IPv6 loopback：应过滤
		mustIPNet("169.254.169.254/16"),          // IPv4 link-local：应过滤
		mustIPNet("0.0.0.0/0"),                   // unspecified：应过滤
		mustIPNet("224.0.0.1/32"),                // multicast：应过滤
		mustIPNet("192.168.10.20/24"),
		mustIPNet("10.0.0.5/24"),
		mustIPNet("10.0.0.5/24"), // 重复：应去重
		&net.IPAddr{IP: net.ParseIP("172.16.0.8")},
		rawAddr("2001:db8::1/64"),
		rawAddr("not-an-ip"),
	}
	got := normalizeNetAddrs(addrs)
	want := []string{
		"10.0.0.5/24",
		"172.16.0.8",
		"192.168.10.20/24",
		"2001:db8::1/64",
		"2408:8207::20/64",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeNetAddrs = %v, want %v", got, want)
	}
}

func TestCollectAddrLookupDegradation(t *testing.T) {
	sysfsDir := buildSysfsFixture(t)

	// 单接口 Addrs() 失败：该口 IPAddresses 置 nil 并记 ProbeErrors，其他口正常填充
	stubInterfaceAddrs(t, func() (map[string][]string, map[string]error, error) {
		return map[string][]string{"eth0": {"192.168.1.10/24"}},
			map[string]error{"enp4s0": errors.New("netlink timeout")}, nil
	})
	inv, err := Collect(sysfsDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.ProbeErrors) != 1 {
		t.Fatalf("probe errors = %v, want 1", inv.ProbeErrors)
	}
	if got := findIface(t, inv.Interfaces, "eth0").IPAddresses; !reflect.DeepEqual(got, []string{"192.168.1.10/24"}) {
		t.Errorf("eth0 ips = %v", got)
	}
	if got := findIface(t, inv.Interfaces, "enp4s0").IPAddresses; got != nil {
		t.Errorf("enp4s0 ips should be nil on lookup error, got %#v", got)
	}
	if got := findIface(t, inv.Interfaces, "usb0").IPAddresses; got == nil || len(got) != 0 {
		t.Errorf("usb0 ips should be empty non-nil slice, got %#v", got)
	}

	// 整体 net.Interfaces() 失败：不阻断清单采集，所有口 IPAddresses 置 nil 并记 ProbeErrors
	stubInterfaceAddrs(t, func() (map[string][]string, map[string]error, error) {
		return nil, nil, errors.New("net.Interfaces failed")
	})
	inv, err = Collect(sysfsDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.ProbeErrors) != 1 {
		t.Fatalf("fatal lookup probe errors = %v, want 1", inv.ProbeErrors)
	}
	for _, ifi := range inv.Interfaces {
		if ifi.IPAddresses != nil {
			t.Errorf("%s ips should be nil on fatal lookup error, got %#v", ifi.IfName, ifi.IPAddresses)
		}
	}
}

func TestSystemInterfaceAddrsSmoke(t *testing.T) {
	byName, _, err := systemInterfaceAddrs()
	if err != nil {
		t.Fatalf("systemInterfaceAddrs failed: %v", err)
	}
	for name, addrs := range byName {
		if isVirtualName(name) {
			t.Errorf("virtual interface %s should be skipped", name)
		}
		for _, a := range addrs {
			if a == "" {
				t.Errorf("empty addr on %s", name)
			}
		}
	}
}
