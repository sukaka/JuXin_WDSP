package gatewayconfig

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/jiuzhang-waf/server/internal/applications"
)

// sidecarTestApps 构造含各部署模式应用的发布快照（rev 反代 / mir 镜像 / tpx 透明）。
func sidecarTestApps() []AppData {
	return []AppData{
		{
			Code: "rev", DeploymentMode: applications.DeployModeReverseProxy,
			Domains: []applications.Domain{{HTTPEnabled: true, HTTPPort: intPtr(80)}},
		},
		{
			Code: "mir", DeploymentMode: applications.DeployModeMirror,
			Domains: []applications.Domain{
				{HTTPEnabled: true, HTTPPort: intPtr(8080)},
				{HTTPSEnabled: true, HTTPSPort: intPtr(8443)},
				{HTTPEnabled: true, HTTPPort: intPtr(8080)}, // 重复端口去重
				{HTTPEnabled: false, HTTPPort: nil},         // 未启用协议不计入
			},
		},
		{
			Code: "tpx", DeploymentMode: applications.DeployModeTransparent,
			Domains: []applications.Domain{
				{NormalizedHostname: "www.test.com", HTTPEnabled: true, HTTPPort: intPtr(8081)},
				{NormalizedHostname: "api.test.com", HTTPSEnabled: true, HTTPSPort: intPtr(443)},
				{NormalizedHostname: "www.test.com"}, // 重复域名去重
				{Hostname: "fallback.test.com"},      // 无规范化域名时回退 Hostname
				{},                                   // 空域名不计入
			},
		},
	}
}

func TestBuildMirrorcapSidecar(t *testing.T) {
	apps := sidecarTestApps()
	disc := buildMirrorcapDiscovery(apps, []string{"eth2", "eth3"}, []string{"eth0"})
	sc := buildMirrorcapSidecar(apps, "gw-test-01", []string{"eth2", "eth3"}, disc)
	if !sc.Enabled {
		t.Error("mirrorcap should be enabled when MIRROR app exists")
	}
	if sc.Node != "gw-test-01" {
		t.Errorf("node = %q, want gw-test-01", sc.Node)
	}
	if !reflect.DeepEqual(sc.Interfaces, []string{"eth2", "eth3"}) {
		t.Errorf("interfaces = %v", sc.Interfaces)
	}
	// 仅取 MIRROR 应用域名监听端口（去重排序；rev/tpx 不计入）
	if !reflect.DeepEqual(sc.Ports, []int{8080, 8443}) {
		t.Errorf("ports = %v, want [8080 8443]", sc.Ports)
	}
	// discovery 块随主配置输出
	if !sc.Discovery.Enabled || len(sc.Discovery.Interfaces) != 3 {
		t.Errorf("discovery = %+v", sc.Discovery)
	}
}

func TestBuildMirrorcapSidecarDisabledWithoutMirrorApp(t *testing.T) {
	apps := sidecarTestApps()
	disc := buildMirrorcapDiscovery(apps[:1], nil, nil)
	sc := buildMirrorcapSidecar(apps[:1], "gw-test-01", nil, disc)
	if sc.Enabled {
		t.Error("mirrorcap should be disabled without MIRROR app")
	}
	if sc.Interfaces == nil || len(sc.Interfaces) != 0 {
		t.Errorf("interfaces = %v, want empty array (not nil)", sc.Interfaces)
	}
	if !reflect.DeepEqual(sc.Ports, []int{80}) {
		t.Errorf("ports = %v, want default [80]", sc.Ports)
	}
	if sc.Discovery.Enabled {
		t.Errorf("discovery should be disabled without MIRROR/ROUTED/TRANSPARENT app: %+v", sc.Discovery)
	}
	// JSON 契约：interfaces/ports/discovery.interfaces 恒为数组而非 null
	buf, err := json.Marshal(sc)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"enabled":false,"node":"gw-test-01","interfaces":[],"ports":[80],` +
		`"discovery":{"enabled":false,"interfaces":[],"flush_interval_sec":30,"log":"/var/log/caddy/site-discovery.jsonl"}}`
	if string(buf) != want {
		t.Errorf("json = %s, want %s", buf, want)
	}
}

// discovery 块：仅 MIRROR 应用 → role=MIRROR 接口逐个 mode=MIRROR。
func TestBuildMirrorcapDiscoveryMirrorOnly(t *testing.T) {
	apps := sidecarTestApps()[1:2]
	d := buildMirrorcapDiscovery(apps, []string{"eth2"}, []string{"eth0"})
	if !d.Enabled {
		t.Fatal("discovery should be enabled with mirror app + mirror iface")
	}
	want := []DiscoveryInterface{{Name: "eth2", Mode: "MIRROR"}}
	if !reflect.DeepEqual(d.Interfaces, want) {
		t.Errorf("interfaces = %+v, want %+v", d.Interfaces, want)
	}
	if d.FlushIntervalSec != 30 || d.Log != DefaultSiteDiscoveryLog {
		t.Errorf("flush/log = %d/%q", d.FlushIntervalSec, d.Log)
	}
}

// discovery 块：仅 ROUTED 应用 → role=TRAFFIC 接口 mode=ROUTED。
func TestBuildMirrorcapDiscoveryRoutedOnly(t *testing.T) {
	apps := []AppData{{Code: "rtd", DeploymentMode: applications.DeployModeRouted}}
	d := buildMirrorcapDiscovery(apps, []string{"eth2"}, []string{"eth0", "eth1"})
	want := []DiscoveryInterface{{Name: "eth0", Mode: "ROUTED"}, {Name: "eth1", Mode: "ROUTED"}}
	if !d.Enabled || !reflect.DeepEqual(d.Interfaces, want) {
		t.Errorf("discovery = %+v, want interfaces %+v", d, want)
	}
}

// discovery 块：仅 TRANSPARENT 应用 → role=TRAFFIC 接口 mode=TRANSPARENT。
func TestBuildMirrorcapDiscoveryTransparentOnly(t *testing.T) {
	apps := sidecarTestApps()[2:3]
	d := buildMirrorcapDiscovery(apps, nil, []string{"eth0"})
	want := []DiscoveryInterface{{Name: "eth0", Mode: "TRANSPARENT"}}
	if !d.Enabled || !reflect.DeepEqual(d.Interfaces, want) {
		t.Errorf("discovery = %+v, want interfaces %+v", d, want)
	}
}

// discovery 块：MIRROR + TRANSPARENT 组合 → 同名接口去重（MIRROR 优先），
// TRAFFIC 口 mode 取 TRANSPARENT（透明优先级高于路由）。
func TestBuildMirrorcapDiscoveryMirrorPlusTransparent(t *testing.T) {
	apps := []AppData{sidecarTestApps()[1], sidecarTestApps()[2]}
	d := buildMirrorcapDiscovery(apps, []string{"eth2", "eth0"}, []string{"eth0", "eth1"})
	want := []DiscoveryInterface{
		{Name: "eth2", Mode: "MIRROR"},
		{Name: "eth0", Mode: "MIRROR"}, // 同名去重：MIRROR 优先，不再以 TRANSPARENT 重复出现
		{Name: "eth1", Mode: "TRANSPARENT"},
	}
	if !d.Enabled || !reflect.DeepEqual(d.Interfaces, want) {
		t.Errorf("discovery = %+v, want interfaces %+v", d, want)
	}
}

// discovery 块：有 MIRROR 应用但节点无 MIRROR 口 → enabled=false 且 interfaces 为空数组。
func TestBuildMirrorcapDiscoveryNoUsableInterface(t *testing.T) {
	apps := sidecarTestApps()[1:2]
	d := buildMirrorcapDiscovery(apps, nil, nil)
	if d.Enabled {
		t.Error("discovery should be disabled when no usable interface")
	}
	if d.Interfaces == nil || len(d.Interfaces) != 0 {
		t.Errorf("interfaces = %v, want empty array (not nil)", d.Interfaces)
	}
	buf, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"enabled":false,"interfaces":[],"flush_interval_sec":30,"log":"/var/log/caddy/site-discovery.jsonl"}`
	if string(buf) != want {
		t.Errorf("json = %s, want %s", buf, want)
	}
}

func TestBuildTproxydSidecar(t *testing.T) {
	sc := buildTproxydSidecar(sidecarTestApps())
	if !sc.Enabled {
		t.Error("tproxyd should be enabled when TRANSPARENT app exists")
	}
	if sc.Listen != "127.0.0.1:15000" || sc.Target != "127.0.0.1:8080" {
		t.Errorf("listen/target = %q/%q", sc.Listen, sc.Target)
	}
	if !reflect.DeepEqual(sc.Ports, []int{443, 8081}) {
		t.Errorf("ports = %v, want [443 8081]", sc.Ports)
	}
	if sc.TargetTLS != "127.0.0.1:8443" {
		t.Errorf("target_tls = %q", sc.TargetTLS)
	}
	// SNI 防护清单自动派生自 TRANSPARENT 应用域名（去重排序、空域名不计入）
	want := []string{"api.test.com", "fallback.test.com", "www.test.com"}
	if !reflect.DeepEqual(sc.ProtectHosts, want) {
		t.Errorf("protect_hosts = %v, want %v", sc.ProtectHosts, want)
	}
}

func TestBuildTproxydSidecarDisabledWithoutTransparentApp(t *testing.T) {
	sc := buildTproxydSidecar(sidecarTestApps()[:1])
	if sc.Enabled {
		t.Error("tproxyd should be disabled without TRANSPARENT app")
	}
	if !reflect.DeepEqual(sc.Ports, []int{80}) {
		t.Errorf("ports = %v, want default [80]", sc.Ports)
	}
	if !reflect.DeepEqual(sc.ProtectHosts, []string{}) {
		t.Errorf("protect_hosts = %v, want []", sc.ProtectHosts)
	}
}

func TestWriteSidecarFileAtomic(t *testing.T) {
	// 目录不存在时自动创建
	dir := filepath.Join(t.TempDir(), "sidecars")
	disc := MirrorcapDiscovery{
		Enabled:          true,
		Interfaces:       []DiscoveryInterface{{Name: "eth2", Mode: "MIRROR"}},
		FlushIntervalSec: 30,
		Log:              DefaultSiteDiscoveryLog,
	}
	v := MirrorcapSidecar{Enabled: true, Node: "gw-01", Interfaces: []string{"eth2"}, Ports: []int{8080}, Discovery: disc}
	if err := writeSidecarFile(dir, "mirrorcap.json", v); err != nil {
		t.Fatalf("writeSidecarFile: %v", err)
	}
	buf, err := os.ReadFile(filepath.Join(dir, "mirrorcap.json"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	want := `{"enabled":true,"node":"gw-01","interfaces":["eth2"],"ports":[8080],` +
		`"discovery":{"enabled":true,"interfaces":[{"name":"eth2","mode":"MIRROR"}],"flush_interval_sec":30,"log":"/var/log/caddy/site-discovery.jsonl"}}` + "\n"
	if string(buf) != want {
		t.Fatalf("content = %q, want %q", buf, want)
	}
	// 再次写出为原子替换（旧内容被覆盖，无临时文件残留）
	v.Enabled = false
	v.Ports = []int{80}
	v.Discovery.Enabled = false
	v.Discovery.Interfaces = []DiscoveryInterface{}
	if err := writeSidecarFile(dir, "mirrorcap.json", v); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	buf, _ = os.ReadFile(filepath.Join(dir, "mirrorcap.json"))
	want = `{"enabled":false,"node":"gw-01","interfaces":["eth2"],"ports":[80],` +
		`"discovery":{"enabled":false,"interfaces":[],"flush_interval_sec":30,"log":"/var/log/caddy/site-discovery.jsonl"}}` + "\n"
	if string(buf) != want {
		t.Fatalf("after rewrite content = %q, want %q", buf, want)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "mirrorcap.json" {
		names := []string{}
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("temp files leaked: %v", names)
	}
}

type fakeMirrorIfaces struct {
	ifaces     []string
	traffic    []string
	err        error
	trafficErr error
}

func (f fakeMirrorIfaces) ListMirrorInterfaces(context.Context, string) ([]string, error) {
	return f.ifaces, f.err
}

func (f fakeMirrorIfaces) ListInterfacesByRole(_ context.Context, _ string, role string) ([]string, error) {
	if role != "TRAFFIC" {
		return nil, nil
	}
	return f.traffic, f.trafficErr
}

func TestPublisherWriteSidecarConfigs(t *testing.T) {
	dir := t.TempDir()
	p := &Publisher{}
	p.SetSidecarConfig("gw-test-01", fakeMirrorIfaces{ifaces: []string{"eth2"}, traffic: []string{"eth0"}})
	p.SetSidecarDir(dir)

	p.writeSidecarConfigs(context.Background(), sidecarTestApps())

	buf, err := os.ReadFile(filepath.Join(dir, "mirrorcap.json"))
	if err != nil {
		t.Fatalf("read mirrorcap.json: %v", err)
	}
	var mc MirrorcapSidecar
	if err := json.Unmarshal(buf, &mc); err != nil {
		t.Fatalf("mirrorcap.json invalid: %v", err)
	}
	if !mc.Enabled || mc.Node != "gw-test-01" ||
		!reflect.DeepEqual(mc.Interfaces, []string{"eth2"}) ||
		!reflect.DeepEqual(mc.Ports, []int{8080, 8443}) {
		t.Errorf("mirrorcap.json = %+v", mc)
	}
	// discovery：MIRROR 应用 + TRANSPARENT 应用 → eth2 镜像口 + eth0 流量口（TRANSPARENT）
	wantDisc := []DiscoveryInterface{{Name: "eth2", Mode: "MIRROR"}, {Name: "eth0", Mode: "TRANSPARENT"}}
	if !mc.Discovery.Enabled || !reflect.DeepEqual(mc.Discovery.Interfaces, wantDisc) {
		t.Errorf("discovery = %+v, want interfaces %+v", mc.Discovery, wantDisc)
	}

	buf, err = os.ReadFile(filepath.Join(dir, "tproxyd.json"))
	if err != nil {
		t.Fatalf("read tproxyd.json: %v", err)
	}
	var tp TproxydSidecar
	if err := json.Unmarshal(buf, &tp); err != nil {
		t.Fatalf("tproxyd.json invalid: %v", err)
	}
	if !tp.Enabled || tp.Listen != "127.0.0.1:15000" || tp.Target != "127.0.0.1:8080" ||
		!reflect.DeepEqual(tp.Ports, []int{443, 8081}) {
		t.Errorf("tproxyd.json = %+v", tp)
	}
	// SNI 防护清单自动派生自 TRANSPARENT 应用域名（去重排序）
	wantHosts := []string{"api.test.com", "fallback.test.com", "www.test.com"}
	if tp.TargetTLS != "127.0.0.1:8443" || !reflect.DeepEqual(tp.ProtectHosts, wantHosts) {
		t.Errorf("tproxyd.json sni dispatch = %+v, want hosts %v", tp, wantHosts)
	}
}

// 接口清单查询失败：不静默（记日志）且仍写出边车文件，interfaces 落空数组，discovery 随之 disabled。
func TestPublisherWriteSidecarConfigsInterfaceError(t *testing.T) {
	dir := t.TempDir()
	p := &Publisher{}
	p.SetSidecarConfig("gw-test-01", fakeMirrorIfaces{err: errors.New("db down"), trafficErr: errors.New("db down")})
	p.SetSidecarDir(dir)

	p.writeSidecarConfigs(context.Background(), sidecarTestApps())

	buf, err := os.ReadFile(filepath.Join(dir, "mirrorcap.json"))
	if err != nil {
		t.Fatalf("read mirrorcap.json: %v", err)
	}
	var mc MirrorcapSidecar
	if err := json.Unmarshal(buf, &mc); err != nil {
		t.Fatalf("mirrorcap.json invalid: %v", err)
	}
	if !mc.Enabled || mc.Interfaces == nil || len(mc.Interfaces) != 0 {
		t.Errorf("mirrorcap.json = %+v, want enabled with empty interfaces", mc)
	}
	if mc.Discovery.Enabled || len(mc.Discovery.Interfaces) != 0 {
		t.Errorf("discovery = %+v, want disabled with empty interfaces", mc.Discovery)
	}
}

// 无任何 MIRROR/TRANSPARENT 应用：两个文件仍写出且 enabled=false（文件保留不删除），
// discovery 块恒输出（enabled=false、空接口数组）。
func TestPublisherWriteSidecarConfigsAllDisabled(t *testing.T) {
	dir := t.TempDir()
	p := &Publisher{}
	p.SetSidecarConfig("gw-test-01", fakeMirrorIfaces{ifaces: []string{"eth2"}})
	p.SetSidecarDir(dir)

	p.writeSidecarConfigs(context.Background(), sidecarTestApps()[:1])

	buf, err := os.ReadFile(filepath.Join(dir, "mirrorcap.json"))
	if err != nil {
		t.Fatalf("read mirrorcap.json: %v", err)
	}
	want := `{"enabled":false,"node":"gw-test-01","interfaces":["eth2"],"ports":[80],` +
		`"discovery":{"enabled":false,"interfaces":[],"flush_interval_sec":30,"log":"/var/log/caddy/site-discovery.jsonl"}}` + "\n"
	if string(buf) != want {
		t.Errorf("mirrorcap.json = %q, want %q", buf, want)
	}
	buf, err = os.ReadFile(filepath.Join(dir, "tproxyd.json"))
	if err != nil {
		t.Fatalf("read tproxyd.json: %v", err)
	}
	want = `{"enabled":false,"listen":"127.0.0.1:15000","target":"127.0.0.1:8080","ports":[80],` +
		`"target_tls":"127.0.0.1:8443","protect_hosts":[]}` + "\n"
	if string(buf) != want {
		t.Errorf("tproxyd.json = %q, want %q", buf, want)
	}
}
