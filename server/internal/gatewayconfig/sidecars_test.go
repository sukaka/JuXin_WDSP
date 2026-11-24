package gatewayconfig

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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
	// 仅取 MIRROR 应用的明文 HTTP 端口（排除 HTTPS 端口 8443，避免破坏 443/8443 TLS SNI 站点发现）
	if !reflect.DeepEqual(sc.Ports, []int{8080}) {
		t.Errorf("ports = %v, want [8080]", sc.Ports)
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
	if sc.Listen != DefaultTproxydListen || sc.Target != DefaultTproxydTarget {
		t.Errorf("listen/target = %q/%q, want %q/%q", sc.Listen, sc.Target, DefaultTproxydListen, DefaultTproxydTarget)
	}
	if !reflect.DeepEqual(sc.Ports, []int{443, 8081}) {
		t.Errorf("ports = %v, want [443 8081]", sc.Ports)
	}
	if sc.TargetTLS != DefaultTproxydTargetTLS {
		t.Errorf("target_tls = %q, want %q", sc.TargetTLS, DefaultTproxydTargetTLS)
	}
	// SNI 防护清单仅收集启用了 HTTPS 的 TRANSPARENT 域名（纯 HTTP 域名不进入 protect_hosts）
	want := []string{"api.test.com"}
	if !reflect.DeepEqual(sc.ProtectHosts, want) {
		t.Errorf("protect_hosts = %v, want %v", sc.ProtectHosts, want)
	}
}

func TestBuildTproxydSidecarDisabledWithoutTransparentApp(t *testing.T) {
	sc := buildTproxydSidecar(sidecarTestApps()[:1])
	if sc.Enabled {
		t.Error("tproxyd should be disabled without TRANSPARENT app")
	}
	if sc.Ports == nil || len(sc.Ports) != 0 {
		t.Errorf("ports = %v, want empty array []", sc.Ports)
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
		!reflect.DeepEqual(mc.Ports, []int{8080}) {
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
	if !tp.Enabled || tp.Listen != DefaultTproxydListen || tp.Target != DefaultTproxydTarget ||
		!reflect.DeepEqual(tp.Ports, []int{443, 8081}) {
		t.Errorf("tproxyd.json = %+v", tp)
	}
	// SNI 防护清单仅包含启用 HTTPS 的 TRANSPARENT 域名
	wantHosts := []string{"api.test.com"}
	if tp.TargetTLS != DefaultTproxydTargetTLS || !reflect.DeepEqual(tp.ProtectHosts, wantHosts) {
		t.Errorf("tproxyd.json sni dispatch = %+v, want hosts %v", tp, wantHosts)
	}
}

// 接口清单查询失败：不静默（记日志）且仍写出有效边车文件——无可用镜像口时 enabled=false
// （避免产出 mirrorcap.json 非法导致 mirrorcap 拒收整份文件连带冻结 discovery），interfaces 落空数组。
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
	if mc.Enabled || mc.Interfaces == nil || len(mc.Interfaces) != 0 {
		t.Errorf("mirrorcap.json = %+v, want disabled with empty interfaces", mc)
	}
	if mc.Discovery.Enabled || len(mc.Discovery.Interfaces) != 0 {
		t.Errorf("discovery = %+v, want disabled with empty interfaces", mc.Discovery)
	}
}

// 回归验证：
// 1. MIRROR 应用仅启用 HTTPS 时：mirrorcap 检测不启用（不把 443 塞进 HTTP 检测端口），但发现保持启用（TLS SNI）；
// 2. MIRROR 应用防护模式为 OFF/BYPASS 时：mirrorcap 检测关闭；
// 3. 域名列表与自定义网关日志路径（裸机场景）正确写入 mirrorcap.json。
func TestBuildMirrorcapSidecarEdgeCasesAndLogPaths(t *testing.T) {
	httpsOnly := []AppData{{
		Code: "mir-https", DeploymentMode: applications.DeployModeMirror, ProtectionMode: applications.ModeObserve,
		Domains: []applications.Domain{{NormalizedHostname: "sec.example.com", HTTPSEnabled: true, HTTPSPort: intPtr(443)}},
	}}
	disc := buildMirrorcapDiscovery(httpsOnly, []string{"eth2"}, nil)
	sc := buildMirrorcapSidecar(httpsOnly, "gw-01", []string{"eth2"}, disc)
	if sc.Enabled {
		t.Fatalf("HTTPS-only MIRROR app should not enable plaintext HTTP detection: %+v", sc)
	}
	if !sc.Discovery.Enabled {
		t.Fatalf("HTTPS-only MIRROR app should still enable TLS SNI discovery: %+v", sc.Discovery)
	}

	bypassMirror := []AppData{{
		Code: "mir-bypass", DeploymentMode: applications.DeployModeMirror, ProtectionMode: applications.ModeBypass,
		Domains: []applications.Domain{{NormalizedHostname: "a.example.com", HTTPEnabled: true, HTTPPort: intPtr(80)}},
	}}
	scBypass := buildMirrorcapSidecar(bypassMirror, "gw-01", []string{"eth2"}, buildMirrorcapDiscovery(bypassMirror, []string{"eth2"}, nil))
	if scBypass.Enabled {
		t.Fatalf("BYPASS MIRROR app should disable detection: %+v", scBypass)
	}

	dir := t.TempDir()
	p := &Publisher{}
	p.SetSidecarConfig("gw-bm-01", fakeMirrorIfaces{ifaces: []string{"eth2"}})
	p.SetSidecarDir(dir)
	p.SetSidecarLogPaths("/opt/jz/logs/api-runtime-events.log", "/opt/jz/logs/coraza-audit.log", "/opt/jz/logs/site-discovery.jsonl")
	apps := []AppData{{
		Code: "mir-http", DeploymentMode: applications.DeployModeMirror, ProtectionMode: applications.ModeObserve,
		Domains: []applications.Domain{
			{NormalizedHostname: "b.example.com", HTTPEnabled: true, HTTPPort: intPtr(8080)},
			{NormalizedHostname: "a.example.com", HTTPEnabled: true, HTTPPort: intPtr(80), HTTPSEnabled: true, HTTPSPort: intPtr(443)},
			{NormalizedHostname: "tls.example.com", HTTPSEnabled: true, HTTPSPort: intPtr(443)},
		},
	}}
	p.writeSidecarConfigs(context.Background(), apps)
	raw, err := os.ReadFile(filepath.Join(dir, "mirrorcap.json"))
	if err != nil {
		t.Fatalf("read mirrorcap.json: %v", err)
	}
	var got MirrorcapSidecar
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.Enabled || !reflect.DeepEqual(got.Ports, []int{80, 8080}) ||
		!reflect.DeepEqual(got.Domains, []string{"a.example.com", "b.example.com"}) ||
		got.EventsLog != "/opt/jz/logs/api-runtime-events.log" ||
		got.AuditLog != "/opt/jz/logs/coraza-audit.log" ||
		got.Discovery.Log != "/opt/jz/logs/site-discovery.jsonl" {
		t.Fatalf("unexpected mirrorcap.json: %+v", got)
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
	want = `{"enabled":false,"listen":"0.0.0.0:15000","target":"127.0.0.1:15080","ports":[],` +
		`"target_tls":"127.0.0.1:15443","protect_hosts":[],"passthrough_allowlist":[]}` + "\n"
	if string(buf) != want {
		t.Errorf("tproxyd.json = %q, want %q", buf, want)
	}
}

type fakeBridgePorts struct {
	ports []string
	err   error
}

func (f fakeBridgePorts) ListBridgePorts(context.Context, string) ([]string, error) {
	return f.ports, f.err
}

func TestTproxydSidecarBypassHTTPOnlyWildcardAndAllowlist(t *testing.T) {
	// 1. OFF / BYPASS（含授权失效强制 BYPASS）完全禁用 tproxyd 牵引
	for _, mode := range []string{applications.ModeOff, applications.ModeBypass} {
		apps := []AppData{{
			Code: "tpx-" + mode, DeploymentMode: applications.DeployModeTransparent, ProtectionMode: mode,
			Domains: []applications.Domain{{
				NormalizedHostname: "app.example.com", HTTPEnabled: true, HTTPPort: intPtr(80),
				HTTPSEnabled: true, HTTPSPort: intPtr(443), Status: "ACTIVE",
			}},
		}}
		sc := buildTproxydSidecar(apps)
		if sc.Enabled || len(sc.Ports) != 0 || len(sc.ProtectHosts) != 0 {
			t.Fatalf("mode %s should disable tproxyd completely: %+v", mode, sc)
		}
	}

	// 2. 纯 HTTP 透明应用：enabled=true、ports=[80]、protect_hosts=[]（不误触发 TLS SNI 嗅探）
	httpOnly := []AppData{{
		Code: "tpx-http", DeploymentMode: applications.DeployModeTransparent, ProtectionMode: applications.ModeProtect,
		Domains: []applications.Domain{{
			NormalizedHostname: "plain.example.com", HTTPEnabled: true, HTTPPort: intPtr(80), Status: "ACTIVE",
		}},
	}}
	scHTTP := buildTproxydSidecar(httpOnly)
	if !scHTTP.Enabled || !reflect.DeepEqual(scHTTP.Ports, []int{80}) || len(scHTTP.ProtectHosts) != 0 {
		t.Fatalf("HTTP-only transparent sidecar = %+v", scHTTP)
	}

	// 3. 通配符域名 *.example.com + passthrough_allowlist（支持逗号/换行与 JSON 数组）+ 自定义地址
	dir := t.TempDir()
	p := &Publisher{}
	p.SetSidecarDir(dir)
	p.SetSidecarConfig("gw-01", fakeMirrorIfaces{})
	p.SetBridgePortsProvider(fakeBridgePorts{ports: []string{"eth2", "eth3"}})
	p.SetTproxyAddresses("0.0.0.0:16000", "127.0.0.1:16080", "127.0.0.1:16443")
	p.SetTproxyPassthroughAllowlistProvider(func(context.Context) (string, error) {
		return "Pass.Other.com,\n*.partner.example.com., pass.other.com", nil
	})
	wildcardApp := []AppData{{
		Code: "tpx-wild", DeploymentMode: applications.DeployModeTransparent, ProtectionMode: applications.ModeProtect,
		Domains: []applications.Domain{
			{NormalizedHostname: "*.example.com", HTTPSEnabled: true, HTTPSPort: intPtr(443), Status: "ACTIVE"},
			{NormalizedHostname: "disabled.example.com", HTTPSEnabled: true, HTTPSPort: intPtr(8443), Status: "DISABLED"},
		},
		Upstreams: []applications.Upstream{{NormalizedHost: "192.0.2.1", Port: 443, Status: "ACTIVE"}},
	}}
	sc, err := p.validateTransparentConfig(context.Background(), wildcardApp)
	if err != nil {
		t.Fatalf("validateTransparentConfig: %v", err)
	}
	if sc.Listen != "0.0.0.0:16000" || sc.Target != "127.0.0.1:16080" || sc.TargetTLS != "127.0.0.1:16443" {
		t.Fatalf("custom tproxy addrs = %+v", sc)
	}
	if !reflect.DeepEqual(sc.ProtectHosts, []string{"*.example.com"}) {
		t.Fatalf("protect_hosts = %v, want [*.example.com]", sc.ProtectHosts)
	}
	if !reflect.DeepEqual(sc.PassthroughAllowlist, []string{"*.partner.example.com", "pass.other.com"}) {
		t.Fatalf("passthrough_allowlist = %v", sc.PassthroughAllowlist)
	}

	// JSON 数组格式解析、空串返回非 nil 空数组、清空设置后显式输出 "passthrough_allowlist":[] 以覆盖 env 基线，以及非法域名拒绝
	emptyHosts, err := ParseTproxyPassthroughAllowlist("")
	if err != nil || emptyHosts == nil || len(emptyHosts) != 0 {
		t.Fatalf("ParseTproxyPassthroughAllowlist(\"\") = %#v, %v; want non-nil empty slice", emptyHosts, err)
	}
	p.SetTproxyPassthroughAllowlistProvider(func(context.Context) (string, error) {
		return "", nil
	})
	p.writeTproxydSidecarConfig(context.Background(), wildcardApp)
	rawCleared, err := os.ReadFile(filepath.Join(dir, "tproxyd.json"))
	if err != nil {
		t.Fatalf("read cleared tproxyd.json: %v", err)
	}
	if !strings.Contains(string(rawCleared), `"passthrough_allowlist":[]`) {
		t.Fatalf("cleared tproxyd.json must explicitly emit empty array to override env fallback, got: %s", rawCleared)
	}
	arrHosts, err := ParseTproxyPassthroughAllowlist(`["a.example.com", "*.b.example.com"]`)
	if err != nil || !reflect.DeepEqual(arrHosts, []string{"*.b.example.com", "a.example.com"}) {
		t.Fatalf("JSON array parse = %v, %v", arrHosts, err)
	}
	for _, bad := range []string{"*", "*.com", "*.*.example.com", "bad host.com", "[not-json"} {
		if _, err := ParseTproxyPassthroughAllowlist(bad); err == nil {
			t.Errorf("ParseTproxyPassthroughAllowlist(%q) should fail", bad)
		}
	}

	// 4. 透明应用 0 活动源站必须被校验拒绝
	noUpstreamApp := []AppData{{
		Code: "tpx-empty", DeploymentMode: applications.DeployModeTransparent, ProtectionMode: applications.ModeProtect,
		Domains: []applications.Domain{{NormalizedHostname: "a.example.com", HTTPEnabled: true, HTTPPort: intPtr(80), Status: "ACTIVE"}},
	}}
	if _, err := p.validateTransparentConfig(context.Background(), noUpstreamApp); err == nil {
		t.Fatal("TRANSPARENT app with enabled domain and 0 active upstreams must fail validation")
	}

	// 5. 网桥成员口并入 mirrorcap.json 透明站点发现
	p.writeMirrorcapSidecarConfig(context.Background(), wildcardApp)
	rawMC, err := os.ReadFile(filepath.Join(dir, "mirrorcap.json"))
	if err != nil {
		t.Fatal(err)
	}
	var mc MirrorcapSidecar
	if err := json.Unmarshal(rawMC, &mc); err != nil {
		t.Fatal(err)
	}
	wantDisc := []DiscoveryInterface{{Name: "eth2", Mode: "TRANSPARENT"}, {Name: "eth3", Mode: "TRANSPARENT"}}
	if !mc.Discovery.Enabled || !reflect.DeepEqual(mc.Discovery.Interfaces, wantDisc) {
		t.Fatalf("bridge ports should populate transparent discovery: %+v", mc.Discovery)
	}

	// 6. 回滚恢复 tproxyd.json：有 snapshot.tproxyd 按快照恢复；历史无透明 server 版本自动关闭
	snapJSON, _ := json.Marshal(map[string]any{
		"tproxyd": TproxydSidecar{
			Enabled: true, Listen: "0.0.0.0:15000", Target: "127.0.0.1:15080",
			TargetTLS: "127.0.0.1:15443", Ports: []int{443}, ProtectHosts: []string{"old.example.com"},
		},
	})
	if err := p.restoreSidecarsAfterRollback(context.Background(), &ConfigVersion{BusinessSnapshot: string(snapJSON)}); err != nil {
		t.Fatalf("restoreSidecarsAfterRollback(snapshot): %v", err)
	}
	rawTP, _ := os.ReadFile(filepath.Join(dir, "tproxyd.json"))
	var restored TproxydSidecar
	if err := json.Unmarshal(rawTP, &restored); err != nil {
		t.Fatal(err)
	}
	if !restored.Enabled || !reflect.DeepEqual(restored.ProtectHosts, []string{"old.example.com"}) ||
		restored.PassthroughAllowlist == nil || len(restored.PassthroughAllowlist) != 0 ||
		!strings.Contains(string(rawTP), `"passthrough_allowlist":[]`) {
		t.Fatalf("restored snapshot tproxyd = %+v, raw = %s", restored, rawTP)
	}

	if err := p.restoreSidecarsAfterRollback(context.Background(), &ConfigVersion{
		BusinessSnapshot:  `{"apps":[{"code":"rev"}]}`,
		ConfigurationJSON: `{"apps":{"http":{"servers":{"srv0":{"listen":[":80"]}}}}}`,
	}); err != nil {
		t.Fatalf("restoreSidecarsAfterRollback(legacy): %v", err)
	}
	rawTP, _ = os.ReadFile(filepath.Join(dir, "tproxyd.json"))
	if err := json.Unmarshal(rawTP, &restored); err != nil {
		t.Fatal(err)
	}
	if restored.Enabled || len(restored.Ports) != 0 || len(restored.ProtectHosts) != 0 {
		t.Fatalf("legacy non-transparent rollback must disable tproxyd: %+v", restored)
	}
}
