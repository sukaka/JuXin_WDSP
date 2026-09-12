package mirrorcap

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// writeFile 写入下发配置文件（测试辅助）。
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
}

func TestLoadFileConfigValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mirrorcap.json")
	writeFile(t, path, `{
		"enabled": true,
		"node": "node-a",
		"interfaces": ["eth2", " eth3 ", "eth2"],
		"ports": [80, 8080, 80],
		"events_log": "/var/log/caddy/api-runtime-events.log",
		"future_field": " tolerated "
	}`)
	fc, err := LoadFileConfig(path)
	if err != nil {
		t.Fatalf("LoadFileConfig: %v", err)
	}
	if !fc.Enabled || fc.Node != "node-a" {
		t.Errorf("enabled/node 解析错误: %+v", fc)
	}
	if !reflect.DeepEqual(fc.Ifaces, []string{"eth2", "eth3"}) {
		t.Errorf("Ifaces=%v 应去空白去重保序", fc.Ifaces)
	}
	if !reflect.DeepEqual(fc.Ports, []uint16{80, 8080}) {
		t.Errorf("Ports=%v 应去重保序", fc.Ports)
	}
	if fc.EventsLog != "/var/log/caddy/api-runtime-events.log" {
		t.Errorf("EventsLog=%q", fc.EventsLog)
	}
}

func TestLoadFileConfigNotExist(t *testing.T) {
	_, err := LoadFileConfig(filepath.Join(t.TempDir(), "nonexistent", "mirrorcap.json"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("文件不存在应可用 errors.Is(os.ErrNotExist) 判别, got %v", err)
	}
}

func TestLoadFileConfigBadJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mirrorcap.json")
	writeFile(t, path, `{"enabled": true, "interfaces": [`)
	if _, err := LoadFileConfig(path); err == nil || !strings.Contains(err.Error(), "解析") {
		t.Fatalf("坏 JSON 应报解析错误, got %v", err)
	}
}

func TestLoadFileConfigEnabledRequiresInterfaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mirrorcap.json")
	writeFile(t, path, `{"enabled": true, "interfaces": []}`)
	if _, err := LoadFileConfig(path); err == nil || !strings.Contains(err.Error(), "interfaces") {
		t.Fatalf("enabled=true 且 interfaces 为空应报错, got %v", err)
	}
}

func TestLoadFileConfigDisabledAllowsEmptyInterfaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mirrorcap.json")
	writeFile(t, path, `{"enabled": false}`)
	fc, err := LoadFileConfig(path)
	if err != nil {
		t.Fatalf("disabled 配置应合法: %v", err)
	}
	if fc.Enabled {
		t.Fatal("Enabled 应为 false")
	}
}

func TestLoadFileConfigPortRange(t *testing.T) {
	cases := []struct {
		name    string
		json    string
		wantErr bool
	}{
		{"端口下界0", `{"enabled":true,"interfaces":["eth0"],"ports":[0]}`, true},
		{"端口上界65535", `{"enabled":true,"interfaces":["eth0"],"ports":[65535]}`, false},
		{"端口超65535", `{"enabled":true,"interfaces":["eth0"],"ports":[65536]}`, true}, // uint16 解码期拒绝
		{"端口负数", `{"enabled":true,"interfaces":["eth0"],"ports":[-1]}`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "mirrorcap.json")
			writeFile(t, path, c.json)
			_, err := LoadFileConfig(path)
			if c.wantErr && err == nil {
				t.Fatal("应报错")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("不应报错: %v", err)
			}
		})
	}
}

func TestFileConfigOverlay(t *testing.T) {
	base := Defaults()
	base.Iface = "eth9"
	base.Ports = []uint16{80, 8080}
	base.NodeName = "env-node"

	// 文件字段非空即以文件为准；未携带字段沿用 env 基线
	fc := FileConfig{Enabled: true, Node: "file-node", Ifaces: []string{"eth2"}, Ports: []uint16{9000}, EventsLog: "/tmp/f.log"}
	cfg := fc.overlay(base)
	if cfg.NodeName != "file-node" || cfg.EventsLog != "/tmp/f.log" {
		t.Errorf("文件字段未生效: %+v", cfg)
	}
	if !reflect.DeepEqual(cfg.Ports, []uint16{9000}) {
		t.Errorf("Ports=%v want [9000]", cfg.Ports)
	}

	// 空字段回退 env 基线（容忍发布端只下发差量字段）
	fc2 := FileConfig{Enabled: true, Ifaces: []string{"eth2"}}
	cfg2 := fc2.overlay(base)
	if cfg2.NodeName != "env-node" || cfg2.EventsLog != base.EventsLog {
		t.Errorf("空字段应回退 env 基线: %+v", cfg2)
	}
	if !reflect.DeepEqual(cfg2.Ports, []uint16{80, 8080}) {
		t.Errorf("Ports=%v 应回退 env [80 8080]", cfg2.Ports)
	}
	if cfg2.BodyMax != base.BodyMax || cfg2.RulesDir != base.RulesDir {
		t.Errorf("运维项应沿用 env 基线: %+v", cfg2)
	}
}

// discovery 块解析：未知字段容忍、mode 归一、去重保序、enabled 约束。
func TestLoadFileConfigDiscovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mirrorcap.json")
	writeFile(t, path, `{
		"enabled": false,
		"discovery": {
			"enabled": true,
			"interfaces": [{"name":"eth2","mode":"routed"},{"name":" eth0 "},{"name":"eth2","mode":"ROUTED"},{"name":"eth1","mode":"transparent"}],
			"flush_interval_sec": 45,
			"log": "/var/log/caddy/disc.jsonl",
			"future_field": " tolerated "
		}
	}`)
	fc, err := LoadFileConfig(path)
	if err != nil {
		t.Fatalf("LoadFileConfig: %v", err)
	}
	d := fc.Discovery
	if d == nil || !d.Enabled {
		t.Fatalf("discovery 块未解析: %+v", fc)
	}
	want := []FileDiscoveryIface{{Name: "eth2", Mode: "ROUTED"}, {Name: "eth0", Mode: "MIRROR"}, {Name: "eth1", Mode: "TRANSPARENT"}}
	if !reflect.DeepEqual(d.Interfaces, want) {
		t.Errorf("Interfaces=%v want %v（mode 大写归一/缺省 MIRROR、去重保序）", d.Interfaces, want)
	}
	if d.FlushIntervalSec != 45 || d.Log != "/var/log/caddy/disc.jsonl" {
		t.Errorf("flush/log 解析错误: %+v", d)
	}
}

func TestLoadFileConfigDiscoveryEnabledRequiresInterfaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mirrorcap.json")
	writeFile(t, path, `{"enabled":true,"interfaces":["eth0"],"discovery":{"enabled":true,"interfaces":[]}}`)
	if _, err := LoadFileConfig(path); err == nil || !strings.Contains(err.Error(), "discovery.interfaces") {
		t.Fatalf("discovery.enabled=true 且 interfaces 为空应报错, got %v", err)
	}
}

func TestLoadFileConfigDiscoveryBadModeAndInterval(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{"非法mode", `{"enabled":false,"discovery":{"enabled":true,"interfaces":[{"name":"eth0","mode":"TAP"}]}}`},
		{"负周期", `{"enabled":false,"discovery":{"enabled":true,"interfaces":[{"name":"eth0"}],"flush_interval_sec":-1}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "mirrorcap.json")
			writeFile(t, path, c.json)
			if _, err := LoadFileConfig(path); err == nil {
				t.Fatal("应报错")
			}
		})
	}
}

// discovery overlay：块存在即 enabled 以文件为准；字段空回退 env 基线。
func TestFileConfigOverlayDiscovery(t *testing.T) {
	base := Defaults()
	base.Discovery.Enabled = true // env 基线开启
	base.Discovery.Ifaces = []DiscoveryIface{{Name: "ethE", Mode: "ROUTED"}}

	// 文件块显式关闭（enabled=false 以文件为准）
	fc := FileConfig{Discovery: &FileDiscovery{Enabled: false}}
	cfg := fc.overlay(base)
	if cfg.Discovery.Enabled {
		t.Error("文件 discovery.enabled=false 应覆盖 env 基线")
	}

	// 文件块下发部分字段：空字段回退 env 基线
	fc2 := FileConfig{Discovery: &FileDiscovery{
		Enabled:    true,
		Interfaces: []FileDiscoveryIface{{Name: "ethF", Mode: "MIRROR"}},
	}}
	cfg2 := fc2.overlay(base)
	if !cfg2.Discovery.Enabled || len(cfg2.Discovery.Ifaces) != 1 || cfg2.Discovery.Ifaces[0].Name != "ethF" {
		t.Errorf("文件发现字段未生效: %+v", cfg2.Discovery)
	}
	if cfg2.Discovery.Log != base.Discovery.Log || cfg2.Discovery.FlushInterval != base.Discovery.FlushInterval {
		t.Errorf("空字段应回退 env 基线: %+v", cfg2.Discovery)
	}

	// 块缺省：整块沿用 env 基线
	fc3 := FileConfig{}
	cfg3 := fc3.overlay(base)
	if !cfg3.Discovery.Enabled || len(cfg3.Discovery.Ifaces) != 1 || cfg3.Discovery.Ifaces[0].Name != "ethE" {
		t.Errorf("discovery 块缺省应沿用 env 基线: %+v", cfg3.Discovery)
	}
}
