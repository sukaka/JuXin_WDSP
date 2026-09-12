package tproxyd

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
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
	path := filepath.Join(t.TempDir(), "tproxyd.json")
	writeFile(t, path, `{
		"enabled": true,
		"listen": "0.0.0.0:15000",
		"target": "127.0.0.1:8080",
		"ports": [80, 8081, 80],
		"future_field": 1
	}`)
	fc, err := LoadFileConfig(path)
	if err != nil {
		t.Fatalf("LoadFileConfig: %v", err)
	}
	if !fc.Enabled || fc.Listen != "0.0.0.0:15000" || fc.Target != "127.0.0.1:8080" {
		t.Errorf("字段解析错误: %+v", fc)
	}
	if !reflect.DeepEqual(fc.Ports, []uint16{80, 8081}) {
		t.Errorf("Ports=%v 应去重保序", fc.Ports)
	}
}

func TestLoadFileConfigNotExist(t *testing.T) {
	_, err := LoadFileConfig(filepath.Join(t.TempDir(), "nonexistent", "tproxyd.json"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("文件不存在应可用 errors.Is(os.ErrNotExist) 判别, got %v", err)
	}
}

func TestLoadFileConfigBadJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tproxyd.json")
	writeFile(t, path, `{"enabled": true, "listen":`)
	if _, err := LoadFileConfig(path); err == nil || !strings.Contains(err.Error(), "解析") {
		t.Fatalf("坏 JSON 应报解析错误, got %v", err)
	}
}

func TestLoadFileConfigRejectsBadAddr(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{"listen 缺端口", `{"enabled":true,"listen":"no-port"}`},
		{"listen 端口非法", `{"enabled":true,"listen":"127.0.0.1:abc"}`},
		{"target 非法", `{"enabled":true,"target":"127.0.0.1:notaport"}`},
		{"端口为0", `{"enabled":true,"ports":[0]}`},
		{"端口超界", `{"enabled":true,"ports":[65536]}`}, // uint16 解码期拒绝
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tproxyd.json")
			writeFile(t, path, c.json)
			if _, err := LoadFileConfig(path); err == nil {
				t.Fatal("应报错")
			}
		})
	}
}

func TestLoadFileConfigDisabledMinimal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tproxyd.json")
	writeFile(t, path, `{"enabled": false}`)
	fc, err := LoadFileConfig(path)
	if err != nil {
		t.Fatalf("disabled 最简配置应合法: %v", err)
	}
	if fc.Enabled || fc.Listen != "" || fc.Target != "" {
		t.Fatalf("字段应为零值: %+v", fc)
	}
}

func TestLoadFileConfigSNIDispatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tproxyd.json")
	writeFile(t, path, `{
		"enabled": true,
		"protect_hosts": ["Www.Test.COM.", "www.test.com", "api.test.com"],
		"target_tls": "127.0.0.1:8443"
	}`)
	fc, err := LoadFileConfig(path)
	if err != nil {
		t.Fatalf("LoadFileConfig: %v", err)
	}
	if !reflect.DeepEqual(fc.ProtectHosts, []string{"www.test.com", "api.test.com"}) {
		t.Fatalf("ProtectHosts 归一化/去重错误: %v", fc.ProtectHosts)
	}
	if fc.TargetTLS != "127.0.0.1:8443" {
		t.Fatalf("TargetTLS=%q", fc.TargetTLS)
	}
}

func TestLoadFileConfigRejectsBadSNIDispatch(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{"target_tls 非法", `{"enabled":true,"target_tls":"no-port"}`},
		{"protect_hosts 非法域名", `{"enabled":true,"protect_hosts":["bad host.com"]}`},
		{"protect_hosts 通配符", `{"enabled":true,"protect_hosts":["*.test.com"]}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tproxyd.json")
			writeFile(t, path, c.json)
			if _, err := LoadFileConfig(path); err == nil {
				t.Fatal("应报错")
			}
		})
	}
}

// 文件空字段回退 env 基线、非空字段覆盖（supervisor.resolve 叠加语义）。
func TestResolveOverlaySemantics(t *testing.T) {
	base := Defaults()
	base.Listen = "127.0.0.1:15000"

	path := filepath.Join(t.TempDir(), "tproxyd.json")
	// 文件仅携带 listen：target 回退 env 基线
	writeFile(t, path, `{"enabled":true,"listen":"0.0.0.0:15000","ports":[80]}`)
	s := NewSupervisor(base, nil, path, time.Minute, &Stats{}, nil)
	d, err := s.resolve()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !d.enabled || d.source != "file" {
		t.Fatalf("期望 file 模式 enabled, got %+v", d)
	}
	if d.cfg.Listen != "0.0.0.0:15000" || d.cfg.Target != base.Target {
		t.Fatalf("overlay 语义错误（文件 listen 优先、target 回退 env）: %+v", d.cfg)
	}
	if !reflect.DeepEqual(d.ports, []uint16{80}) {
		t.Fatalf("ports=%v want [80]", d.ports)
	}
}

// 文件携带 protect_hosts/target_tls 时叠加进生效配置，且纳入重启指纹。
func TestResolveOverlaySNIDispatch(t *testing.T) {
	base := Defaults()
	base.Listen = "127.0.0.1:15000"

	path := filepath.Join(t.TempDir(), "tproxyd.json")
	writeFile(t, path, `{"enabled":true,"protect_hosts":["www.test.com"],"target_tls":"127.0.0.1:8443"}`)
	s := NewSupervisor(base, nil, path, time.Minute, &Stats{}, nil)
	d, err := s.resolve()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !reflect.DeepEqual(d.cfg.ProtectHosts, []string{"www.test.com"}) {
		t.Fatalf("protect_hosts 叠加错误: %v", d.cfg.ProtectHosts)
	}
	if d.cfg.TargetTLS != "127.0.0.1:8443" || d.cfg.Target != base.Target {
		t.Fatalf("target_tls 应取文件、target 回退 env: %+v", d.cfg)
	}
	// 指纹应含分流配置（清单变化触发监听重启）
	k1 := d.stateKey()
	writeFile(t, path, `{"enabled":true,"protect_hosts":["www.test.com","api.test.com"],"target_tls":"127.0.0.1:8443"}`)
	d2, err := s.resolve()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if d2.stateKey() == k1 || cfgKey(d2.cfg) == cfgKey(d.cfg) {
		t.Fatal("protect_hosts 变化应改变状态/监听指纹")
	}
}
