package netmgrd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeCfg 落盘临时配置并加载（应通过校验，否则测试即失败）。
func writeCfg(t *testing.T, content string) Config {
	t.Helper()
	cfg, err := LoadConfig(writeOnly(t, content))
	if err != nil {
		t.Fatalf("测试配置应通过校验: %v", err)
	}
	return cfg
}

func TestLoadConfigValid(t *testing.T) {
	cfg := writeCfg(t, `{
		"bridges":[{"name":"br0","ports":["eth2","eth3"]}],
		"ip_forward":true,
		"routes":[{"dst":"10.9.0.0/24","via":"192.168.50.1"}],
		"updated_at":"2026-08-19T00:00:00Z",
		"future_field":"前向兼容：未知字段应容忍"
	}`)
	if len(cfg.Bridges) != 1 || cfg.Bridges[0].Name != "br0" {
		t.Fatalf("bridges 解析错误: %+v", cfg.Bridges)
	}
	if got := cfg.Bridges[0].Ports; len(got) != 2 || got[0] != "eth2" || got[1] != "eth3" {
		t.Fatalf("ports 解析错误: %v", got)
	}
	if !cfg.IPForward {
		t.Fatal("ip_forward 应为 true")
	}
	if len(cfg.Routes) != 1 || cfg.Routes[0].Dst != "10.9.0.0/24" || cfg.Routes[0].Via != "192.168.50.1" {
		t.Fatalf("routes 解析错误: %+v", cfg.Routes)
	}
	if cfg.UpdatedAt == "" {
		t.Fatal("updated_at 应保留")
	}
}

func TestLoadConfigCanonicalizesDst(t *testing.T) {
	cfg, err := LoadConfig(writeOnly(t, `{"routes":[{"dst":"10.9.0.1/24","via":"192.168.50.1"}]}`))
	if err != nil {
		t.Fatalf("应通过校验: %v", err)
	}
	if cfg.Routes[0].Dst != "10.9.0.0/24" {
		t.Fatalf("dst 应归一化为掩码后网络地址: %s", cfg.Routes[0].Dst)
	}
}

func writeOnly(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "network.json")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("写临时配置: %v", err)
	}
	return path
}

func TestLoadConfigNotExist(t *testing.T) {
	_, err := LoadConfig(filepath.Join(t.TempDir(), "network.json"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("缺失文件应可用 errors.Is(os.ErrNotExist) 判别: %v", err)
	}
}

func TestLoadConfigBadJSON(t *testing.T) {
	if _, err := LoadConfig(writeOnly(t, `{"bridges": [}`)); err == nil {
		t.Fatal("坏 JSON 应报错")
	}
}

func TestLoadConfigValidation(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"空网桥名", `{"bridges":[{"name":"","ports":[]}]}`, "网桥名非法"},
		{"网桥名注入字符", `{"bridges":[{"name":"br0;rm -rf /","ports":[]}]}`, "网桥名非法"},
		{"网桥名过长", `{"bridges":[{"name":"br0123456789abcd","ports":[]}]}`, "网桥名非法"},
		{"网桥名非字母数字开头", `{"bridges":[{"name":"-br0","ports":[]}]}`, "网桥名非法"},
		{"口名非法", `{"bridges":[{"name":"br0","ports":["eth 2"]}]}`, "接口名非法"},
		{"口名注入", `{"bridges":[{"name":"br0","ports":["eth2,$(id)"]}]}`, "接口名非法"},
		{"自身为成员", `{"bridges":[{"name":"br0","ports":["br0"]}]}`, "自身"},
		{"口跨两桥", `{"bridges":[{"name":"br0","ports":["eth2"]},{"name":"br1","ports":["eth2"]}]}`, "同时出现"},
		{"dst缺掩码", `{"routes":[{"dst":"10.9.0.0","via":"192.168.50.1"}]}`, "dst 非法"},
		{"dst掩码越界", `{"routes":[{"dst":"10.9.0.0/33","via":"192.168.50.1"}]}`, "dst 非法"},
		{"dst非法IP", `{"routes":[{"dst":"999.0.0.0/24","via":"192.168.50.1"}]}`, "dst 非法"},
		{"dst为IPv6", `{"routes":[{"dst":"fd00::/64","via":"192.168.50.1"}]}`, "仅支持 IPv4"},
		{"via非法", `{"routes":[{"dst":"10.9.0.0/24","via":"192.168.1"}]}`, "via 非法"},
		{"via为IPv6", `{"routes":[{"dst":"10.9.0.0/24","via":"fd00::1"}]}`, "via 非法"},
		{"via为空", `{"routes":[{"dst":"10.9.0.0/24","via":""}]}`, "via 非法"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadConfig(writeOnly(t, tc.content))
			if err == nil {
				t.Fatalf("应拒绝: %s", tc.content)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("错误应含 %q: %v", tc.want, err)
			}
		})
	}
}

func TestLoadConfigDedupPorts(t *testing.T) {
	cfg, err := LoadConfig(writeOnly(t, `{"bridges":[{"name":"br0","ports":["eth2"," eth2 ","eth3"]}]}`))
	if err != nil {
		t.Fatalf("重复口应去重而非拒绝: %v", err)
	}
	if got := cfg.Bridges[0].Ports; len(got) != 2 || got[0] != "eth2" || got[1] != "eth3" {
		t.Fatalf("去重保序错误: %v", got)
	}
}

func TestFingerprint(t *testing.T) {
	base, err := LoadConfig(writeOnly(t, `{"bridges":[{"name":"br0","ports":["eth2"]}],"ip_forward":true,"updated_at":"t1"}`))
	if err != nil {
		t.Fatal(err)
	}
	sameSemantics, err := LoadConfig(writeOnly(t, `{"bridges":[{"name":"br0","ports":["eth2"]}],"ip_forward":true,"updated_at":"t2-仅时间戳变化"}`))
	if err != nil {
		t.Fatal(err)
	}
	changed, err := LoadConfig(writeOnly(t, `{"bridges":[{"name":"br0","ports":["eth2","eth3"]}],"ip_forward":true,"updated_at":"t1"}`))
	if err != nil {
		t.Fatal(err)
	}
	if base.fingerprint() != sameSemantics.fingerprint() {
		t.Fatal("updated_at 变化不应改变指纹（同一期望重复发布不触发重复执行）")
	}
	if base.fingerprint() == changed.fingerprint() {
		t.Fatal("执行字段变化应改变指纹")
	}
}
