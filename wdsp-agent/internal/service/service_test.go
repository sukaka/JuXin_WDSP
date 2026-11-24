package service

import (
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSupportsCapBPF(t *testing.T) {
	cases := []struct {
		kernel string
		want   bool
	}{
		{"3.10.0-1160.el7.x86_64", false},
		{"4.18.0-513.el8.x86_64", false},
		{"5.4.0-150-generic", false},
		{"5.7.19", false},
		{"5.8.0-1-amd64", true},
		{"5.14.0-427.el9.x86_64", true},
		{"6.1.0-21-amd64", true},
		{"6.8.12", true},
		{"", false},
		{"invalid", false},
	}
	for _, tc := range cases {
		if got := SupportsCapBPF(tc.kernel); got != tc.want {
			t.Fatalf("SupportsCapBPF(%q)=%v, want %v", tc.kernel, got, tc.want)
		}
	}
}

func TestRenderSystemdUnit(t *testing.T) {
	cfg := Config{
		BinaryPath: "/usr/local/bin/wdsp-agent",
		ConfigPath: "/etc/wdsp-agent/agent.json",
		StateDir:   "/var/lib/wdsp-agent",
	}
	legacy := RenderSystemdUnit(cfg, false)
	if strings.Contains(legacy, "CAP_BPF") {
		t.Fatalf("CentOS 7/旧内核 unit 不应包含 CAP_BPF:\n%s", legacy)
	}
	if !strings.Contains(legacy, "AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN\n") {
		t.Fatalf("unit 缺少 CAP_NET_RAW/CAP_NET_ADMIN:\n%s", legacy)
	}
	if !strings.Contains(legacy, "ExecStart=/usr/local/bin/wdsp-agent run --config /etc/wdsp-agent/agent.json --state-dir /var/lib/wdsp-agent\n") {
		t.Fatalf("ExecStart 不符合预期:\n%s", legacy)
	}

	modern := RenderSystemdUnit(cfg, true)
	if !strings.Contains(modern, "AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_BPF\n") {
		t.Fatalf("现代内核 unit 应包含 CAP_BPF:\n%s", modern)
	}

	spaced := RenderSystemdUnit(Config{
		BinaryPath: "/opt/wdsp agent/wdsp-agent",
		ConfigPath: "/etc/wdsp agent/agent.json",
		StateDir:   "/var/lib/wdsp-agent",
	}, true)
	if !strings.Contains(spaced, `"/opt/wdsp agent/wdsp-agent"`) || !strings.Contains(spaced, `"/etc/wdsp agent/agent.json"`) {
		t.Fatalf("含空格路径应加引号:\n%s", spaced)
	}
}

func TestRenderLaunchdPlistValidXML(t *testing.T) {
	cfg := Config{
		BinaryPath: "/usr/local/bin/wdsp-agent",
		ConfigPath: "/Library/Application Support/WDSPAgent/agent.json",
		StateDir:   "/Library/Application Support/WDSPAgent/state",
		LogDir:     "/Library/Logs/WDSPAgent",
	}
	plist, err := RenderLaunchdPlist(cfg)
	if err != nil {
		t.Fatalf("RenderLaunchdPlist failed: %v", err)
	}
	var doc any
	if err := xml.Unmarshal([]byte(plist), &doc); err != nil {
		t.Fatalf("plist XML 无效: %v\n%s", err, plist)
	}
	if !strings.Contains(plist, DarwinServiceLabel) {
		t.Fatalf("plist 缺少 Label: %s", plist)
	}
	// macOS 本机额外跑系统原生 plutil -lint 校验
	if runtime.GOOS == "darwin" {
		if plutil, err := exec.LookPath("plutil"); err == nil {
			p := filepath.Join(t.TempDir(), "test.plist")
			if err := os.WriteFile(p, []byte(plist), 0o644); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command(plutil, "-lint", p).CombinedOutput(); err != nil {
				t.Fatalf("plutil -lint 失败: %v (%s)", err, string(out))
			}
		}
	}
}

func TestBuildWindowsServiceArgs(t *testing.T) {
	args := BuildWindowsServiceArgs(Config{
		BinaryPath: `C:\Program Files\JiuZhang\WDSPAgent\wdsp-agent.exe`,
		ConfigPath: `C:\ProgramData\JiuZhang\WDSPAgent\agent.json`,
		StateDir:   `C:\ProgramData\JiuZhang\WDSPAgent\state`,
	})
	want := []string{
		"run",
		"--config", `C:\ProgramData\JiuZhang\WDSPAgent\agent.json`,
		"--state-dir", `C:\ProgramData\JiuZhang\WDSPAgent\state`,
	}
	if strings.Join(args, "|") != strings.Join(want, "|") {
		t.Fatalf("args=%v want %v", args, want)
	}
}
