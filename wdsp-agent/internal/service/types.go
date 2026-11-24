// Package service 跨平台系统服务管理（Linux systemd / macOS launchd / Windows SCM）。
//
// 纯 Go 零外部依赖：
//   - Linux：生成 /etc/systemd/system/wdsp-agent.service（自动适配低内核 CentOS 7）；
//   - macOS：生成 /Library/LaunchDaemons/com.jiuzhang.wdsp-agent.plist；
//   - Windows：通过 golang.org/x/sys/windows/svc 与 svc/mgr 原生注册并托管 WDSPAgent 服务。
package service

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	LinuxServiceName   = "wdsp-agent"
	LinuxUnitPath      = "/etc/systemd/system/wdsp-agent.service"
	DarwinServiceLabel = "com.jiuzhang.wdsp-agent"
	DarwinPlistPath    = "/Library/LaunchDaemons/com.jiuzhang.wdsp-agent.plist"
	WindowsServiceName = "WDSPAgent"
	WindowsDisplayName = "JiuZhang WDSP Traffic Agent"
	WindowsDescription = "JiuZhang WDSP distributed passive traffic & API observation agent."
)

// State 服务运行状态枚举。
type State string

const (
	StateRunning      State = "RUNNING"
	StateStopped      State = "STOPPED"
	StateNotInstalled State = "NOT_INSTALLED"
	StateUnknown      State = "UNKNOWN"
)

// Config 服务注册参数（所有路径应为绝对路径）。
type Config struct {
	BinaryPath string
	ConfigPath string
	StateDir   string
	LogDir     string
}

// StatusInfo 服务状态快照。
type StatusInfo struct {
	ServiceName string `json:"service_name"`
	State       State  `json:"state"`
	UnitPath    string `json:"unit_path,omitempty"`
	Detail      string `json:"detail,omitempty"`
}

// Manager 跨平台服务管理器接口。
type Manager interface {
	ServiceName() string
	UnitPath() string
	CheckPrivileges() error
	Install(cfg Config) error
	Uninstall() error
	Start() error
	Stop() error
	Restart() error
	Status() (StatusInfo, error)
}

// SupportsCapBPF 根据 Linux 内核版本串（如 "5.14.0-427.el9.x86_64"、"3.10.0-1160.el7"）
// 判断是否支持 CAP_BPF（Linux 5.8 引入）。低内核系统（如 CentOS 7/8）不写 CAP_BPF，
// 避免旧版 systemd 解析失败导致服务无法启动。
func SupportsCapBPF(kernelRelease string) bool {
	s := strings.TrimSpace(kernelRelease)
	if s == "" {
		return false
	}
	// 取第一个 '-' 或 '+' 之前的主次版本段
	if idx := strings.IndexAny(s, "-+_ "); idx >= 0 {
		s = s[:idx]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	return major > 5 || (major == 5 && minor >= 8)
}

// quoteSystemdArg 按 systemd ExecStart 规则对含空格或特殊字符的参数加引号。
func quoteSystemdArg(arg string) string {
	if !strings.ContainsAny(arg, " \t\n\"'\\") {
		return arg
	}
	esc := strings.ReplaceAll(arg, `\`, `\\`)
	esc = strings.ReplaceAll(esc, `"`, `\"`)
	return `"` + esc + `"`
}

// RenderSystemdUnit 渲染 Linux systemd unit 文件内容（纯函数，全平台可单测）。
func RenderSystemdUnit(cfg Config, includeCapBPF bool) string {
	caps := "CAP_NET_RAW CAP_NET_ADMIN"
	if includeCapBPF {
		caps += " CAP_BPF"
	}
	execStart := strings.Join([]string{
		quoteSystemdArg(cfg.BinaryPath),
		"run",
		"--config", quoteSystemdArg(cfg.ConfigPath),
		"--state-dir", quoteSystemdArg(cfg.StateDir),
	}, " ")
	var b strings.Builder
	b.WriteString("[Unit]\n")
	b.WriteString("Description=JiuZhang WDSP Distributed Traffic Agent\n")
	b.WriteString("After=network-online.target\n")
	b.WriteString("Wants=network-online.target\n\n")
	b.WriteString("[Service]\n")
	b.WriteString("Type=simple\n")
	b.WriteString("ExecStart=" + execStart + "\n")
	b.WriteString("Restart=always\n")
	b.WriteString("RestartSec=5\n")
	b.WriteString("TimeoutStopSec=15\n")
	b.WriteString("LimitNOFILE=65536\n")
	b.WriteString("AmbientCapabilities=" + caps + "\n")
	b.WriteString("CapabilityBoundingSet=" + caps + "\n")
	b.WriteString("NoNewPrivileges=true\n\n")
	b.WriteString("[Install]\n")
	b.WriteString("WantedBy=multi-user.target\n")
	return b.String()
}

func xmlEscape(s string) (string, error) {
	var buf bytes.Buffer
	if err := xml.EscapeText(&buf, []byte(s)); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// RenderLaunchdPlist 渲染 macOS LaunchDaemon plist（XML 转义安全，纯函数全平台可单测）。
func RenderLaunchdPlist(cfg Config) (string, error) {
	logFile := filepath.Join(cfg.LogDir, "wdsp-agent.log")
	args := []string{
		cfg.BinaryPath,
		"run",
		"--config", cfg.ConfigPath,
		"--state-dir", cfg.StateDir,
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0">` + "\n")
	b.WriteString("<dict>\n")
	b.WriteString("\t<key>Label</key>\n")
	b.WriteString("\t<string>" + DarwinServiceLabel + "</string>\n")
	b.WriteString("\t<key>ProgramArguments</key>\n")
	b.WriteString("\t<array>\n")
	for _, a := range args {
		esc, err := xmlEscape(a)
		if err != nil {
			return "", fmt.Errorf("转义 plist 参数失败: %w", err)
		}
		b.WriteString("\t\t<string>" + esc + "</string>\n")
	}
	b.WriteString("\t</array>\n")
	b.WriteString("\t<key>RunAtLoad</key>\n")
	b.WriteString("\t<true/>\n")
	b.WriteString("\t<key>KeepAlive</key>\n")
	b.WriteString("\t<true/>\n")
	escLog, err := xmlEscape(logFile)
	if err != nil {
		return "", fmt.Errorf("转义 plist 日志路径失败: %w", err)
	}
	b.WriteString("\t<key>StandardOutPath</key>\n")
	b.WriteString("\t<string>" + escLog + "</string>\n")
	b.WriteString("\t<key>StandardErrorPath</key>\n")
	b.WriteString("\t<string>" + escLog + "</string>\n")
	b.WriteString("\t<key>SoftResourceLimits</key>\n")
	b.WriteString("\t<dict>\n")
	b.WriteString("\t\t<key>NumberOfFiles</key>\n")
	b.WriteString("\t\t<integer>65536</integer>\n")
	b.WriteString("\t</dict>\n")
	b.WriteString("\t<key>HardResourceLimits</key>\n")
	b.WriteString("\t<dict>\n")
	b.WriteString("\t\t<key>NumberOfFiles</key>\n")
	b.WriteString("\t\t<integer>65536</integer>\n")
	b.WriteString("\t</dict>\n")
	b.WriteString("</dict>\n")
	b.WriteString("</plist>\n")
	return b.String(), nil
}

// BuildWindowsServiceArgs 构造 Windows SCM 启动参数切片。
func BuildWindowsServiceArgs(cfg Config) []string {
	return []string{
		"run",
		"--config", cfg.ConfigPath,
		"--state-dir", cfg.StateDir,
	}
}
